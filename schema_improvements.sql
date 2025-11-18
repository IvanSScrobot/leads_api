-- ============================================================================
-- Database Schema Improvements for API Key Management
-- ============================================================================
-- This script contains recommended improvements to the api_keys and companies
-- tables to enhance security, performance, and management capabilities.
--
-- Apply these changes after the base tables are created.
-- ============================================================================

-- ============================================================================
-- 1. Performance Indexes
-- ============================================================================

-- Add composite index for faster lookups of active keys
CREATE INDEX IF NOT EXISTS idx_api_keys_public_key_active 
ON api_keys(public_key, active) 
WHERE active = true;

-- Add index for company active status
CREATE INDEX IF NOT EXISTS idx_companies_active 
ON companies(id, active) 
WHERE active = true;

-- Add index for expired keys lookup
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at 
ON api_keys(expires_at) 
WHERE active = true AND expires_at IS NOT NULL;

-- ============================================================================
-- 2. Audit and Metadata Columns for API Keys
-- ============================================================================

-- Add metadata columns to api_keys table
ALTER TABLE api_keys 
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(255),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_by VARCHAR(255),
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS key_type VARCHAR(50) DEFAULT 'hmac';

-- Add auto-update trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_api_keys_updated_at ON api_keys;
CREATE TRIGGER update_api_keys_updated_at 
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 3. Company Metadata and Rate Limiting Configuration
-- ============================================================================

-- Add rate limiting and metadata to companies
ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS rate_limit_per_minute INTEGER DEFAULT 600,
    ADD COLUMN IF NOT EXISTS rate_limit_per_hour INTEGER DEFAULT 10000,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    ADD COLUMN IF NOT EXISTS description TEXT;

-- Add auto-update trigger for companies.updated_at
DROP TRIGGER IF EXISTS update_companies_updated_at ON companies;
CREATE TRIGGER update_companies_updated_at 
    BEFORE UPDATE ON companies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 4. API Key Permissions and Security Features
-- ============================================================================

-- Add security and permission columns
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS scopes TEXT[] DEFAULT ARRAY['leads:write', 'leads:read'],
    ADD COLUMN IF NOT EXISTS ip_whitelist INET[],
    ADD COLUMN IF NOT EXISTS environment VARCHAR(50) DEFAULT 'production';

-- Add check constraint for environment
ALTER TABLE api_keys
    DROP CONSTRAINT IF EXISTS check_environment;
ALTER TABLE api_keys
    ADD CONSTRAINT check_environment 
    CHECK (environment IN ('development', 'staging', 'production'));

-- ============================================================================
-- 5. API Key Usage Statistics Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_key_usage_stats (
    id BIGSERIAL PRIMARY KEY,
    api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    request_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    last_success_at TIMESTAMP WITH TIME ZONE,
    last_failure_at TIMESTAMP WITH TIME ZONE,
    stat_date DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    UNIQUE(api_key_id, stat_date)
);

CREATE INDEX IF NOT EXISTS idx_api_key_usage_stats_key_date 
ON api_key_usage_stats(api_key_id, stat_date DESC);

CREATE INDEX IF NOT EXISTS idx_api_key_usage_stats_date 
ON api_key_usage_stats(stat_date DESC);

-- ============================================================================
-- 6. Security Events Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_key_security_events (
    id BIGSERIAL PRIMARY KEY,
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
    public_key VARCHAR(255),
    event_type VARCHAR(100) NOT NULL,
    event_details JSONB,
    source_ip INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_security_events_api_key 
ON api_key_security_events(api_key_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_type 
ON api_key_security_events(event_type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_occurred 
ON api_key_security_events(occurred_at DESC);

-- ============================================================================
-- 7. Helper Views
-- ============================================================================

-- View for active API keys with company info
CREATE OR REPLACE VIEW v_active_api_keys AS
SELECT 
    ak.id,
    ak.public_key,
    ak.active as key_active,
    ak.expires_at,
    ak.last_used_at,
    ak.created_at as key_created_at,
    ak.scopes,
    ak.environment,
    c.id as company_id,
    c.name as company_name,
    c.active as company_active,
    c.rate_limit_per_minute,
    c.rate_limit_per_hour,
    CASE 
        WHEN ak.expires_at IS NOT NULL AND ak.expires_at < NOW() THEN 'expired'
        WHEN NOT ak.active THEN 'inactive'
        WHEN NOT c.active THEN 'company_inactive'
        ELSE 'active'
    END as status
FROM api_keys ak
JOIN companies c ON ak.company_id = c.id;

-- View for API key usage summary
CREATE OR REPLACE VIEW v_api_key_usage_summary AS
SELECT 
    ak.public_key,
    c.name as company_name,
    ak.last_used_at,
    COALESCE(SUM(us.request_count), 0) as total_requests,
    COALESCE(SUM(us.success_count), 0) as total_success,
    COALESCE(SUM(us.failure_count), 0) as total_failures,
    CASE 
        WHEN SUM(us.request_count) > 0 THEN 
            ROUND((SUM(us.success_count)::NUMERIC / SUM(us.request_count)::NUMERIC) * 100, 2)
        ELSE 0 
    END as success_rate_percent
FROM api_keys ak
JOIN companies c ON ak.company_id = c.id
LEFT JOIN api_key_usage_stats us ON ak.id = us.api_key_id
GROUP BY ak.id, ak.public_key, c.name, ak.last_used_at;

-- ============================================================================
-- 8. Helpful Functions
-- ============================================================================

-- Function to check if an API key is valid
CREATE OR REPLACE FUNCTION is_api_key_valid(p_public_key VARCHAR)
RETURNS TABLE(
    is_valid BOOLEAN,
    reason VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        CASE 
            WHEN ak.id IS NULL THEN FALSE
            WHEN NOT c.active THEN FALSE
            WHEN NOT ak.active THEN FALSE
            WHEN ak.expires_at IS NOT NULL AND ak.expires_at < NOW() THEN FALSE
            ELSE TRUE
        END as is_valid,
        CASE 
            WHEN ak.id IS NULL THEN 'Key not found'
            WHEN NOT c.active THEN 'Company inactive'
            WHEN NOT ak.active THEN 'Key inactive'
            WHEN ak.expires_at IS NOT NULL AND ak.expires_at < NOW() THEN 'Key expired'
            ELSE 'Valid'
        END as reason
    FROM api_keys ak
    JOIN companies c ON ak.company_id = c.id
    WHERE ak.public_key = p_public_key;
END;
$$ LANGUAGE plpgsql;

-- Function to get keys expiring soon
CREATE OR REPLACE FUNCTION get_expiring_keys(days_ahead INTEGER DEFAULT 30)
RETURNS TABLE(
    public_key VARCHAR,
    company_name VARCHAR,
    expires_at TIMESTAMP WITH TIME ZONE,
    days_until_expiry NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ak.public_key,
        c.name as company_name,
        ak.expires_at,
        ROUND(EXTRACT(EPOCH FROM (ak.expires_at - NOW())) / 86400, 1) as days_until_expiry
    FROM api_keys ak
    JOIN companies c ON ak.company_id = c.id
    WHERE ak.active = true
      AND ak.expires_at IS NOT NULL
      AND ak.expires_at < NOW() + (days_ahead || ' days')::INTERVAL
      AND ak.expires_at > NOW()
    ORDER BY ak.expires_at ASC;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 9. Sample Data for Testing (Optional - Comment out for production)
-- ============================================================================

-- Insert test companies if they don't exist
INSERT INTO companies (id, name, active, rate_limit_per_minute, description) VALUES
(123, 'Test Company 123', true, 600, 'Test company for development'),
(456, 'Test Company 456', true, 1000, 'Premium test company')
ON CONFLICT (id) DO NOTHING;

-- Insert test API keys (matching the old hardcoded values)
INSERT INTO api_keys (company_id, public_key, secret_key, active, description, environment) VALUES
(123, 'pk_test_123', 'sk_test_secret_key_demo_only_change_in_prod', true, 'Development test key', 'development'),
(456, 'pk_test_456', 'sk_test_another_secret_key_for_testing', true, 'Development test key', 'development')
ON CONFLICT (public_key) DO NOTHING;

-- ============================================================================
-- 10. Verification Queries
-- ============================================================================

-- Verify the schema improvements
DO $$
BEGIN
    RAISE NOTICE 'Schema improvements applied successfully!';
    RAISE NOTICE '';
    RAISE NOTICE 'Run these queries to verify:';
    RAISE NOTICE '1. SELECT * FROM v_active_api_keys;';
    RAISE NOTICE '2. SELECT * FROM is_api_key_valid(''pk_test_123'');';
    RAISE NOTICE '3. SELECT * FROM get_expiring_keys(30);';
    RAISE NOTICE '4. SELECT * FROM v_api_key_usage_summary;';
END $$;