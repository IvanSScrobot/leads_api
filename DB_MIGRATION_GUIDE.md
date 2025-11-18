# Database-Backed API Key Authentication - Migration Guide

## Overview

The `leads_api` has been updated to replace in-memory API key storage with database-backed storage using the `api_keys` and `companies` tables. This provides better security, scalability, and management capabilities.

## Changes Made

### 1. Database Operations (`leads_api/db.py`)

Added two new methods to the `DatabaseOperations` class:

#### `get_api_key_by_public_key(public_key: str)`
- Fetches API key and company information from the database
- Performs a JOIN between `api_keys` and `companies` tables
- Returns all necessary information for validation:
  - API key details (id, public_key, secret_key, active status, expiration)
  - Company details (id, name, active status)
- Returns `None` if the public key doesn't exist

#### `update_api_key_last_used(api_key_id: int)`
- Updates the `last_used_at` timestamp for tracking API key usage
- Uses retry logic for reliability
- Non-blocking: failures are logged but don't affect authentication

### 2. Authentication Logic (`leads_api/main.py`)

#### Updated `verify_hmac_auth()` function:
- **Removed**: In-memory `store.companies` dictionary lookup
- **Added**: Database query via `DatabaseOperations.get_api_key_by_public_key()`
- **New validations**:
  - ✅ Company must be active (`companies.active = true`)
  - ✅ API key must be active (`api_keys.active = true`)
  - ✅ API key must not be expired (checks `api_keys.expires_at`)
- **Tracking**: Updates `api_keys.last_used_at` on successful authentication

#### Updated `InMemoryStore` class:
- **Removed**: `self.companies` dictionary (no longer needed)
- **Kept**: Runtime caches for:
  - Nonce replay protection (`nonce_cache`)
  - Idempotency tracking (`idempotency_store`)
  - Rate limiting (`rate_limits`)
  - Submission metadata (`submissions`)

## Database Schema - Current State

### Existing Tables

```sql
-- Companies table
CREATE TABLE companies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true
);

-- API Keys table
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES companies(id) ON UPDATE CASCADE ON DELETE CASCADE,
    public_key VARCHAR(255) NOT NULL UNIQUE,
    secret_key TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_api_keys_company_id ON api_keys(company_id);
```

## Recommended Database Schema Improvements

### 1. Add Index on `active` Status for Performance

```sql
-- Add composite index for faster lookups of active keys
CREATE INDEX idx_api_keys_public_key_active ON api_keys(public_key, active) 
WHERE active = true;

-- Add index for company active status
CREATE INDEX idx_companies_active ON companies(id, active) 
WHERE active = true;
```

**Rationale**: Most queries filter by `active = true`, so a partial index improves performance.

### 2. Add Metadata Columns for Auditing

```sql
-- Add metadata to api_keys table
ALTER TABLE api_keys 
    ADD COLUMN created_by VARCHAR(255),
    ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    ADD COLUMN updated_by VARCHAR(255),
    ADD COLUMN description TEXT,
    ADD COLUMN key_type VARCHAR(50) DEFAULT 'hmac';

-- Add trigger to auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_api_keys_updated_at 
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

**Rationale**: Helps with auditing and tracking who created/modified keys.

### 3. Add Rate Limit Configuration to Companies

```sql
-- Add rate limiting configuration per company
ALTER TABLE companies
    ADD COLUMN rate_limit_per_minute INTEGER DEFAULT 600,
    ADD COLUMN rate_limit_per_hour INTEGER DEFAULT 10000,
    ADD COLUMN created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT now();
```

**Rationale**: Allows per-company rate limit customization instead of hardcoded values.

### 4. Add API Key Scope/Permissions

```sql
-- Add permissions/scopes to api_keys
ALTER TABLE api_keys
    ADD COLUMN scopes TEXT[] DEFAULT ARRAY['leads:write', 'leads:read'],
    ADD COLUMN ip_whitelist INET[],
    ADD COLUMN environment VARCHAR(50) DEFAULT 'production';

-- Add check constraint for environment
ALTER TABLE api_keys
    ADD CONSTRAINT check_environment 
    CHECK (environment IN ('development', 'staging', 'production'));
```

**Rationale**: Enables fine-grained access control and security restrictions.

### 5. Add API Key Usage Statistics Table

```sql
-- Track API key usage statistics
CREATE TABLE api_key_usage_stats (
    id BIGSERIAL PRIMARY KEY,
    api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    request_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    last_success_at TIMESTAMP WITH TIME ZONE,
    last_failure_at TIMESTAMP WITH TIME ZONE,
    stat_date DATE NOT NULL DEFAULT CURRENT_DATE,
    UNIQUE(api_key_id, stat_date)
);

CREATE INDEX idx_api_key_usage_stats_key_date ON api_key_usage_stats(api_key_id, stat_date);
```

**Rationale**: Enables usage analytics and monitoring without querying production logs.

### 6. Add Security Events Table

```sql
-- Track security events for API keys
CREATE TABLE api_key_security_events (
    id BIGSERIAL PRIMARY KEY,
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
    public_key VARCHAR(255),
    event_type VARCHAR(100) NOT NULL,
    event_details JSONB,
    source_ip INET,
    user_agent TEXT,
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE INDEX idx_security_events_api_key ON api_key_security_events(api_key_id, occurred_at DESC);
CREATE INDEX idx_security_events_type ON api_key_security_events(event_type, occurred_at DESC);
```

**Rationale**: Tracks security events like expired keys, inactive companies, failed authentications.

## Migration Steps

### Step 1: Create Test Data

```sql
-- Insert test companies
INSERT INTO companies (id, name, active) VALUES
(123, 'Test Company 123', true),
(456, 'Test Company 456', true)
ON CONFLICT (id) DO NOTHING;

-- Insert test API keys (matching the old hardcoded values)
INSERT INTO api_keys (company_id, public_key, secret_key, active) VALUES
(123, 'pk_test_123', 'sk_test_secret_key_demo_only_change_in_prod', true),
(456, 'pk_test_456', 'sk_test_another_secret_key_for_testing', true)
ON CONFLICT (public_key) DO NOTHING;
```

### Step 2: Apply Schema Improvements (Optional)

Apply the recommended schema improvements from above in order to enhance security and monitoring.

### Step 3: Update Environment Variables

Remove the hardcoded HMAC secrets from `.env` (they're now in the database):

```bash
# REMOVE these lines (no longer needed):
# HMAC_SECRET_KEY_PK_TEST_123=sk_test_secret_key_demo_only_change_in_prod
# HMAC_SECRET_KEY_PK_TEST_456=sk_test_another_secret_key_for_testing

# ENSURE database connection is configured:
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=ardent_survey
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_secure_password_here
```

### Step 4: Deploy Updated Code

Deploy the updated `leads_api/main.py` and `leads_api/db.py` files.

### Step 5: Verify Authentication

Test authentication with existing keys:

```bash
# Test with pk_test_123
curl -X POST https://your-api.com/api/v1/leads \
  -H "Authorization: Ardent-HMAC key=pk_test_123, ts=<timestamp>, nonce=<uuid>, sig=<signature>" \
  -H "X-Ardent-Company: 123" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","businessName":"Test Co",...}'
```

## Security Improvements

### Before (In-Memory)
- ❌ API keys hardcoded in environment variables
- ❌ No expiration support
- ❌ No active/inactive status
- ❌ No tracking of last usage
- ❌ Manual key rotation required code changes

### After (Database-Backed)
- ✅ API keys stored securely in database
- ✅ Support for key expiration (`expires_at`)
- ✅ Active/inactive status for keys and companies
- ✅ Automatic tracking of `last_used_at`
- ✅ Easy key rotation via database updates
- ✅ Company-level access control
- ✅ Centralized key management

## Key Management Operations

### Create a New API Key

```sql
INSERT INTO api_keys (company_id, public_key, secret_key, active, expires_at)
VALUES (
    123,
    'pk_prod_' || md5(random()::text),
    'sk_' || encode(gen_random_bytes(32), 'base64'),
    true,
    NOW() + INTERVAL '1 year'
);
```

### Rotate an API Key (Mark Old Inactive, Create New)

```sql
BEGIN;

-- Deactivate old key
UPDATE api_keys 
SET active = false 
WHERE public_key = 'pk_old_key_123';

-- Create new key
INSERT INTO api_keys (company_id, public_key, secret_key, active)
VALUES (123, 'pk_new_key_456', 'sk_new_secret', true);

COMMIT;
```

### Deactivate a Company

```sql
-- This will prevent all API keys for this company from authenticating
UPDATE companies 
SET active = false 
WHERE id = 123;
```

### Check Last Usage

```sql
SELECT 
    ak.public_key,
    ak.last_used_at,
    c.name as company_name,
    ak.active as key_active,
    c.active as company_active
FROM api_keys ak
JOIN companies c ON ak.company_id = c.id
ORDER BY ak.last_used_at DESC NULLS LAST;
```

## Testing Checklist

- [ ] Test authentication with valid active key
- [ ] Test authentication with inactive key (should fail with `api_key_inactive`)
- [ ] Test authentication with inactive company (should fail with `company_inactive`)
- [ ] Test authentication with expired key (should fail with `api_key_expired`)
- [ ] Test authentication with non-existent key (should fail with `invalid_credentials`)
- [ ] Test company ID mismatch (should fail with `company_mismatch`)
- [ ] Verify `last_used_at` is updated after successful auth
- [ ] Test database unavailability (should return `database_unavailable` error)

## Monitoring

### Key Metrics to Monitor

1. **API Key Usage**: Check `last_used_at` to identify unused keys
2. **Authentication Failures**: Monitor logs for `invalid_credentials`, `api_key_inactive`, etc.
3. **Expired Keys**: Query for keys approaching expiration
4. **Database Performance**: Monitor query performance on `api_keys` table

### Query for Keys Expiring Soon

```sql
SELECT 
    ak.public_key,
    c.name as company_name,
    ak.expires_at,
    (ak.expires_at - NOW()) as time_until_expiry
FROM api_keys ak
JOIN companies c ON ak.company_id = c.id
WHERE ak.active = true
  AND ak.expires_at IS NOT NULL
  AND ak.expires_at < NOW() + INTERVAL '30 days'
ORDER BY ak.expires_at ASC;
```

## Rollback Plan

If issues occur, you can temporarily rollback by:

1. Reverting `leads_api/main.py` and `leads_api/db.py` to previous versions
2. Re-adding HMAC secrets to environment variables
3. The database tables can remain (they won't interfere)

## Support

For questions or issues, please refer to:
- Database schema: `\d api_keys` and `\d companies` in PostgreSQL
- Application logs: Check for authentication-related errors
- API documentation: See main README.md