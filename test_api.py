"""
Comprehensive test suite for Ardent Intake API
Tests HMAC authentication, survey validation, and database operations
"""

import base64
import hashlib
import hmac
import json
import time
import uuid
from unittest.mock import Mock, patch, MagicMock
import pytest
import logging
from fastapi.testclient import TestClient

# Import the app and dependencies
from main import app, store
from db import DatabaseOperations, PhoneValidator

logging.basicConfig(level=logging.DEBUG)

# Test client
client = TestClient(app)

# Test credentials
TEST_SECRET_KEY = "sk_test_secret_key_demo_only_change_in_prod"
TEST_PUBLIC_KEY = "pk_test_123"
TEST_COMPANY_ID = "cmp_123"


# Helper functions
def generate_hmac_signature(method: str, path: str, company_id: str, body: dict) -> dict:
    """Generate HMAC signature and return headers"""
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    body_json = json.dumps(body)
    body_hash = hashlib.sha256(body_json.encode('utf-8')).hexdigest()
    
    # Build canonical string
    canonical = "\n".join([
        method,
        path,
        company_id,
        f"ts={timestamp}",
        f"nonce={nonce}",
        f"sha256={body_hash}"
    ])
    
    # Compute signature
    signature = hmac.new(
        TEST_SECRET_KEY.encode('utf-8'),
        canonical.encode('utf-8'),
        hashlib.sha256
    ).digest()
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    
    return {
        "Authorization": f"Ardent-HMAC key={TEST_PUBLIC_KEY}, ts={timestamp}, nonce={nonce}, sig={sig_b64}",
        "X-Ardent-Company": company_id,
        "Content-Type": "application/json"
    }


def get_valid_survey_payload():
    """Return a valid survey payload"""
    return {
        "email": "test@example.com",
        "name": "Test User",
        "businessName": "Tech Solutions Inc.",
        "phoneNumber": "+17786964111",
        "privacyConsent": True,
        "consentToUseAI": True,
        # Extra fields (allowed but not required)
        "businessType": "Technology",
        "employeeCount": "6-20",
        "revenue": "$100,000 - $500,000"
    }


# Fixtures
@pytest.fixture
def mock_db_pool():
    """Mock database pool"""
    with patch('main.db.db_pool') as mock_pool:
        mock_pool.__bool__ = Mock(return_value=True)
        yield mock_pool


@pytest.fixture
def mock_db_operations():
    """Mock database operations"""
    with patch.object(DatabaseOperations, 'insert_customer_and_survey') as mock_insert:
        mock_insert.return_value = 123  # Mock customer_id
        yield mock_insert


@pytest.fixture
def mock_phone_validator():
    """Mock phone validator"""
    with patch.object(PhoneValidator, 'validate') as mock_validate:
        mock_validate.return_value = {
            'status': 'approved',
            'reason': 'Valid number',
            'risk_level': 'none',
            'validated': True,
            'original_number': '+12045551234',
            'cleaned_number': '+12045551234'
        }
        yield mock_validate


@pytest.fixture(autouse=True)
def reset_store():
    """Reset in-memory store before each test"""
    store.nonce_cache.clear()
    store.idempotency_store.clear()
    store.submissions.clear()
    store.rate_limits.clear()
    yield


# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================

class TestAuthentication:
    """Test HMAC authentication"""
    
    def test_valid_hmac_signature(self, mock_db_pool, mock_db_operations, mock_phone_validator):
        """Test successful authentication with valid HMAC signature"""
        payload = get_valid_survey_payload()
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "accepted"
        assert data["company_id"] == TEST_COMPANY_ID
        assert "submission_id" in data
        assert "customer_id" in data
    
    def test_missing_authorization_header(self):
        """Test request without Authorization header"""
        payload = get_valid_survey_payload()
        headers = {
            "X-Ardent-Company": TEST_COMPANY_ID,
            "Content-Type": "application/json"
        }
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422  # FastAPI validation error
    
    def test_missing_company_header(self):
        """Test request without X-Ardent-Company header"""
        payload = get_valid_survey_payload()
        headers = {
            "Authorization": "Ardent-HMAC key=pk_test_123, ts=123, nonce=abc, sig=def",
            "Content-Type": "application/json"
        }
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422  # FastAPI validation error
    
    def test_invalid_signature(self, mock_db_pool):
        """Test request with invalid HMAC signature"""
        payload = get_valid_survey_payload()
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        # Corrupt the signature
        headers["Authorization"] = headers["Authorization"].replace("sig=", "sig=invalid")
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 401
        assert "invalid_signature" in response.json()["error"]["code"]
    
    def test_stale_timestamp(self, mock_db_pool):
        """Test request with stale timestamp (outside ±300s window)"""
        payload = get_valid_survey_payload()
        old_timestamp = str(int(time.time()) - 400)  # 400 seconds ago
        nonce = str(uuid.uuid4())
        
        body_json = json.dumps(payload)
        body_hash = hashlib.sha256(body_json.encode('utf-8')).hexdigest()
        
        canonical = "\n".join([
            "POST",
            "/api/v1/leads",
            TEST_COMPANY_ID,
            f"ts={old_timestamp}",
            f"nonce={nonce}",
            f"sha256={body_hash}"
        ])
        
        signature = hmac.new(
            TEST_SECRET_KEY.encode('utf-8'),
            canonical.encode('utf-8'),
            hashlib.sha256
        ).digest()
        sig_b64 = base64.b64encode(signature).decode('utf-8')
        
        headers = {
            "Authorization": f"Ardent-HMAC key={TEST_PUBLIC_KEY}, ts={old_timestamp}, nonce={nonce}, sig={sig_b64}",
            "X-Ardent-Company": TEST_COMPANY_ID,
            "Content-Type": "application/json"
        }
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 400
        assert "stale_timestamp" in response.json()["error"]["code"]
    
    def test_replay_attack_prevention(self, mock_db_pool, mock_db_operations, mock_phone_validator):
        """Test that the same nonce cannot be reused"""
        payload = get_valid_survey_payload()
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
       # First request - should succeed
        response1 = client.post("/api/v1/leads", json=payload, headers=headers)
        assert response1.status_code == 201
        
        # Second request with same nonce - should fail
        response2 = client.post("/api/v1/leads", json=payload, headers=headers)
        assert response2.status_code == 400
        assert "replay_detected" in response2.json()["error"]["code"]


# ============================================================================
# VALIDATION TESTS
# ============================================================================

class TestValidation:
    """Test payload validation"""
    
    def test_missing_email(self, mock_db_pool):
        """Test request missing email field"""
        payload = get_valid_survey_payload()
        del payload["email"]
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422  # Pydantic validation error
    
    def test_missing_name(self, mock_db_pool):
        """Test request missing name field"""
        payload = get_valid_survey_payload()
        del payload["name"]
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422
    
    def test_missing_phone_number(self, mock_db_pool):
        """Test request missing phoneNumber field"""
        payload = get_valid_survey_payload()
        del payload["phoneNumber"]
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        print(response.json())
        
        assert response.status_code == 422
    
    def test_missing_business_name(self, mock_db_pool):
        """Test request missing businessName field"""
        payload = get_valid_survey_payload()
        del payload["businessName"]
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422
    
    def test_missing_privacy_consent(self, mock_db_pool):
        """Test request missing privacyConsent field"""
        payload = get_valid_survey_payload()
        del payload["privacyConsent"]
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422
    
    def test_missing_consent_to_use_ai(self, mock_db_pool):
        """Test request missing consentToUseAI field"""
        payload = get_valid_survey_payload()
        del payload["consentToUseAI"]
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422
    
    def test_invalid_email_format(self, mock_db_pool):
        """Test request with invalid email format"""
        payload = get_valid_survey_payload()
        payload["email"] = "not-an-email"
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422
    
    def test_invalid_phone_format(self, mock_db_pool):
        """Test request with invalid phone number format (not E.164)"""
        payload = get_valid_survey_payload()
        payload["phoneNumber"] = "1234567890"  # Missing + prefix
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422
    
    def test_empty_name(self, mock_db_pool):
        """Test request with empty name"""
        payload = get_valid_survey_payload()
        payload["name"] = ""
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422
    
    def test_extra_fields_allowed(self, mock_db_pool, mock_db_operations, mock_phone_validator):
        """Test that arbitrary extra fields are accepted"""
        payload = get_valid_survey_payload()
        # Add arbitrary extra fields
        payload["business_name"] = "Solar Solutions Ltd."
        payload["customField1"] = "custom value"
        payload["customField2"] = 12345
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "accepted"


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limit_exceeded(self, mock_db_pool, mock_db_operations, mock_phone_validator):
        """Test rate limit enforcement"""
        payload = get_valid_survey_payload()
        
        # Make 600 requests (the limit)
        for i in range(600):
            headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
            response = client.post("/api/v1/leads", json=payload, headers=headers)
            assert response.status_code == 201
        
        # 601st request should be rate limited
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 429
        assert "rate_limit_exceeded" in response.json()["error"]["code"]


# ============================================================================
# IDEMPOTENCY TESTS
# ============================================================================

class TestIdempotency:
    """Test idempotency functionality"""
    
    def test_idempotent_request_same_body(self, mock_db_pool, mock_db_operations, mock_phone_validator):
        """Test that same idempotency key with same body returns same result"""
        payload = get_valid_survey_payload()
        idempotency_key = str(uuid.uuid4())
        
        # First request
        headers1 = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        headers1["Idempotency-Key"] = idempotency_key
        response1 = client.post("/api/v1/leads", json=payload, headers=headers1)
        
        assert response1.status_code == 201
        data1 = response1.json()
        
        # Second request with same key and body (different nonce)
        headers2 = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        headers2["Idempotency-Key"] = idempotency_key
        response2 = client.post("/api/v1/leads", json=payload, headers=headers2)
        
        assert response2.status_code == 201
        data2 = response2.json()
        
        # Should return same submission_id
        assert data1["submission_id"] == data2["submission_id"]
    
    def test_idempotent_request_different_body(self, mock_db_pool, mock_db_operations, mock_phone_validator):
        """Test that same idempotency key with different body returns conflict"""
        payload1 = get_valid_survey_payload()
        payload2 = get_valid_survey_payload()
        payload2["name"] = "Different Name"
        
        idempotency_key = str(uuid.uuid4())
        
        # First request
        headers1 = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload1)
        headers1["Idempotency-Key"] = idempotency_key
        response1 = client.post("/api/v1/leads", json=payload1, headers=headers1)
        
        assert response1.status_code == 201
        
        # Second request with same key but different body
        headers2 = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload2)
        headers2["Idempotency-Key"] = idempotency_key
        response2 = client.post("/api/v1/leads", json=payload2, headers=headers2)
        
        assert response2.status_code == 409
        assert "idempotency_conflict" in response2.json()["error"]["code"]


# ============================================================================
# DATABASE TESTS
# ============================================================================

class TestDatabase:
    """Test database operations"""
    
    def test_database_unavailable(self):
        """Test request when database is not available"""
        with patch('main.db.db_pool', None):
            payload = get_valid_survey_payload()
            headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
            
            response = client.post("/api/v1/leads", json=payload, headers=headers)
            
            assert response.status_code == 503
            assert "database_unavailable" in response.json()["error"]["code"]
    
    def test_database_insert_called(self, mock_db_pool, mock_db_operations, mock_phone_validator):
        """Test that database insert is called with correct data"""
        payload = get_valid_survey_payload()
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 201
        assert mock_db_operations.called
        # Verify the survey data was passed correctly
        call_args = mock_db_operations.call_args[0]
        assert call_args[0].email == payload["email"]
        assert call_args[0].name == payload["name"]
    
    def test_database_error_handling(self, mock_db_pool, mock_phone_validator):
        """Test handling of database errors after retries"""
        with patch.object(DatabaseOperations, 'insert_customer_and_survey') as mock_insert:
            mock_insert.side_effect = Exception("Database error")
            
            payload = get_valid_survey_payload()
            headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
            
            response = client.post("/api/v1/leads", json=payload, headers=headers)
            
            assert response.status_code == 500
            assert "database_error" in response.json()["error"]["code"]


# ============================================================================
# HEALTH CHECK TESTS
# ============================================================================

class TestHealthCheck:
    """Test health check endpoint"""
    
    def test_health_check_with_database(self, mock_db_pool):
        """Test health check when database is available"""
        with patch.object(DatabaseOperations, 'get_connection') as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_get_conn.return_value = mock_conn
            
            with patch.object(DatabaseOperations, 'release_connection'):
                response = client.get("/api/v1/leads/health")
                
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "healthy"
                assert data["database"] == "connected"
    
    def test_health_check_without_database(self):
        """Test health check when database is not configured"""
        with patch('main.db.db_pool', None):
            response = client.get("/api/v1/leads/health")
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["database"] == "not_configured"
    
    def test_health_check_database_error(self, mock_db_pool):
        """Test health check when database has errors"""
        with patch.object(DatabaseOperations, 'get_connection') as mock_get_conn:
            mock_get_conn.side_effect = Exception("Connection error")
            
            response = client.get("/api/v1/leads/health")
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "degraded"
            assert data["database"] == "error"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])