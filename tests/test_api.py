"""
Comprehensive test suite for Ardent Intake API
Tests HMAC authentication, survey validation, and database operations
All tests use mocked database - no real DB required
"""

import base64
import hashlib
import hmac
import json
import time
import uuid
from unittest.mock import Mock, patch, MagicMock, ANY
from datetime import datetime, timezone, timedelta
import pytest
import logging
from fastapi.testclient import TestClient

# Import the app and dependencies
from main import app
from lib.db import DatabaseOperations
from lib.phone_validator import PhoneValidator
from lib.store import store

logging.basicConfig(level=logging.DEBUG)

# Test client
client = TestClient(app)

# Test credentials (now from mocked DB)
TEST_SECRET_KEY = "sk_test_secret_key_demo_only_change_in_prod"
TEST_PUBLIC_KEY = "pk_test_123"
TEST_COMPANY_ID = "123"


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


def generate_hmac_signature_for_get(method: str, path: str, company_id: str, query_params: dict = None) -> dict:
    """Generate HMAC signature for GET requests (empty body)"""
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    
    # For GET requests, body is empty so hash is of empty string
    body_hash = hashlib.sha256(b'').hexdigest()
    
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
        "X-Ardent-Company": company_id
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
    with patch('lib.db.db_pool') as mock_pool:
        mock_pool.__bool__ = Mock(return_value=True)
        yield mock_pool


@pytest.fixture
def mock_api_key_lookup():
    """Mock API key lookup from database"""
    with patch.object(DatabaseOperations, 'get_api_key_by_public_key') as mock_lookup:
        # Return valid API key info for TEST_PUBLIC_KEY
        mock_lookup.return_value = {
            'api_key_id': 1,
            'public_key': TEST_PUBLIC_KEY,
            'secret_key': TEST_SECRET_KEY,
            'api_key_active': True,
            'api_key_expires_at': None,
            'company_id': 123,
            'company_name': 'Test Company',
            'company_active': True
        }
        yield mock_lookup


@pytest.fixture
def mock_api_key_update():
    """Mock API key last_used_at update"""
    with patch.object(DatabaseOperations, 'update_api_key_last_used') as mock_update:
        mock_update.return_value = True
        yield mock_update


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
    """Test HMAC authentication with database-backed API keys"""
    
    def test_valid_hmac_signature(self, mock_db_pool, mock_api_key_lookup, mock_api_key_update, mock_db_operations, mock_phone_validator):
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
        
        # Verify API key lookup was called
        mock_api_key_lookup.assert_called_once_with(TEST_PUBLIC_KEY)
        # Verify last_used_at was updated
        mock_api_key_update.assert_called_once_with(1)
    
    def test_unknown_public_key(self, mock_db_pool):
        """Test request with unknown public key"""
        with patch.object(DatabaseOperations, 'get_api_key_by_public_key') as mock_lookup:
            mock_lookup.return_value = None  # Key not found
            
            payload = get_valid_survey_payload()
            headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
            
            response = client.post("/api/v1/leads", json=payload, headers=headers)
            
            assert response.status_code == 401
            assert "invalid_credentials" in response.json()["error"]["code"]
    
    def test_inactive_company(self, mock_db_pool):
        """Test request with inactive company"""
        with patch.object(DatabaseOperations, 'get_api_key_by_public_key') as mock_lookup:
            mock_lookup.return_value = {
                'api_key_id': 1,
                'public_key': TEST_PUBLIC_KEY,
                'secret_key': TEST_SECRET_KEY,
                'api_key_active': True,
                'api_key_expires_at': None,
                'company_id': 123,
                'company_name': 'Test Company',
                'company_active': False  # Company is inactive
            }
            
            payload = get_valid_survey_payload()
            headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
            
            response = client.post("/api/v1/leads", json=payload, headers=headers)
            
            assert response.status_code == 401
            assert "company_inactive" in response.json()["error"]["code"]
    
    def test_inactive_api_key(self, mock_db_pool):
        """Test request with inactive API key"""
        with patch.object(DatabaseOperations, 'get_api_key_by_public_key') as mock_lookup:
            mock_lookup.return_value = {
                'api_key_id': 1,
                'public_key': TEST_PUBLIC_KEY,
                'secret_key': TEST_SECRET_KEY,
                'api_key_active': False,  # API key is inactive
                'api_key_expires_at': None,
                'company_id': 123,
                'company_name': 'Test Company',
                'company_active': True
            }
            
            payload = get_valid_survey_payload()
            headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
            
            response = client.post("/api/v1/leads", json=payload, headers=headers)
            
            assert response.status_code == 401
            assert "api_key_inactive" in response.json()["error"]["code"]
    
    def test_expired_api_key(self, mock_db_pool):
        """Test request with expired API key"""
        with patch.object(DatabaseOperations, 'get_api_key_by_public_key') as mock_lookup:
            # Create an expired timestamp
            expired_time = datetime.now(timezone.utc) - timedelta(days=1)
            
            mock_lookup.return_value = {
                'api_key_id': 1,
                'public_key': TEST_PUBLIC_KEY,
                'secret_key': TEST_SECRET_KEY,
                'api_key_active': True,
                'api_key_expires_at': expired_time,  # Expired yesterday
                'company_id': 123,
                'company_name': 'Test Company',
                'company_active': True
            }
            
            payload = get_valid_survey_payload()
            headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
            
            response = client.post("/api/v1/leads", json=payload, headers=headers)
            
            assert response.status_code == 401
            assert "api_key_expired" in response.json()["error"]["code"]
    
    def test_missing_authorization_header(self):
        """Test request without Authorization header"""
        payload = get_valid_survey_payload()
        headers = {
            "X-Ardent-Company": TEST_COMPANY_ID,
            "Content-Type": "application/json"
        }
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 422  # FastAPI validation error
    
    def test_invalid_signature(self, mock_db_pool, mock_api_key_lookup, mock_api_key_update):
        """Test request with invalid HMAC signature"""
        payload = get_valid_survey_payload()
        headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
        
        # Corrupt the signature
        headers["Authorization"] = headers["Authorization"].replace("sig=", "sig=invalid")
        
        response = client.post("/api/v1/leads", json=payload, headers=headers)
        
        assert response.status_code == 401
        assert "invalid_signature" in response.json()["error"]["code"]
    
    def test_replay_attack_prevention(self, mock_db_pool, mock_api_key_lookup, mock_api_key_update, mock_db_operations, mock_phone_validator):
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
# DATABASE TESTS
# ============================================================================

class TestDatabase:
    """Test database operations"""
    
    def test_database_unavailable(self):
        """Test request when database is not available"""
        with patch('lib.db.db_pool', None):
            payload = get_valid_survey_payload()
            headers = generate_hmac_signature("POST", "/api/v1/leads", TEST_COMPANY_ID, payload)
            
            response = client.post("/api/v1/leads", json=payload, headers=headers)
            
            assert response.status_code == 503
            assert "database_unavailable" in response.json()["error"]["code"]
    
    def test_database_insert_called(self, mock_db_pool, mock_api_key_lookup, mock_api_key_update, mock_db_operations, mock_phone_validator):
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


# ============================================================================
# LEAD STATUS GET ENDPOINT TESTS
# ============================================================================

class TestLeadStatusEndpoint:
    """Test GET /api/v1/lead-status endpoint"""
    
    def test_successful_lead_status_retrieval(self, mock_db_pool, mock_api_key_lookup, mock_api_key_update):
        """Test successful retrieval of lead status with call_summary"""
        company_id = TEST_COMPANY_ID
        submission_id = "sub_test123"
        
        # Mock database response
        with patch.object(DatabaseOperations, 'get_lead_status') as mock_get_status:
            mock_get_status.return_value = {
                'call_summary': 'Customer interested in solar panels',
                'processed': True
            }
            
            headers = generate_hmac_signature_for_get(
                "GET",
                "/api/v1/lead-status",
                company_id
            )
            
            response = client.get(
                f"/api/v1/lead-status?company_id={company_id}&submission_id={submission_id}",
                headers=headers
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["company_id"] == company_id
            assert data["submission_id"] == submission_id
            assert data["call_summary"] == "Customer interested in solar panels"
            
            # Verify database was called with correct params
            mock_get_status.assert_called_once_with(company_id, submission_id)
    
    def test_lead_not_found(self, mock_db_pool, mock_api_key_lookup, mock_api_key_update):
        """Test 404 when lead does not exist"""
        company_id = TEST_COMPANY_ID
        submission_id = "sub_nonexistent"
        
        # Mock database response - no record found
        with patch.object(DatabaseOperations, 'get_lead_status') as mock_get_status:
            mock_get_status.return_value = None
            
            headers = generate_hmac_signature_for_get(
                "GET",
                "/api/v1/lead-status",
                company_id
            )
            
            response = client.get(
                f"/api/v1/lead-status?company_id={company_id}&submission_id={submission_id}",
                headers=headers
            )
            
            assert response.status_code == 404
            data = response.json()
            assert data["error"] == "not_found"


class TestGetLeadsEndpoint:
    """Test GET /api/v1/get-leads endpoint"""
    
    def test_successful_get_leads(self, mock_db_pool, mock_api_key_lookup, mock_api_key_update):
        """Test successful retrieval of leads within date range"""
        company_id = TEST_COMPANY_ID
        start_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        end_date = datetime.now(timezone.utc).isoformat()
        
        db_results = [
            {
                "customer_name": "Alice",
                "email": "alice@example.com",
                "phone_number": "+15550000001",
                "processed": True,
                "call_summary": "Interested in solar panels",
                "transcript": "Call transcript 1"
            },
            {
                "customer_name": "Bob",
                "email": "bob@example.com",
                "phone_number": "+15550000002",
                "processed": False,
                "call_summary": "Initial notes",
                "transcript": ""
            },
            {
                "customer_name": "Cara",
                "email": "cara@example.com",
                "phone_number": "+15550000003",
                "processed": False,
                "call_summary": "",
                "transcript": ""
            }
        ]
        
        with patch.object(DatabaseOperations, 'get_leads') as mock_get_leads:
            mock_get_leads.return_value = db_results
            
            headers = generate_hmac_signature_for_get(
                "GET",
                "/api/v1/get-leads",
                company_id
            )
            
            response = client.get(
                f"/api/v1/get-leads?company_id={company_id}&start_date={start_date}&end_date={end_date}",
                headers=headers
            )
            
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 3
            assert data[0]["status"] == "ready"
            assert data[1]["status"] == "being processed"
            assert data[2]["status"] == "new"
            mock_get_leads.assert_called_once_with(company_id, ANY, ANY)
    
    def test_start_date_in_future(self, mock_db_pool, mock_api_key_lookup, mock_api_key_update):
        """start_date in the future should return 400"""
        company_id = TEST_COMPANY_ID
        start_date = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        end_date = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        
        headers = generate_hmac_signature_for_get(
            "GET",
            "/api/v1/get-leads",
            company_id
        )
        
        response = client.get(
            f"/api/v1/get-leads?company_id={company_id}&start_date={start_date}&end_date={end_date}",
            headers=headers
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "invalid_date_range"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
