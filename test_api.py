"""
Pytest test suite for Ardent Intake API
Tests all security features and edge cases
"""

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Dict, Any

import pytest
from fastapi.testclient import TestClient

from main import app, store


# Test client
client = TestClient(app)


# Test configuration
PUBLIC_KEY = "pk_test_123"
SECRET_KEY = "sk_test_secret_key_demo_only_change_in_prod"
COMPANY_ID = "cmp_123"


def build_canonical_string(
    method: str,
    path: str,
    company_id: str,
    timestamp: str,
    nonce: str,
    body_hash: str
) -> str:
    """Build canonical string for HMAC signature"""
    return "\n".join([
        method,
        path,
        company_id,
        f"ts={timestamp}",
        f"nonce={nonce}",
        f"sha256={body_hash}"
    ])


def create_hmac_signature(
    method: str,
    path: str,
    company_id: str,
    timestamp: str,
    nonce: str,
    body: str,
    secret_key: str
) -> str:
    """Create HMAC-SHA256 signature for request"""
    body_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()
    
    canonical = build_canonical_string(
        method=method,
        path=path,
        company_id=company_id,
        timestamp=timestamp,
        nonce=nonce,
        body_hash=body_hash
    )
    
    signature = hmac.new(
        secret_key.encode('utf-8'),
        canonical.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    return base64.b64encode(signature).decode('utf-8')


def make_signed_request(
    payload: Dict[str, Any],
    public_key: str = PUBLIC_KEY,
    secret_key: str = SECRET_KEY,
    company_id: str = COMPANY_ID,
    idempotency_key: str = None,
    nonce: str = None,
    timestamp: int = None,
    invalid_sig: bool = False,
    invalid_key: bool = False
):
    """Helper to create signed requests"""
    method = "POST"
    path = "/v1/intake/leads"
    
    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        nonce = str(uuid.uuid4())
    
    timestamp_str = str(timestamp)
    body = json.dumps(payload)
    
    signature = create_hmac_signature(
        method=method,
        path=path,
        company_id=company_id,
        timestamp=timestamp_str,
        nonce=nonce,
        body=body,
        secret_key=secret_key
    )
    
    if invalid_sig:
        signature = signature[:-3] + "XXX"
    
    if invalid_key:
        public_key = "invalid_key_123"
    
    headers = {
        "Content-Type": "application/json",
        "X-Ardent-Company": company_id,
        "Authorization": f"Ardent-HMAC key={public_key}, ts={timestamp_str}, nonce={nonce}, sig={signature}"
    }
    
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    
    return client.post(path, json=payload, headers=headers)


@pytest.fixture(autouse=True)
def reset_store():
    """Reset in-memory stores before each test"""
    store.nonce_cache.clear()
    store.idempotency_store.clear()
    store.rate_limits.clear()
    store.submissions.clear()
    yield


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check(self):
        """Health endpoint should return 200"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "ardent-intake-api"


class TestAuthenticationSuccess:
    """Test successful authentication scenarios"""
    
    def test_valid_request(self):
        """Valid signed request should succeed"""
        payload = {
            "data": {
                "client_name": "Jane Doe",
                "client_email": "jane@example.com"
            },
            "context": {
                "source_url": "https://example.com/signup"
            }
        }
        
        response = make_signed_request(payload)
        assert response.status_code == 201
        data = response.json()
        assert "submission_id" in data
        assert data["company_id"] == COMPANY_ID
        assert data["status"] == "accepted"
        assert "received_at" in data
    
    def test_minimal_payload(self):
        """Request with minimal data field should work"""
        payload = {"data": {"email": "test@example.com"}}
        
        response = make_signed_request(payload)
        assert response.status_code == 201
    
    def test_complex_nested_data(self):
        """Request with complex nested data should work"""
        payload = {
            "data": {
                "personal": {
                    "name": "John",
                    "age": 30,
                    "addresses": [
                        {"type": "home", "city": "NYC"},
                        {"type": "work", "city": "SF"}
                    ]
                },
                "preferences": {
                    "notifications": True,
                    "language": "en"
                }
            }
        }
        
        response = make_signed_request(payload)
        assert response.status_code == 201


class TestAuthenticationFailures:
    """Test authentication failure scenarios"""
    
    def test_invalid_signature(self):
        """Invalid signature should return 401"""
        payload = {"data": {"email": "test@example.com"}}
        
        response = make_signed_request(payload, invalid_sig=True)
        assert response.status_code == 401
        data = response.json()
        assert data["error"]["code"] == "invalid_signature"
        assert not data["error"]["retryable"]
    
    def test_invalid_public_key(self):
        """Unknown public key should return 401"""
        payload = {"data": {"email": "test@example.com"}}
        
        response = make_signed_request(payload, invalid_key=True)
        assert response.status_code == 401
        data = response.json()
        assert data["error"]["code"] == "invalid_credentials"
    
    def test_company_id_mismatch(self):
        """Mismatched company ID should return 401"""
        payload = {"data": {"email": "test@example.com"}}
        
        response = make_signed_request(payload, company_id="wrong_company")
        assert response.status_code == 401
        data = response.json()
        assert data["error"]["code"] == "company_mismatch"
    
    def test_missing_authorization_header(self):
        """Missing Authorization header should return 422"""
        response = client.post(
            "/v1/intake/leads",
            json={"data": {"email": "test@example.com"}},
            headers={"Content-Type": "application/json", "X-Ardent-Company": COMPANY_ID}
        )
        assert response.status_code == 422
    
    def test_missing_company_header(self):
        """Missing X-Ardent-Company header should return 422"""
        payload = {"data": {"email": "test@example.com"}}
        nonce = str(uuid.uuid4())
        timestamp = str(int(time.time()))
        
        response = client.post(
            "/v1/intake/leads",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Ardent-HMAC key={PUBLIC_KEY}, ts={timestamp}, nonce={nonce}, sig=dummy"
            }
        )
        assert response.status_code == 422
    
    def test_malformed_authorization_header(self):
        """Malformed Authorization header should return 401"""
        response = client.post(
            "/v1/intake/leads",
            json={"data": {"email": "test@example.com"}},
            headers={
                "Content-Type": "application/json",
                "X-Ardent-Company": COMPANY_ID,
                "Authorization": "Bearer invalid_token"
            }
        )
        assert response.status_code == 401


class TestTimestampValidation:
    """Test timestamp validation"""
    
    def test_timestamp_within_window(self):
        """Timestamp within ±300s should succeed"""
        payload = {"data": {"email": "test@example.com"}}
        
        # Test with current time
        response = make_signed_request(payload)
        assert response.status_code == 201
        
        # Test with time 200s in the past
        past_time = int(time.time()) - 200
        response = make_signed_request(payload, timestamp=past_time)
        assert response.status_code == 201
        
        # Test with time 200s in the future
        future_time = int(time.time()) + 200
        response = make_signed_request(payload, timestamp=future_time)
        assert response.status_code == 201
    
    def test_stale_timestamp_past(self):
        """Timestamp >300s in the past should be rejected"""
        payload = {"data": {"email": "test@example.com"}}
        old_timestamp = int(time.time()) - 400
        
        response = make_signed_request(payload, timestamp=old_timestamp)
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "stale_timestamp"
        assert data["error"]["retryable"]
    
    def test_stale_timestamp_future(self):
        """Timestamp >300s in the future should be rejected"""
        payload = {"data": {"email": "test@example.com"}}
        future_timestamp = int(time.time()) + 400
        
        response = make_signed_request(payload, timestamp=future_timestamp)
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "stale_timestamp"
    
    def test_invalid_timestamp_format(self):
        """Non-numeric timestamp should be rejected"""
        payload = {"data": {"email": "test@example.com"}}
        nonce = str(uuid.uuid4())
        
        response = client.post(
            "/v1/intake/leads",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Ardent-Company": COMPANY_ID,
                "Authorization": f"Ardent-HMAC key={PUBLIC_KEY}, ts=invalid, nonce={nonce}, sig=dummy"
            }
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "invalid_timestamp"


class TestReplayProtection:
    """Test nonce replay protection"""
    
    def test_nonce_reuse_rejected(self):
        """Reusing a nonce should be rejected"""
        payload = {"data": {"email": "test@example.com"}}
        nonce = str(uuid.uuid4())
        
        # First request should succeed
        response1 = make_signed_request(payload, nonce=nonce)
        assert response1.status_code == 201
        
        # Second request with same nonce should fail
        response2 = make_signed_request(payload, nonce=nonce)
        assert response2.status_code == 400
        data = response2.json()
        assert data["error"]["code"] == "replay_detected"
        assert not data["error"]["retryable"]
    
    def test_different_nonces_allowed(self):
        """Different nonces should all succeed"""
        payload = {"data": {"email": "test@example.com"}}
        
        response1 = make_signed_request(payload, nonce=str(uuid.uuid4()))
        assert response1.status_code == 201
        
        response2 = make_signed_request(payload, nonce=str(uuid.uuid4()))
        assert response2.status_code == 201
        
        response3 = make_signed_request(payload, nonce=str(uuid.uuid4()))
        assert response3.status_code == 201


class TestIdempotency:
    """Test idempotency key handling"""
    
    def test_idempotency_same_key_same_body(self):
        """Same key and body should return same submission_id"""
        payload = {"data": {"email": "test@example.com"}}
        idem_key = f"idem_{uuid.uuid4()}"
        
        response1 = make_signed_request(payload, idempotency_key=idem_key)
        assert response1.status_code == 201
        submission_id1 = response1.json()["submission_id"]
        
        response2 = make_signed_request(payload, idempotency_key=idem_key)
        assert response2.status_code == 201
        submission_id2 = response2.json()["submission_id"]
        
        assert submission_id1 == submission_id2
    
    def test_idempotency_same_key_different_body(self):
        """Same key but different body should return 409 conflict"""
        idem_key = f"idem_{uuid.uuid4()}"
        
        payload1 = {"data": {"email": "test1@example.com"}}
        response1 = make_signed_request(payload1, idempotency_key=idem_key)
        assert response1.status_code == 201
        
        payload2 = {"data": {"email": "test2@example.com"}}
        response2 = make_signed_request(payload2, idempotency_key=idem_key)
        assert response2.status_code == 409
        data = response2.json()
        assert data["error"]["code"] == "idempotency_conflict"
        assert not data["error"]["retryable"]
    
    def test_no_idempotency_key(self):
        """Without idempotency key, same payload should create new submissions"""
        payload = {"data": {"email": "test@example.com"}}
        
        response1 = make_signed_request(payload)
        assert response1.status_code == 201
        submission_id1 = response1.json()["submission_id"]
        
        response2 = make_signed_request(payload)
        assert response2.status_code == 201
        submission_id2 = response2.json()["submission_id"]
        
        assert submission_id1 != submission_id2


class TestRateLimiting:
    """Test rate limiting (600 requests per minute)"""
    
    def test_rate_limit_enforcement(self):
        """Exceeding 600 requests/minute should return 429"""
        payload = {"data": {"email": "test@example.com"}}
        
        # Simulate 600 requests
        for _ in range(600):
            store.check_rate_limit(COMPANY_ID)
        
        # 601st request should be rate limited
        response = make_signed_request(payload)
        assert response.status_code == 429
        data = response.json()
        assert data["error"]["code"] == "rate_limit_exceeded"
        assert data["error"]["retryable"]


class TestPayloadValidation:
    """Test request payload validation"""
    
    def test_missing_data_field(self):
        """Request without 'data' field should be rejected"""
        payload = {"context": {"source_url": "https://example.com"}}
        
        response = make_signed_request(payload)
        assert response.status_code == 422
    
    def test_data_not_object(self):
        """'data' field must be an object, not string/array"""
        payload = {"data": "invalid_string"}
        
        response = make_signed_request(payload)
        assert response.status_code == 422
    
    def test_empty_data_object(self):
        """Empty data object should be accepted"""
        payload = {"data": {}}
        
        response = make_signed_request(payload)
        assert response.status_code == 201
    
    def test_oversized_payload(self):
        """Payload >64KB should be rejected"""
        # Create a large payload (>64KB)
        large_data = {"data": {"field": "x" * (65 * 1024)}}
        
        response = make_signed_request(large_data)
        assert response.status_code == 413
        data = response.json()
        assert data["error"]["code"] == "payload_too_large"


class TestRequestHeaders:
    """Test request header handling"""
    
    def test_request_id_in_response(self):
        """Response should include X-Request-ID header"""
        payload = {"data": {"email": "test@example.com"}}
        
        response = make_signed_request(payload)
        assert "x-request-id" in response.headers
        assert response.headers["x-request-id"].startswith("req_")
    
    def test_request_id_in_error(self):
        """Error responses should include request_id"""
        payload = {"data": {"email": "test@example.com"}}
        
        response = make_signed_request(payload, invalid_sig=True)
        assert response.status_code == 401
        data = response.json()
        assert "request_id" in data["error"]


class TestMultipleTenants:
    """Test multi-tenant isolation"""
    
    def test_different_companies(self):
        """Different companies should be isolated"""
        # Company 1
        payload1 = {"data": {"email": "company1@example.com"}}
        response1 = make_signed_request(
            payload1,
            public_key="pk_test_123",
            secret_key="sk_test_secret_key_demo_only_change_in_prod",
            company_id="cmp_123"
        )
        assert response1.status_code == 201
        assert response1.json()["company_id"] == "cmp_123"
        
        # Company 2
        payload2 = {"data": {"email": "company2@example.com"}}
        response2 = make_signed_request(
            payload2,
            public_key="pk_test_456",
            secret_key="sk_test_another_secret_key_for_testing",
            company_id="cmp_456"
        )
        assert response2.status_code == 201
        assert response2.json()["company_id"] == "cmp_456"