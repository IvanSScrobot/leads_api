"""
Test client for Ardent Intake API
Demonstrates HMAC authentication with various scenarios
"""

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Dict, Any

import httpx


# Configuration
API_BASE_URL = "http://localhost:8000"
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
    # Hash the body
    body_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()
    
    # Build canonical string
    canonical = build_canonical_string(
        method=method,
        path=path,
        company_id=company_id,
        timestamp=timestamp,
        nonce=nonce,
        body_hash=body_hash
    )
    
    # Compute HMAC signature
    signature = hmac.new(
        secret_key.encode('utf-8'),
        canonical.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    # Return base64-encoded signature
    return base64.b64encode(signature).decode('utf-8')


def send_signed_request(
    payload: Dict[str, Any],
    public_key: str = PUBLIC_KEY,
    secret_key: str = SECRET_KEY,
    company_id: str = COMPANY_ID,
    idempotency_key: str = None,
    nonce: str = None,
    timestamp: int = None,
    invalid_sig: bool = False
) -> httpx.Response:
    """
    Send a signed request to the intake API
    
    Args:
        payload: Request body
        public_key: Public key ID
        secret_key: Secret key for signing
        company_id: Company ID
        idempotency_key: Optional idempotency key
        nonce: Optional nonce (generated if not provided)
        timestamp: Optional timestamp (current time if not provided)
        invalid_sig: If True, corrupt the signature to test failure
    """
    # Prepare request
    method = "POST"
    path = "/v1/intake/leads"
    url = f"{API_BASE_URL}{path}"
    
    # Generate timestamp and nonce if not provided
    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        nonce = str(uuid.uuid4())
    
    timestamp_str = str(timestamp)
    body = json.dumps(payload)
    
    # Create signature
    signature = create_hmac_signature(
        method=method,
        path=path,
        company_id=company_id,
        timestamp=timestamp_str,
        nonce=nonce,
        body=body,
        secret_key=secret_key
    )
    
    # Optionally corrupt signature for testing
    if invalid_sig:
        signature = signature[:-3] + "XXX"
    
    # Build headers
    headers = {
        "Content-Type": "application/json",
        "X-Ardent-Company": company_id,
        "Authorization": f"Ardent-HMAC key={public_key}, ts={timestamp_str}, nonce={nonce}, sig={signature}"
    }
    
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    
    # Send request
    response = httpx.post(url, json=payload, headers=headers, timeout=10.0)
    return response


def print_response(response: httpx.Response, title: str):
    """Pretty print response"""
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")
    print(f"Status Code: {response.status_code}")
    print(f"Headers: {dict(response.headers)}")
    print(f"Body:")
    try:
        print(json.dumps(response.json(), indent=2))
    except:
        print(response.text)
    print(f"{'='*70}\n")


def main():
    """Run test scenarios"""
    
    print("\n" + "="*70)
    print("ARDENT INTAKE API - TEST CLIENT")
    print("="*70)
    
    # Test 1: Valid signed request (SUCCESS)
    print("\n[TEST 1] Valid signed request - Should succeed")
    payload1 = {
        "data": {
            "client_name": "Jane Doe",
            "client_email": "jane@example.com",
            "phone": "+1-555-0123"
        },
        "context": {
            "source_url": "https://partner.example.com/signup"
        }
    }
    
    try:
        response1 = send_signed_request(payload1)
        print_response(response1, "TEST 1: Valid Request")
        assert response1.status_code == 201, f"Expected 201, got {response1.status_code}"
        print("✅ TEST 1 PASSED")
    except Exception as e:
        print(f"❌ TEST 1 FAILED: {e}")
    
    # Test 2: Invalid signature (FAILURE)
    print("\n[TEST 2] Invalid signature - Should fail with 401")
    payload2 = {
        "data": {
            "client_name": "John Smith",
            "client_email": "john@example.com"
        }
    }
    
    try:
        response2 = send_signed_request(payload2, invalid_sig=True)
        print_response(response2, "TEST 2: Invalid Signature")
        assert response2.status_code == 401, f"Expected 401, got {response2.status_code}"
        error_data = response2.json()
        assert error_data["error"]["code"] == "invalid_signature", "Expected invalid_signature error"
        print("✅ TEST 2 PASSED")
    except Exception as e:
        print(f"❌ TEST 2 FAILED: {e}")
    
    # Test 3: Replay attack (REJECTED)
    print("\n[TEST 3] Replay attack - Should be rejected")
    payload3 = {
        "data": {
            "client_name": "Alice Brown",
            "client_email": "alice@example.com"
        }
    }
    
    # Use a fixed nonce for both requests
    replay_nonce = str(uuid.uuid4())
    
    try:
        # First request with the nonce (should succeed)
        response3a = send_signed_request(payload3, nonce=replay_nonce)
        print_response(response3a, "TEST 3a: First Request (Original)")
        assert response3a.status_code == 201, f"Expected 201, got {response3a.status_code}"
        
        # Second request with same nonce (should be rejected)
        time.sleep(0.5)  # Small delay
        response3b = send_signed_request(payload3, nonce=replay_nonce)
        print_response(response3b, "TEST 3b: Replay Request (Same Nonce)")
        assert response3b.status_code == 400, f"Expected 400, got {response3b.status_code}"
        error_data = response3b.json()
        assert error_data["error"]["code"] == "replay_detected", "Expected replay_detected error"
        print("✅ TEST 3 PASSED")
    except Exception as e:
        print(f"❌ TEST 3 FAILED: {e}")
    
    # Test 4: Idempotency - Same key, same body (SUCCESS)
    print("\n[TEST 4] Idempotency - Same key, same body")
    payload4 = {
        "data": {
            "client_name": "Bob Wilson",
            "client_email": "bob@example.com"
        }
    }
    
    idempotency_key = f"idem_{uuid.uuid4()}"
    
    try:
        # First request
        response4a = send_signed_request(payload4, idempotency_key=idempotency_key)
        print_response(response4a, "TEST 4a: First Request with Idempotency Key")
        assert response4a.status_code == 201, f"Expected 201, got {response4a.status_code}"
        submission_id_1 = response4a.json()["submission_id"]
        
        # Second request with same key and body (should return same submission_id)
        time.sleep(0.5)
        response4b = send_signed_request(payload4, idempotency_key=idempotency_key)
        print_response(response4b, "TEST 4b: Duplicate Request (Same Key, Same Body)")
        assert response4b.status_code == 201, f"Expected 201, got {response4b.status_code}"
        submission_id_2 = response4b.json()["submission_id"]
        assert submission_id_1 == submission_id_2, "Submission IDs should match for idempotent requests"
        print("✅ TEST 4 PASSED")
    except Exception as e:
        print(f"❌ TEST 4 FAILED: {e}")
    
    # Test 5: Idempotency conflict - Same key, different body (CONFLICT)
    print("\n[TEST 5] Idempotency conflict - Same key, different body")
    payload5a = {
        "data": {
            "client_name": "Charlie Davis",
            "client_email": "charlie@example.com"
        }
    }
    payload5b = {
        "data": {
            "client_name": "Charlie Davis",
            "client_email": "charlie_different@example.com"  # Different email
        }
    }
    
    idempotency_key2 = f"idem_{uuid.uuid4()}"
    
    try:
        # First request
        response5a = send_signed_request(payload5a, idempotency_key=idempotency_key2)
        print_response(response5a, "TEST 5a: First Request")
        assert response5a.status_code == 201, f"Expected 201, got {response5a.status_code}"
        
        # Second request with same key but different body (should fail with 409)
        time.sleep(0.5)
        response5b = send_signed_request(payload5b, idempotency_key=idempotency_key2)
        print_response(response5b, "TEST 5b: Conflict Request (Same Key, Different Body)")
        assert response5b.status_code == 409, f"Expected 409, got {response5b.status_code}"
        error_data = response5b.json()
        assert error_data["error"]["code"] == "idempotency_conflict", "Expected idempotency_conflict error"
        print("✅ TEST 5 PASSED")
    except Exception as e:
        print(f"❌ TEST 5 FAILED: {e}")
    
    # Test 6: Stale timestamp (REJECTED)
    print("\n[TEST 6] Stale timestamp - Should be rejected")
    payload6 = {
        "data": {
            "client_name": "Eve Miller",
            "client_email": "eve@example.com"
        }
    }
    
    try:
        # Use a timestamp from 10 minutes ago (outside ±300s window)
        old_timestamp = int(time.time()) - 600
        response6 = send_signed_request(payload6, timestamp=old_timestamp)
        print_response(response6, "TEST 6: Stale Timestamp")
        assert response6.status_code == 400, f"Expected 400, got {response6.status_code}"
        error_data = response6.json()
        assert error_data["error"]["code"] == "stale_timestamp", "Expected stale_timestamp error"
        print("✅ TEST 6 PASSED")
    except Exception as e:
        print(f"❌ TEST 6 FAILED: {e}")
    
    print("\n" + "="*70)
    print("ALL TESTS COMPLETED")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()