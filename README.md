# Ardent Intake API

Production-grade FastAPI endpoint for secure lead ingestion with HMAC authentication, rate limiting, and replay protection.

## Features

- ✅ **HMAC-SHA256 Authentication** - Secure request signing with public/secret key pairs
- ✅ **Timestamp Validation** - Only accepts requests within ±300 seconds
- ✅ **Replay Protection** - Nonce-based prevention of replay attacks (24h cache)
- ✅ **Rate Limiting** - 600 requests per minute per company
- ✅ **Idempotency** - Safe retry mechanism using Idempotency-Key header
- ✅ **Multi-tenant Support** - Isolated company namespaces
- ✅ **Structured Error Responses** - Consistent error format with request tracing
- ✅ **Request Logging** - All requests logged with unique request IDs

## Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Running the API

```bash
# Start the server
uvicorn main:app --reload

# Server will start at http://localhost:8000
```

The API will be available at:
- **Intake Endpoint**: `POST http://localhost:8000/v1/intake/leads`
- **Health Check**: `GET http://localhost:8000/health`

## API Usage

### Authentication

All requests must include HMAC-SHA256 authentication headers:

**Required Headers:**
```
Content-Type: application/json
X-Ardent-Company: <company_id>
Authorization: Ardent-HMAC key=<public_key_id>, ts=<unix_timestamp>, nonce=<uuid>, sig=<base64_signature>
```

**Optional Header:**
```
Idempotency-Key: <unique_string>
```

### Request Body

```json
{
  "data": {
    "client_name": "Jane Doe",
    "client_email": "jane@example.com"
  },
  "context": {
    "source_url": "https://partner.example.com/signup"
  }
}
```

The `data` field is required and must be a valid JSON object. The `context` field is optional.

### Success Response (201 Created)

```json
{
  "submission_id": "sub_01HZXJ2V0J3WZ9G2FS3F40ZC5D",
  "company_id": "cmp_123",
  "received_at": "2025-11-01T18:22:34Z",
  "status": "accepted"
}
```

### Error Response

```json
{
  "error": {
    "code": "invalid_signature",
    "message": "Signature verification failed",
    "request_id": "req_cx2j8i8V2r",
    "retryable": false
  }
}
```

## HMAC Signature Generation

### Canonical String Format

```
HTTP_METHOD
REQUEST_PATH
X-Ardent-Company
ts=<unix_timestamp>
nonce=<uuid>
sha256=<hex_of_body>
```

### Python Example

```python
import base64
import hashlib
import hmac
import json
import time
import uuid

# Configuration
secret_key = "sk_test_secret_key_demo_only_change_in_prod"
public_key = "pk_test_123"
company_id = "cmp_123"

# Request data
method = "POST"
path = "/v1/intake/leads"
timestamp = str(int(time.time()))
nonce = str(uuid.uuid4())
payload = {"data": {"client_name": "Jane Doe"}}
body = json.dumps(payload)

# Compute body hash
body_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()

# Build canonical string
canonical = "\n".join([
    method,
    path,
    company_id,
    f"ts={timestamp}",
    f"nonce={nonce}",
    f"sha256={body_hash}"
])

# Compute HMAC signature
signature = hmac.new(
    secret_key.encode('utf-8'),
    canonical.encode('utf-8'),
    hashlib.sha256
).digest()
sig_b64 = base64.b64encode(signature).decode('utf-8')

# Build Authorization header
auth_header = f"Ardent-HMAC key={public_key}, ts={timestamp}, nonce={nonce}, sig={sig_b64}"
```

## Testing

### Run Test Client

The test client demonstrates all key scenarios:

```bash
# Make sure the API is running first
python test_client.py
```

This will run 6 test scenarios:
1. Valid signed request (success)
2. Invalid signature (failure)
3. Replay attack (rejected)
4. Idempotency - same key, same body
5. Idempotency conflict - same key, different body
6. Stale timestamp (rejected)

### Run Pytest Suite

```bash
# Run all tests
pytest test_api.py -v

# Run with coverage
pytest test_api.py -v --cov=main

# Run specific test class
pytest test_api.py::TestAuthenticationSuccess -v
```

Test coverage includes:
- Authentication (success & failures)
- Timestamp validation
- Replay protection
- Idempotency handling
- Rate limiting
- Payload validation
- Multi-tenant isolation
- Error handling

## Demo Credentials

**Company 1:**
- Public Key: `pk_test_123`
- Secret Key: `sk_test_secret_key_demo_only_change_in_prod`
- Company ID: `cmp_123`

**Company 2:**
- Public Key: `pk_test_456`
- Secret Key: `sk_test_another_secret_key_for_testing`
- Company ID: `cmp_456`

⚠️ **Note:** These are demo credentials. In production, use secure key generation and storage.

## Security Features

### HMAC Authentication
- Uses HMAC-SHA256 for message authentication
- Prevents tampering with request body
- Constant-time signature comparison to prevent timing attacks

### Timestamp Validation
- Accepts only requests within ±300 seconds
- Prevents replay of old requests
- Helps synchronize client/server clocks

### Nonce Replay Protection
- Every nonce can only be used once
- 24-hour cache window
- Prevents exact replay attacks

### Rate Limiting
- 600 requests per minute per company
- Simple in-memory counter
- Returns 429 Too Many Requests when exceeded

### Request Size Limits
- Maximum payload size: 64KB
- Prevents DoS attacks via large payloads

### Idempotency
- Same key + same body → returns original submission
- Same key + different body → returns 409 Conflict
- Prevents duplicate processing

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Client Request                       │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Request ID Middleware                      │
│              Body Size Validator                        │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│           HMAC Authentication Dependency                │
│  ┌───────────────────────────────────────────────┐     │
│  │ 1. Parse Authorization header                 │     │
│  │ 2. Verify timestamp (±300s)                   │     │
│  │ 3. Check nonce replay                         │     │
│  │ 4. Validate company ID                        │     │
│  │ 5. Compute & compare HMAC signature           │     │
│  └───────────────────────────────────────────────┘     │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                 Rate Limit Check                        │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Idempotency Handler                        │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│            Process & Store Submission                   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                 Return Response                         │
└─────────────────────────────────────────────────────────┘
```

## Production Considerations

For production deployment, consider:

1. **Database** - Replace in-memory stores with Redis/PostgreSQL
2. **Key Management** - Use secure key storage (e.g., AWS Secrets Manager, HashiCorp Vault)
3. **Distributed Rate Limiting** - Use Redis for multi-instance rate limiting
4. **Monitoring** - Add Prometheus metrics, distributed tracing
5. **HTTPS** - Ensure TLS termination at load balancer
6. **Logging** - Centralized logging (e.g., ELK stack, CloudWatch)
7. **Key Rotation** - Implement key rotation strategy
8. **Webhook/Queue** - Process submissions asynchronously

## License

Proprietary - Ardent