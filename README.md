# Ardent Intake API

Production-grade FastAPI endpoint for HMAC-authenticated survey submission with PostgreSQL storage.

## Features

- ✅ **HMAC-SHA256 Authentication** - Secure request signing with public/secret key pairs
- ✅ **Timestamp Validation** - Only accepts requests within ±300 seconds
- ✅ **Replay Protection** - Nonce-based prevention (2h cache)
- ✅ **Rate Limiting** - 600 requests per minute per company
- ✅ **Idempotency** - Safe retry with Idempotency-Key header
- ✅ **Multi-tenant Support** - Isolated company namespaces via HMAC keys
- ✅ **PostgreSQL Storage** - All survey data stored in database
- ✅ **Phone Validation** - Canadian focus with E.164 format, blocks premium/emergency numbers
- ✅ **Automatic Retry** - 3 attempts with exponential backoff for database failures
- ✅ **Mandatory Field Validation** - email, name, phoneNumber, businessType, privacyConsent

## Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

### Environment Variables

Create a `.env` file (see `.env.example`):

```bash
# HMAC Authentication (required)
HMAC_SECRET_KEY_PK_TEST_123=sk_test_secret_key_demo_only_change_in_prod
HMAC_SECRET_KEY_PK_TEST_456=sk_test_another_secret_key_for_testing

# PostgreSQL (required)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=ardent_survey
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_secure_password

# Phone Validation
INTERNATIONAL_NUMBERS_ALLOWED=false

# Application
PORT=8000
```

### Database Setup (Required)

PostgreSQL database with the following schema:

```sql
-- Customers table
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    phone_number VARCHAR(50),
    phone_number_validated BOOLEAN DEFAULT FALSE,
    privacy_consent BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Survey responses table
CREATE TABLE survey_responses (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    survey_answers JSONB NOT NULL,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
```

## Running the API

```bash
# Start the server
uvicorn main:app --reload

# Server will start at http://localhost:8000
```

## API Usage

### Survey Submission Endpoint

**Endpoint:** `POST /api/v1/leads`

All requests must include:
1. **HMAC authentication headers** (see below)
2. **All mandatory fields** in the request body

### Required Headers

```
Content-Type: application/json
X-Ardent-Company: <company_id>
Authorization: Ardent-HMAC key=<public_key_id>, ts=<unix_timestamp>, nonce=<uuid>, sig=<base64_signature>
```

**Optional Header:**
```
Idempotency-Key: <unique_string>
```

### Request Body Format

```json
{
  "email": "customer@example.com",
  "name": "John Doe",
  "phoneNumber": "+17786961321",
  "businessType": "Retail",
  "privacyConsent": true,
  "employeeCount": "6-20",
  "revenue": "$100,000 - $500,000",
  "operationalFrustration": "Manual data entry",
  "timeConsumingTasks": "Inventory management",
  "inefficiencies": "Slow reporting",
  "automationArea": "Sales process",
  "oneTaskToAutomate": "Invoice generation",
  "hoursToSave": "10-20 hours/week",
  "growthObstacle": "Limited resources",
  "importantOutcome": "Increased revenue"
}
```

### Mandatory Fields

- `email` - Valid email address (cannot be empty)
- `name` - Customer name (cannot be empty)
- `phoneNumber` - E.164 format (e.g., +12045551234)
- `businessType` - Type of business (cannot be empty)
- `privacyConsent` - Must be `true`

All other fields are optional.

### Success Response (201 Created)

```json
{
  "submission_id": "sub_abc123xyz",
  "company_id": "cmp_123",
  "customer_id": 42,
  "received_at": "2025-11-07T18:22:34Z",
  "status": "accepted"
}
```

### Error Responses

**400 Bad Request** (Missing/Invalid Field):
```json
{
  "error": {
    "code": "validation_error",
    "message": "Phone number is required and cannot be empty",
    "request_id": "req_abc123",
    "retryable": false
  }
}
```

**401 Unauthorized** (Invalid HMAC Signature):
```json
{
  "error": {
    "code": "invalid_signature",
    "message": "Signature verification failed",
    "request_id": "req_abc123",
    "retryable": false
  }
}
```

**429 Too Many Requests** (Rate Limit):
```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Too many requests. Rate limit: 600 requests per minute",
    "request_id": "req_abc123",
    "retryable": true
  }
}
```

**503 Service Unavailable** (Database Not Available):
```json
{
  "error": {
    "code": "database_unavailable",
    "message": "Database not configured or unavailable",
    "request_id": "req_abc123",
    "retryable": true
  }
}
```

## HMAC Authentication

All requests must be authenticated using HMAC-SHA256 signatures.

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
path = "/api/v1/leads"
timestamp = str(int(time.time()))
nonce = str(uuid.uuid4())
payload = {
    "email": "test@example.com",
    "name": "Test User",
    "phoneNumber": "+17786974255",
    "businessType": "Technology",
    "privacyConsent": True
}
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

print(f"Authorization: {auth_header}")
```

## Phone Number Validation

Phone numbers are validated with these rules:

### Blocked Numbers
- Premium rate (900, 976, 540 prefixes)
- Emergency services (911, 999, 112, etc.)
- Special services (411, 311, 211, etc.)
- Toll-free numbers (800, 833, 844, 855, 866, 877, 888)

### Accepted Formats
- **US/Canada**: E.164 format `+1XXXXXXXXXX` (10 digits after +1)
- **International**: Optional if `INTERNATIONAL_NUMBERS_ALLOWED=true`

Phone validation results are logged. The `phone_number_validated` flag is set in the database.

## Health Check

**Endpoint:** `GET /api/v1/leads/health`

```json
{
  "status": "healthy",
  "service": "ardent-intake-api",
  "version": "1.0.0",
  "database": "connected"
}
```

Status values:
- `healthy` - All systems operational
- `degraded` - Service running but database has issues
- `unhealthy` - Critical failure (503 response)

Database values:
- `connected` - PostgreSQL accessible
- `not_configured` - No database credentials provided
- `error` - Database connection failed

## Testing

### Test with Python

```python
import requests
import base64
import hashlib
import hmac
import json
import time
import uuid

# Configuration
url = "http://localhost:8000/api/v1/leads"
secret_key = "sk_test_secret_key_demo_only_change_in_prod"
public_key = "pk_test_123"
company_id = "cmp_123"

# Payload
payload = {
    "email": "test@example.com",
    "name": "Test User",
    "phoneNumber": "+17786974255",
    "businessType": "Technology",
    "privacyConsent": True
}

# Generate signature (see HMAC Authentication section above)
method = "POST"
path = "/api/v1/leads"
timestamp = str(int(time.time()))
nonce = str(uuid.uuid4())
body = json.dumps(payload)
body_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()

canonical = "\n".join([method, path, company_id, f"ts={timestamp}", f"nonce={nonce}", f"sha256={body_hash}"])
signature = hmac.new(secret_key.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha256).digest()
sig_b64 = base64.b64encode(signature).decode('utf-8')

# Make request
headers = {
    "Content-Type": "application/json",
    "X-Ardent-Company": company_id,
    "Authorization": f"Ardent-HMAC key={public_key}, ts={timestamp}, nonce={nonce}, sig={sig_b64}"
}

response = requests.post(url, json=payload, headers=headers)
print(response.status_code)
print(response.json())
```

### Run Test Client

```bash
python test_client.py
```

### Run Pytest

```bash
pytest test_api.py -v
```

## Kubernetes Deployment

### Prerequisites
1. Kubernetes cluster
2. PostgreSQL database

### Deploy

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Check status
kubectl get pods -l app=ardent-intake-api
kubectl logs -f deployment/ardent-intake-api
```

### Configuration

Update `k8s/secret.yaml` with:
1. HMAC secret keys (required)
2. PostgreSQL credentials (required)

```bash
# Encode secrets
echo -n "your_password" | base64
```

## Architecture

```
┌────────────────────────────────────────────────┐
│    POST /api/v1/leads (HMAC Auth Required)     │
│                                                │
│  ┌──────────────────────────────────────────┐ │
│  │ 1. HMAC Signature Verification           │ │
│  │ 2. Rate Limiting Check                   │ │
│  │ 3. Idempotency Check                     │ │
│  │ 4. Mandatory Field Validation            │ │
│  │ 5. Phone Number Validation               │ │
│  │ 6. PostgreSQL Storage (with 3x retry)    │ │
│  │ 7. Return submission_id + customer_id    │ │
│  └──────────────────────────────────────────┘ │
│                                                │
│         All survey data → PostgreSQL           │
│     (customers + survey_responses tables)      │
└────────────────────────────────────────────────┘
```

## Demo Credentials

**Company 1 (Test Provider 1):**
- Public Key: `pk_test_123`
- Secret Key: `sk_test_secret_key_demo_only_change_in_prod`
- Company ID: `cmp_123`

**Company 2 (Test Provider 2):**
- Public Key: `pk_test_456`
- Secret Key: `sk_test_another_secret_key_for_testing`
- Company ID: `cmp_456`

⚠️ **Note:** These are demo credentials for beta testing. In production:
- Each customer will have their own unique HMAC key
- Keys will be securely generated and stored
- Regular key rotation will be implemented

## Security Features

- **HMAC-SHA256** - Message authentication prevents tampering
- **Timestamp Validation** - Prevents replay of old requests (±300s window)
- **Nonce Cache** - Prevents exact replay attacks (2h cache)
- **Rate Limiting** - 600 req/min per company
- **Phone Validation** - Blocks premium/emergency numbers
- **Input Sanitization** - Pydantic validation on all fields
- **SQL Injection Protection** - Parameterized queries
- **Constant-time Comparison** - Prevents timing attacks
- **Request Size Limits** - 64KB maximum
- **Database Retry** - 3 attempts with exponential backoff

## Beta Version Notes

This is a beta version with the following characteristics:

1. **Trusted Providers**: Survey data comes from 1-2 trusted providers with HMAC keys
2. **In-Memory Key Storage**: HMAC keys stored in-memory (will move to database in production)
3. **Future Architecture**: One customer ID → One unique HMAC key (coming in v2.0)

## Production Roadmap

1. **Database Key Storage** - Move HMAC keys from in-memory to PostgreSQL
2. **Customer-Key Mapping** - One customer → one unique HMAC key
3. **Key Management API** - CRUD operations for HMAC keys
4. **Key Rotation** - Automated rotation strategy
5. **Monitoring** - Add Prometheus metrics, distributed tracing
6. **Scaling** - Redis for distributed rate limiting
7. **Backup** - Automated PostgreSQL backups

## License

Proprietary - Ardent