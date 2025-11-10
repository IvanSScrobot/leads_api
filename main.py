"""
Ardent Intake API - Production-grade FastAPI endpoint for secure lead ingestion
with HMAC authentication, rate limiting, and replay protection.
EXTENDED: Survey submission with PostgreSQL integration and phone validation.
"""

import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, Response, Header, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator, EmailStr

# Import database operations and phone validation
# from db import (
#     DatabaseOperations,
#     PhoneValidator,
#     db_pool,
#     initialize_db_pool,
#     close_db_pool
# )
import db
from db import (DatabaseOperations, PhoneValidator)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class SurveyRequest(BaseModel):
    """Survey submission request model - required fields with arbitrary extras allowed"""
    name: str = Field(..., min_length=1, max_length=255)
    businessName: str = Field(..., alias='businessName', min_length=1, max_length=255)
    email: EmailStr
    phoneNumber: str = Field(..., alias='phoneNumber')
    privacyConsent: bool = Field(..., alias='privacyConsent')
    consentToUseAI: bool = Field(..., alias='consentToUseAI')
    
    class Config:
        populate_by_name = True
        extra = "allow"  # Allows arbitrary key-value pairs
    
    @validator('email')
    def validate_email(cls, v):
        if not v or not v.strip():
            raise ValueError('Email is required and cannot be empty')
        return v.strip().lower()
    
    @validator('name', 'businessName')
    def validate_required_string(cls, v):
        if not v or not v.strip():
            raise ValueError('Field is required and cannot be empty')
        return v.strip()
    
    @validator('phoneNumber')
    def validate_phone(cls, v):
        if not v or not v.strip():
            raise ValueError('Phone number is required and cannot be empty')
        if not re.match(r'^\+[1-9]\d{1,14}$', v.strip()):
            raise ValueError('Phone number must be in E.164 format (e.g., +12125551234)')
        return v.strip()
    
    @validator('privacyConsent', 'consentToUseAI')
    def validate_consent(cls, v):
        if not v:
            raise ValueError('Consent is required')
        return v


class IntakeResponse(BaseModel):
    """Successful response for survey submission"""
    submission_id: str
    company_id: str
    customer_id: int
    received_at: str
    status: str = "accepted"


class ErrorDetail(BaseModel):
    """Structured error response"""
    code: str
    message: str
    request_id: str
    retryable: bool = False


class ErrorResponse(BaseModel):
    """Error response wrapper"""
    error: ErrorDetail


# ============================================================================
# IN-MEMORY STORES
# ============================================================================

class InMemoryStore:
    """Thread-safe in-memory storage for demo purposes"""
    
    def __init__(self):
        # Company registry: public_key_id -> {secret_key, company_id}
        # Load HMAC secrets from environment variables (K8s secrets)
        # Fallback to hardcoded values for local development/testing
        self.companies: Dict[str, Dict[str, str]] = {
            "pk_test_123": {
                "secret_key": os.getenv(
                    "HMAC_SECRET_KEY_PK_TEST_123",
                    "sk_test_secret_key_demo_only_change_in_prod"
                ),
                "company_id": "cmp_123"
            },
            "pk_test_456": {
                "secret_key": os.getenv(
                    "HMAC_SECRET_KEY_PK_TEST_456",
                    "sk_test_another_secret_key_for_testing"
                ),
                "company_id": "cmp_456"
            }
        }
        
        # Nonce cache: stores nonce -> expiry_timestamp for 2h
        self.nonce_cache: Dict[str, float] = {}
        
        # Idempotency store: idempotency_key -> {body_hash, submission_id}
        self.idempotency_store: Dict[str, Dict[str, str]] = {}
        
        # Rate limiting: company_id -> {count, window_start}
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        
        # Submissions log (for demo)
        self.submissions: Dict[str, Dict[str, Any]] = {}
    
    def cleanup_expired_nonces(self):
        """Remove expired nonces from cache"""
        current_time = time.time()
        expired = [nonce for nonce, expiry in self.nonce_cache.items() 
                   if expiry < current_time]
        for nonce in expired:
            del self.nonce_cache[nonce]
    
    def check_rate_limit(self, company_id: str, limit: int = 600, window: int = 60) -> bool:
        """
        Check if company has exceeded rate limit
        Returns True if within limit, False if exceeded
        """
        current_time = time.time()
        
        if company_id not in self.rate_limits:
            self.rate_limits[company_id] = {
                "count": 1,
                "window_start": current_time
            }
            return True
        
        rl = self.rate_limits[company_id]
        
        # Reset window if expired
        if current_time - rl["window_start"] >= window:
            rl["count"] = 1
            rl["window_start"] = current_time
            return True
        
        # Check limit
        if rl["count"] >= limit:
            return False
        
        rl["count"] += 1
        return True


# Global store instance
store = InMemoryStore()


# ============================================================================
# LIFECYCLE
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    logger.info("Starting Ardent Intake API...")
    
    # Initialize database connection pool
    db.initialize_db_pool()
    
    yield
    
    # Shutdown
    logger.info("Shutting down Ardent Intake API...")
    db.close_db_pool()


# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Ardent Intake API",
    version="1.0.0",
    lifespan=lifespan
)


# ============================================================================
# MIDDLEWARE
# ============================================================================

@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    """Add unique request_id to all requests for logging/tracing"""
    request_id = f"req_{secrets.token_urlsafe(12)}"
    request.state.request_id = request_id
    
    logger.info(f"[{request_id}] {request.method} {request.url.path}")
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    
    return response


@app.middleware("http")
async def body_size_validator(request: Request, call_next):
    """Validate request body size (max 64KB)"""
    if request.method in ["POST", "PUT", "PATCH"]:
        # Read and cache body in request.state
        body = await request.body()
        request.state.cached_body = body
        
        # Check size limit (64 KB)
        if len(body) > 64 * 1024:
            request_id = getattr(request.state, "request_id", "unknown")
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "error": {
                        "code": "payload_too_large",
                        "message": "Request body exceeds 64KB limit",
                        "request_id": request_id,
                        "retryable": False
                    }
                }
            )
    
    return await call_next(request)


# ============================================================================
# HMAC AUTHENTICATION
# ============================================================================

def parse_authorization_header(auth_header: str) -> Dict[str, str]:
    """
    Parse Authorization header in format:
    Ardent-HMAC key=<public_key_id>, ts=<unix>, nonce=<uuid>, sig=<base64>
    """
    if not auth_header.startswith("Ardent-HMAC "):
        raise ValueError("Invalid authorization scheme")
    
    parts = auth_header[12:].split(", ")
    parsed = {}
    
    for part in parts:
        if "=" not in part:
            raise ValueError(f"Invalid header format: {part}")
        key, value = part.split("=", 1)
        parsed[key.strip()] = value.strip()
    
    required_keys = {"key", "ts", "nonce", "sig"}
    if not required_keys.issubset(parsed.keys()):
        missing = required_keys - parsed.keys()
        raise ValueError(f"Missing required fields: {missing}")
    
    return parsed


def build_canonical_string(
    method: str,
    path: str,
    company_id: str,
    timestamp: str,
    nonce: str,
    body_hash: str
) -> str:
    """
    Build canonical string for HMAC signature:
    HTTP_METHOD
    REQUEST_PATH
    X-Ardent-Company
    ts=<unix_timestamp>
    nonce=<uuid>
    sha256=<hex_of_body>
    """
    return "\n".join([
        method,
        path,
        company_id,
        f"ts={timestamp}",
        f"nonce={nonce}",
        f"sha256={body_hash}"
    ])


async def verify_hmac_auth(
    request: Request,
    authorization: str = Header(..., alias="Authorization"),
    company_id: str = Header(..., alias="X-Ardent-Company")
) -> Dict[str, str]:
    """
    Dependency to verify HMAC authentication
    Returns company info if valid, raises HTTPException otherwise
    """
    request_id = getattr(request.state, "request_id", "unknown")
    
    try:
        # Parse authorization header
        auth_params = parse_authorization_header(authorization)
        public_key_id = auth_params["key"]
        timestamp_str = auth_params["ts"]
        nonce = auth_params["nonce"]
        provided_sig = auth_params["sig"]
        
        # Verify company exists
        if public_key_id not in store.companies:
            logger.warning(f"[{request_id}] Unknown public key: {public_key_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": "invalid_credentials",
                        "message": "Invalid public key",
                        "request_id": request_id,
                        "retryable": False
                    }
                }
            )
        
        company_info = store.companies[public_key_id]
        secret_key = company_info["secret_key"]
        expected_company_id = company_info["company_id"]
        
        # Verify X-Ardent-Company matches the key's company
        if company_id != expected_company_id:
            logger.warning(f"[{request_id}] Company ID mismatch: {company_id} != {expected_company_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": "company_mismatch",
                        "message": "X-Ardent-Company header does not match key's company",
                        "request_id": request_id,
                        "retryable": False
                    }
                }
            )
        
        # Verify timestamp (±300 seconds)
        try:
            timestamp = int(timestamp_str)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "invalid_timestamp",
                        "message": "Timestamp must be a valid Unix timestamp",
                        "request_id": request_id,
                        "retryable": False
                    }
                }
            )
        
        current_time = int(time.time())
        time_diff = abs(current_time - timestamp)
        
        if time_diff > 300:
            logger.warning(f"[{request_id}] Stale timestamp: {time_diff}s difference")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "stale_timestamp",
                        "message": f"Timestamp outside acceptable window (±300s). Difference: {time_diff}s",
                        "request_id": request_id,
                        "retryable": True
                    }
                }
            )
        
        # Check nonce replay (2h window)
        store.cleanup_expired_nonces()
        
        if nonce in store.nonce_cache:
            logger.warning(f"[{request_id}] Replay attack detected: nonce={nonce}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "replay_detected",
                        "message": "Nonce has already been used",
                        "request_id": request_id,
                        "retryable": False
                    }
                }
            )
        
        # Store nonce with 2h expiry
        store.nonce_cache[nonce] = time.time() + (2 * 60 * 60)
        
        # Get request body (use cached version if available from middleware)
        if hasattr(request.state, 'cached_body'):
            body = request.state.cached_body
        else:
            body = await request.body()
        body_hash = hashlib.sha256(body).hexdigest()
        
        # Build canonical string
        canonical = build_canonical_string(
            method=request.method,
            path=request.url.path,
            company_id=company_id,
            timestamp=timestamp_str,
            nonce=nonce,
            body_hash=body_hash
        )
        
        # Compute expected signature
        expected_sig = hmac.new(
            secret_key.encode('utf-8'),
            canonical.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        # Decode provided signature (base64)
        import base64
        try:
            provided_sig_bytes = base64.b64decode(provided_sig)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": "invalid_signature_format",
                        "message": "Signature must be valid base64",
                        "request_id": request_id,
                        "retryable": False
                    }
                }
            )
        
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(expected_sig, provided_sig_bytes):
            logger.warning(f"[{request_id}] Signature verification failed")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": "invalid_signature",
                        "message": "Signature verification failed",
                        "request_id": request_id,
                        "retryable": False
                    }
                }
            )
        
        logger.info(f"[{request_id}] HMAC authentication successful for company {company_id}")
        
        return {
            "company_id": company_id,
            "public_key_id": public_key_id,
            "body_hash": body_hash
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{request_id}] Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "authentication_failed",
                    "message": str(e),
                    "request_id": request_id,
                    "retryable": False
                }
            }
        )


# ============================================================================
# EXCEPTION HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with structured error format"""
    request_id = getattr(request.state, "request_id", "unknown")
    
    # If detail is already structured, use it
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail
        )
    
    # Otherwise, create structured response
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": "http_error",
                "message": str(exc.detail),
                "request_id": request_id,
                "retryable": False
            }
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors"""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(f"[{request_id}] Unexpected error: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "internal_error",
                "message": "An unexpected error occurred",
                "request_id": request_id,
                "retryable": True
            }
        }
    )


# ============================================================================
# ENDPOINTS
# ============================================================================

@app.post("/api/v1/leads", response_model=IntakeResponse, status_code=status.HTTP_201_CREATED)
async def intake_lead(
    request: Request,
    survey: SurveyRequest,
    auth_info: Dict[str, str] = Depends(verify_hmac_auth),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key")
):
    """
    Submit survey data with HMAC authentication
    
    All mandatory fields must be provided:
    - name, businessName, email, phoneNumber, privacyConsent, consentToUseAI
    
    Additional arbitrary key-value pairs are accepted.
    
    Security features:
    - HMAC-SHA256 signature verification
    - Timestamp validation (±300s)
    - Nonce replay protection (2h)
    - Rate limiting (600 req/min per company)
    - Idempotency key support
    - Phone number validation (blocks premium/emergency numbers)
    
    Database:
    - Stores in PostgreSQL (customers + survey_responses tables)
    - Automatic retry (3 attempts) for transient failures
    - Falls back to error if database unavailable
    """
    request_id = request.state.request_id
    company_id = auth_info["company_id"]
    body_hash = auth_info["body_hash"]
    
    logger.info(f"[{request_id}] Processing survey submission for company {company_id}")
    
    # Check database availability
    if db.db_pool is None:
        logger.error(f"[{request_id}] Database not available")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": {
                    "code": "database_unavailable",
                    "message": "Database not configured or unavailable",
                    "request_id": request_id,
                    "retryable": True
                }
            }
        )
    
    # Check rate limit
    if not store.check_rate_limit(company_id):
        logger.warning(f"[{request_id}] Rate limit exceeded for company {company_id}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "Too many requests. Rate limit: 600 requests per minute",
                    "request_id": request_id,
                    "retryable": True
                }
            }
        )
    
    # Handle idempotency
    if idempotency_key:
        if idempotency_key in store.idempotency_store:
            stored = store.idempotency_store[idempotency_key]
            
            # Same key, same body -> return original submission
            if stored["body_hash"] == body_hash:
                logger.info(f"[{request_id}] Idempotent request, returning original: {stored['submission_id']}")
                existing_submission = store.submissions[stored["submission_id"]]
                return IntakeResponse(**existing_submission)
            
            # Same key, different body -> conflict
            else:
                logger.warning(f"[{request_id}] Idempotency key conflict: same key, different body")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": {
                            "code": "idempotency_conflict",
                            "message": "Idempotency key already used with different request body",
                            "request_id": request_id,
                            "retryable": False
                        }
                    }
                )
    
    # Get user IP
    user_ip = request.client.host if request.client else 'unknown'
    
    # Validate phone number
    phone_validation = PhoneValidator.validate(survey.phoneNumber, user_ip)
    phone_validated = phone_validation['validated']
    
    # Log security events
    if phone_validation.get('log_security_event', False):
        logger.warning(
            f"[SECURITY_EVENT] Phone validation: {phone_validation['reason']} - "
            f"Phone: {phone_validation['original_number']} - Risk: {phone_validation['risk_level']} - IP: {user_ip}"
        )
    
    logger.info(f"[PHONE_VALIDATION] Result: {phone_validation}")
    
    # Insert into database with retry logic
    try:
        customer_id = DatabaseOperations.insert_customer_and_survey(survey, phone_validated)
        logger.info(f"[{request_id}] Survey stored in PostgreSQL, customer_id: {customer_id}")
    except Exception as db_error:
        logger.error(f"[{request_id}] Database operation failed after retries: {str(db_error)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": "database_error",
                    "message": "Failed to store survey data after retries",
                    "request_id": request_id,
                    "retryable": True
                }
            }
        )
    
    # Generate submission ID
    submission_id = f"sub_{secrets.token_urlsafe(20)}"
    received_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    # Store submission metadata in-memory for idempotency tracking
    submission_data = {
        "submission_id": submission_id,
        "company_id": company_id,
        "customer_id": customer_id,
        "received_at": received_at,
        "status": "accepted"
    }
    
    store.submissions[submission_id] = submission_data
    
    # Store idempotency mapping if key provided
    if idempotency_key:
        store.idempotency_store[idempotency_key] = {
            "body_hash": body_hash,
            "submission_id": submission_id
        }
    
    logger.info(f"[{request_id}] Survey accepted: {submission_id}, customer_id: {customer_id}, company: {company_id}")
    
    return IntakeResponse(
        submission_id=submission_id,
        company_id=company_id,
        customer_id=customer_id,
        received_at=received_at,
        status="accepted"
    )


@app.get("/api/v1/leads/health")
async def health_check():
    """
    Comprehensive health check endpoint
    
    Checks:
    - Service status
    - Database connection (if configured)
    """
    try:
        health_status = {
            "status": "healthy",
            "service": "ardent-intake-api",
            "version": "1.0.0"
        }
        
        # Check database if available
        if db.db_pool:
            try:
                conn = DatabaseOperations.get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
                DatabaseOperations.release_connection(conn)
                health_status["database"] = "connected"
            except Exception as db_error:
                logger.error(f"Database health check failed: {str(db_error)}")
                health_status["database"] = "error"
                health_status["status"] = "degraded"
        else:
            health_status["database"] = "not_configured"
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "service": "ardent-intake-api",
                "version": "1.0.0",
                "error": str(e)
            }
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)