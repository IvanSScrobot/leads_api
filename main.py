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
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, Request, Response, Header, HTTPException, status, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator, EmailStr
# Import PhoneValidator (always available, independent of database)
from PhoneValidator import PhoneValidator

# Test mode flag - when True, uses mock API keys instead of database
TEST_MODE = os.getenv("TEST_MODE", "false").lower() == "true"

# Consent checking flag - when True, rejects submissions with False consent values
CHECK_CONSENTS = os.getenv("CHECK_CONSENTS", "true").lower() == "true"

# Import database operations conditionally (only if not in test mode)
if not TEST_MODE:
    try:
        import db
        from db import DatabaseOperations
    except ImportError as e:
        logger.error(f"Database module import failed: {e}")
        logger.error("If running in test mode, set TEST_MODE=true environment variable")
        raise
else:
    # Mock objects for test mode
    db = None
    DatabaseOperations = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Mock API keys for testing (only used when TEST_MODE=true)
MOCK_API_KEYS = {
    "pk_test_123": {
        "secret_key": "sk_test_secret_key_demo_only_change_in_prod",
        "company_id": "2",
        "api_key_id": 1,
        "company_active": True,
        "api_key_active": True,
        "api_key_expires_at": None
    }
}


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
        
        # Normalize email
        email = v.strip().lower()
        
        # Basic format validation (EmailStr already does this, but be explicit)
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError('Invalid email format')
        
        # Reject common invalid patterns
        if email.startswith('.') or email.endswith('.'):
            raise ValueError('Email cannot start or end with a period')
        
        if '..' in email:
            raise ValueError('Email cannot contain consecutive periods')
        
        # Reject disposable/temporary email domains (common ones)
        disposable_domains = [
            'tempmail.com', 'throwaway.email', '10minutemail.com',
            'guerrillamail.com', 'mailinator.com', 'trashmail.com',
            'yopmail.com', 'fakeinbox.com', 'temp-mail.org'
        ]
        domain = email.split('@')[1] if '@' in email else ''
        if domain in disposable_domains:
            raise ValueError('Disposable email addresses are not accepted')
        
        # Reject emails with no domain extension or single character domains
        domain_parts = domain.split('.')
        if len(domain_parts) < 2 or len(domain_parts[-1]) < 2:
            raise ValueError('Invalid email domain')
        
        return email
    
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


class LeadStatusResponse(BaseModel):
    """Response model for lead status query"""
    company_id: str
    submission_id: str
    call_summary: str


class LeadStatusNotFoundResponse(BaseModel):
    """Response when lead status is not found"""
    error: str = "not_found"


class LeadRecord(BaseModel):
    """Lead record returned by get-leads"""
    customer_name: str
    email: EmailStr
    phone_number: str
    status: str
    call_summary: Optional[str] = ""
    transcript: Optional[str] = ""


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
    """
    Thread-safe in-memory storage for caching and rate limiting
    
    Note: API keys are now stored in the database (api_keys and companies tables).
    This class only maintains runtime caches for:
    - Nonce replay protection
    - Idempotency tracking
    - Rate limiting
    - Submission metadata
    """
    
    def __init__(self):
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
    
    if TEST_MODE:
        logger.info("TEST MODE ENABLED - Using mock API keys, no database required")
    else:
        # Initialize database connection pool
        db.initialize_db_pool()
    
    yield
    
    # Shutdown
    logger.info("Shutting down Ardent Intake API...")
    if not TEST_MODE and db:
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
    Dependency to verify HMAC authentication with database-backed API key validation
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
        
        # Check database availability (skip in test mode)
        if not TEST_MODE and (db is None or db.db_pool is None):
            logger.error(f"[{request_id}] Database not available for authentication")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": {
                        "code": "database_unavailable",
                        "message": "Authentication service unavailable",
                        "request_id": request_id,
                        "retryable": True
                    }
                }
            )
        
        # Fetch API key from database or mock (test mode)
        if TEST_MODE:
            logger.info(f"[{request_id}] TEST MODE: Using mock API keys")
            api_key_info = MOCK_API_KEYS.get(public_key_id)
        else:
            try:
                api_key_info = DatabaseOperations.get_api_key_by_public_key(public_key_id)
            except Exception as db_error:
                logger.error(f"[{request_id}] Database error fetching API key: {str(db_error)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={
                        "error": {
                            "code": "database_error",
                            "message": "Authentication service error",
                            "request_id": request_id,
                            "retryable": True
                        }
                    }
                )
        
        # Verify API key exists
        if api_key_info is None:
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
        
        # Verify company is active
        if not api_key_info.get('company_active', False):
            logger.warning(f"[{request_id}] Inactive company for key: {public_key_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": "company_inactive",
                        "message": "Company account is inactive",
                        "request_id": request_id,
                        "retryable": False
                    }
                }
            )
        
        # Verify API key is active
        if not api_key_info.get('api_key_active', False):
            logger.warning(f"[{request_id}] Inactive API key: {public_key_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": "api_key_inactive",
                        "message": "API key is inactive",
                        "request_id": request_id,
                        "retryable": False
                    }
                }
            )
        
        # Verify API key has not expired
        expires_at = api_key_info.get('api_key_expires_at')
        if expires_at is not None:
            from datetime import datetime, timezone
            if datetime.now(timezone.utc) > expires_at:
                logger.warning(f"[{request_id}] Expired API key: {public_key_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "error": {
                            "code": "api_key_expired",
                            "message": "API key has expired",
                            "request_id": request_id,
                            "retryable": False
                        }
                    }
                )
        
        secret_key = api_key_info['secret_key']
        expected_company_id = str(api_key_info['company_id'])
        api_key_id = api_key_info['api_key_id']
        
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
        
        # Update last_used_at timestamp asynchronously (non-blocking) - skip in test mode
        if not TEST_MODE:
            try:
                DatabaseOperations.update_api_key_last_used(api_key_id)
            except Exception as e:
                # Log but don't fail authentication if timestamp update fails
                logger.warning(f"[{request_id}] Failed to update last_used_at: {str(e)}")
        
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


def parse_iso8601_utc(date_str: str, field_name: str, request_id: str) -> datetime:
    """Parse ISO8601 date string into UTC datetime or raise HTTPException"""
    normalized = (date_str or "").strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "invalid_date_format",
                    "message": f"{field_name} must be a valid ISO8601 UTC datetime",
                    "request_id": request_id,
                    "retryable": False
                }
            }
        )
    
    if parsed.tzinfo is None:
        # Assume UTC if timezone missing
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    
    return parsed


def determine_lead_status(processed: Optional[bool], call_summary: Optional[str], transcript: Optional[str]) -> str:
    """Derive lead status from database fields"""
    if processed:
        return "processed"
    
    if (call_summary and call_summary.strip()) or (transcript and transcript.strip()):
        return "being processed"
    
    return "new"


# ============================================================================
# EXCEPTION HANDLERS
# ============================================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle Pydantic validation errors with detailed error messages"""
    request_id = getattr(request.state, "request_id", "unknown")
    
    errors = exc.errors()
    logger.warning(f"[{request_id}] Validation error: {errors}")
    
    # Build detailed validation errors
    validation_errors = []
    
    for error in errors:
        # Extract field location (e.g., ('body', 'email') -> 'email')
        field_path = error.get('loc', ())
        field_name = field_path[-1] if field_path else 'unknown'
        
        # Get error message and type
        error_msg = error.get('msg', 'Validation failed')
        error_type = error.get('type', 'value_error')
        
        # Create user-friendly error messages based on error type
        if error_type == 'missing':
            user_message = f"Required field '{field_name}' is missing"
        elif error_type == 'value_error.missing':
            user_message = f"Required field '{field_name}' is missing"
        elif error_type == 'type_error.none.not_allowed':
            user_message = f"Field '{field_name}' cannot be null"
        elif 'email' in error_type.lower() or field_name == 'email':
            # Email validation errors
            if 'valid email' in error_msg.lower() or 'email' in error_msg.lower():
                user_message = f"Invalid email format for field '{field_name}'. Email must contain '@' symbol and valid domain (e.g., user@example.com)"
            else:
                user_message = f"Email validation failed: {error_msg}"
        elif field_name == 'phoneNumber':
            # Phone number validation errors
            if 'E.164 format' in error_msg:
                user_message = error_msg
            else:
                user_message = f"Phone number validation failed: {error_msg}"
        elif error_type.startswith('value_error'):
            # Custom validator errors - use the message directly
            user_message = f"Validation failed for field '{field_name}': {error_msg}"
        elif error_type.startswith('type_error'):
            # Type errors
            user_message = f"Invalid type for field '{field_name}': {error_msg}"
        else:
            # Fallback for other errors
            user_message = f"Validation failed for field '{field_name}': {error_msg}"
        
        validation_errors.append({
            "field": field_name,
            "message": user_message
        })
    
    # Create summary message
    if len(validation_errors) == 1:
        summary_message = validation_errors[0]["message"]
    else:
        summary_message = f"Request validation failed for {len(validation_errors)} field(s)"
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": {
                "code": "validation_error",
                "message": summary_message,
                "request_id": request_id,
                "retryable": False,
                "validation_errors": validation_errors
            }
        }
    )


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
    
    # Check database availability (skip in test mode)
    if not TEST_MODE and db.db_pool is None:
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
    
    # REJECT request if phone number is invalid - DO NOT write to database
    if not phone_validated:
        logger.warning(
            f"[{request_id}] Rejecting request due to invalid phone number: {phone_validation['reason']}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "validation_error",
                    "message": f"Phone number validation failed: {phone_validation['reason']}",
                    "request_id": request_id,
                    "retryable": False,
                    "validation_errors": [{
                        "field": "phoneNumber",
                        "message": phone_validation['reason']
                    }]
                }
            }
        )
    
    # Check consents if enabled
    if CHECK_CONSENTS:
        consent_errors = []
        
        if not survey.privacyConsent:
            consent_errors.append({
                "field": "privacyConsent",
                "message": "Privacy consent must be True. User must agree to privacy policy."
            })
        
        if not survey.consentToUseAI:
            consent_errors.append({
                "field": "consentToUseAI",
                "message": "AI usage consent must be True. User must agree to AI processing."
            })
        
        if consent_errors:
            logger.warning(f"[{request_id}] Rejecting request due to missing consents")
            error_message = "Consent validation failed: "
            if len(consent_errors) == 1:
                error_message += consent_errors[0]["message"]
            else:
                error_message += f"{len(consent_errors)} consent(s) required but not granted"
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "validation_error",
                        "message": error_message,
                        "request_id": request_id,
                        "retryable": False,
                        "validation_errors": consent_errors
                    }
                }
            )
    
    # Generate submission ID before database call
    submission_id = f"sub_{secrets.token_urlsafe(20)}"
    
    # Insert into database with retry logic (or use mock in test mode)
    if TEST_MODE:
        # Mock customer_id in test mode
        customer_id = int(time.time()) % 1000000
        logger.info(f"[{request_id}] TEST MODE: Mock survey storage, customer_id: {customer_id}")
    else:
        try:
            customer_id = DatabaseOperations.insert_customer_and_survey(survey, phone_validated, submission_id, company_id)
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
    
    # Generate received_at timestamp
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


@app.get("/api/v1/lead-status")
async def get_lead_status(
    request: Request,
    company_id: str,
    submission_id: str,
    auth_info: Dict[str, str] = Depends(verify_hmac_auth)
):
    """
    Get lead status by company_id and submission_id with HMAC authentication
    
    Query Parameters:
    - company_id: Company identifier (must match authenticated company)
    - submission_id: Unique submission identifier
    
    Security:
    - HMAC-SHA256 signature verification (same as POST endpoint)
    - Timestamp validation (±300s)
    - Nonce replay protection
    
    Returns:
    - 200: Lead status with call_summary
    - 400: Bad request (missing parameters)
    - 401: Unauthorized (invalid signature/headers)
    - 404: Lead not found
    - 503: Database unavailable
    """
    request_id = request.state.request_id
    authenticated_company_id = auth_info["company_id"]
    
    logger.info(f"[{request_id}] Querying lead status for company {company_id}, submission {submission_id}")
    
    # Validate query parameters
    if not company_id or not submission_id:
        logger.warning(f"[{request_id}] Missing required query parameters")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "missing_parameters",
                    "message": "Both company_id and submission_id are required",
                    "request_id": request_id,
                    "retryable": False
                }
            }
        )
    
    # Verify company_id matches authenticated company
    if company_id != authenticated_company_id:
        logger.warning(f"[{request_id}] Company ID mismatch: {company_id} != {authenticated_company_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "company_mismatch",
                    "message": "Query parameter company_id does not match authenticated company",
                    "request_id": request_id,
                    "retryable": False
                }
            }
        )
    
    # Check database availability (skip in test mode)
    if not TEST_MODE and db.db_pool is None:
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
    
    # Query database for lead status (or use mock in test mode)
    if TEST_MODE:
        # Mock response in test mode - check in-memory store
        if submission_id in store.submissions:
            logger.info(f"[{request_id}] TEST MODE: Lead found in memory")
            return LeadStatusResponse(
                company_id=company_id,
                submission_id=submission_id,
                call_summary="call result is being processed"
            )
        else:
            logger.info(f"[{request_id}] TEST MODE: Lead not found")
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "not_found"}
            )
    else:
        try:
            result = DatabaseOperations.get_lead_status(company_id, submission_id)
            
            if result is None:
                logger.info(f"[{request_id}] Lead not found: {company_id}/{submission_id}")
                return JSONResponse(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content={"error": "not_found"}
                )
            
            # Check if call is being processed
            call_summary = result.get('call_summary')
            processed = result.get('processed', False)
            
            if not processed and (call_summary is None or call_summary == ''):
                call_summary = "call result is being processed"
            
            logger.info(f"[{request_id}] Lead status retrieved successfully")
            
            return LeadStatusResponse(
                company_id=company_id,
                submission_id=submission_id,
                call_summary=call_summary or ""
            )
            
        except Exception as db_error:
            logger.error(f"[{request_id}] Database query failed: {str(db_error)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": {
                        "code": "database_error",
                        "message": "Failed to retrieve lead status",
                        "request_id": request_id,
                        "retryable": True
                    }
                }
            )


@app.get("/api/v1/get-leads", response_model=List[LeadRecord])
async def get_leads(
    request: Request,
    company_id: str,
    start_date: str,
    end_date: str,
    auth_info: Dict[str, str] = Depends(verify_hmac_auth)
):
    """
    Retrieve leads for a company within a date range (UTC) with HMAC authentication.
    """
    request_id = request.state.request_id
    authenticated_company_id = auth_info["company_id"]
    logger.info(f"[{request_id}] Fetching leads for company {company_id} from {start_date} to {end_date}")
    
    if not company_id or not start_date or not end_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "missing_parameters",
                    "message": "company_id, start_date, and end_date are required",
                    "request_id": request_id,
                    "retryable": False
                }
            }
        )
    
    if company_id != authenticated_company_id:
        logger.warning(f"[{request_id}] Company ID mismatch: {company_id} != {authenticated_company_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "company_mismatch",
                    "message": "Query parameter company_id does not match authenticated company",
                    "request_id": request_id,
                    "retryable": False
                }
            }
        )
    
    start_dt = parse_iso8601_utc(start_date, "start_date", request_id)
    end_dt = parse_iso8601_utc(end_date, "end_date", request_id)
    now_utc = datetime.now(timezone.utc)
    
    if start_dt > now_utc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "invalid_date_range",
                    "message": "start_date cannot be in the future",
                    "request_id": request_id,
                    "retryable": False
                }
            }
        )
    
    if end_dt <= start_dt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "invalid_date_range",
                    "message": "end_date must be greater than start_date",
                    "request_id": request_id,
                    "retryable": False
                }
            }
        )
    
    if not TEST_MODE and db.db_pool is None:
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
    
    # Fetch leads from database (or empty list in test mode)
    if TEST_MODE:
        leads = []
    else:
        try:
            leads = DatabaseOperations.get_leads(company_id, start_dt, end_dt)
        except Exception as db_error:
            logger.error(f"[{request_id}] Database query failed: {str(db_error)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": {
                        "code": "database_error",
                        "message": "Failed to retrieve leads",
                        "request_id": request_id,
                        "retryable": True
                    }
                }
            )
    
    formatted_leads: List[LeadRecord] = []
    for lead in leads:
        call_summary = lead.get("call_summary") or ""
        transcript = lead.get("transcript") or ""
        status_value = determine_lead_status(lead.get("processed"), call_summary, transcript)
        
        formatted_leads.append(
            LeadRecord(
                customer_name=lead.get("customer_name") or "",
                email=lead.get("email") or "",
                phone_number=lead.get("phone_number") or "",
                status=status_value,
                call_summary=call_summary,
                transcript=transcript
            )
        )
    
    logger.info(f"[{request_id}] Retrieved {len(formatted_leads)} leads")
    return formatted_leads


@app.get("/api/v1/lead-status/health")
async def lead_status_health_check():
    """
    Health check endpoint for lead-status service
    
    Checks:
    - Service status
    - Database connection (if configured)
    """
    try:
        health_status = {
            "status": "healthy",
            "service": "ardent-lead-status-api",
            "version": "1.0.0",
            "test_mode": TEST_MODE
        }
        
        # Check database if available (skip in test mode)
        if TEST_MODE:
            health_status["database"] = "test_mode_mock"
        elif db.db_pool:
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
                "service": "ardent-lead-status-api",
                "version": "1.0.0",
                "error": str(e)
            }
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
            "version": "1.0.0",
            "test_mode": TEST_MODE
        }
        
        # Check database if available (skip in test mode)
        if TEST_MODE:
            health_status["database"] = "test_mode_mock"
        elif db.db_pool:
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
