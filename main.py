"""
Ardent Intake API - Production-grade FastAPI endpoint for secure lead ingestion
with HMAC authentication, rate limiting, and replay protection.
"""

import hashlib
import hmac
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, Response, Header, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class LeadContext(BaseModel):
    """Context information about the lead source"""
    source_url: Optional[str] = None
    
    class Config:
        extra = "allow"


class IntakeRequest(BaseModel):
    """Request body for lead intake"""
    data: Dict[str, Any] = Field(..., description="Lead data as JSON object")
    context: Optional[LeadContext] = None
    
    @validator('data')
    def validate_data(cls, v):
        """Ensure data is a valid dict"""
        if not isinstance(v, dict):
            raise ValueError("data must be a JSON object")
        return v


class IntakeResponse(BaseModel):
    """Successful response for lead intake"""
    submission_id: str
    company_id: str
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
    yield
    logger.info("Shutting down Ardent Intake API...")


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
    payload: IntakeRequest,
    auth_info: Dict[str, str] = Depends(verify_hmac_auth),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key")
):
    """
    Ingest lead data from third-party websites with HMAC authentication
    
    Security features:
    - HMAC-SHA256 signature verification
    - Timestamp validation (±300s)
    - Nonce replay protection (2h)
    - Rate limiting (600 req/min per company)
    - Idempotency key support
    """
    request_id = request.state.request_id
    company_id = auth_info["company_id"]
    body_hash = auth_info["body_hash"]
    
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
    
    # Generate submission ID (ULID-like format for demo)
    submission_id = f"sub_{secrets.token_urlsafe(20)}"
    received_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    # Store submission
    submission_data = {
        "submission_id": submission_id,
        "company_id": company_id,
        "received_at": received_at,
        "status": "accepted",
        "data": payload.data,
        "context": payload.context.dict() if payload.context else None
    }
    
    store.submissions[submission_id] = submission_data
    
    # Store idempotency mapping if key provided
    if idempotency_key:
        store.idempotency_store[idempotency_key] = {
            "body_hash": body_hash,
            "submission_id": submission_id
        }
    
    logger.info(f"[{request_id}] Lead accepted: {submission_id} for company {company_id}")
    
    return IntakeResponse(
        submission_id=submission_id,
        company_id=company_id,
        received_at=received_at,
        status="accepted"
    )


@app.get("/api/v1/leads/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "ardent-intake-api", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)