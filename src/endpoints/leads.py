import hashlib
import os
import secrets
from datetime import datetime, timezone
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from lib import db
from lib.auth import verify_hmac_auth
from lib.db import DatabaseOperations
from lib.phone_validator import PhoneValidator
from lib.schemas import IntakeResponse, SurveyRequest
from lib.settings import CHECK_CONSENTS, logger
from lib.store import store

router = APIRouter()


@router.post("/leads", response_model=IntakeResponse, status_code=status.HTTP_201_CREATED)
async def intake_lead(
    request: Request,
    survey: SurveyRequest,
    auth_info: Dict[str, str] = Depends(verify_hmac_auth),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    """
    Submit survey data with HMAC authentication.
    Implements nonce/idempotency protection, consent checks, phone validation, and DB insertion.
    """
    request_id = request.state.request_id
    company_id = auth_info["company_id"]
    body_hash = auth_info["body_hash"]

    # Enforce consent flags if enabled
    if CHECK_CONSENTS:
        if not survey.privacyConsent:
            logger.warning(f"[{request_id}] Privacy consent is false")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "consent_required",
                        "message": "Privacy consent must be True. User must agree to privacy policy.",
                        "request_id": request_id,
                        "retryable": False,
                    }
                },
            )
        if not survey.consentToUseAI:
            logger.warning(f"[{request_id}] consentToUseAI is false")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "consent_required",
                        "message": "consentToUseAI must be True. User must agree to AI usage.",
                        "request_id": request_id,
                        "retryable": False,
                    }
                },
            )

    # Rate limiting: company_id -> {count, window_start}
    if not store.check_rate_limit(company_id, limit=600, window=60):
        logger.warning(f"[{request_id}] Rate limit exceeded for company {company_id}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "Rate limit exceeded. Try again later.",
                    "request_id": request_id,
                    "retryable": True,
                }
            },
        )

    # Idempotency handling
    if idempotency_key:
        existing = store.idempotency_store.get(idempotency_key)
        if existing:
            if existing["body_hash"] != body_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": {
                            "code": "idempotency_body_mismatch",
                            "message": "Idempotency-Key already used with different payload",
                            "request_id": request_id,
                            "retryable": False,
                        }
                    },
                )

            submission_id = existing["submission_id"]
            logger.info(f"[{request_id}] Idempotent replay for submission {submission_id}")
            return IntakeResponse(
                submission_id=submission_id,
                company_id=company_id,
                customer_id=0,
                received_at=datetime.now(timezone.utc).isoformat(),
                status="accepted",
            )

    # Phone validation (skip heavy checks in TEST_MODE)
    user_ip = request.client.host if request.client else "unknown"
    if os.getenv("TEST_MODE", "false").lower() == "true":
        phone_validation = {"validated": True}
    else:
        phone_validation = PhoneValidator.validate(survey.phoneNumber, user_ip=user_ip)
    phone_validated = phone_validation.get("validated", False)
    if not phone_validated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "invalid_phone",
                    "message": phone_validation.get("reason", "Invalid phone number"),
                    "request_id": request_id,
                    "retryable": False,
                }
            },
        )

    submission_id = f"sub_{secrets.token_urlsafe(12)}"
    received_at = datetime.now(timezone.utc).isoformat()

    # Save submission locally for test/demo
    store.submissions[submission_id] = {
        "data": survey.dict(),
        "company_id": company_id,
        "received_at": received_at,
    }

    if db.db_pool is None:
        logger.error(f"[{request_id}] Database not available")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": {
                    "code": "database_unavailable",
                    "message": "Database not configured or unavailable",
                    "request_id": request_id,
                    "retryable": True,
                }
            },
        )

    try:
        customer_id = DatabaseOperations.insert_customer_and_survey(
            survey,
            phone_validated,
            submission_id,
            company_id,
        )
    except Exception as db_error:
        logger.error(f"[{request_id}] Database insert failed: {str(db_error)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": "database_error",
                    "message": "Failed to store survey data",
                    "request_id": request_id,
                    "retryable": True,
                }
            },
        )

    # Store idempotency mapping
    if idempotency_key:
        store.idempotency_store[idempotency_key] = {
            "body_hash": body_hash,
            "submission_id": submission_id,
        }

    logger.info(f"[{request_id}] Submission accepted: {submission_id}")
    return IntakeResponse(
        submission_id=submission_id,
        company_id=company_id,
        customer_id=customer_id,
        received_at=received_at,
        status="accepted",
    )
