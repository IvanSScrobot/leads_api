from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from lib import db
from lib.auth import verify_hmac_auth
from lib.db import DatabaseOperations
from lib.schemas import LeadStatusResponse
from lib.settings import logger

router = APIRouter()


@router.get("/lead-status", response_model=LeadStatusResponse)
async def get_lead_status(
    request: Request, company_id: str, submission_id: str, auth_info: Dict[str, str] = Depends(verify_hmac_auth)
):
    """
    Retrieve lead status with HMAC authentication.
    """
    request_id = request.state.request_id
    authenticated_company_id = auth_info["company_id"]
    logger.info(f"[{request_id}] Retrieving lead status for {company_id}/{submission_id}")

    if not company_id or not submission_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "missing_parameters",
                    "message": "company_id and submission_id are required",
                    "request_id": request_id,
                    "retryable": False,
                }
            },
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
                    "retryable": False,
                }
            },
        )

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
        result: Optional[Dict] = DatabaseOperations.get_lead_status(company_id, submission_id)
        if result is None:
            logger.info(f"[{request_id}] Lead not found: {company_id}/{submission_id}")
            return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "not_found"})

        call_summary = result.get("call_summary")
        processed = result.get("processed", False)
        if not processed and (call_summary is None or call_summary == ""):
            call_summary = "call result is being processed"

        logger.info(f"[{request_id}] Lead status retrieved successfully")
        return LeadStatusResponse(company_id=company_id, submission_id=submission_id, call_summary=call_summary or "")
    except Exception as db_error:
        logger.error(f"[{request_id}] Database query failed: {str(db_error)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": "database_error",
                    "message": "Failed to retrieve lead status",
                    "request_id": request_id,
                    "retryable": True,
                }
            },
        )
