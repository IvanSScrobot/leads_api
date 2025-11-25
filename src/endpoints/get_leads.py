from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from lib import db
from lib.auth import verify_hmac_auth
from lib.dates import parse_iso8601_utc
from lib.db import DatabaseOperations
from lib.schemas import LeadRecord
from lib.settings import logger
from lib.status import determine_lead_status

router = APIRouter()


@router.get("/get-leads", response_model=List[LeadRecord])
async def get_leads(
    request: Request, company_id: str, start_date: str, end_date: str, auth_info: Dict[str, str] = Depends(verify_hmac_auth)
):
    """Retrieve leads for a company within a date range (UTC) with HMAC authentication."""
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

    start_dt = parse_iso8601_utc(start_date, "start_date", request_id)
    end_dt = parse_iso8601_utc(end_date, "end_date", request_id)

    if start_dt > end_dt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "invalid_date_range",
                    "message": "end_date must be greater than start_date",
                    "request_id": request_id,
                    "retryable": False,
                }
            },
        )

    from datetime import datetime, timezone

    now_utc = datetime.now(timezone.utc)
    if start_dt > now_utc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": "invalid_date_range",
                    "message": "start_date cannot be in the future",
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
                    "retryable": True,
                }
            },
        )

    formatted_leads: List[LeadRecord] = []
    for lead in leads:
        call_summary = lead.get("call_summary") or ""
        transcript = lead.get("transcript") or ""
        status_value = determine_lead_status(lead.get("processed"), call_summary, transcript)

        formatted_leads.append(
            LeadRecord(
                id=lead.get("id"),
                customer_name=lead.get("customer_name") or "",
                email=lead.get("email") or "",
                phone_number=lead.get("phone_number") or "",
                status=status_value,
                created_at=lead.get("created_at"),
                call_summary=call_summary,
                transcript=transcript,
            )
        )

    logger.info(f"[{request_id}] Retrieved {len(formatted_leads)} leads")
    return formatted_leads
