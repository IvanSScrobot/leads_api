import base64
import json
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from lib import db
from lib.auth import verify_hmac_auth
from lib.dates import parse_iso8601_utc
from lib.db import DatabaseOperations
from lib.schemas import LeadRecord, PaginatedLeadsResponse
from lib.settings import GET_LEADS_DEFAULT_LIMIT, logger
from lib.status import determine_lead_status

router = APIRouter()


def _decode_cursor(raw_cursor: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Decode the opaque cursor from base64 JSON: {"created_at": "...", "id": int}.
    Raises HTTPException on any decoding/validation error.
    """
    try:
        decoded = base64.b64decode(raw_cursor).decode("utf-8")
        payload = json.loads(decoded)
        created_at = payload.get("created_at")
        cursor_id = payload.get("id")
        if not created_at or cursor_id is None:
            raise ValueError("cursor missing fields")
        return created_at, int(cursor_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_CURSOR", "message": "The cursor parameter is not valid"}},
        )


def _encode_cursor(created_at: str, cursor_id: int) -> str:
    """
    Build an opaque cursor by base64-encoding JSON containing created_at and id.
    """
    payload = json.dumps({"created_at": created_at, "id": cursor_id})
    return base64.b64encode(payload.encode("utf-8")).decode("utf-8")


@router.get("/get-leads", response_model=PaginatedLeadsResponse)
async def get_leads(
    request: Request,
    company_id: str,
    start_date: str,
    end_date: str,
    cursor: Optional[str] = None,
    limit: Optional[int] = Query(None, ge=1, le=1000),
    auth_info: Dict[str, str] = Depends(verify_hmac_auth),
):
    """
    Retrieve leads with cursor-based pagination.
    
    Pagination uses ORDER BY created_at ASC, id ASC. The cursor is an opaque base64-encoded
    JSON object containing {"created_at": ISO8601 UTC string, "id": int}. Clients pass
    the cursor to fetch rows strictly after that pair using (created_at > c) OR
    (created_at = c AND id > cursor_id). limit defaults to GET_LEADS_DEFAULT_LIMIT and
    is capped at 1000; limit+1 rows are fetched to determine has_more/next_cursor.
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

    # Pagination: decode cursor (if any) and enforce default/max limits
    cursor_created_at_str = None
    cursor_id = None
    if cursor:
        cursor_created_at_str, cursor_id = _decode_cursor(cursor)
    page_limit = limit if limit is not None else GET_LEADS_DEFAULT_LIMIT
    page_limit = min(page_limit, 1000)

    try:
        leads = DatabaseOperations.get_leads(
            company_id=company_id,
            start_date=start_dt,
            end_date=end_dt,
            limit=page_limit + 1,
            cursor_created_at=parse_iso8601_utc(cursor_created_at_str, "cursor.created_at", request_id) if cursor_created_at_str else None,
            cursor_id=cursor_id,
        )
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

    has_more = len(leads) > page_limit
    items_slice = leads[:page_limit]

    next_cursor_val = ""
    if has_more and items_slice:
        last = items_slice[-1]
        created_at_iso = last.get("created_at")
        if hasattr(created_at_iso, "astimezone"):
            created_at_iso = created_at_iso.astimezone().isoformat().replace("+00:00", "Z")
        next_cursor_val = _encode_cursor(created_at_iso, last.get("id"))

    items: List[LeadRecord] = []
    for lead in items_slice:
        call_summary = lead.get("call_summary")
        transcript = lead.get("transcript")
        status_value = determine_lead_status(lead.get("processed"), call_summary, transcript)

        created_at_val = lead.get("created_at")
        if hasattr(created_at_val, "astimezone"):
            created_at_val = created_at_val.astimezone().isoformat().replace("+00:00", "Z")

        items.append(
            LeadRecord(
                id=lead.get("id"),
                customer_name=lead.get("customer_name") or "",
                email=lead.get("email") or "",
                phone_number=lead.get("phone_number") or "",
                status=status_value,
                created_at=created_at_val,
                call_summary=call_summary,
                transcript=transcript,
            )
        )

    logger.info(f"[{request_id}] Retrieved {len(items)} leads; has_more={has_more}")
    return PaginatedLeadsResponse(items=items, next_cursor=next_cursor_val if has_more else "", has_more=has_more)
