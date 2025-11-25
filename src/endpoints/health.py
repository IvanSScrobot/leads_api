from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from lib import db
from lib.db import DatabaseOperations
from lib.settings import TEST_MODE, logger

router = APIRouter()


@router.get("/lead-status/health")
async def lead_status_health_check():
    """Health check endpoint for lead-status service."""
    try:
        health_status = {
            "status": "healthy",
            "service": "ardent-lead-status-api",
            "version": "1.0.0",
            "test_mode": TEST_MODE,
        }

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
        elif TEST_MODE:
            health_status["database"] = "test_mode_mock"
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
                "error": str(e),
            },
        )


@router.get("/leads/health")
async def health_check():
    """Comprehensive health check endpoint."""
    try:
        health_status = {
            "status": "healthy",
            "service": "ardent-intake-api",
            "version": "1.0.0",
            "test_mode": TEST_MODE,
        }

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
        elif TEST_MODE:
            health_status["database"] = "test_mode_mock"
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
                "error": str(e),
            },
        )
