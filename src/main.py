"""
Ardent Intake API - FastAPI application wiring.
Routers are split per-endpoint under src/endpoints and shared utilities live under src/lib.
"""

from fastapi import FastAPI

from endpoints import get_leads, health, lead_status, leads
from lib.exceptions import register_exception_handlers
from lib.lifecycle import lifespan
from lib.middleware import add_request_id_middleware, body_size_validator

app = FastAPI(title="Ardent Intake API", version="1.0.0", lifespan=lifespan)

# Middleware
app.middleware("http")(add_request_id_middleware)
app.middleware("http")(body_size_validator)

# Exception handlers
register_exception_handlers(app)

# Routers
app.include_router(leads.router, prefix="/api/v1")
app.include_router(lead_status.router, prefix="/api/v1")
app.include_router(get_leads.router, prefix="/api/v1")
app.include_router(health.router, prefix="/api/v1")
