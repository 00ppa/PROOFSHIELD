"""API routers and endpoints for PROOFSHIELD."""

from proofshield.api.routes_evaluation import router as evaluation_router
from proofshield.api.routes_health import router as health_router
from proofshield.api.routes_telemetry import router as telemetry_router

__all__ = ["evaluation_router", "health_router", "telemetry_router"]
