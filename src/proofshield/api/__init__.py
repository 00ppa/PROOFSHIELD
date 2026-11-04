"""API routers and endpoints for PROOFSHIELD."""

from proofshield.api.routes_campaigns import router as campaigns_router
from proofshield.api.routes_evaluation import router as evaluation_router
from proofshield.api.routes_execution import router as execution_router
from proofshield.api.routes_explanation import router as explanation_router
from proofshield.api.routes_elastic import router as elastic_router
from proofshield.api.routes_health import router as health_router
from proofshield.api.routes_splunk import router as splunk_router
from proofshield.api.routes_reports import router as reports_router
from proofshield.api.routes_ui import router as ui_router
from proofshield.api.routes_telemetry import router as telemetry_router

__all__ = [
    "campaigns_router",
    "evaluation_router",
    "execution_router",
    "explanation_router",
    "elastic_router",
    "health_router",
    "telemetry_router",
    "splunk_router",
    "reports_router",
    "ui_router",
]
