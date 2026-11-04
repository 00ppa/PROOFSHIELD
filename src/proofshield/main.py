import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from proofshield.api.auth import APITokenMiddleware

from proofshield import __version__
from proofshield.api.routes_campaigns import router as campaigns_router
from proofshield.api.routes_evaluation import router as evaluation_router
from proofshield.api.routes_execution import router as execution_router
from proofshield.api.routes_explanation import router as explanation_router
from proofshield.api.routes_elastic import router as elastic_router
from proofshield.api.routes_health import router as health_router
from proofshield.api.routes_splunk import router as splunk_router
from proofshield.api.routes_reports import router as reports_router
from proofshield.api.routes_ui import router as ui_router
from proofshield.api.routes_research import router as research_router
from proofshield.api.routes_workflow import router as workflow_router
from proofshield.api.routes_telemetry import router as telemetry_router
from proofshield.services.store import close_store, get_store


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: initializes and validates storage on startup, cleans up on shutdown."""
    # Eagerly initialize and validate the configured store on startup.
    # If the configured backend or path is invalid, fails fast with clear exception.
    get_store()
    try:
        yield
    finally:
        from proofshield.execution.process_manager import get_default_process_manager
        get_default_process_manager().cancel_all()
        close_store()


def create_application() -> FastAPI:
    """Application factory for PROOFSHIELD FastAPI service."""
    app = FastAPI(
        title="PROOFSHIELD",
        description=(
            "Cybersecurity detection assurance and failure-diagnosis platform. "
            "Evaluates detection engineering efficacy, root-cause telemetry gaps, "
            "and alert pipeline determinism without executing intrusive commands.\n\n"
            "SECURITY NOTICE & TRUST BOUNDARY:\n"
            "- Single-Tenant Architecture: All endpoints operate on a shared global entity store without tenant isolation.\n"
            "- Authentication Boundary: non-public API routes require the deployment bearer token; "
            "controlled execution routes require their separate execution token. Missing deployment credentials fail closed.\n"
            "- Ingestion Limits: Bulk ingestion endpoints enforce payload size and batch record boundaries "
            "to prevent denial-of-service and memory exhaustion."
        ),
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    cors_env = os.environ.get("PROOFSHIELD_CORS_ORIGINS")
    if cors_env:
        origins = [o.strip() for o in cors_env.split(",") if o.strip()]
    else:
        origins = [
            "http://localhost",
            "http://localhost:8000",
            "http://localhost:3000",
            "http://127.0.0.1",
            "http://127.0.0.1:8000",
            "http://127.0.0.1:3000",
        ]

    # When wildcards are allowed, credentials cannot be enabled per CORS specification
    allow_credentials = False if "*" in origins else True

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(APITokenMiddleware)

    # Register routers
    app.include_router(health_router)
    app.include_router(telemetry_router)
    app.include_router(evaluation_router)
    app.include_router(campaigns_router)
    app.include_router(execution_router)
    app.include_router(explanation_router)
    app.include_router(elastic_router)
    app.include_router(splunk_router)
    app.include_router(reports_router)
    app.include_router(ui_router)
    app.include_router(research_router)
    app.include_router(workflow_router)

    return app


app = create_application()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("proofshield.main:app", host="127.0.0.1", port=8000, reload=True)
