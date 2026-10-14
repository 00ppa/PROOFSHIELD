"""PROOFSHIELD FastAPI Application Entry Point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from proofshield import __version__
from proofshield.api.routes_evaluation import router as evaluation_router
from proofshield.api.routes_health import router as health_router
from proofshield.api.routes_telemetry import router as telemetry_router


def create_application() -> FastAPI:
    """Application factory for PROOFSHIELD FastAPI service."""
    app = FastAPI(
        title="PROOFSHIELD",
        description=(
            "Cybersecurity detection assurance and failure-diagnosis platform. "
            "Evaluates detection engineering efficacy, root-cause telemetry gaps, "
            "and alert pipeline determinism without executing intrusive commands."
        ),
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Permissive local CORS for development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(health_router)
    app.include_router(telemetry_router)
    app.include_router(evaluation_router)

    return app


app = create_application()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("proofshield.main:app", host="127.0.0.1", port=8000, reload=True)
