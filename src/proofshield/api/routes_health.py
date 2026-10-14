"""System health and diagnostic status endpoints."""

from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter
from pydantic import BaseModel, Field

from proofshield import __version__
from proofshield.schemas.common import SCHEMA_VERSION

router = APIRouter(tags=["Health & Status"])


class HealthResponse(BaseModel):
    """Health check payload response."""
    status: str = Field("healthy", description="Operational status of the service")
    service: str = Field("proofshield", description="Service identifier")
    version: str = Field(__version__, description="Application release version")
    supported_schema_versions: List[str] = Field(
        default_factory=lambda: [SCHEMA_VERSION],
        description="List of supported schema versions",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Current server timestamp (UTC)",
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Root health probe",
    description="Returns the current operational status and versioning metadata of the PROOFSHIELD service.",
)
@router.get(
    "/api/v1/health",
    response_model=HealthResponse,
    summary="Versioned API v1 health probe",
    description="Returns the current operational status and versioning metadata of the PROOFSHIELD service under /api/v1.",
)
def get_health() -> HealthResponse:
    """Return platform operational status."""
    return HealthResponse()
