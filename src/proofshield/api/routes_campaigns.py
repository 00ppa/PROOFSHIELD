"""FastAPI router for detection validation campaigns, replays, and comparisons."""

import re
import sqlite3
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from proofshield.schemas.campaign import (
    CampaignComparisonV1,
    CampaignDefinitionV1,
    CampaignExecutionConfigV1,
    CampaignReplayResultV1,
    CampaignRunV1,
)
from proofshield.services.campaign_engine import CampaignEngine
from proofshield.services.store import get_store

router = APIRouter(prefix="/api/v1", tags=["Campaign Validation & Replay Engine"])


def _sanitize_error_detail(exc: Exception, prefix: str = "Operation failed") -> str:
    """Sanitize error messages to prevent leakage of internal absolute filesystem paths."""
    msg = str(exc)
    # Strip absolute Windows paths (e.g. C:\... or D:\...)
    msg = re.sub(r"[A-Za-z]:\\[\w\s\-\\\.]+", "[REDACTED_PATH]", msg)
    # Strip absolute POSIX paths
    msg = re.sub(r"/(?:var|tmp|home|etc|usr|opt|root)/[\w\s\-/\.]+", "[REDACTED_PATH]", msg)
    return f"{prefix}: {msg}"


class CampaignExecutionRequest(BaseModel):
    """Optional execution parameters supplied when triggering a campaign run."""

    execution_config_override: Optional[CampaignExecutionConfigV1] = Field(
        default=None,
        description="Optional runtime execution policy or attribution settings override",
    )
    scenario_run_map: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional mapping of scenario_id -> test_run_id to bind specific runs",
    )


# ── Campaign Definitions ───────────────────────────────────────────────────

@router.post(
    "/campaigns",
    response_model=CampaignDefinitionV1,
    status_code=status.HTTP_201_CREATED,
    summary="Register a detection validation campaign definition",
)
def create_campaign(campaign: CampaignDefinitionV1) -> CampaignDefinitionV1:
    """Create a new validation campaign definition declaring an ordered suite of scenarios."""
    store = get_store()
    try:
        return store.add_campaign(campaign)
    except (ValueError, sqlite3.Error) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_sanitize_error_detail(exc, prefix="Campaign registration conflict"),
        )


@router.get(
    "/campaigns",
    response_model=List[CampaignDefinitionV1],
    summary="List registered campaign definitions",
)
def list_campaigns(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of records to return (default 50, max 1000)"),
    offset: int = Query(0, ge=0, description="Number of records to skip for pagination (default 0)"),
) -> List[CampaignDefinitionV1]:
    """List all registered campaign definitions with bounded pagination."""
    items = get_store().list_campaigns()
    return items[offset : offset + limit]


@router.get(
    "/campaigns/{campaign_id}",
    response_model=CampaignDefinitionV1,
    summary="Retrieve campaign definition by identifier",
)
def get_campaign(
    campaign_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=3,
        max_length=64,
        description="Unique campaign identifier",
    ),
) -> CampaignDefinitionV1:
    """Retrieve a campaign definition by its unique identifier."""
    campaign = get_store().get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign definition not found: {campaign_id}",
        )
    return campaign


# ── Campaign Runs ──────────────────────────────────────────────────────────

@router.post(
    "/campaigns/{campaign_id}/runs",
    response_model=CampaignRunV1,
    status_code=status.HTTP_201_CREATED,
    summary="Execute a detection validation campaign",
)
def execute_campaign(
    campaign_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=3,
        max_length=64,
        description="Unique campaign identifier",
    ),
    request: Optional[CampaignExecutionRequest] = Body(default=None),
) -> CampaignRunV1:
    """Execute a validation campaign against stored scenarios and telemetry evidence.

    Reuses the deterministic AssuranceEngine (Layer 5) to evaluate each scenario,
    preserves diagnostic outcomes and canonical evidence manifests, and computes
    aggregated summary metrics and root-cause groupings.

    Notice: This endpoint is unauthenticated; access control must be enforced
    at the network boundary or API gateway.
    """
    store = get_store()
    engine = CampaignEngine(store)

    config_override = request.execution_config_override if request else None
    scenario_run_map = request.scenario_run_map if request else None

    try:
        return engine.execute_campaign(
            campaign_id=campaign_id,
            execution_config_override=config_override,
            scenario_run_map=scenario_run_map,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(exc).lower() else status.HTTP_400_BAD_REQUEST,
            detail=_sanitize_error_detail(exc, prefix="Invalid execution request"),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_sanitize_error_detail(exc, prefix="Campaign execution failed"),
        )


@router.get(
    "/campaign-runs",
    response_model=List[CampaignRunV1],
    summary="List executed campaign runs",
)
def list_campaign_runs(
    campaign_id: Optional[str] = Query(
        None,
        pattern=r"^[A-Za-z0-9_-]+$",
        max_length=64,
        description="Filter runs by campaign identifier",
    ),
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of records to return (default 50, max 1000)"),
    offset: int = Query(0, ge=0, description="Number of records to skip for pagination (default 0)"),
) -> List[CampaignRunV1]:
    """List historical campaign runs with optional filtering and bounded pagination."""
    items = get_store().list_campaign_runs(campaign_id=campaign_id)
    return items[offset : offset + limit]


@router.get(
    "/campaign-runs/{run_id}",
    response_model=CampaignRunV1,
    summary="Retrieve campaign run record",
)
def get_campaign_run(
    run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Unique campaign run identifier",
    ),
) -> CampaignRunV1:
    """Retrieve an executed campaign run record by its unique identifier."""
    run = get_store().get_campaign_run(run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign run not found: {run_id}",
        )
    return run


@router.get(
    "/campaign-runs/{run_id}/report",
    response_model=Dict[str, Any],
    summary="Retrieve structured auditable campaign report",
)
def get_campaign_report(
    run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Unique campaign run identifier",
    ),
) -> Dict[str, Any]:
    """Retrieve an auditable, deterministic report summarizing a campaign execution run."""
    run = get_store().get_campaign_run(run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign run not found: {run_id}",
        )

    return {
        "report_schema_version": "v1",
        "run_id": run.run_id,
        "campaign_id": run.campaign_id,
        "status": run.status.value,
        "started_at": run.started_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "summary": run.summary.model_dump(mode="json"),
        "root_cause_analysis": [g.model_dump(mode="json") for g in run.root_cause_analysis],
        "evidence_manifest": run.evidence_manifest.model_dump(mode="json"),
        "scenario_results": [r.model_dump(mode="json") for r in run.scenario_results],
        "errors": run.errors,
        "warnings": run.warnings,
        "is_replay": run.is_replay,
        "source_run_id": run.source_run_id,
    }


# ── Replay & Comparison ────────────────────────────────────────────────────

@router.post(
    "/campaign-runs/{run_id}/replay",
    response_model=CampaignReplayResultV1,
    status_code=status.HTTP_201_CREATED,
    summary="Replay a recorded campaign run against preserved evidence",
)
def replay_campaign_run(
    run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Unique campaign run identifier to replay",
    ),
    config_override: Optional[CampaignExecutionConfigV1] = None,
) -> CampaignReplayResultV1:
    """Replay evaluation against preserved historical evidence.

    Verifies evidence manifest internal integrity, detects missing or altered evidence,
    distinguishes exact replay from evidence re-evaluation and engine comparison,
    executes re-evaluation without overwriting historical records, and outputs
    a deterministic comparison between original and replay runs.
    """
    store = get_store()
    engine = CampaignEngine(store)

    try:
        return engine.replay_campaign_run(run_id, execution_config_override=config_override)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(exc).lower() else status.HTTP_400_BAD_REQUEST,
            detail=_sanitize_error_detail(exc, prefix="Invalid replay request"),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_sanitize_error_detail(exc, prefix="Campaign replay failed"),
        )


@router.get(
    "/campaign-runs/{run_id}/compare/{other_run_id}",
    response_model=CampaignComparisonV1,
    summary="Compare two campaign execution runs",
)
def compare_campaign_runs_endpoint(
    run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Baseline campaign run identifier",
    ),
    other_run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Target campaign run identifier to compare against baseline",
    ),
) -> CampaignComparisonV1:
    """Deterministically compare two campaign runs to identify regressions, improvements, and evidence variance."""
    store = get_store()
    engine = CampaignEngine(store)

    try:
        return engine.compare_runs(run_id, other_run_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_sanitize_error_detail(exc, prefix="Comparison failed"),
        )
