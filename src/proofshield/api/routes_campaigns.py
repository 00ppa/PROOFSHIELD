"""FastAPI router for detection validation campaigns, replays, and comparisons."""

import re
import sqlite3
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from proofshield.schemas.assurance_report import (
    CampaignAssuranceReportV1,
    CampaignRegressionAnalysisV1,
    RootCauseIntelligenceV1,
)
from proofshield.schemas.campaign import (
    CampaignComparisonV1,
    CampaignDefinitionV1,
    CampaignExecutionConfigV1,
    CampaignReplayResultV1,
    CampaignRunV1,
)
from proofshield.services.assurance_report import CampaignAssuranceReportGenerator
from proofshield.services.campaign_engine import CampaignEngine
from proofshield.services.regression_analyzer import CampaignRegressionAnalyzer
from proofshield.services.root_cause import RootCauseIntelligenceService
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


class AssuranceReportRequest(BaseModel):
    """Parameters for compiling an assurance report."""

    verify_manifest: bool = Field(
        default=True,
        description="Whether to audit and verify evidence manifest hashes against store",
    )


class RegressionAnalysisRequest(BaseModel):
    """Parameters for running comparative regression analysis."""

    baseline_run_id: str = Field(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Baseline campaign run identifier",
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


# ── Phase 17: Campaign Assurance Intelligence & Regression Analysis ────────

@router.post(
    "/campaign-runs/{run_id}/assurance-report",
    response_model=CampaignAssuranceReportV1,
    status_code=status.HTTP_201_CREATED,
    summary="Compile and persist a campaign assurance report",
)
def generate_assurance_report(
    run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Unique campaign run identifier",
    ),
    request: Optional[AssuranceReportRequest] = Body(default=None),
) -> CampaignAssuranceReportV1:
    """Compile an auditable, deterministic assurance report from stored campaign execution evidence.

    Computes explicit mathematical detection metrics, aggregates the seven canonical diagnostic
    distributions, audits evidence quality and manifest integrity against the store, and seals
    the report with an RFC 8785 canonical SHA-256 digest.
    """
    store = get_store()
    generator = CampaignAssuranceReportGenerator(store)
    verify_manifest = request.verify_manifest if request else True

    try:
        report = generator.generate_report(run_id=run_id, verify_manifest=verify_manifest)
        try:
            return store.add_assurance_report(report)
        except ValueError:
            # If report with this deterministic ID already stored, retrieve and return it
            existing = store.get_assurance_report(report.report_id)
            if existing:
                return existing
            raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(exc).lower() else status.HTTP_400_BAD_REQUEST,
            detail=_sanitize_error_detail(exc, prefix="Assurance report generation failed"),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_sanitize_error_detail(exc, prefix="Assurance report generation failed"),
        )


@router.get(
    "/campaign-assurance-reports/{report_id}",
    response_model=CampaignAssuranceReportV1,
    summary="Retrieve a stored campaign assurance report",
)
def get_assurance_report(
    report_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Unique campaign assurance report identifier",
    ),
) -> CampaignAssuranceReportV1:
    """Retrieve an assurance report by ID and cryptographically verify its canonical content digest."""
    store = get_store()
    try:
        report = store.get_assurance_report(report_id)
        if report is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Assurance report not found: {report_id}",
            )

        # Validate report integrity against its canonical SHA-256 digest
        if not CampaignAssuranceReportGenerator.verify_report_integrity(report):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Report integrity compromised: computed digest does not match stored digest for {report_id}",
            )

        return report
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_sanitize_error_detail(exc, prefix="Failed to retrieve assurance report"),
        )


@router.get(
    "/campaign-assurance-reports",
    response_model=List[CampaignAssuranceReportV1],
    summary="List stored campaign assurance reports",
)
def list_assurance_reports(
    campaign_id: Optional[str] = Query(
        None,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        max_length=128,
        description="Filter reports by campaign identifier",
    ),
    run_id: Optional[str] = Query(
        None,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        max_length=128,
        description="Filter reports by campaign run identifier",
    ),
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of records to return (default 50, max 1000)"),
    offset: int = Query(0, ge=0, description="Number of records to skip for pagination (default 0)"),
) -> List[CampaignAssuranceReportV1]:
    """List historical assurance reports with optional campaign/run filters and bounded pagination."""
    items = get_store().list_assurance_reports(campaign_id=campaign_id, run_id=run_id)
    return items[offset : offset + limit]


@router.post(
    "/campaign-runs/{run_id}/regression-analysis",
    response_model=CampaignRegressionAnalysisV1,
    summary="Perform regression analysis against a baseline campaign run",
)
def analyze_campaign_regression(
    run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Candidate campaign run identifier",
    ),
    request: RegressionAnalysisRequest = Body(...),
) -> CampaignRegressionAnalysisV1:
    """Perform deterministic regression analysis comparing a candidate run against a baseline run.

    Detects newly failing scenarios, metric deterioration, increased missing telemetry,
    alert uncorrelation, execution errors, and scenario suite changes.
    """
    store = get_store()
    analyzer = CampaignRegressionAnalyzer(store)

    try:
        return analyzer.analyze_runs(
            baseline_run_id=request.baseline_run_id,
            candidate_run_id=run_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(exc).lower() else status.HTTP_400_BAD_REQUEST,
            detail=_sanitize_error_detail(exc, prefix="Regression analysis failed"),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_sanitize_error_detail(exc, prefix="Regression analysis failed"),
        )


@router.get(
    "/campaign-runs/{run_id}/regression/{base_run_id}",
    response_model=CampaignRegressionAnalysisV1,
    summary="Quick comparative regression analysis between two runs",
)
def compare_regression_quick(
    run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Candidate campaign run identifier",
    ),
    base_run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Baseline campaign run identifier",
    ),
) -> CampaignRegressionAnalysisV1:
    """Retrieve comparative regression findings between a candidate run and baseline run."""
    store = get_store()
    analyzer = CampaignRegressionAnalyzer(store)

    try:
        return analyzer.analyze_runs(
            baseline_run_id=base_run_id,
            candidate_run_id=run_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(exc).lower() else status.HTTP_400_BAD_REQUEST,
            detail=_sanitize_error_detail(exc, prefix="Regression analysis failed"),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_sanitize_error_detail(exc, prefix="Regression analysis failed"),
        )


@router.get(
    "/campaign-runs/{run_id}/root-cause-intelligence",
    response_model=RootCauseIntelligenceV1,
    summary="Retrieve structured root-cause intelligence for a campaign run",
)
def get_root_cause_intelligence(
    run_id: str = Path(
        ...,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        min_length=3,
        max_length=128,
        description="Unique campaign run identifier",
    ),
) -> RootCauseIntelligenceV1:
    """Retrieve structured root cause patterns across failed and anomalous scenarios in a campaign run."""
    store = get_store()
    service = RootCauseIntelligenceService(store)

    try:
        return service.analyze_campaign_run(run_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(exc).lower() else status.HTTP_400_BAD_REQUEST,
            detail=_sanitize_error_detail(exc, prefix="Root-cause intelligence analysis failed"),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_sanitize_error_detail(exc, prefix="Root-cause intelligence analysis failed"),
        )
