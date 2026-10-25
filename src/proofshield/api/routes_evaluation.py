"""Diagnostic evaluation, entity management, and assurance engine endpoints."""

from typing import List, Optional, Union
from fastapi import APIRouter, Body, HTTPException, Query

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticResultV1,
    GroundTruthV1,
    ScenarioV1,
    TestRunV1,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.store import get_store

router = APIRouter(prefix="/api/v1", tags=["Diagnostic Evaluation & Management"])


# ── Scenarios ─────────────────────────────────────────────────────────────

@router.post(
    "/scenarios",
    response_model=ScenarioV1,
    summary="Register a validation test scenario",
)
def create_scenario(scenario: ScenarioV1) -> ScenarioV1:
    """Register a new scenario in the in-memory store."""
    store = get_store()
    try:
        return store.add_scenario(scenario)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get(
    "/scenarios",
    response_model=List[ScenarioV1],
    summary="List registered test scenarios",
)
def list_scenarios() -> List[ScenarioV1]:
    return get_store().list_scenarios()


@router.get(
    "/scenarios/{scenario_id}",
    response_model=ScenarioV1,
    summary="Get scenario by identifier",
)
def get_scenario(scenario_id: str) -> ScenarioV1:
    scenario = get_store().get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario not found: {scenario_id}")
    return scenario


# ── Test Runs ─────────────────────────────────────────────────────────────

@router.post(
    "/runs",
    response_model=TestRunV1,
    summary="Record a test run execution",
)
def create_test_run(run: TestRunV1) -> TestRunV1:
    """Record a test run. Requires referenced scenario to exist."""
    store = get_store()
    try:
        return store.add_run(run)
    except ValueError as exc:
        if "Scenario not found" in str(exc):
            raise HTTPException(status_code=404, detail=str(exc))
        raise HTTPException(status_code=409, detail=str(exc))


@router.get(
    "/runs",
    response_model=List[TestRunV1],
    summary="List test runs",
)
def list_test_runs(
    scenario_id: Optional[str] = Query(None, description="Filter by scenario ID")
) -> List[TestRunV1]:
    return get_store().list_runs(scenario_id=scenario_id)


@router.get(
    "/runs/{run_id}",
    response_model=TestRunV1,
    summary="Get test run by identifier",
)
def get_test_run(run_id: str) -> TestRunV1:
    run = get_store().get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Test run not found: {run_id}")
    return run


# ── Detection Rules ───────────────────────────────────────────────────────

@router.post(
    "/rules",
    response_model=DetectionRuleV1,
    summary="Register a detection rule",
)
def create_rule(rule: DetectionRuleV1) -> DetectionRuleV1:
    store = get_store()
    try:
        return store.add_rule(rule)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get(
    "/rules",
    response_model=List[DetectionRuleV1],
    summary="List detection rules",
)
def list_rules() -> List[DetectionRuleV1]:
    return get_store().list_rules()


@router.get(
    "/rules/{rule_id}",
    response_model=DetectionRuleV1,
    summary="Get detection rule by identifier",
)
def get_rule(rule_id: str) -> DetectionRuleV1:
    rule = get_store().get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Detection rule not found: {rule_id}")
    return rule


# ── Alerts ────────────────────────────────────────────────────────────────

@router.post(
    "/alerts",
    response_model=List[AlertV1],
    summary="Ingest security alerts",
)
def ingest_alerts(
    alerts: Union[AlertV1, List[AlertV1]] = Body(...)
) -> List[AlertV1]:
    store = get_store()
    alert_list = [alerts] if isinstance(alerts, AlertV1) else alerts
    ingested = []
    try:
        with store.transaction():
            for a in alert_list:
                store.add_alert(a)
                ingested.append(a)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return ingested


@router.get(
    "/alerts",
    response_model=List[AlertV1],
    summary="List ingested alerts",
)
def list_alerts() -> List[AlertV1]:
    return get_store().list_alerts()


# ── Ground Truth ──────────────────────────────────────────────────────────

@router.post(
    "/ground-truth",
    response_model=GroundTruthV1,
    summary="Record independent ground truth label",
)
def create_ground_truth(gt: GroundTruthV1) -> GroundTruthV1:
    store = get_store()
    try:
        return store.add_ground_truth(gt)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get(
    "/ground-truth",
    response_model=List[GroundTruthV1],
    summary="List all ground truth records",
)
def list_ground_truths() -> List[GroundTruthV1]:
    return get_store().list_ground_truths()


@router.get(
    "/ground-truth/{run_id}",
    response_model=GroundTruthV1,
    summary="Get ground truth for a test run",
)
def get_ground_truth_for_run(run_id: str) -> GroundTruthV1:
    gt = get_store().get_ground_truth_for_run(run_id)
    if not gt:
        raise HTTPException(
            status_code=404, detail=f"Ground truth not found for run: {run_id}"
        )
    return gt


# ── Evaluation (Assurance Engine) ─────────────────────────────────────────

@router.post(
    "/evaluation/{run_id}",
    response_model=DiagnosticResultV1,
    summary="Trigger deterministic diagnostic evaluation of a test run",
)
def evaluate_test_run(
    run_id: str,
    strict_attribution: Optional[bool] = Query(
        None,
        description="Opt-in strict token attribution requiring execution token provenance",
    ),
) -> DiagnosticResultV1:
    """Evaluate a test run against scenario expectations and telemetry evidence.

    Uses the deterministic Assurance Engine (Layer 5) to classify the outcome
    into one of the seven diagnostic categories:
    PASS, TEST_NOT_EXECUTED, EXPECTED_TELEMETRY_MISSING,
    DETECTION_NOT_TRIGGERED, ALERT_NOT_CORRELATED, INCONCLUSIVE, ERROR.
    """
    store = get_store()
    engine = AssuranceEngine(store)
    result = engine.evaluate_run(run_id, strict_attribution=strict_attribution)
    store.add_result(result)
    return result


@router.get(
    "/evaluation/{run_id}",
    response_model=DiagnosticResultV1,
    summary="Get latest diagnostic result for a test run",
)
def get_evaluation_for_run(run_id: str) -> DiagnosticResultV1:
    result = get_store().get_result_for_run(run_id)
    if not result:
        raise HTTPException(
            status_code=404, detail=f"Diagnostic result not found for run: {run_id}"
        )
    return result


@router.get(
    "/evaluation",
    response_model=List[DiagnosticResultV1],
    summary="List all diagnostic evaluation results",
)
def list_evaluations() -> List[DiagnosticResultV1]:
    return get_store().list_results()
