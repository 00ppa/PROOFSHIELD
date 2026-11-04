"""API endpoints for persisted evidence-grounded analyst explanations."""

from typing import List

from fastapi import APIRouter, HTTPException, Path

from proofshield.schemas.explanation import AnalystExplanationV1
from proofshield.services.explanation import EvidenceGroundedExplanationService
from proofshield.services.store import get_store

router = APIRouter(prefix="/api/v1", tags=["Analyst Explanation"])


@router.post(
    "/explanations/{run_id}",
    response_model=AnalystExplanationV1,
    summary="Generate and persist an evidence-grounded explanation",
)
def generate_explanation(
    run_id: str = Path(..., pattern=r"^[A-Za-z0-9_\-.]+$", min_length=3, max_length=128),
) -> AnalystExplanationV1:
    store = get_store()
    result = store.get_result_for_run(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Diagnostic result not found for run: {run_id}")
    try:
        explanation = EvidenceGroundedExplanationService(store).explain(result)
        return store.add_explanation(explanation)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/explanations/{run_id}",
    response_model=List[AnalystExplanationV1],
    summary="List explanations for a test run",
)
def list_explanations(
    run_id: str = Path(..., pattern=r"^[A-Za-z0-9_\-.]+$", min_length=3, max_length=128),
) -> List[AnalystExplanationV1]:
    explanations = get_store().list_explanations(run_id=run_id)
    if any(not EvidenceGroundedExplanationService.verify(item) for item in explanations):
        raise HTTPException(409, "Stored explanation integrity verification failed")
    return explanations
