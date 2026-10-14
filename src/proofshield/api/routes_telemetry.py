"""Telemetry ingestion and normalisation endpoints."""

from typing import Any, Dict, List, Literal, Union
from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel, Field

from proofshield.normalisation.engine import NormalisationEngine
from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticResultV1,
    GroundTruthV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
)
from proofshield.schemas.common import SCHEMA_VERSION
from proofshield.storage.jsonl_loader import (
    JSONLLineError,
    validate_jsonl_stream,
)

router = APIRouter(prefix="/api/v1", tags=["Telemetry & Normalisation"])
normalisation_engine = NormalisationEngine()


class IngestJSONLRequest(BaseModel):
    """Payload for direct JSONL text stream ingestion."""
    schema_type: Literal[
        "raw_telemetry",
        "scenario",
        "test_run",
        "normalized_telemetry",
        "detection_rule",
        "alert",
        "ground_truth",
    ] = Field(
        ...,
        description="Target Pydantic schema model to validate against",
    )
    content: str = Field(..., description="Raw newline-delimited JSON (JSONL) text")


class IngestJSONLResponse(BaseModel):
    """Result of JSONL text stream ingestion and validation."""
    schema_type: str
    total_lines: int
    valid_count: int
    error_count: int
    is_valid: bool
    errors: List[JSONLLineError]
    sample_valid_records: List[Dict[str, Any]]


@router.get("/schemas/info", summary="Schema catalog metadata")
def get_schemas_info() -> Dict[str, Any]:
    """Return catalog of versioned platform schemas and architectural roles."""
    return {
        "version": SCHEMA_VERSION,
        "schemas": {
            "ScenarioV1": {
                "role": "Detection validation test specification & independent ground-truth expectation",
                "ground_truth_independent": True,
            },
            "TestRunV1": {
                "role": "Execution run record with telemetry window & provenance (synthetic vs live)",
                "synthetic_flag_required": True,
            },
            "RawTelemetryEventV1": {
                "role": "Unaltered evidence record preserving original payload, source ID, and source timestamp",
                "immutable_evidence": True,
            },
            "NormalizedTelemetryEventV1": {
                "role": "Canonical security event schema with preserved source ID and timestamp",
                "derived_from": "RawTelemetryEventV1",
            },
            "DetectionRuleV1": {
                "role": "Detection rule tracking versioning, rule content, and evaluation backend",
                "reproducible_evaluation": True,
            },
            "AlertV1": {
                "role": "Security monitoring alert correlated to detection testing windows",
                "correlated_to_runs": True,
            },
            "DiagnosticResultV1": {
                "role": "Deterministic verdict and root-cause failure classification from the diagnostic engine",
                "independent_from_ground_truth": True,
            },
            "GroundTruthV1": {
                "role": "Independently established expected diagnostic outcome for evaluating diagnostic accuracy",
                "independent_from_predictions": True,
            },
        },
    }


@router.post(
    "/telemetry/raw",
    response_model=List[RawTelemetryEventV1],
    summary="Validate and ingest raw telemetry events",
)
def ingest_raw_telemetry(
    events: Union[RawTelemetryEventV1, List[RawTelemetryEventV1]] = Body(
        ...,
        description="Single raw telemetry event or batch of events",
    )
) -> List[RawTelemetryEventV1]:
    """Validate one or more raw telemetry events against RawTelemetryEventV1."""
    if isinstance(events, RawTelemetryEventV1):
        return [events]
    return events


@router.post(
    "/telemetry/normalize",
    response_model=List[NormalizedTelemetryEventV1],
    summary="Normalize raw telemetry events into canonical schema",
)
def normalize_telemetry(
    events: Union[RawTelemetryEventV1, List[RawTelemetryEventV1]] = Body(
        ...,
        description="Raw telemetry events to normalize",
    )
) -> List[NormalizedTelemetryEventV1]:
    """Convert raw telemetry events to canonical NormalizedTelemetryEventV1 records.

    Preserves source event identifiers and original source timestamps.
    """
    event_list = [events] if isinstance(events, RawTelemetryEventV1) else events
    try:
        return normalisation_engine.normalize_batch(event_list)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Normalisation failure: {str(exc)}")


@router.post(
    "/ingest/jsonl",
    response_model=IngestJSONLResponse,
    summary="Validate and ingest JSONL dataset",
)
def ingest_jsonl_payload(payload: IngestJSONLRequest) -> IngestJSONLResponse:
    """Validate a multi-line JSONL stream against the requested schema."""
    schema_map = {
        "raw_telemetry": RawTelemetryEventV1,
        "scenario": ScenarioV1,
        "test_run": TestRunV1,
        "normalized_telemetry": NormalizedTelemetryEventV1,
        "detection_rule": DetectionRuleV1,
        "alert": AlertV1,
        "ground_truth": GroundTruthV1,
    }

    schema_cls = schema_map[payload.schema_type]
    lines = payload.content.splitlines()
    report = validate_jsonl_stream(lines, schema_cls)

    # Return up to first 5 valid records as a preview
    samples = [r.model_dump(mode="json") for r in report.records[:5]]

    return IngestJSONLResponse(
        schema_type=payload.schema_type,
        total_lines=report.total_lines,
        valid_count=report.valid_count,
        error_count=report.error_count,
        is_valid=report.is_valid,
        errors=report.errors,
        sample_valid_records=samples,
    )
