"""Telemetry ingestion and normalisation endpoints."""

from typing import Any, Dict, List, Literal, Optional, Union
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
from proofshield.services.base_store import StoreProtocol
from proofshield.services.store import get_store
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
    store: Optional[bool] = Field(
        default=False,
        description="Persist valid records to store if True (default: False)",
    )
    atomic: Optional[bool] = Field(
        default=False,
        description="If True with store=True, transaction rolls back on any error (default: False)",
    )


class IngestJSONLResponse(BaseModel):
    """Result of JSONL text stream ingestion and validation."""
    schema_type: str
    total_lines: int
    valid_count: int
    error_count: int
    is_valid: bool
    errors: List[JSONLLineError]
    sample_valid_records: List[Dict[str, Any]]
    stored: bool = Field(
        default=False,
        description="Whether valid records were persisted to store",
    )
    persisted_count: int = Field(
        default=0,
        description="Number of valid records successfully persisted",
    )


def _get_record_id(record: Any) -> str:
    for attr in (
        "raw_event_id",
        "scenario_id",
        "run_id",
        "normalized_event_id",
        "rule_id",
        "alert_id",
        "ground_truth_id",
    ):
        if hasattr(record, attr):
            return str(getattr(record, attr))
    return "unknown"


def _persist_single_record(store: StoreProtocol, schema_type: str, record: Any) -> None:
    if schema_type == "raw_telemetry":
        store.add_raw_event(record)
    elif schema_type == "scenario":
        store.add_scenario(record)
    elif schema_type == "test_run":
        store.add_run(record)
    elif schema_type == "normalized_telemetry":
        store.add_normalized_event(record)
    elif schema_type == "detection_rule":
        store.add_rule(record)
    elif schema_type == "alert":
        store.add_alert(record)
    elif schema_type == "ground_truth":
        store.add_ground_truth(record)
    else:
        raise ValueError(f"Unsupported schema type for persistence: {schema_type}")


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
    ),
    store: bool = Query(
        False,
        description="Persist validated events to store if True (default: False)",
    ),
) -> List[RawTelemetryEventV1]:
    """Validate one or more raw telemetry events against RawTelemetryEventV1.

    If store=True, validated events are persisted to the active entity store.
    Raises HTTP 409 if any event has a duplicate identifier.
    """
    event_list = [events] if isinstance(events, RawTelemetryEventV1) else events
    if store:
        s = get_store()
        try:
            with s.transaction():
                for evt in event_list:
                    s.add_raw_event(evt)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
    return event_list


@router.post(
    "/telemetry/normalize",
    response_model=List[NormalizedTelemetryEventV1],
    summary="Normalize raw telemetry events into canonical schema",
)
def normalize_telemetry(
    events: Union[RawTelemetryEventV1, List[RawTelemetryEventV1]] = Body(
        ...,
        description="Raw telemetry events to normalize",
    ),
    store: bool = Query(
        False,
        description="Persist normalized events to store if True (default: False)",
    ),
) -> List[NormalizedTelemetryEventV1]:
    """Convert raw telemetry events to canonical NormalizedTelemetryEventV1 records.

    Preserves source event identifiers and original source timestamps.
    If store=True, normalized events are persisted to the active entity store.
    Raises HTTP 409 if any normalized event has a duplicate identifier.
    """
    event_list = [events] if isinstance(events, RawTelemetryEventV1) else events
    try:
        normalized = normalisation_engine.normalize_batch(event_list)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Normalisation failure: {str(exc)}")

    if store:
        s = get_store()
        try:
            with s.transaction():
                for norm_evt in normalized:
                    s.add_normalized_event(norm_evt)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    return normalized


@router.post(
    "/ingest/jsonl",
    response_model=IngestJSONLResponse,
    summary="Validate and ingest JSONL dataset",
)
def ingest_jsonl_payload(
    payload: IngestJSONLRequest,
    store: Optional[bool] = Query(None, description="Persist valid records to store if True"),
    atomic: Optional[bool] = Query(None, description="Enforce all-or-nothing atomic batch transaction"),
) -> IngestJSONLResponse:
    """Validate a multi-line JSONL stream against the requested schema.

    Optionally persists valid records when store=True (default: False).
    When atomic=True, any parsing, validation, or persistence error rolls back all insertions.
    """
    should_store = store if store is not None else (payload.store or False)
    should_atomic = atomic if atomic is not None else (payload.atomic or False)

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

    persisted_count = 0
    stored = False

    if should_store and report.valid_count > 0:
        s = get_store()
        line_numbers = getattr(report, "record_line_numbers", list(range(1, len(report.records) + 1)))

        if should_atomic:
            # Atomic mode: if any line-level error occurred during parsing, do not persist anything
            if report.error_count > 0:
                stored = False
                persisted_count = 0
            else:
                try:
                    with s.transaction():
                        for rec in report.records:
                            _persist_single_record(s, payload.schema_type, rec)
                    persisted_count = len(report.records)
                    stored = True
                except ValueError as exc:
                    stored = False
                    persisted_count = 0
                    report.errors.append(
                        JSONLLineError(
                            line_number=0,
                            raw_content="atomic_batch_transaction",
                            error_type="StorageError",
                            error_message=f"Atomic batch insertion aborted: {str(exc)}",
                        )
                    )
                    report.error_count += 1
        else:
            # Fault-isolated (best-effort) mode: persist each valid record individually
            successful_persists = 0
            for line_no, rec in zip(line_numbers, report.records):
                try:
                    _persist_single_record(s, payload.schema_type, rec)
                    successful_persists += 1
                except ValueError as exc:
                    rec_id = _get_record_id(rec)
                    report.errors.append(
                        JSONLLineError(
                            line_number=line_no,
                            raw_content=f"{rec.__class__.__name__}(id={rec_id})",
                            error_type="StorageError",
                            error_message=str(exc),
                        )
                    )
                    report.error_count += 1
                    report.valid_count -= 1

            persisted_count = successful_persists
            stored = (persisted_count > 0)

    # Return up to first 5 valid records as a preview
    samples = [r.model_dump(mode="json") for r in report.records[:5]]

    return IngestJSONLResponse(
        schema_type=payload.schema_type,
        total_lines=report.total_lines,
        valid_count=report.valid_count,
        error_count=report.error_count,
        is_valid=(report.error_count == 0 and report.valid_count > 0),
        errors=report.errors,
        sample_valid_records=samples,
        stored=stored,
        persisted_count=persisted_count,
    )
