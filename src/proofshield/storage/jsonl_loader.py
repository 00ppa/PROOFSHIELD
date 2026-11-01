"""Streaming JSONL import, serialization, and schema validation."""

import json
from pathlib import Path
import re
from typing import Any, Dict, Generic, Iterable, List, Optional, Sequence, TextIO, Type, TypeVar, Union
from pydantic import BaseModel, Field, ValidationError

T = TypeVar("T", bound=BaseModel)


class JSONLLineError(BaseModel):
    """Details of a failed record validation during JSONL processing."""
    line_number: int
    raw_content: str
    error_type: str
    error_message: str


class JSONLValidationReport(BaseModel, Generic[T]):
    """Aggregated report of JSONL file or stream validation."""
    total_lines: int = 0
    valid_count: int = 0
    error_count: int = 0
    errors: List[JSONLLineError] = []
    records: List[T] = []
    record_line_numbers: List[int] = []

    @property
    def is_valid(self) -> bool:
        """True if all non-empty lines were successfully validated with zero errors."""
        return self.error_count == 0 and self.valid_count > 0


def load_jsonl_raw(source: Union[str, Path, TextIO]) -> List[Dict[str, Any]]:
    """Load JSONL lines as raw dictionaries, skipping malformed lines.

    Malformed JSON lines are silently skipped so that a single corrupted
    record cannot abort ingestion of the remaining valid records.  This
    is consistent with the fault-isolation guarantee already provided by
    :func:`validate_jsonl_stream`.

    Args:
        source: File path or open text stream.

    Returns:
        List of parsed JSON dictionaries (one per successfully decoded line).
    """
    records: List[Dict[str, Any]] = []

    if isinstance(source, (str, Path)):
        with open(source, "r", encoding="utf-8") as f:
            lines = f.readlines()
    else:
        lines = source.readlines()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except json.JSONDecodeError:
            # Skip malformed lines; partial import is preferred over full abort.
            continue

    return records


def validate_jsonl_stream(
    lines: Iterable[str],
    schema_cls: Type[T],
) -> JSONLValidationReport[T]:
    """Validate a sequence of lines against a Pydantic schema model.

    Errors are collected per line with line numbers and messages, without
    failing the entire ingestion process.

    Args:
        lines: Sequence of string lines.
        schema_cls: Pydantic model class to validate against.

    Returns:
        JSONLValidationReport containing parsed records and collected errors.
    """
    report = JSONLValidationReport[T]()

    for idx, raw_line in enumerate(lines, start=1):
        report.total_lines += 1
        line = raw_line.strip()
        if not line:
            # Cleanly skip empty lines without counting as errors
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            report.error_count += 1
            report.errors.append(
                JSONLLineError(
                    line_number=idx,
                    raw_content=line[:200],
                    error_type="JSONDecodeError",
                    error_message=f"Invalid JSON syntax: {str(exc)}",
                )
            )
            continue

        if not isinstance(data, dict):
            report.error_count += 1
            report.errors.append(
                JSONLLineError(
                    line_number=idx,
                    raw_content=line[:200],
                    error_type="InvalidRecordFormat",
                    error_message="JSONL line must be a JSON object (dictionary)",
                )
            )
            continue

        try:
            record = schema_cls.model_validate(data)
            report.records.append(record)
            report.record_line_numbers.append(idx)
            report.valid_count += 1
        except ValidationError as exc:
            report.error_count += 1
            report.errors.append(
                JSONLLineError(
                    line_number=idx,
                    raw_content=line[:200],
                    error_type="ValidationError",
                    error_message=str(exc),
                )
            )

    return report


def validate_jsonl_file(
    filepath: Union[str, Path],
    schema_cls: Type[T],
) -> JSONLValidationReport[T]:
    """Validate a JSONL file on disk against a Pydantic schema model."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"JSONL file not found at: {filepath}")

    with open(path, "r", encoding="utf-8") as f:
        return validate_jsonl_stream(f, schema_cls)


def write_jsonl(
    records: Iterable[Union[BaseModel, Dict[str, Any]]],
    filepath: Union[str, Path],
) -> int:
    """Serialize a sequence of Pydantic models or dicts to a JSONL file.

    Args:
        records: Iterable of models or dicts.
        filepath: Destination file path.

    Returns:
        Number of records written.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open(path, "w", encoding="utf-8") as f:
        for item in records:
            if isinstance(item, BaseModel):
                json_str = item.model_dump_json()
            else:
                json_str = json.dumps(item, default=str)
            f.write(json_str + "\n")
            count += 1

    return count


class BulkIngestReport(BaseModel):
    """Aggregated outcome of bulk telemetry or entity persistence."""
    source_records: int = 0
    total_records: int = 0
    persisted_raw_count: int = 0
    persisted_normalized_count: int = 0
    persisted_other_count: int = 0
    failed_count: int = 0
    total_operations_attempted: int = 0
    physical_lines_read: int = 0
    blank_lines_skipped: int = 0
    persisted_ids: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    @property
    def total_persisted(self) -> int:
        """Total records successfully committed to the store."""
        return self.persisted_raw_count + self.persisted_normalized_count + self.persisted_other_count

    @property
    def is_success(self) -> bool:
        """True if batch had zero failures and at least one record was persisted."""
        return self.failed_count == 0 and self.total_persisted > 0


def _sanitize_storage_error(exc: Exception) -> str:
    """Sanitize internal filesystem paths from storage exception messages."""
    msg = str(exc)
    msg = re.sub(
        r"(?:\\\\\?\\)?[A-Za-z]:[\\/](?:[\w\-\.@\(\)\+~%]+(?: +[\w\-\.@\(\)\+~%]+)*[\\/])*[\w\-\.@\(\)\+~%]*",
        "[REDACTED_PATH]",
        msg,
    )
    msg = re.sub(
        r"\\\\[\w\.\-]+[\\/](?:[\w\-\.@\(\)\+~%]+(?: +[\w\-\.@\(\)\+~%]+)*[\\/])*[\w\-\.@\(\)\+~%]*",
        "[REDACTED_PATH]",
        msg,
    )
    msg = re.sub(
        r"/(?:var|tmp|home|etc|usr|opt|root|app|srv|data)/[\w\-\./@\(\)\+~%]*",
        "[REDACTED_PATH]",
        msg,
    )
    return msg


def _get_entity_id(record: Any) -> str:
    for attr in (
        "raw_event_id",
        "normalized_event_id",
        "scenario_id",
        "run_id",
        "rule_id",
        "alert_id",
        "ground_truth_id",
    ):
        if hasattr(record, attr):
            return str(getattr(record, attr))
    return "unknown"


def _persist_entity_to_store(store: Any, record: Any) -> str:
    cls_name = record.__class__.__name__
    if cls_name == "RawTelemetryEventV1":
        store.add_raw_event(record)
        return record.raw_event_id
    elif cls_name == "NormalizedTelemetryEventV1":
        store.add_normalized_event(record)
        return record.normalized_event_id
    elif cls_name == "ScenarioV1":
        store.add_scenario(record)
        return record.scenario_id
    elif cls_name == "TestRunV1":
        store.add_run(record)
        return record.run_id
    elif cls_name == "DetectionRuleV1":
        store.add_rule(record)
        return record.rule_id
    elif cls_name == "AlertV1":
        store.add_alert(record)
        return record.alert_id
    elif cls_name == "GroundTruthV1":
        store.add_ground_truth(record)
        return record.ground_truth_id
    else:
        raise ValueError(f"Unsupported record type for persistence: {cls_name}")


def bulk_ingest_telemetry(
    store: Any,
    raw_events: Optional[Sequence[Any]] = None,
    normalized_events: Optional[Sequence[Any]] = None,
    normalize_raw: bool = False,
    atomic: bool = True,
) -> BulkIngestReport:
    """Reliably persist raw and/or normalized telemetry into a ProofShield store.

    Args:
        store: StoreProtocol implementation (InMemoryStore or SQLiteStore).
        raw_events: Optional sequence of RawTelemetryEventV1 models.
        normalized_events: Optional sequence of NormalizedTelemetryEventV1 models.
        normalize_raw: If True, also normalizes raw_events via NormalisationEngine
            and persists the resulting NormalizedTelemetryEventV1 records.
        atomic: If True, wraps ingestion in store.transaction(). On any error,
            all changes are rolled back and failed_count is updated.
            If False, best-effort ingestion persists valid records and records
            failures individually.

    Returns:
        BulkIngestReport with accurate counts of persisted vs failed records.
    """
    report = BulkIngestReport()
    raw_list = list(raw_events or [])
    norm_list = list(normalized_events or [])

    report.source_records = len(raw_list) + len(norm_list)
    report.total_operations_attempted = len(raw_list) + len(norm_list)
    report.total_records = report.total_operations_attempted

    if not raw_list and not norm_list:
        return report

    derived_normalized = []
    if normalize_raw and raw_list:
        from proofshield.normalisation.engine import NormalisationEngine
        engine = NormalisationEngine()
        try:
            derived_normalized = engine.normalize_batch(raw_list)
        except Exception as exc:
            report.failed_count = len(raw_list)
            sanitized = _sanitize_storage_error(exc)
            report.errors.append(f"Normalisation failure: {sanitized}")
            return report

    all_normalized = list(norm_list) + derived_normalized
    report.total_operations_attempted = len(raw_list) + len(all_normalized)
    report.total_records = report.total_operations_attempted

    if atomic:
        try:
            with store.transaction():
                persisted_ids: List[str] = []
                for raw in raw_list:
                    store.add_raw_event(raw)
                    persisted_ids.append(raw.raw_event_id)
                for norm in all_normalized:
                    store.add_normalized_event(norm)
                    persisted_ids.append(norm.normalized_event_id)

                report.persisted_raw_count = len(raw_list)
                report.persisted_normalized_count = len(all_normalized)
                report.persisted_ids = persisted_ids
        except Exception as exc:
            report.failed_count = report.total_operations_attempted
            report.persisted_raw_count = 0
            report.persisted_normalized_count = 0
            report.persisted_ids = []
            sanitized = _sanitize_storage_error(exc)
            report.errors.append(f"Atomic transaction aborted: {sanitized}")
    else:
        for raw in raw_list:
            try:
                store.add_raw_event(raw)
                report.persisted_raw_count += 1
                report.persisted_ids.append(raw.raw_event_id)
            except Exception as exc:
                report.failed_count += 1
                sanitized = _sanitize_storage_error(exc)
                report.errors.append(f"Raw event '{raw.raw_event_id}': {sanitized}")

        for norm in all_normalized:
            try:
                store.add_normalized_event(norm)
                report.persisted_normalized_count += 1
                report.persisted_ids.append(norm.normalized_event_id)
            except Exception as exc:
                report.failed_count += 1
                sanitized = _sanitize_storage_error(exc)
                report.errors.append(f"Normalized event '{norm.normalized_event_id}': {sanitized}")

    return report


def ingest_jsonl_file_to_store(
    filepath: Union[str, Path],
    schema_cls: Type[T],
    store: Any,
    atomic: bool = True,
    normalize_if_raw: bool = False,
) -> BulkIngestReport:
    """Read a JSONL file, validate records, and persist them into a ProofShield store.

    Args:
        filepath: Path to the JSONL file.
        schema_cls: Target Pydantic model class.
        store: StoreProtocol implementation (InMemoryStore or SQLiteStore).
        atomic: If True, rolls back on any parsing, validation, or persistence error.
        normalize_if_raw: If True and schema_cls is RawTelemetryEventV1, also
            normalizes raw events and stores the derived NormalizedTelemetryEventV1.

    Returns:
        BulkIngestReport with detailed success, failure, and ID metrics.
    """
    report = BulkIngestReport()
    val_report = validate_jsonl_file(filepath, schema_cls)

    report.physical_lines_read = val_report.total_lines
    report.blank_lines_skipped = val_report.total_lines - (val_report.valid_count + val_report.error_count)
    report.source_records = val_report.valid_count
    report.total_operations_attempted = val_report.valid_count + val_report.error_count
    report.total_records = report.total_operations_attempted

    # In atomic mode, if any line validation or JSON decoding failed, abort persistence entirely
    if atomic and val_report.error_count > 0:
        report.failed_count = report.total_operations_attempted
        for err in val_report.errors:
            report.errors.append(f"Line {err.line_number} [{err.error_type}]: {err.error_message}")
        return report

    cls_name = schema_cls.__name__

    if cls_name == "RawTelemetryEventV1":
        telemetry_report = bulk_ingest_telemetry(
            store=store,
            raw_events=val_report.records,
            normalize_raw=normalize_if_raw,
            atomic=atomic,
        )
        telemetry_report.physical_lines_read = report.physical_lines_read
        telemetry_report.blank_lines_skipped = report.blank_lines_skipped
        telemetry_report.source_records = report.source_records
        if val_report.error_count > 0:
            telemetry_report.failed_count += val_report.error_count
            telemetry_report.total_operations_attempted += val_report.error_count
            telemetry_report.total_records = telemetry_report.total_operations_attempted
            for err in val_report.errors:
                telemetry_report.errors.append(f"Line {err.line_number} [{err.error_type}]: {err.error_message}")
        return telemetry_report

    elif cls_name == "NormalizedTelemetryEventV1":
        telemetry_report = bulk_ingest_telemetry(
            store=store,
            normalized_events=val_report.records,
            atomic=atomic,
        )
        telemetry_report.physical_lines_read = report.physical_lines_read
        telemetry_report.blank_lines_skipped = report.blank_lines_skipped
        telemetry_report.source_records = report.source_records
        if val_report.error_count > 0:
            telemetry_report.failed_count += val_report.error_count
            telemetry_report.total_operations_attempted += val_report.error_count
            telemetry_report.total_records = telemetry_report.total_operations_attempted
            for err in val_report.errors:
                telemetry_report.errors.append(f"Line {err.line_number} [{err.error_type}]: {err.error_message}")
        return telemetry_report

    # Other schemas (ScenarioV1, TestRunV1, DetectionRuleV1, AlertV1, GroundTruthV1)
    if atomic:
        try:
            with store.transaction():
                persisted_ids: List[str] = []
                for rec in val_report.records:
                    rec_id = _persist_entity_to_store(store, rec)
                    persisted_ids.append(rec_id)
                report.persisted_other_count = len(val_report.records)
                report.persisted_ids = persisted_ids
        except Exception as exc:
            report.failed_count = report.total_operations_attempted
            report.persisted_other_count = 0
            sanitized = _sanitize_storage_error(exc)
            report.errors.append(f"Atomic transaction aborted: {sanitized}")
    else:
        for idx, rec in zip(val_report.record_line_numbers, val_report.records):
            try:
                rec_id = _persist_entity_to_store(store, rec)
                report.persisted_other_count += 1
                report.persisted_ids.append(rec_id)
            except Exception as exc:
                report.failed_count += 1
                rec_id = _get_entity_id(rec)
                sanitized = _sanitize_storage_error(exc)
                report.errors.append(f"Line {idx} record '{rec_id}': {sanitized}")

        report.failed_count += val_report.error_count
        for err in val_report.errors:
            report.errors.append(f"Line {err.line_number} [{err.error_type}]: {err.error_message}")

    return report
