"""Unit tests for JSONL streaming ingestion and validation."""

from pathlib import Path
import pytest

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    GroundTruthV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
)
from proofshield.storage.jsonl_loader import (
    load_jsonl_raw,
    validate_jsonl_file,
    validate_jsonl_stream,
    write_jsonl,
)


def test_validate_scenarios_jsonl_fixture(scenarios_jsonl_path: Path):
    """Verify scenarios_v1.jsonl validates with zero errors."""
    report = validate_jsonl_file(scenarios_jsonl_path, ScenarioV1)
    assert report.is_valid is True
    assert report.valid_count == 3
    assert report.error_count == 0
    assert len(report.records) == 3
    assert report.records[0].scenario_id == "SCN-T1059.001-01"


def test_validate_test_runs_jsonl_fixture(test_runs_jsonl_path: Path):
    """Verify test_runs_v1.jsonl validates with zero errors and enforces synthetic marking."""
    report = validate_jsonl_file(test_runs_jsonl_path, TestRunV1)
    assert report.is_valid is True
    assert report.valid_count == 3
    assert all(r.is_synthetic for r in report.records)


def test_validate_raw_telemetry_valid_fixture(raw_telemetry_valid_path: Path):
    """Verify raw_telemetry_valid_v1.jsonl parses all 4 events properly."""
    report = validate_jsonl_file(raw_telemetry_valid_path, RawTelemetryEventV1)
    assert report.is_valid is True
    assert report.valid_count == 4
    assert report.error_count == 0


def test_validate_raw_telemetry_malformed_fixture(raw_telemetry_malformed_path: Path):
    """Verify malformed JSONL cleanly isolates invalid lines without crashing the stream."""
    report = validate_jsonl_file(raw_telemetry_malformed_path, RawTelemetryEventV1)
    assert report.is_valid is False
    assert report.valid_count == 2
    assert report.error_count == 3

    # Check error line numbers
    error_lines = [e.line_number for e in report.errors]
    assert 3 in error_lines  # Corrupted JSON line
    assert 6 in error_lines  # Missing source_event_id
    assert 7 in error_lines  # Bad datetime format


def test_jsonl_write_and_reload(tmp_path: Path, scenarios_jsonl_path: Path):
    """Verify writing records to JSONL and reloading matches original models."""
    original = validate_jsonl_file(scenarios_jsonl_path, ScenarioV1)
    dest_file = tmp_path / "exported_scenarios.jsonl"

    count = write_jsonl(original.records, dest_file)
    assert count == len(original.records)

    reloaded = validate_jsonl_file(dest_file, ScenarioV1)
    assert reloaded.is_valid is True
    assert reloaded.valid_count == original.valid_count
    assert reloaded.records[0].scenario_id == original.records[0].scenario_id


def test_validate_detection_rules_jsonl_fixture(detection_rules_jsonl_path: Path):
    """Verify detection_rules_v1.jsonl validates with zero errors."""
    report = validate_jsonl_file(detection_rules_jsonl_path, DetectionRuleV1)
    assert report.is_valid is True
    assert report.valid_count == 2
    assert report.error_count == 0
    assert report.records[0].rule_id == "RULE-WIN-PS-CRADLE-01"


def test_validate_alerts_jsonl_fixture(alerts_jsonl_path: Path):
    """Verify alerts_v1.jsonl validates with zero errors."""
    report = validate_jsonl_file(alerts_jsonl_path, AlertV1)
    assert report.is_valid is True
    assert report.valid_count == 3
    assert report.error_count == 0
    assert report.records[0].alert_id == "ALT-WAZ-20261012-001"


def test_validate_ground_truth_jsonl_fixture(ground_truth_jsonl_path: Path):
    """Verify ground_truth_v1.jsonl validates with zero errors."""
    report = validate_jsonl_file(ground_truth_jsonl_path, GroundTruthV1)
    assert report.is_valid is True
    assert report.valid_count == 3
    assert report.error_count == 0
    assert report.records[0].ground_truth_id == "GT-RUN-20261012-001"


def test_load_jsonl_raw_tolerates_malformed_lines(
    raw_telemetry_malformed_path: Path,
) -> None:
    """Regression: load_jsonl_raw must not raise on malformed JSON lines.

    Fixture layout (raw_telemetry_malformed_v1.jsonl):
      line 1 – valid JSON dict  (RAW-SYS-OK-01)
      line 2 – blank
      line 3 – corrupted JSON   (must be skipped)
      line 4 – blank
      line 5 – valid JSON dict  (RAW-SYS-OK-02)
      line 6 – valid JSON dict, schema-invalid (missing source_event_id) – RAW-ERR-03
      line 7 – valid JSON dict, schema-invalid (bad datetime)             – RAW-ERR-04

    load_jsonl_raw is a raw decoder only (no schema validation), so lines 6
    and 7 must be included.  The corrupted line 3 must produce no record.
    Previously the function propagated json.JSONDecodeError on line 3, aborting
    the entire import and losing the four records that follow it.
    """
    records = load_jsonl_raw(raw_telemetry_malformed_path)

    assert isinstance(records, list), "load_jsonl_raw must always return a list"
    # Exactly 4 parseable dicts: lines 1, 5, 6, 7.  Line 3 (corrupted JSON)
    # must be skipped; blank lines are ignored.
    assert len(records) == 4, (
        f"Expected exactly 4 parsed dicts from malformed fixture, got {len(records)}"
    )

    raw_ids = {r.get("raw_event_id") for r in records if isinstance(r, dict)}

    # Records before the bad line must be preserved.
    assert "RAW-SYS-OK-01" in raw_ids, "Record before bad line must be present"
    # Records after the bad line must be preserved (this was the pre-fix failure mode).
    assert "RAW-SYS-OK-02" in raw_ids, "Record after bad line must be present"
    # Schema-invalid-but-syntactically-valid records must also be returned
    # (schema enforcement is the caller's responsibility, not load_jsonl_raw's).
    assert "RAW-ERR-03" in raw_ids, "Schema-invalid-but-parseable record must be returned"
    assert "RAW-ERR-04" in raw_ids, "Schema-invalid-but-parseable record must be returned"


def test_validate_raw_telemetry_realistic_fixture(raw_telemetry_realistic_path: Path):
    """Verify raw_telemetry_realistic_v1.jsonl parses all 3 realistic enterprise events cleanly."""
    report = validate_jsonl_file(raw_telemetry_realistic_path, RawTelemetryEventV1)
    assert report.is_valid is True
    assert report.valid_count == 3
    assert report.error_count == 0
    assert len(report.records) == 3
