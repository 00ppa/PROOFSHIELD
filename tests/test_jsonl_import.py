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

