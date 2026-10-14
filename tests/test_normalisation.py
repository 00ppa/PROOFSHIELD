"""Unit tests for the telemetry normalisation layer."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from proofshield.normalisation.engine import (
    FallbackNormaliser,
    GenericEDRNormaliser,
    NormalisationEngine,
    SysmonNormaliser,
)
from proofshield.schemas import (
    EventCategory,
    RawTelemetryEventV1,
)
from proofshield.storage.jsonl_loader import validate_jsonl_file


def test_sysmon_process_creation_normalisation(raw_telemetry_valid_path: Path):
    """Verify Sysmon Event 1 process creation normalisation and attribute preservation."""
    report = validate_jsonl_file(raw_telemetry_valid_path, RawTelemetryEventV1)
    raw_event = report.records[0]  # First event is Sysmon EventID 1

    engine = NormalisationEngine()
    norm = engine.normalize(raw_event)

    # Architectural preservation guarantees
    assert norm.source_event_id == "98214"
    assert norm.source_timestamp == raw_event.source_timestamp
    assert norm.raw_event_id == raw_event.raw_event_id

    # Canonical field extraction
    assert norm.event_category == EventCategory.PROCESS_CREATION
    assert norm.process_name == "powershell.exe"
    assert "System32\\WindowsPowerShell" in (norm.process_path or "")
    assert "Net.WebClient" in (norm.command_line or "")
    assert norm.parent_process_name == "cmd.exe"
    assert norm.host == "WORKSTATION-01.corp.local"
    assert norm.user == "CORP\\victim_user"
    assert "sha256" in norm.hashes
    assert norm.hashes["sha256"].startswith("9b489d")


def test_sysmon_network_connection_normalisation(raw_telemetry_valid_path: Path):
    """Verify Sysmon Event 3 network connection normalisation."""
    report = validate_jsonl_file(raw_telemetry_valid_path, RawTelemetryEventV1)
    raw_event = report.records[1]  # Second event is Sysmon EventID 3

    engine = NormalisationEngine()
    norm = engine.normalize(raw_event)

    assert norm.source_event_id == "98215"
    assert norm.source_timestamp == raw_event.source_timestamp
    assert norm.event_category == EventCategory.NETWORK_CONNECTION
    assert norm.network_destination_ip == "198.51.100.45"
    assert norm.network_destination_port == 80


def test_generic_edr_normalisation(raw_telemetry_valid_path: Path):
    """Verify Generic EDR JSON telemetry normalisation."""
    report = validate_jsonl_file(raw_telemetry_valid_path, RawTelemetryEventV1)
    raw_event = report.records[2]  # Third event is Generic EDR procdump

    engine = NormalisationEngine()
    norm = engine.normalize(raw_event)

    assert norm.source_event_id == "EDR-EVT-77401"
    assert norm.source_timestamp == raw_event.source_timestamp
    assert norm.event_category == EventCategory.PROCESS_CREATION
    assert norm.process_name == "procdump.exe"
    assert norm.host == "DC-PROD-01"
    assert norm.user == "CORP\\admin_svc"
    assert "-ma lsass.exe" in (norm.command_line or "")


def test_fallback_normaliser_preserves_identifiers_and_timestamps():
    """Verify unknown format normaliser guarantees source-id and timestamp preservation."""
    t0 = datetime(2026, 10, 12, 12, 30, tzinfo=timezone.utc)
    raw_event = RawTelemetryEventV1(
        raw_event_id="RAW-UNKNOWN-01",
        source_event_id="PROV-CUSTOM-99",
        source_format="proprietary_custom_sensor",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={"custom_metric": 42, "node": "SENSOR-NODE-A"},
    )

    engine = NormalisationEngine()
    norm = engine.normalize(raw_event)

    # Guarantees must hold even for unfamiliar formats
    assert norm.raw_event_id == "RAW-UNKNOWN-01"
    assert norm.source_event_id == "PROV-CUSTOM-99"
    assert norm.source_timestamp == t0
    assert norm.event_category == EventCategory.OTHER
    assert norm.extra_attributes["custom_metric"] == 42


def test_batch_normalisation(raw_telemetry_valid_path: Path):
    """Verify NormalisationEngine processes full batch of valid telemetry."""
    report = validate_jsonl_file(raw_telemetry_valid_path, RawTelemetryEventV1)
    engine = NormalisationEngine()
    norm_list = engine.normalize_batch(report.records)

    assert len(norm_list) == len(report.records)
    for raw, norm in zip(report.records, norm_list):
        assert norm.raw_event_id == raw.raw_event_id
