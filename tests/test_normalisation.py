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


def test_sysmon_wef_event_record_id_and_token_normalisation(raw_telemetry_realistic_path: Path):
    """Verify realistic Sysmon Event 1 forwarded via WEF with EventRecordID and command-line token."""
    report = validate_jsonl_file(raw_telemetry_realistic_path, RawTelemetryEventV1)
    raw_event = report.records[0]

    engine = NormalisationEngine()
    norm = engine.normalize(raw_event)

    assert norm.event_category == EventCategory.PROCESS_CREATION
    assert norm.source_event_id == "410029"  # Preserved from payload EventRecordID
    assert norm.host == "WS-FIN-CORP-04.corp.acme.internal"
    assert norm.user == "ACME\\operator_jdoe"
    assert norm.process_name == "cmd.exe"
    assert norm.process_path == "C:\\Windows\\System32\\cmd.exe"
    assert norm.parent_process_name == "explorer.exe"
    assert norm.parent_command_line is None  # Missing optional field handled cleanly
    assert norm.execution_token == "TOK-SIM-SYS-001"  # Extracted from command line
    assert norm.hashes["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert norm.extra_attributes["ProcessId"] == 7824
    assert norm.extra_attributes["ProcessGuid"] == "{a27f54c2-9a3b-670e-1100-000000004f00}"


def test_crowdstrike_edr_alternate_fields_and_dict_hashes_normalisation(raw_telemetry_realistic_path: Path):
    """Verify realistic CrowdStrike EDR process creation with device_name, account, binary_path, and dict hashes."""
    report = validate_jsonl_file(raw_telemetry_realistic_path, RawTelemetryEventV1)
    raw_event = report.records[1]

    engine = NormalisationEngine()
    norm = engine.normalize(raw_event)

    assert norm.event_category == EventCategory.PROCESS_CREATION
    assert norm.source_event_id == "CS-AID-99214-EVT-88201"
    assert norm.host == "SRV-APP-PROD01"  # Mapped from device_name
    assert norm.user == "NT AUTHORITY\\SYSTEM"  # Mapped from account
    assert norm.process_name == "worker.exe"  # Extracted from binary_path basename
    assert norm.process_path == "C:\\Program Files\\Acme\\worker.exe"
    assert norm.parent_process_name == "services.exe"  # Mapped from parent_name
    assert norm.parent_command_line is None
    assert norm.execution_token == "TOK-EDR-CS-002"  # Extracted from [TOKEN:...]
    assert norm.hashes["sha256"] == "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"
    assert norm.hashes["md5"] == "c3fcd3d76192e4007dfb496cca67e13b"
    assert norm.extra_attributes["agent_version"] == "7.12.18104.0"


def test_sysmon_network_string_port_and_missing_cmdline_normalisation(raw_telemetry_realistic_path: Path):
    """Verify realistic Sysmon Event 3 network connection with string port and omitted cmdline/hashes."""
    report = validate_jsonl_file(raw_telemetry_realistic_path, RawTelemetryEventV1)
    raw_event = report.records[2]

    engine = NormalisationEngine()
    norm = engine.normalize(raw_event)

    assert norm.event_category == EventCategory.NETWORK_CONNECTION
    assert norm.source_event_id == "410035"
    assert norm.host == "WS-FIN-CORP-04.corp.acme.internal"
    assert norm.process_name == "powershell.exe"
    assert norm.network_destination_ip == "192.0.2.145"
    assert norm.network_destination_port == 443
    assert isinstance(norm.network_destination_port, int)
    assert norm.command_line is None  # Omitted in standard Sysmon Event 3
    assert norm.hashes == {}  # Hashes not recorded for network connections
    assert norm.extra_attributes["DestinationHostname"] == "c2-staging.acme.threat"
    assert norm.extra_attributes["Protocol"] == "tcp"
    assert norm.extra_attributes["Initiated"] is True


def test_malformed_and_missing_optional_telemetry_resilience():
    """Verify normalizers gracefully handle string event IDs, non-numeric ports, and missing optional fields."""
    t0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    engine = NormalisationEngine()

    # 1. Sysmon with string EventID, non-numeric port string, and null optional fields
    raw_sysmon = RawTelemetryEventV1(
        raw_event_id="RAW-EDGE-SYS-01",
        source_event_id="EVTX-EDGE-1",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "EventID": "3",
            "Computer": "HOST-EDGE-01",
            "DestinationIp": "10.0.0.1",
            "DestinationPort": "N/A",  # Non-numeric port string
            "Image": None,
            "CommandLine": None,
            "User": None,
            "Hashes": None,
        },
    )
    norm_sysmon = engine.normalize(raw_sysmon)
    assert norm_sysmon.event_category == EventCategory.NETWORK_CONNECTION
    assert norm_sysmon.network_destination_port is None  # Non-numeric gracefully handled
    assert norm_sysmon.process_name is None
    assert norm_sysmon.command_line is None
    assert norm_sysmon.user is None
    assert norm_sysmon.hashes == {}

    # 2. Generic EDR with non-numeric dst_port and omitted command/parent
    raw_edr = RawTelemetryEventV1(
        raw_event_id="RAW-EDGE-EDR-02",
        source_event_id="EDR-EDGE-2",
        source_format="generic_edr",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "action": "net_connect",
            "hostname": "HOST-EDGE-02",
            "dst_ip": "10.0.0.2",
            "dst_port": "unknown",  # Non-numeric port string
        },
    )
    norm_edr = engine.normalize(raw_edr)
    assert norm_edr.event_category == EventCategory.NETWORK_CONNECTION
    assert norm_edr.network_destination_port is None
    assert norm_edr.process_name is None
    assert norm_edr.command_line is None


def test_malformed_hashes_resilience_and_no_fabrication():
    """Verify malformed and heterogeneous hash representations do not crash or fabricate values."""
    t0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    engine = NormalisationEngine()

    # 1. Sysmon with dictionary hashes instead of comma-separated string
    raw_sysmon_dict = RawTelemetryEventV1(
        raw_event_id="RAW-HASH-01",
        source_event_id="EVT-HASH-1",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "EventID": 1,
            "Computer": "HOST-01",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "Hashes": {
                "SHA256": "A1B2C3D4E5F6",
                "MD5": None,  # Must NOT produce fabricated "none"
                "EMPTY": "",  # Must be omitted
                "IMPHASH": "deadbeef",
            },
        },
    )
    norm = engine.normalize(raw_sysmon_dict)
    assert norm.hashes["sha256"] == "a1b2c3d4e5f6"
    assert norm.hashes["imphash"] == "deadbeef"
    assert "md5" not in norm.hashes, "None value must not become 'none'"
    assert "empty" not in norm.hashes, "Empty string hash must be omitted"

    # 2. Sysmon with malformed string: empty parts, algo= without val, =val without algo
    raw_sysmon_str = RawTelemetryEventV1(
        raw_event_id="RAW-HASH-02",
        source_event_id="EVT-HASH-2",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "EventID": 1,
            "Computer": "HOST-01",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "Hashes": "SHA256=11223344, , =badalgo, BADVAL= , SHA1=55667788",
        },
    )
    norm = engine.normalize(raw_sysmon_str)
    assert norm.hashes == {"sha256": "11223344", "sha1": "55667788"}
    assert "" not in norm.hashes

    # 3. Sysmon with non-string/non-dict Hashes (int, bool, list)
    for bad_hashes in (12345, True, ["SHA256=99887766"]):
        raw_bad = RawTelemetryEventV1(
            raw_event_id="RAW-HASH-03",
            source_event_id="EVT-HASH-3",
            source_format="sysmon",
            source_timestamp=t0,
            ingested_at=t0,
            raw_payload={
                "EventID": 1,
                "Computer": "HOST-01",
                "Image": "cmd.exe",
                "Hashes": bad_hashes,
            },
        )
        norm = engine.normalize(raw_bad)
        if isinstance(bad_hashes, list):
            assert norm.hashes.get("sha256") == "99887766"
        else:
            assert norm.hashes == {}

    # 4. Generic EDR with string hashes and top-level overwrite protection
    raw_edr = RawTelemetryEventV1(
        raw_event_id="RAW-HASH-04",
        source_event_id="EVT-HASH-4",
        source_format="generic_edr",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "action": "process_create",
            "hostname": "HOST-02",
            "process_name": "notepad.exe",
            "hashes": "SHA256=aabbccdd,MD5=eeff0011",
            "sha256": "   ",  # Blank top-level must NOT overwrite parsed structured hash
        },
    )
    norm = engine.normalize(raw_edr)
    assert norm.hashes["sha256"] == "aabbccdd"
    assert norm.hashes["md5"] == "eeff0011"

    # 5. Fallback normaliser extracts hashes if available
    raw_fallback = RawTelemetryEventV1(
        raw_event_id="RAW-HASH-05",
        source_event_id="EVT-HASH-5",
        source_format="custom_audit_feed",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "endpoint": "SRV-LINUX-01",
            "file_name": "/usr/bin/sudo",
            "hashes": {"SHA256": "fedcba9876543210"},
        },
    )
    norm = engine.normalize(raw_fallback)
    assert norm.hashes["sha256"] == "fedcba9876543210"
    assert norm.process_name == "sudo"


def test_destination_port_bounds_and_whitespace_resilience():
    """Verify ports are validated against [0, 65535], accept whitespace, and reject out-of-range."""
    t0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    engine = NormalisationEngine()

    cases = [
        (" 443 ", 443),
        (0, 0),
        (65535, 65535),
        ("70000", None),   # Out of bounds (> 65535) must NOT raise ValidationError
        (99999, None),     # Out of bounds integer
        ("-1", None),      # Negative port
        ("invalid", None), # Non-numeric
        (None, None),
    ]

    for raw_port, expected_port in cases:
        raw_event = RawTelemetryEventV1(
            raw_event_id="RAW-PORT-01",
            source_event_id="EVT-PORT-1",
            source_format="sysmon",
            source_timestamp=t0,
            ingested_at=t0,
            raw_payload={
                "EventID": 3,
                "Computer": "HOST-01",
                "DestinationIp": "192.168.1.1",
                "DestinationPort": raw_port,
            },
        )
        norm = engine.normalize(raw_event)
        assert norm.network_destination_port == expected_port


def test_whitespace_identifiers_fallback():
    """Verify whitespace-only identifiers safely fall back to defaults rather than failing min_length."""
    t0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    engine = NormalisationEngine()

    raw_event = RawTelemetryEventV1(
        raw_event_id="RAW-WS-01",
        source_event_id="EVT-SRC-ORIGINAL",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "EventID": " 1 ",  # Whitespace-padded EventID
            "Computer": "   ",  # Whitespace-only host
            "RecordId": "   ",  # Whitespace-only record ID
            "EventRecordID": "   ",
            "Image": "   ",
        },
    )
    norm = engine.normalize(raw_event)
    assert norm.event_category == EventCategory.PROCESS_CREATION  # " 1 " correctly recognized
    assert norm.host == "unknown_host"  # Safely fell back to default
    assert norm.source_event_id == "EVT-SRC-ORIGINAL"  # Fell back to raw_event.source_event_id
    assert norm.process_name is None
    assert norm.process_path is None


def test_cross_platform_path_basename_and_non_string_resilience():
    """Verify path normalization handles Windows and POSIX separators and non-string inputs safely."""
    t0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    engine = NormalisationEngine()

    # 1. Windows path representation
    raw_win = RawTelemetryEventV1(
        raw_event_id="RAW-PATH-01",
        source_event_id="EVT-PATH-1",
        source_format="generic_edr",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "action": " process ",  # Whitespace-padded action
            "hostname": "HOST-WIN",
            "binary_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        },
    )
    norm_win = engine.normalize(raw_win)
    assert norm_win.event_category == EventCategory.PROCESS_CREATION
    assert norm_win.process_name == "powershell.exe"

    # 2. Non-string path inputs (int, dict, bool) do not crash
    raw_non_str = RawTelemetryEventV1(
        raw_event_id="RAW-PATH-02",
        source_event_id="EVT-PATH-2",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "EventID": 1,
            "Computer": "HOST-01",
            "Image": 99999,  # Non-string image
            "ParentImage": {"nested": "path"},  # Dict image
        },
    )
    norm_non_str = engine.normalize(raw_non_str)
    assert norm_non_str.process_name is None
    assert norm_non_str.parent_process_name is None


def test_hash_adversarial_rejections_and_merging():
    """Verify paths, drive letters, and invalid characters are not treated as hashes."""
    t0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    engine = NormalisationEngine()

    raw_event = RawTelemetryEventV1(
        raw_event_id="RAW-HASH-ADV-01",
        source_event_id="EVT-HASH-ADV-1",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "EventID": 1,
            "Computer": "HOST-01",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            # Contains Windows path with colon (C:), spaces in value, short algo
            "Hashes": "C:\\Windows\\System32\\cmd.exe, a=123, SHA256=abcdef123456, BAD=val with spaces",
            "hashes": {"md5": "deadbeefcafebabe"},
        },
    )
    norm = engine.normalize(raw_event)
    assert norm.hashes["sha256"] == "abcdef123456"
    assert norm.hashes["md5"] == "deadbeefcafebabe"
    assert "c" not in norm.hashes
    assert "a" not in norm.hashes
    assert "bad" not in norm.hashes


def test_fallback_candidate_whitespace_and_port_zero_resilience():
    """Verify whitespace in primary candidate does not mask valid secondary candidate and port 0 is preserved."""
    t0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    engine = NormalisationEngine()

    # 1. Generic EDR: whitespace in username must not mask valid user; port 0 must be preserved
    raw_edr = RawTelemetryEventV1(
        raw_event_id="RAW-EDR-ADV-01",
        source_event_id="EVT-EDR-ADV-1",
        source_format="generic_edr",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "action": "net_connect",
            "hostname": "HOST-EDR",
            "username": "   ",  # Whitespace must not mask "user"
            "user": "CORP\\operator_jdoe",
            "destination_port": 0,  # Valid port 0 must be preserved
            "dst_port": 443,        # Must not overwrite port 0
        },
    )
    norm_edr = engine.normalize(raw_edr)
    assert norm_edr.user == "CORP\\operator_jdoe"
    assert norm_edr.network_destination_port == 0

    # 2. FallbackNormaliser: null or whitespace in host candidate must not mask valid hostname
    raw_fallback = RawTelemetryEventV1(
        raw_event_id="RAW-FALLBACK-ADV-01",
        source_event_id="EVT-FALLBACK-ADV-1",
        source_format="unrecognized_feed",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={
            "host": "   ",  # Whitespace host must not mask "hostname"
            "hostname": "SRV-FALLBACK-PROD",
        },
    )
    norm_fallback = engine.normalize(raw_fallback)
    assert norm_fallback.host == "SRV-FALLBACK-PROD"
