"""Adversarial audit and evidence integrity tests for Phase 16.1.

Validates:
1. RFC 8785 Canonical JSON conformity (numbers, UTF-16 key sort, escaping, NaN rejection).
2. Evidence manifest binding of telemetry and alert content hashes.
3. Detection of modified telemetry/alerts retaining identical IDs.
4. Detection of manifest internal tampering.
5. Replay classification: EXACT_REPLAY vs EVIDENCE_REEVALUATION vs ENGINE_COMPARISON.
6. InMemoryStore copy immutability.
7. API identifier and pagination bounds.
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from proofshield.schemas.campaign import (
    CampaignDefinitionV1,
    CampaignExecutionConfigV1,
    CampaignExecutionPolicy,
    CampaignRunV1,
    EvidenceManifestV1,
    ReplayClassification,
    ScenarioEvidenceRefV1,
)
from proofshield.schemas.common import DiagnosticCategory, EventCategory, ValidationTarget
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1
from proofshield.schemas.alert import AlertV1
from proofshield.schemas.test_run import TestRunV1, ExecutionStatus
from proofshield.services.canonical import (
    canonical_json_bytes,
    compute_canonical_hash,
)
from proofshield.services.campaign_engine import CampaignEngine
from proofshield.services.store import InMemoryStore
from proofshield.services.sqlite_store import SQLiteStore


def test_reproduce_canonical_numbers_and_utf16_sorting():
    """Verify that canonical JSON correctly handles ECMAScript numbers and UTF-16 code units."""
    # Test numbers per RFC 8785
    data_numbers = {
        "float_integer": 1.0,
        "negative_zero": -0.0,
        "fixed_small": 0.000001,
        "exp_small": 1e-7,
        "large_fixed": 1e20,
        "exp_large": 1e21,
    }
    raw_bytes = canonical_json_bytes(data_numbers)
    json_str = raw_bytes.decode("utf-8")

    # In RFC 8785: 1.0 must serialize as 1, -0.0 as 0, 0.000001 as 0.000001, 1e-7 as 1e-7, 1e20 as 100000000000000000000, 1e21 as 1e+21
    assert '"float_integer":1' in json_str, f"Expected '1', got: {json_str}"
    assert '"negative_zero":0' in json_str, f"Expected '0', got: {json_str}"
    assert '"fixed_small":0.000001' in json_str, f"Expected '0.000001', got: {json_str}"
    assert '"exp_small":1e-7' in json_str, f"Expected '1e-7', got: {json_str}"
    assert '"large_fixed":100000000000000000000' in json_str, f"Expected '100000000000000000000', got: {json_str}"
    assert '"exp_large":1e+21' in json_str, f"Expected '1e+21', got: {json_str}"

    # Test UTF-16 code unit sorting: \U0001D11E (d834 dd1e) comes BEFORE \uFFFF (ffff) in UTF-16
    data_utf16 = {
        "\uffff": "high_bmp",
        "\U0001D11E": "astral_g_clef",
    }
    utf16_json = canonical_json_bytes(data_utf16).decode("utf-8")
    expected_start = '{"\\uD834\\uDD1E"' if "\\uD834" in utf16_json else '{"\U0001D11E"'
    assert utf16_json.startswith(expected_start), f"Astral char must precede \\uffff in UTF-16 order: {utf16_json}"


def test_reproduce_nan_infinity_rejected():
    """Verify that NaN and Infinity are strictly rejected by canonical JSON."""
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonical_json_bytes({"bad": float("nan")})

    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonical_json_bytes({"bad": float("inf")})


def test_reproduce_telemetry_tampering_detected_in_replay():
    """Adversarial test: A telemetry event is modified in the store but keeps its ID.
    Replay must detect the altered evidence hash and reject exact replay.
    """
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-TAMPER-01",
        name="Tamper Test Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="legit.exe",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-TAMPER-01",
        scenario_id="SCN-TAMPER-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-TAMPER-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="legit.exe",
    )
    store.add_normalized_event(event)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-TAMPER-01",
        name="Tamper Campaign",
        description="Verify detection of modified telemetry",
        scenario_ids=["SCN-TAMPER-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-TAMPER-01")
    assert orig_run.scenario_results[0].predicted_category == DiagnosticCategory.PASS

    # Adversary alters telemetry event in store with same ID
    tampered_event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-TAMPER-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="malicious.exe",  # Process changed!
    )
    # Overwrite in store
    store._normalized_events["EV-TAMPER-01"] = tampered_event

    # Replay must catch this!
    replay_result = engine.replay_campaign_run(orig_run.run_id)
    print("REPLAY RESULT is_exact_replay:", replay_result.is_exact_replay)
    print("REPLAY RESULT altered_evidence:", replay_result.altered_evidence)
    print("REPLAY RESULT verdict:", replay_result.verdict)
    assert not replay_result.is_exact_replay
    assert replay_result.replay_classification == ReplayClassification.EVIDENCE_REEVALUATION
    assert any("EV-TAMPER-01" in item for item in replay_result.altered_evidence)


def test_reproduce_manifest_internal_tampering_detected():
    """Adversarial test: A stored manifest's scenario references are modified without updating manifest_hash.
    Replay must detect manifest integrity failure.
    """
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-MANIFEST-01",
        name="Manifest Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="legit.exe",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-MANIFEST-01",
        scenario_id="SCN-MANIFEST-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-MANIFEST-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="legit.exe",
    )
    store.add_normalized_event(event)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-MANIFEST-01",
        name="Manifest Campaign",
        description="Verify detection of manifest tampering",
        scenario_ids=["SCN-MANIFEST-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-MANIFEST-01")

    # Tamper with the manifest scenario hash inside the stored run record directly
    stored_run = store.get_campaign_run(orig_run.run_id)
    # Alter reference hash while leaving manifest_hash untouched
    stored_run.evidence_manifest.scenario_references[0].scenario_hash = "0" * 64
    store._campaign_runs[orig_run.run_id] = stored_run

    replay_result = engine.replay_campaign_run(orig_run.run_id)
    assert not replay_result.is_exact_replay
    assert replay_result.replay_classification == ReplayClassification.INVALID_MANIFEST
    assert replay_result.manifest_valid is False


def test_reproduce_in_memory_store_immutability():
    """Verify that InMemoryStore returns deep copies of stored campaign runs to prevent mutation."""
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-IMMUTABLE-01",
        name="Immutable Campaign",
        description="Check in-memory store copy immutability",
        scenario_ids=["SCN-1"],
    )
    store.add_campaign(campaign)

    # Fetch and mutate returned definition
    retrieved = store.get_campaign("CAMP-IMMUTABLE-01")
    retrieved.name = "Mutated Name"

    # Store copy must NOT be mutated
    fresh = store.get_campaign("CAMP-IMMUTABLE-01")
    assert fresh.name == "Immutable Campaign", "InMemoryStore returned mutable reference!"


def test_exact_replay_classification_and_manifest_validity():
    """Verify that exact replay against identical preserved evidence yields EXACT_REPLAY."""
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-EXACT-01",
        name="Exact Replay Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="powershell.exe",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-EXACT-01",
        scenario_id="SCN-EXACT-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-EXACT-01",
        raw_event_id="RAW-EXACT-01",
        source_event_id="SRC-EXACT-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="powershell.exe",
    )
    store.add_normalized_event(event)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-EXACT-01",
        name="Exact Replay Campaign",
        description="Verify exact replay outcome",
        scenario_ids=["SCN-EXACT-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-EXACT-01")

    replay_result = engine.replay_campaign_run(orig_run.run_id)
    assert replay_result.is_exact_replay is True
    assert replay_result.replay_classification == ReplayClassification.EXACT_REPLAY
    assert replay_result.manifest_valid is True
    assert len(replay_result.missing_evidence) == 0
    assert len(replay_result.altered_evidence) == 0
    assert replay_result.comparison.comparison_verdict == "IDENTICAL"


def test_alert_tampering_detected_in_replay():
    """Adversarial test: An alert is modified in the store but keeps its ID."""
    from proofshield.schemas.detection_rule import DetectionRuleV1
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    rule = DetectionRuleV1(
        rule_id="RULE-ALERT-01",
        rule_name="Test Rule",
        rule_format="SIGMA",
        evaluation_backend="SIGMA",
    )
    store.add_rule(rule)

    scenario = ScenarioV1(
        scenario_id="SCN-ALERT-01",
        name="Alert Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
        expected_process_name="powershell.exe",
        expected_detection_rule_id="RULE-ALERT-01",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-ALERT-01",
        scenario_id="SCN-ALERT-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-ALERT-01",
        raw_event_id="RAW-ALERT-01",
        source_event_id="SRC-ALERT-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="powershell.exe",
    )
    store.add_normalized_event(event)

    alert = AlertV1(
        alert_id="ALT-ORIG-01",
        source_alert_id="SRC-ALT-01",
        source_type="wazuh",
        rule_reference="RULE-ALERT-01",
        alert_timestamp=now,
        host_id="HOST-01",
        severity="high",
    )
    store.add_alert(alert)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-ALERT-01",
        name="Alert Campaign",
        description="Verify detection of altered alert",
        scenario_ids=["SCN-ALERT-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-ALERT-01")
    assert orig_run.scenario_results[0].status.value == "PASS"

    # Tamper with the alert severity/rule in store while keeping same alert_id
    tampered_alert = AlertV1(
        alert_id="ALT-ORIG-01",
        source_alert_id="SRC-ALT-01",
        source_type="wazuh",
        rule_reference="RULE-ALERT-01",
        alert_timestamp=now,
        host_id="HOST-01",
        severity="low",  # Changed!
    )
    store._alerts["ALT-ORIG-01"] = tampered_alert

    replay_result = engine.replay_campaign_run(orig_run.run_id)
    assert not replay_result.is_exact_replay
    assert replay_result.replay_classification == ReplayClassification.EVIDENCE_REEVALUATION
    assert any("ALT-ORIG-01" in item for item in replay_result.altered_evidence)


def test_deleted_evidence_detected_in_replay():
    """Verify that deleting an evidence record from store is classified as EVIDENCE_REEVALUATION."""
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-DEL-01",
        name="Delete Test Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="cmd.exe",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-DEL-01",
        scenario_id="SCN-DEL-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-DEL-01",
        raw_event_id="RAW-DEL-01",
        source_event_id="SRC-DEL-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="cmd.exe",
    )
    store.add_normalized_event(event)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-DEL-01",
        name="Delete Campaign",
        description="Verify detection of deleted evidence",
        scenario_ids=["SCN-DEL-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-DEL-01")

    # Delete the event from store
    del store._normalized_events["EV-DEL-01"]

    replay_result = engine.replay_campaign_run(orig_run.run_id)
    assert not replay_result.is_exact_replay
    assert replay_result.replay_classification == ReplayClassification.EVIDENCE_REEVALUATION
    assert any("EV-DEL-01" in item for item in replay_result.missing_evidence)


def test_sqlite_store_content_manifest_parity(tmp_path):
    """Verify that SQLiteStore implements identical content-hashed manifests and replay detection."""
    db_file = tmp_path / "parity_audit.db"
    store = SQLiteStore(db_file)
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-SQLITE-01",
        name="SQLite Parity Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="whoami.exe",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-SQLITE-01",
        scenario_id="SCN-SQLITE-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-SQLITE-01",
        raw_event_id="RAW-SQLITE-01",
        source_event_id="SRC-SQLITE-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="whoami.exe",
    )
    store.add_normalized_event(event)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-SQLITE-01",
        name="SQLite Parity Campaign",
        description="Verify SQLite manifest integrity",
        scenario_ids=["SCN-SQLITE-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-SQLITE-01")

    # Verify exact replay on SQLite
    replay_result = engine.replay_campaign_run(orig_run.run_id)
    assert replay_result.is_exact_replay is True
    assert replay_result.replay_classification == ReplayClassification.EXACT_REPLAY
    assert replay_result.manifest_valid is True

    # Adversarial tampering on SQLite directly:
    # 1. Update event payload in normalized_telemetry table while retaining normalized_event_id
    cursor = store.connection.cursor()
    tampered_event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-SQLITE-01",
        raw_event_id="RAW-SQLITE-01",
        source_event_id="SRC-SQLITE-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="mimikatz.exe",  # Tampered!
    )
    cursor.execute(
        "UPDATE normalized_telemetry SET payload_json = ? WHERE normalized_event_id = ?",
        (tampered_event.model_dump_json(), "EV-SQLITE-01"),
    )

    # SQLite replay must catch the tampered evidence
    tamper_replay = engine.replay_campaign_run(orig_run.run_id)
    assert not tamper_replay.is_exact_replay
    assert tamper_replay.replay_classification == ReplayClassification.EVIDENCE_REEVALUATION
    assert any("EV-SQLITE-01" in item for item in tamper_replay.altered_evidence)

    store.close()


def test_api_bounded_pagination_and_path_validation():
    """Verify that API routes enforce bounded pagination and path regex validation."""
    from fastapi.testclient import TestClient
    from proofshield.main import app

    client = TestClient(app)

    # 1. Invalid path parameter regex (e.g. traversal pattern or illegal chars)
    resp = client.get("/api/v1/campaigns/../../etc/passwd")
    assert resp.status_code in (404, 422), f"Expected 404 or 422 for path traversal, got: {resp.status_code}"

    resp = client.get("/api/v1/campaigns/bad$id!")
    assert resp.status_code == 422, f"Expected 422 for illegal regex chars, got: {resp.status_code}"

    # 2. Bounded pagination: limit over 1000 rejected
    resp = client.get("/api/v1/campaigns?limit=5000")
    assert resp.status_code == 422, f"Expected 422 for limit > 1000, got: {resp.status_code}"

    # 3. Default pagination works
    resp = client.get("/api/v1/campaigns")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_evidence_reordering_invariance():
    """Adversarial test: Manifest hash must be invariant to dict/ref input ordering."""
    ref1 = ScenarioEvidenceRefV1(
        scenario_id="SCN-B",
        scenario_hash="b" * 64,
        telemetry_event_hashes={"EV-2": "hash2", "EV-1": "hash1"},
    )
    ref2 = ScenarioEvidenceRefV1(
        scenario_id="SCN-A",
        scenario_hash="a" * 64,
        telemetry_event_hashes={"EV-3": "hash3"},
    )

    from proofshield.services.campaign_engine import compute_manifest_hash_from_manifest

    # Compute with [ref1, ref2]
    hash_12 = compute_manifest_hash_from_manifest("CAMP-1", "v1.0.0", "cfg123", [ref1, ref2])
    # Compute with [ref2, ref1]
    hash_21 = compute_manifest_hash_from_manifest("CAMP-1", "v1.0.0", "cfg123", [ref2, ref1])

    assert hash_12 == hash_21, "Manifest hash must be invariant to scenario reference input ordering!"


def test_official_rfc8785_appendix_b_all_24_vectors():
    """Verify all 24 official IEEE-754 number vectors from RFC 8785 Appendix B."""
    import struct
    from proofshield.services.canonical import ecmascript_float

    vectors = [
        ("0000000000000000", "0"),
        ("8000000000000000", "0"),
        ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"),
        ("4340000000000000", "9007199254740992"),
        ("c340000000000000", "-9007199254740992"),
        ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"),
        ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ]

    for hx, expected in vectors:
        val = struct.unpack("!d", bytes.fromhex(hx))[0]
        actual = ecmascript_float(val)
        assert actual == expected, f"Hex {hx} (val={val}): expected {expected}, got {actual}"


def test_official_rfc8785_section_3_2_3_property_sorting_vector():
    """Verify official RFC 8785 Section 3.2.3 property sorting test vector."""
    import json
    from proofshield.services.canonical import canonical_jcs_serialize

    raw_rfc_json = '''{
        "\\u20ac": "Euro Sign",
        "\\r": "Carriage Return",
        "\\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\\ud83d\\ude00": "Emoji: Grinning Face",
        "\\u0080": "Control",
        "\\u00f6": "Latin Small Letter O With Diaeresis"
    }'''

    rfc_obj = json.loads(raw_rfc_json)
    serialized = canonical_jcs_serialize(rfc_obj)

    expected_order = [
        "Carriage Return",
        "One",
        "Control",
        "Latin Small Letter O With Diaeresis",
        "Euro Sign",
        "Emoji: Grinning Face",
        "Hebrew Letter Dalet With Dagesh",
    ]

    positions = [serialized.index(v) for v in expected_order]
    assert positions == sorted(positions), f"RFC 8785 Section 3.2.3 order violated: {positions}"


def test_official_rfc8785_section_3_2_4_sample_vector():
    """Verify official RFC 8785 Section 3.2.4 comprehensive sample hex bytes."""
    import json
    from proofshield.services.canonical import canonical_json_bytes

    expected_hex = (
        "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62657273223a"
        "5b3333333333333333332e333333333333332c31652b33302c342e352c302e3030322c31652d3237"
        "5d2c22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d"
    )
    expected_bytes = bytes.fromhex(expected_hex)
    data = json.loads(expected_bytes.decode("utf-8"))

    actual_bytes = canonical_json_bytes(data)
    assert actual_bytes == expected_bytes, "RFC 8785 Section 3.2.4 exact byte representation mismatch!"


def test_unpaired_surrogates_and_invalid_unicode_rejected():
    """Verify that unpaired surrogates in string literals or dict keys are strictly rejected with ValueError."""
    from proofshield.services.canonical import canonical_jcs_serialize

    # Unpaired high surrogate in string value
    with pytest.raises(ValueError, match="Unpaired surrogates or invalid Unicode"):
        canonical_jcs_serialize({"key": "\ud800"})

    # Unpaired low surrogate in string value
    with pytest.raises(ValueError, match="Unpaired surrogates or invalid Unicode"):
        canonical_jcs_serialize("\udfff")

    # Unpaired surrogate in dict key
    with pytest.raises(ValueError, match="Unpaired surrogates or invalid Unicode in key"):
        canonical_jcs_serialize({"\ud800": "bad_key"})


def test_ground_truth_tampering_detected_in_replay():
    """Adversarial test: Ground truth record is modified while keeping ID.
    Replay must detect altered evidence hash and classify as EVIDENCE_REEVALUATION.
    """
    from proofshield.schemas.ground_truth import GroundTruthV1
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-GT-01",
        name="Ground Truth Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="proc.exe",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-GT-01",
        scenario_id="SCN-GT-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-GT-01",
        raw_event_id="RAW-GT-01",
        source_event_id="SRC-GT-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="proc.exe",
    )
    store.add_normalized_event(event)

    gt = GroundTruthV1(
        ground_truth_id="GT-01",
        run_id="RUN-GT-01",
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="manual_inspection",
    )
    store.add_ground_truth(gt)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-GT-01",
        name="Ground Truth Campaign",
        description="Verify detection of altered ground truth",
        scenario_ids=["SCN-GT-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-GT-01")

    # Mutate ground truth in store keeping identical ID
    tampered_gt = GroundTruthV1(
        ground_truth_id="GT-01",
        run_id="RUN-GT-01",
        expected_diagnostic_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        verification_method="tampered_method",
    )
    store._ground_truths["GT-01"] = tampered_gt

    replay_res = engine.replay_campaign_run(orig_run.run_id)
    assert not replay_res.is_exact_replay
    assert replay_res.replay_classification == ReplayClassification.EVIDENCE_REEVALUATION
    assert any("GroundTruth:GT-01" in item for item in replay_res.altered_evidence)


def test_scenario_and_test_run_tampering_detected_in_replay():
    """Adversarial test: Scenario definition or test run record is modified in store.
    Replay must detect the altered hash and classify as EVIDENCE_REEVALUATION.
    """
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-DEF-01",
        name="Original Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="target.exe",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-DEF-01",
        scenario_id="SCN-DEF-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-DEF-01",
        raw_event_id="RAW-DEF-01",
        source_event_id="SRC-DEF-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="target.exe",
    )
    store.add_normalized_event(event)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-DEF-01",
        name="Definition Tamper Campaign",
        description="Verify detection of altered scenario definition",
        scenario_ids=["SCN-DEF-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-DEF-01")

    # Case A: Alter scenario definition in store
    mutated_scen = ScenarioV1(
        scenario_id="SCN-DEF-01",
        name="Mutated Scenario Definition",
        mitre_technique_id="T1059.003",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="target.exe",
    )
    store._scenarios["SCN-DEF-01"] = mutated_scen

    replay_scen = engine.replay_campaign_run(orig_run.run_id)
    assert not replay_scen.is_exact_replay
    assert replay_scen.replay_classification == ReplayClassification.EVIDENCE_REEVALUATION
    assert any("Scenario:SCN-DEF-01" in item for item in replay_scen.altered_evidence)

    # Restore scenario, then alter TestRun in store
    store._scenarios["SCN-DEF-01"] = scenario
    mutated_run = TestRunV1(
        run_id="RUN-DEF-01",
        scenario_id="SCN-DEF-01",
        target_host="HOST-02",  # Changed host
        target_user="ADMIN",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store._runs["RUN-DEF-01"] = mutated_run

    replay_run = engine.replay_campaign_run(orig_run.run_id)
    assert not replay_run.is_exact_replay
    assert replay_run.replay_classification == ReplayClassification.EVIDENCE_REEVALUATION
    assert any("TestRun:RUN-DEF-01" in item for item in replay_run.altered_evidence)


def test_execution_config_override_classified_as_engine_comparison():
    """Verify that replaying with a modified execution configuration yields ENGINE_COMPARISON."""
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-CFG-01",
        name="Config Test Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="cmd.exe",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-CFG-01",
        scenario_id="SCN-CFG-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-CFG-01",
        raw_event_id="RAW-CFG-01",
        source_event_id="SRC-CFG-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="cmd.exe",
    )
    store.add_normalized_event(event)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-CFG-01",
        name="Config Campaign",
        description="Verify detection of changed configuration",
        scenario_ids=["SCN-CFG-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-CFG-01")

    # Replay with execution_config_override (e.g. strict_attribution=True)
    override_cfg = CampaignExecutionConfigV1(
        execution_policy=CampaignExecutionPolicy.CONTINUE_ON_ERROR,
        strict_attribution=True,
    )
    replay_res = engine.replay_campaign_run(orig_run.run_id, execution_config_override=override_cfg)

    assert not replay_res.is_exact_replay
    assert replay_res.replay_classification == ReplayClassification.ENGINE_COMPARISON
    assert replay_res.verdict == "ENGINE_COMPARISON"
    assert len(replay_res.missing_evidence) == 0
    assert len(replay_res.altered_evidence) == 0


def test_adversary_modifies_evidence_and_recomputes_manifest_hash_boundary():
    """Threat Model Verification: If an attacker modifies evidence AND recomputes the manifest hash,
    local manifest validation passes, but run comparison against the original run isolates the divergence.
    This demonstrates why local hashing requires independent reference digest protection for non-repudiation.
    """
    store = InMemoryStore()
    now = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 10, 20, 10, 5, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-FORGE-01",
        name="Forge Test Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        expected_process_name="legit.exe",
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-FORGE-01",
        scenario_id="SCN-FORGE-01",
        target_host="HOST-01",
        target_user="SYSTEM",
        execution_mode="SYNTHETIC_SIMULATION",
        executed_at=now,
        window_start=now,
        window_end=after,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-FORGE-01",
        raw_event_id="RAW-FORGE-01",
        source_event_id="SRC-FORGE-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="legit.exe",
    )
    store.add_normalized_event(event)

    campaign = CampaignDefinitionV1(
        campaign_id="CAMP-FORGE-01",
        name="Forge Campaign",
        description="Verify threat model when adversary recomputes manifest hash",
        scenario_ids=["SCN-FORGE-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store)
    orig_run = engine.execute_campaign("CAMP-FORGE-01")

    # Attacker alters event in store
    tampered_event = NormalizedTelemetryEventV1(
        normalized_event_id="EV-FORGE-01",
        raw_event_id="RAW-FORGE-01",
        source_event_id="SRC-FORGE-01",
        source_timestamp=now,
        normalized_timestamp=now,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-01",
        process_name="tampered.exe",
    )
    store._normalized_events["EV-FORGE-01"] = tampered_event

    # Attacker also updates the manifest scenario reference and recomputes the manifest_hash
    from proofshield.services.campaign_engine import compute_manifest_hash_from_manifest
    stored_run = store.get_campaign_run(orig_run.run_id)
    new_event_hash = compute_canonical_hash(tampered_event)
    stored_run.evidence_manifest.scenario_references[0].telemetry_event_hashes["EV-FORGE-01"] = new_event_hash
    recomputed_hash = compute_manifest_hash_from_manifest(
        campaign_id=stored_run.evidence_manifest.campaign_id,
        engine_version=stored_run.evidence_manifest.engine_version,
        execution_config_hash=stored_run.evidence_manifest.execution_config_hash,
        scenario_references=stored_run.evidence_manifest.scenario_references,
    )
    stored_run.evidence_manifest.manifest_hash = recomputed_hash
    store._campaign_runs[orig_run.run_id] = stored_run

    # Replay against forged manifest passes local verification
    replay_res = engine.replay_campaign_run(orig_run.run_id)
    assert replay_res.manifest_valid is True
    # However, comparison with original run result identifies the diagnostic outcome shift (PASS -> EXPECTED_TELEMETRY_MISSING)
    assert replay_res.comparison.comparison_verdict != "IDENTICAL"
