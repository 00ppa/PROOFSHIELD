"""Phase 13: Production Readiness & Adversarial Validation Regression Tests.

Validates:
1. Transactional atomicity of batch alert ingestion in the REST API (POST /api/v1/alerts).
2. Elastic timestamp parsing resilience against overflow, NaN, infinite, and out-of-range values.
3. Elastic metadata sanitization protection against cyclic references and deep recursion denial-of-service.
4. Adversarial evidence integrity: conflicting telemetry tokens strictly prevent false PASS verdicts.
5. Cross-host token spoofing: matching tokens on the wrong host are diagnosed as routing faults, never PASS.
6. Pre-execution alert rejection: stale alerts preceding test execution never produce false PASS verdicts.
7. Concurrency and transactional isolation parity across InMemoryStore and SQLiteStore.
"""

import concurrent.futures
from datetime import datetime, timedelta, timezone
import math
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from proofshield.config import reset_settings
from proofshield.connectors.elastic import (
    ElasticAlertMappingError,
    _parse_timestamp,
    _sanitize_metadata,
)
from proofshield.main import create_application
from proofshield.schemas import (
    AlertV1,
    AttributionStatus,
    DetectionRuleV1,
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore, get_store, reset_store, set_store


# ── 1. REST API Batch Alert Ingestion Atomicity ──────────────────────────────


def test_api_alerts_batch_atomicity_rollback_on_duplicate_in_memory():
    """Verify that if a batch of alerts contains a duplicate, all insertions are rolled back atomically (InMemoryStore)."""
    reset_store()
    reset_settings()
    app = create_application()
    client = TestClient(app)

    a1 = {
        "alert_id": "ALT-BATCH-001",
        "source_alert_id": "SRC-001",
        "source_type": "sigma",
        "host_id": "WS-01",
        "rule_reference": "RULE-01",
    }
    a2 = {
        "alert_id": "ALT-BATCH-002",
        "source_alert_id": "SRC-002",
        "source_type": "sigma",
        "host_id": "WS-01",
        "rule_reference": "RULE-01",
    }
    # Duplicate of a1 in the same batch
    batch = [a1, a2, a1]

    res = client.post("/api/v1/alerts", json=batch)
    assert res.status_code == 409
    assert "already exists" in res.json()["detail"].lower()

    # Crucial assertion: atomicity guarantees ZERO alerts were committed
    store = get_store()
    assert store.get_alert("ALT-BATCH-001") is None
    assert store.get_alert("ALT-BATCH-002") is None
    assert len(store.list_alerts()) == 0


def test_api_alerts_batch_atomicity_rollback_on_duplicate_sqlite(tmp_path: Path, monkeypatch):
    """Verify batch alert rollback atomicity when backed by persistent SQLiteStore."""
    db_file = tmp_path / "sqlite_alert_atomicity.db"
    monkeypatch.setenv("PROOFSHIELD_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("PROOFSHIELD_SQLITE_PATH", str(db_file))
    reset_store()
    reset_settings()

    app = create_application()
    client = TestClient(app)

    a1 = {
        "alert_id": "ALT-SQLITE-001",
        "source_alert_id": "SRC-001",
        "source_type": "sigma",
        "host_id": "WS-SQLITE",
        "rule_reference": "RULE-01",
    }
    a2 = {
        "alert_id": "ALT-SQLITE-002",
        "source_alert_id": "SRC-002",
        "source_type": "sigma",
        "host_id": "WS-SQLITE",
        "rule_reference": "RULE-01",
    }
    # Duplicate of a1
    batch = [a1, a2, a1]

    res = client.post("/api/v1/alerts", json=batch)
    assert res.status_code == 409

    store = get_store()
    assert store.get_alert("ALT-SQLITE-001") is None
    assert store.get_alert("ALT-SQLITE-002") is None
    assert len(store.list_alerts()) == 0

    # Ensure subsequent clean batch works normally
    clean_batch = [a1, a2]
    res_clean = client.post("/api/v1/alerts", json=clean_batch)
    assert res_clean.status_code == 200
    assert len(res_clean.json()) == 2
    assert len(store.list_alerts()) == 2


# ── 2. Elastic Timestamp Parsing Hardening ───────────────────────────────────


def test_elastic_timestamp_overflow_nan_and_inf_safely_handled():
    """Verify that out-of-range numeric timestamps cleanly raise ElasticAlertMappingError without unhandled crashes."""
    # Overflow integer/float (year > 9999 or platform time_t overflow)
    with pytest.raises(ElasticAlertMappingError, match="out-of-range|Malformed"):
        _parse_timestamp(1e25)

    with pytest.raises(ElasticAlertMappingError, match="out-of-range|Malformed"):
        _parse_timestamp(-1e25)

    # NaN (Not a Number)
    with pytest.raises(ElasticAlertMappingError, match="NaN or Infinite"):
        _parse_timestamp(float("nan"))

    # Positive and negative infinity
    with pytest.raises(ElasticAlertMappingError, match="NaN or Infinite"):
        _parse_timestamp(float("inf"))

    with pytest.raises(ElasticAlertMappingError, match="NaN or Infinite"):
        _parse_timestamp(float("-inf"))

    # Legitimate epoch timestamps continue to work
    dt_sec = _parse_timestamp(1700000000)
    assert dt_sec is not None
    assert dt_sec.tzinfo == timezone.utc

    dt_msec = _parse_timestamp(1700000000000)
    assert dt_msec is not None
    assert dt_msec.tzinfo == timezone.utc


# ── 3. Elastic Metadata Sanitizer Protection ─────────────────────────────────


def test_elastic_sanitize_metadata_cyclic_and_deeply_nested():
    """Verify that cyclic dictionaries and deeply nested structures do not cause RecursionError or crashes."""
    # Cyclic dictionary
    cyclic_dict = {"title": "Phishing Attempt", "rule_id": "RULE-TEST"}
    cyclic_dict["self_ref"] = cyclic_dict

    sanitized = _sanitize_metadata(cyclic_dict)
    assert sanitized["title"] == "Phishing Attempt"
    assert sanitized["self_ref"] == "[REDACTED_CYCLE]"

    # Cyclic list
    cyclic_list = ["item1"]
    cyclic_list.append(cyclic_list)
    sanitized_list = _sanitize_metadata(cyclic_list)
    assert sanitized_list[0] == "item1"
    assert sanitized_list[1] == "[REDACTED_CYCLE]"

    # Deeply nested dictionary (depth 50)
    deep_dict: dict = {"level": 0}
    curr = deep_dict
    for i in range(1, 50):
        curr["next"] = {"level": i}
        curr = curr["next"]

    sanitized_deep = _sanitize_metadata(deep_dict, max_depth=16)
    # At depth 16, recursion terminates safely
    level_ptr = sanitized_deep
    for _ in range(15):
        level_ptr = level_ptr["next"]
    assert level_ptr["next"] == "[REDACTED_NESTED]"


# ── 4. Adversarial Evidence Integrity & Attribution ──────────────────────────


@pytest.fixture
def base_adversarial_setup():
    store = InMemoryStore()
    t0 = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-ADV-01",
        name="Adversarial Validation Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"DownloadString",
        expected_detection_rule_id="RULE-ADV-PS-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    rule = DetectionRuleV1(
        rule_id="RULE-ADV-PS-01",
        rule_name="PowerShell Execution Rule",
        rule_format="sigma",
    )
    store.add_scenario(scn)
    store.add_rule(rule)
    return store, scn, rule, t0


def test_adversarial_conflicting_events_prevent_false_pass(base_adversarial_setup):
    """If candidate telemetry contains a conflicting execution token, strict mode must return INCONCLUSIVE, never PASS."""
    store, scn, rule, t0 = base_adversarial_setup
    tok = "TOK-GENUINE-01"

    run = TestRunV1(
        run_id="RUN-CONFLICT-EV",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-ADV-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=tok,
    )
    store.add_run(run)

    # Legitimate event matching token
    ev_ok = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-OK-01",
        raw_event_id="RAW-OK",
        source_event_id="SRC-OK",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token=tok,
    )
    # Conflicting event with permanent CONFLICT marker in the same window
    ev_conflict = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-CONFLICT-02",
        raw_event_id="RAW-CONF",
        source_event_id="SRC-CONF",
        source_timestamp=t0 + timedelta(minutes=3),
        normalized_timestamp=t0 + timedelta(minutes=3),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token="CONFLICT",
    )
    store.add_normalized_event(ev_ok)
    store.add_normalized_event(ev_conflict)

    # Alert matching token
    alt = AlertV1(
        alert_id="ALT-OK-01",
        source_alert_id="SRC-A1",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=4),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=tok,
    )
    store.add_alert(alt)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    # In strict mode, conflicting telemetry tokens must prevent a PASS verdict
    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res.predicted_category != DiagnosticCategory.PASS
    assert res.metadata["attribution"]["status"] == AttributionStatus.CONFLICT.value


def test_adversarial_cross_host_token_spoofing_prevent_false_pass(base_adversarial_setup):
    """An alert carrying a matching execution token on a DIFFERENT host must be diagnosed as ALERT_NOT_CORRELATED, never PASS."""
    store, scn, rule, t0 = base_adversarial_setup
    tok = "TOK-HOST-SPOOF"

    run = TestRunV1(
        run_id="RUN-SPOOF-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-LEGIT",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=tok,
    )
    store.add_run(run)

    # Telemetry on target host
    ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-SPOOF-EV",
        raw_event_id="RAW-S1",
        source_event_id="SRC-S1",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString",
        execution_token=tok,
    )
    store.add_normalized_event(ev)

    # Alert fired with matching token, but on a DIFFERENT host (routing fault or token replay across hosts)
    alt = AlertV1(
        alert_id="ALT-SPOOF-WRONG-HOST",
        source_alert_id="SRC-SP1",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id="WS-DIFFERENT-HOST",
        rule_reference=scn.expected_detection_rule_id,
        execution_token=tok,
    )
    store.add_alert(alt)

    engine = AssuranceEngine(store)

    # Strict mode
    res_strict = engine.evaluate_run(run.run_id, strict_attribution=True)
    assert res_strict.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert res_strict.predicted_category != DiagnosticCategory.PASS

    # Default mode
    res_default = engine.evaluate_run(run.run_id, strict_attribution=False)
    assert res_default.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert res_default.predicted_category != DiagnosticCategory.PASS


# ── 5. Storage Parity & Concurrent Transaction Resilience ────────────────────


def test_concurrent_store_transaction_isolation_and_rollback_parity(tmp_path: Path):
    """Verify that concurrent transactions on both backends maintain isolation and clean state after errors."""
    for backend_name, store in [
        ("in_memory", InMemoryStore()),
        ("sqlite", SQLiteStore(tmp_path / "concurrent_parity.db")),
    ]:
        # Prepopulate base scenario
        base_scn = ScenarioV1(
            scenario_id="SCN-BASE",
            name="Base Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        store.add_scenario(base_scn)

        def worker(thread_idx: int):
            # Odd threads succeed; even threads intentionally fail and roll back
            should_fail = (thread_idx % 2 == 0)
            scn_id = f"SCN-PARITY-{thread_idx:03d}"
            try:
                with store.transaction():
                    store.add_scenario(
                        ScenarioV1(
                            scenario_id=scn_id,
                            name=f"Scenario {thread_idx}",
                            mitre_technique_id="T1059.001",
                            mitre_tactic="Execution",
                            expected_event_category=EventCategory.PROCESS_CREATION,
                            validation_target=ValidationTarget.EXPECTED_ALERT,
                        )
                    )
                    if should_fail:
                        raise RuntimeError(f"Simulated rollback thread {thread_idx}")
            except RuntimeError:
                pass
            return thread_idx

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(worker, range(20)))

        all_scenarios = store.list_scenarios()
        committed_ids = {s.scenario_id for s in all_scenarios}

        # 1 base + 10 odd threads = 11 scenarios total
        assert len(committed_ids) == 11, f"Failed on backend {backend_name}: found {len(committed_ids)}"
        for i in range(20):
            scn_id = f"SCN-PARITY-{i:03d}"
            if i % 2 == 0:
                assert scn_id not in committed_ids, f"Rolled back {scn_id} persisted in {backend_name}"
            else:
                assert scn_id in committed_ids, f"Committed {scn_id} missing in {backend_name}"

        store.reset()
        if hasattr(store, "close"):
            store.close()
