"""Phase 6: Evidence Integrity & Diagnostic Correctness Adversarial Test Suite.

Verifies:
1. Ground-truth/prediction independence: GroundTruthV1 is never queried by the
   assurance engine and has zero influence on predicted diagnostic outcomes.
2. Duplicate and conflicting telemetry handling.
3. Microsecond-accurate window boundary semantics (inclusive edges, exclusive exterior).
4. Alert non-correlation isolation (host mismatch, rule mismatch, out-of-window).
5. Missing expected telemetry classification and evidence attribution.
6. Incomplete execution (RUNNING -> INCONCLUSIVE, FAILED/ERROR/PENDING -> TEST_NOT_EXECUTED).
7. Cross-backend diagnostic determinism across InMemoryStore and SQLiteStore.
8. Evidence traceability: checks_performed, alternative_eliminations, and missing_evidence.
9. Evaluation metric denominators and inconclusive/error separation.
"""

from datetime import datetime, timezone, timedelta
import tempfile
import pytest

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    FailureCategory,
    GroundTruthV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.store import InMemoryStore
from proofshield.services.sqlite_store import SQLiteStore
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from test_benchmark import compute_metrics


@pytest.fixture
def base_scenario():
    return ScenarioV1(
        scenario_id="SCN-INTEG-001",
        name="Adversarial Integrity Validation Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"DownloadString",
        expected_detection_rule_id="RULE-SIGMA-CRADLE-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
        max_acceptable_latency_seconds=300,
    )


@pytest.fixture
def base_run(base_scenario):
    t0 = datetime(2026, 10, 16, 10, 0, 0, 0, tzinfo=timezone.utc)
    return TestRunV1(
        run_id="RUN-INTEG-001",
        scenario_id=base_scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-SEC-01",
        target_user="CORP\\analyst",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
    )


@pytest.fixture
def base_rule(base_scenario):
    return DetectionRuleV1(
        rule_id=base_scenario.expected_detection_rule_id,
        rule_name="PowerShell Cradle Detection",
        rule_format="sigma",
        mitre_technique_ids=["T1059.001"],
    )


def _create_norm_event(event_id, host, timestamp, process_name="powershell.exe", cmd="powershell.exe DownloadString"):
    return NormalizedTelemetryEventV1(
        normalized_event_id=event_id,
        raw_event_id=f"RAW-{event_id}",
        source_event_id=f"SRC-{event_id}",
        source_timestamp=timestamp,
        normalized_timestamp=timestamp,
        event_category=EventCategory.PROCESS_CREATION,
        host=host,
        process_name=process_name,
        command_line=cmd,
    )


# ── 1. Ground-Truth / Prediction Independence ────────────────────────────────

def test_ground_truth_independence_no_leakage(base_scenario, base_run, base_rule):
    """AssuranceEngine evaluation must be 100% invariant to ground truth records.

    Predictions must be identical whether ground truth is missing, matching,
    or maliciously conflicting.
    """
    t0 = base_run.window_start

    def _setup_store_and_evaluate(gt_label=None):
        store = InMemoryStore()
        store.add_scenario(base_scenario)
        store.add_run(base_run)
        store.add_rule(base_rule)

        ev = _create_norm_event("NORM-GT-01", base_run.target_host, t0 + timedelta(minutes=2))
        store.add_normalized_event(ev)

        alt = AlertV1(
            alert_id="ALT-GT-01",
            source_alert_id="SRC-GT-01",
            source_type="sigma",
            alert_timestamp=t0 + timedelta(minutes=3),
            host_id=base_run.target_host,
            rule_reference=base_rule.rule_id,
        )
        store.add_alert(alt)

        if gt_label is not None:
            gt = GroundTruthV1(
                ground_truth_id="GT-INDEP-TEST",
                run_id=base_run.run_id,
                expected_diagnostic_category=gt_label,
                verification_method="adversarial_test",
            )
            store.add_ground_truth(gt)

        engine = AssuranceEngine(store)
        return engine.evaluate_run(base_run.run_id)

    # Outcome with NO ground truth in store
    res_none = _setup_store_and_evaluate(gt_label=None)
    # Outcome with MATCHING ground truth in store
    res_match = _setup_store_and_evaluate(gt_label=DiagnosticCategory.PASS)
    # Outcome with DELIBERATELY CONFLICTING ground truth in store
    res_conflict = _setup_store_and_evaluate(gt_label=DiagnosticCategory.ERROR)
    res_conflict2 = _setup_store_and_evaluate(gt_label=DiagnosticCategory.TEST_NOT_EXECUTED)

    assert res_none.predicted_category == DiagnosticCategory.PASS
    assert res_match.predicted_category == DiagnosticCategory.PASS
    assert res_conflict.predicted_category == DiagnosticCategory.PASS
    assert res_conflict2.predicted_category == DiagnosticCategory.PASS

    # Invariant reasons and evidence references
    assert res_none.reason == res_conflict.reason
    assert res_none.supporting_evidence_ids == res_conflict.supporting_evidence_ids
    assert res_none.confidence == res_conflict.confidence


# ── 2. Duplicate and Conflicting Telemetry Handling ──────────────────────────

def test_duplicate_telemetry_events_handling(base_scenario, base_run, base_rule):
    """Multiple identical telemetry events (e.g. at-least-once delivery replay) must not skew diagnosis."""
    store = InMemoryStore()
    store.add_scenario(base_scenario)
    store.add_run(base_run)
    store.add_rule(base_rule)

    t0 = base_run.window_start

    # Inject 3 duplicate events with identical content but distinct IDs
    ev1 = _create_norm_event("NORM-DUP-01", base_run.target_host, t0 + timedelta(minutes=2))
    ev2 = _create_norm_event("NORM-DUP-02", base_run.target_host, t0 + timedelta(minutes=2))
    ev3 = _create_norm_event("NORM-DUP-03", base_run.target_host, t0 + timedelta(minutes=2))
    store.add_normalized_event(ev1)
    store.add_normalized_event(ev2)
    store.add_normalized_event(ev3)

    alt = AlertV1(
        alert_id="ALT-DUP-01",
        source_alert_id="SRC-DUP-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=base_run.target_host,
        rule_reference=base_rule.rule_id,
    )
    store.add_alert(alt)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(base_run.run_id)

    assert res.predicted_category == DiagnosticCategory.PASS
    # All 3 events and the alert are deterministically tracked in supporting evidence
    assert "NORM-DUP-01" in res.supporting_evidence_ids
    assert "NORM-DUP-02" in res.supporting_evidence_ids
    assert "NORM-DUP-03" in res.supporting_evidence_ids
    assert "ALT-DUP-01" in res.supporting_evidence_ids


def test_concurrent_unrelated_telemetry_noise_isolation(base_scenario, base_run, base_rule):
    """Presence of concurrent background noise telemetry must not prevent matching attack telemetry."""
    store = InMemoryStore()
    store.add_scenario(base_scenario)
    store.add_run(base_run)
    store.add_rule(base_rule)

    t0 = base_run.window_start

    # 1. Unrelated noise event on same host (calc.exe, notepad.exe)
    noise_ev1 = _create_norm_event("NORM-NOISE-01", base_run.target_host, t0 + timedelta(minutes=1), process_name="calc.exe", cmd="calc.exe")
    noise_ev2 = _create_norm_event("NORM-NOISE-02", base_run.target_host, t0 + timedelta(minutes=2), process_name="notepad.exe", cmd="notepad.exe doc.txt")
    # 2. Genuine attack telemetry event
    attack_ev = _create_norm_event("NORM-ATTACK-01", base_run.target_host, t0 + timedelta(minutes=3), process_name="powershell.exe", cmd="powershell.exe -enc DownloadString")

    store.add_normalized_event(noise_ev1)
    store.add_normalized_event(noise_ev2)
    store.add_normalized_event(attack_ev)

    alt = AlertV1(
        alert_id="ALT-ATTACK-01",
        source_alert_id="SRC-ATTACK-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=4),
        host_id=base_run.target_host,
        rule_reference=base_rule.rule_id,
    )
    store.add_alert(alt)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(base_run.run_id)

    assert res.predicted_category == DiagnosticCategory.PASS
    assert "NORM-ATTACK-01" in res.supporting_evidence_ids
    assert "NORM-NOISE-01" not in res.supporting_evidence_ids
    assert "NORM-NOISE-02" not in res.supporting_evidence_ids


# ── 3. Exact Window Boundary and Microsecond Precision ────────────────────────

def test_exact_window_boundary_microsecond_precision(base_scenario, base_rule):
    """Verify inclusive boundaries [window_start, window_end] and exclusive microsecond boundaries."""
    t0 = datetime(2026, 10, 16, 10, 0, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 16, 10, 15, 0, 0, tzinfo=timezone.utc)

    run = TestRunV1(
        run_id="RUN-BOUNDARY-TEST",
        scenario_id=base_scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-BOUND-01",
        target_user="analyst",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
    )

    # Subcase A: Telemetry exactly at window_start (inclusive) -> MATCH
    store_a = InMemoryStore()
    store_a.add_scenario(base_scenario)
    store_a.add_run(run)
    store_a.add_rule(base_rule)
    ev_a = _create_norm_event("NORM-BOUND-A", run.target_host, t0)
    alt_a = AlertV1(
        alert_id="ALT-BOUND-A",
        source_alert_id="SRC-A",
        source_type="sigma",
        alert_timestamp=t0,
        host_id=run.target_host,
        rule_reference=base_rule.rule_id,
    )
    store_a.add_normalized_event(ev_a)
    store_a.add_alert(alt_a)

    res_a = AssuranceEngine(store_a).evaluate_run(run.run_id)
    assert res_a.predicted_category == DiagnosticCategory.PASS
    assert "NORM-BOUND-A" in res_a.supporting_evidence_ids

    # Subcase B: Telemetry exactly at window_end (inclusive) -> MATCH
    store_b = InMemoryStore()
    store_b.add_scenario(base_scenario)
    store_b.add_run(run)
    store_b.add_rule(base_rule)
    ev_b = _create_norm_event("NORM-BOUND-B", run.target_host, t1)
    alt_b = AlertV1(
        alert_id="ALT-BOUND-B",
        source_alert_id="SRC-B",
        source_type="sigma",
        alert_timestamp=t1,
        host_id=run.target_host,
        rule_reference=base_rule.rule_id,
    )
    store_b.add_normalized_event(ev_b)
    store_b.add_alert(alt_b)

    res_b = AssuranceEngine(store_b).evaluate_run(run.run_id)
    assert res_b.predicted_category == DiagnosticCategory.PASS
    assert "NORM-BOUND-B" in res_b.supporting_evidence_ids

    # Subcase C: Telemetry 1 microsecond before window_start -> EXCLUDED
    store_c = InMemoryStore()
    store_c.add_scenario(base_scenario)
    store_c.add_run(run)
    store_c.add_rule(base_rule)
    ev_c = _create_norm_event("NORM-BOUND-C", run.target_host, t0 - timedelta(microseconds=1))
    store_c.add_normalized_event(ev_c)

    res_c = AssuranceEngine(store_c).evaluate_run(run.run_id)
    assert res_c.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    # Subcase D: Alert 1 microsecond after window_end -> EXCLUDED from PASS (fails window correlation)
    store_d = InMemoryStore()
    store_d.add_scenario(base_scenario)
    store_d.add_run(run)
    store_d.add_rule(base_rule)
    ev_d = _create_norm_event("NORM-BOUND-D", run.target_host, t0 + timedelta(minutes=5))
    alt_d = AlertV1(
        alert_id="ALT-BOUND-D",
        source_alert_id="SRC-D",
        source_type="sigma",
        alert_timestamp=t1 + timedelta(microseconds=1),
        host_id=run.target_host,
        rule_reference=base_rule.rule_id,
    )
    store_d.add_normalized_event(ev_d)
    store_d.add_alert(alt_d)

    res_d = AssuranceEngine(store_d).evaluate_run(run.run_id)
    assert res_d.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert "ALT-BOUND-D" in res_d.contradictory_evidence_ids


# ── 4. Uncorrelated Alert Isolation ───────────────────────────────────────────

def test_uncorrelated_alerts_host_and_rule_mismatch(base_scenario, base_run, base_rule):
    """Alerts for wrong host or wrong rule must not produce false PASS."""
    store = InMemoryStore()
    store.add_scenario(base_scenario)
    store.add_run(base_run)
    store.add_rule(base_rule)

    t0 = base_run.window_start

    # Valid telemetry matching signature on target host
    ev = _create_norm_event("NORM-EV-UNCORR", base_run.target_host, t0 + timedelta(minutes=2))
    store.add_normalized_event(ev)

    # Alert 1: Expected rule, but routed to WRONG host
    alt_wrong_host = AlertV1(
        alert_id="ALT-WRONG-HOST",
        source_alert_id="SRC-WH",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id="WS-DIFFERENT-HOST-99",
        rule_reference=base_rule.rule_id,
    )
    store.add_alert(alt_wrong_host)

    # Alert 2: Target host, but for WRONG rule
    alt_wrong_rule = AlertV1(
        alert_id="ALT-WRONG-RULE",
        source_alert_id="SRC-WR",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=base_run.target_host,
        rule_reference="RULE-OTHER-UNRELATED",
    )
    store.add_alert(alt_wrong_rule)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(base_run.run_id)

    # Must diagnose ALERT_NOT_CORRELATED (because expected rule fired, but on wrong host)
    assert res.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert "ALT-WRONG-HOST" in res.contradictory_evidence_ids
    assert "ALT-WRONG-RULE" not in res.contradictory_evidence_ids


# ── 5. Missing Expected Telemetry Nuances ─────────────────────────────────────

def test_missing_telemetry_signature_vs_category_mismatch(base_scenario, base_run, base_rule):
    """Distinguish telemetry complete absence from telemetry signature mismatch."""
    t0 = base_run.window_start

    # Case 1: Complete absence of events
    store_empty = InMemoryStore()
    store_empty.add_scenario(base_scenario)
    store_empty.add_run(base_run)
    store_empty.add_rule(base_rule)

    res_empty = AssuranceEngine(store_empty).evaluate_run(base_run.run_id)
    assert res_empty.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert res_empty.supporting_evidence_ids == []
    assert res_empty.missing_evidence is True

    # Case 2: Events observed, but process_name does not match
    store_mismatch = InMemoryStore()
    store_mismatch.add_scenario(base_scenario)
    store_mismatch.add_run(base_run)
    store_mismatch.add_rule(base_rule)

    ev_wrong_proc = _create_norm_event(
        "NORM-WRONG-PROC", base_run.target_host, t0 + timedelta(minutes=2),
        process_name="cmd.exe", cmd="cmd.exe /c DownloadString"
    )
    store_mismatch.add_normalized_event(ev_wrong_proc)

    res_mismatch = AssuranceEngine(store_mismatch).evaluate_run(base_run.run_id)
    assert res_mismatch.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    # Non-matching event ID is cited as supporting evidence of observation
    assert "NORM-WRONG-PROC" in res_mismatch.supporting_evidence_ids
    assert res_mismatch.missing_evidence is True


# ── 6. Incomplete Execution & Explicit Error Conditions ───────────────────────

def test_incomplete_execution_states(base_scenario):
    """Verify non-completed test execution outcomes."""
    t0 = datetime(2026, 10, 16, 10, 0, tzinfo=timezone.utc)

    # Subcase A: RUNNING status -> INCONCLUSIVE
    run_running = TestRunV1(
        run_id="RUN-RUNNING",
        scenario_id=base_scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-01",
        target_user="analyst",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_status=ExecutionStatus.RUNNING,
    )
    store_a = InMemoryStore()
    store_a.add_scenario(base_scenario)
    store_a.add_run(run_running)
    res_a = AssuranceEngine(store_a).evaluate_run(run_running.run_id)
    assert res_a.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res_a.confidence == "uncertain"
    assert res_a.missing_evidence is True

    # Subcase B: FAILED status -> TEST_NOT_EXECUTED
    run_failed = TestRunV1(
        run_id="RUN-FAILED",
        scenario_id=base_scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-01",
        target_user="analyst",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_status=ExecutionStatus.FAILED,
    )
    store_b = InMemoryStore()
    store_b.add_scenario(base_scenario)
    store_b.add_run(run_failed)
    res_b = AssuranceEngine(store_b).evaluate_run(run_failed.run_id)
    assert res_b.predicted_category == DiagnosticCategory.TEST_NOT_EXECUTED
    assert res_b.confidence == "definitive"
    assert res_b.missing_evidence is False

    # Subcase C: Nonexistent run ID -> ERROR
    res_c = AssuranceEngine(store_b).evaluate_run("NONEXISTENT-RUN-999")
    assert res_c.predicted_category == DiagnosticCategory.ERROR
    assert res_c.missing_evidence is True


# ── 7. Evidence Traceability & Alternative Eliminations ──────────────────────

def test_evidence_traceability_structure(base_scenario, base_run, base_rule):
    """Every diagnostic result must identify checks performed and why alternatives were eliminated."""
    store = InMemoryStore()
    store.add_scenario(base_scenario)
    store.add_run(base_run)
    store.add_rule(base_rule)

    t0 = base_run.window_start
    ev = _create_norm_event("NORM-TRACE-01", base_run.target_host, t0 + timedelta(minutes=2))
    store.add_normalized_event(ev)

    # Ingest alert to produce PASS
    alt = AlertV1(
        alert_id="ALT-TRACE-01",
        source_alert_id="SRC-T1",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=base_run.target_host,
        rule_reference=base_rule.rule_id,
    )
    store.add_alert(alt)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(base_run.run_id)

    # Verify convenience properties
    assert isinstance(res.checks_performed, list)
    assert len(res.checks_performed) >= 3
    check_names = [c["check"] for c in res.checks_performed]
    assert "run_and_scenario_existence" in check_names
    assert "execution_status" in check_names
    assert "telemetry_signature_match" in check_names
    assert "alert_correlation" in check_names

    assert isinstance(res.alternative_eliminations, dict)
    assert DiagnosticCategory.EXPECTED_TELEMETRY_MISSING.value in res.alternative_eliminations
    assert DiagnosticCategory.DETECTION_NOT_TRIGGERED.value in res.alternative_eliminations
    assert DiagnosticCategory.TEST_NOT_EXECUTED.value in res.alternative_eliminations
    assert DiagnosticCategory.ALERT_NOT_CORRELATED.value in res.alternative_eliminations

    assert res.missing_evidence is False


# ── 8. Cross-Backend Determinism: InMemoryStore vs SQLiteStore ────────────────

def test_cross_backend_diagnostic_determinism(base_scenario, base_run, base_rule, tmp_path):
    """AssuranceEngine must produce byte-for-byte identical verdicts across InMemoryStore and SQLiteStore."""
    t0 = base_run.window_start
    ev = _create_norm_event("NORM-DET-01", base_run.target_host, t0 + timedelta(minutes=2))
    alt = AlertV1(
        alert_id="ALT-DET-01",
        source_alert_id="SRC-DET-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=base_run.target_host,
        rule_reference=base_rule.rule_id,
    )

    # 1. Evaluate with InMemoryStore
    store_mem = InMemoryStore()
    store_mem.add_scenario(base_scenario)
    store_mem.add_run(base_run)
    store_mem.add_rule(base_rule)
    store_mem.add_normalized_event(ev)
    store_mem.add_alert(alt)
    res_mem = AssuranceEngine(store_mem).evaluate_run(base_run.run_id)

    # 2. Evaluate with SQLiteStore (file-backed)
    db_file = tmp_path / "determinism.db"
    store_sqlite = SQLiteStore(db_file)
    try:
        store_sqlite.add_scenario(base_scenario)
        store_sqlite.add_run(base_run)
        store_sqlite.add_rule(base_rule)
        store_sqlite.add_normalized_event(ev)
        store_sqlite.add_alert(alt)
        res_sqlite = AssuranceEngine(store_sqlite).evaluate_run(base_run.run_id)
    finally:
        store_sqlite.close()

    # 3. Evaluate with SQLiteStore (:memory:)
    store_sqlite_mem = SQLiteStore(":memory:")
    try:
        store_sqlite_mem.add_scenario(base_scenario)
        store_sqlite_mem.add_run(base_run)
        store_sqlite_mem.add_rule(base_rule)
        store_sqlite_mem.add_normalized_event(ev)
        store_sqlite_mem.add_alert(alt)
        res_sqlite_mem = AssuranceEngine(store_sqlite_mem).evaluate_run(base_run.run_id)
    finally:
        store_sqlite_mem.close()

    # Compare verdicts across InMemoryStore, SQLiteStore (file), and SQLiteStore (:memory:)
    assert res_mem.predicted_category == res_sqlite.predicted_category == res_sqlite_mem.predicted_category
    assert res_mem.reason == res_sqlite.reason == res_sqlite_mem.reason
    assert res_mem.confidence == res_sqlite.confidence == res_sqlite_mem.confidence
    assert res_mem.supporting_evidence_ids == res_sqlite.supporting_evidence_ids == res_sqlite_mem.supporting_evidence_ids
    assert res_mem.contradictory_evidence_ids == res_sqlite.contradictory_evidence_ids == res_sqlite_mem.contradictory_evidence_ids
    assert res_mem.failure_category == res_sqlite.failure_category == res_sqlite_mem.failure_category
    assert res_mem.checks_performed == res_sqlite.checks_performed == res_sqlite_mem.checks_performed
    assert res_mem.alternative_eliminations == res_sqlite.alternative_eliminations == res_sqlite_mem.alternative_eliminations
    assert res_mem.missing_evidence == res_sqlite.missing_evidence == res_sqlite_mem.missing_evidence


# ── 9. Evaluation Metrics Integrity & Denominators ────────────────────────────

def test_evaluation_metrics_denominator_integrity():
    """Verify metrics calculation correctly separates inconclusive/unexecuted cases and avoids inflation."""
    true_labels = [
        DiagnosticCategory.PASS,
        DiagnosticCategory.PASS,
        DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        DiagnosticCategory.INCONCLUSIVE,
        DiagnosticCategory.TEST_NOT_EXECUTED,
        DiagnosticCategory.ERROR,
    ]
    # Prediction has 1 correct PASS, 1 false PASS, 1 correct DET_NOT_TRIG, 1 INCONCL, 1 TEST_NOT_EX, 1 ERROR
    pred_labels = [
        DiagnosticCategory.PASS,
        DiagnosticCategory.DETECTION_NOT_TRIGGERED,  # Disagreement (false confident)
        DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        DiagnosticCategory.INCONCLUSIVE,
        DiagnosticCategory.TEST_NOT_EXECUTED,
        DiagnosticCategory.ERROR,
    ]
    valid_evidence = [True, True, True, True, True, True]

    metrics = compute_metrics(true_labels, pred_labels, valid_evidence)

    # Total samples = 6
    assert metrics.total_samples == 6
    # Accuracy = 5/6 = 0.8333
    assert metrics.accuracy == pytest.approx(5 / 6)

    # Confident predictions: [PASS, DET_NOT_TRIG, DET_NOT_TRIG, TEST_NOT_EX, ERROR] = 5
    # False confident predictions: [pred_labels[1]] = 1
    # FDR = 1 / 5 = 0.20
    assert metrics.false_diagnosis_rate == pytest.approx(1 / 5)

    # Inconclusive rate = 1 / 6 = 0.1667
    assert metrics.inconclusive_rate == pytest.approx(1 / 6)

    # Zero denominator edge case: all predictions are inconclusive
    zero_m = compute_metrics(
        [DiagnosticCategory.PASS],
        [DiagnosticCategory.INCONCLUSIVE],
        [True],
    )
    assert zero_m.false_diagnosis_rate == 0.0
    assert zero_m.inconclusive_rate == 1.0
    assert zero_m.accuracy == 0.0
