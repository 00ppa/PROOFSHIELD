from datetime import datetime, timezone, timedelta
import pytest

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    FailureCategory,
    GroundTruthLabel,
    GroundTruthV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.store import InMemoryStore


@pytest.fixture
def store():
    return InMemoryStore()


@pytest.fixture
def engine(store):
    return AssuranceEngine(store)


@pytest.fixture
def scenario_with_rule(store):
    scn = ScenarioV1(
        scenario_id="SCN-T1059.001-01",
        name="PowerShell Execution Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"powershell(\.exe)?\s+.*-enc",
        expected_detection_rule_id="RULE-SIGMA-001",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scn)
    return scn


@pytest.fixture
def scenario_telemetry_only(store):
    scn = ScenarioV1(
        scenario_id="SCN-TELEMETRY-ONLY",
        name="Telemetry Health Check",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
    )
    store.add_scenario(scn)
    return scn


@pytest.fixture
def completed_run(store, scenario_with_rule):
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    run = TestRunV1(
        run_id="RUN-001",
        scenario_id=scenario_with_rule.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-WIN11-01",
        target_user="CORP\\alice",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)
    return run


def test_evaluate_nonexistent_run(engine):
    res = engine.evaluate_run("NONEXISTENT-RUN")
    assert res.predicted_category == DiagnosticCategory.ERROR
    assert "not found" in res.reason


def test_evaluate_nonexistent_scenario(store, engine):
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    run = TestRunV1(
        run_id="RUN-ORPHAN",
        scenario_id="SCN-MISSING",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-WIN11-01",
        target_user="CORP\\alice",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    # Directly inject into internal dict to bypass store.add_run check
    store._runs[run.run_id] = run
    res = engine.evaluate_run("RUN-ORPHAN")
    assert res.predicted_category == DiagnosticCategory.ERROR
    assert "Scenario not found" in res.reason


def test_evaluate_test_not_executed(store, engine, scenario_with_rule):
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    run = TestRunV1(
        run_id="RUN-FAILED",
        scenario_id=scenario_with_rule.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-WIN11-01",
        target_user="CORP\\alice",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_status=ExecutionStatus.FAILED,
    )
    store.add_run(run)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.TEST_NOT_EXECUTED
    assert "FAILED" in res.reason


def test_evaluate_running_status_inconclusive(store, engine, scenario_with_rule):
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    run = TestRunV1(
        run_id="RUN-RUNNING",
        scenario_id=scenario_with_rule.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-WIN11-01",
        target_user="CORP\\alice",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_status=ExecutionStatus.RUNNING,
    )
    store.add_run(run)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res.confidence == "uncertain"
    assert "RUNNING" in res.reason


def test_evaluate_telemetry_missing_empty(engine, completed_run):
    res = engine.evaluate_run(completed_run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert res.confidence == "likely"
    assert "No telemetry events observed" in res.reason


def test_evaluate_telemetry_missing_wrong_signature(store, engine, completed_run):
    t = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t,
        normalized_timestamp=t,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
        process_name="notepad.exe",
        command_line="notepad.exe text.txt",
    )
    store.add_normalized_event(event)

    res = engine.evaluate_run(completed_run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert res.confidence == "likely"
    assert "none match the expected signature" in res.reason


def test_evaluate_detection_not_triggered(store, engine, completed_run):
    t = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t,
        normalized_timestamp=t,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    res = engine.evaluate_run(completed_run.run_id)
    assert res.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED
    assert "did not trigger" in res.reason
    assert "NORM-01" in res.supporting_evidence_ids


def test_evaluate_alert_not_correlated_different_host(store, engine, completed_run):
    t = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t,
        normalized_timestamp=t,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    # Alert exists in SIEM for expected rule, but on another host
    alert = AlertV1(
        alert_id="ALT-DIFF-HOST",
        source_alert_id="SRC-ALT-1",
        source_type="wazuh",
        alert_timestamp=t,
        host_id="WS-SERVER-02",
        rule_reference="RULE-SIGMA-001",
    )
    store.add_alert(alert)

    res = engine.evaluate_run(completed_run.run_id)
    assert res.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert "could not be correlated" in res.reason
    assert "NORM-01" in res.supporting_evidence_ids
    assert "ALT-DIFF-HOST" in res.contradictory_evidence_ids


def test_evaluate_pass_with_correlated_alert(store, engine, completed_run):
    t = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t,
        normalized_timestamp=t,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    alert_matched = AlertV1(
        alert_id="ALT-MATCH",
        source_alert_id="SRC-ALT-2",
        source_type="wazuh",
        alert_timestamp=t,
        host_id="WS-WIN11-01",
        rule_reference="RULE-SIGMA-001",
    )
    store.add_alert(alert_matched)

    res = engine.evaluate_run(completed_run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS
    assert "ALT-MATCH" in res.supporting_evidence_ids
    assert "NORM-01" in res.supporting_evidence_ids


def test_evaluate_telemetry_only_pass(store, engine, scenario_telemetry_only):
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    t_ev = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)

    run = TestRunV1(
        run_id="RUN-TEL-ONLY",
        scenario_id=scenario_telemetry_only.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-WIN11-01",
        target_user="CORP\\alice",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-TEL-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t_ev,
        normalized_timestamp=t_ev,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
    )
    store.add_normalized_event(event)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS
    assert "telemetry-only scenario" in res.reason


def test_evaluate_inconclusive_no_rule_not_telemetry_only(store, engine):
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    t_ev = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)

    scn = ScenarioV1(
        scenario_id="SCN-NO-RULE",
        name="No Rule Specified",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,  # expects alert, but no expected_detection_rule_id
    )
    store.add_scenario(scn)

    run = TestRunV1(
        run_id="RUN-NO-RULE",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-WIN11-01",
        target_user="CORP\\alice",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t_ev,
        normalized_timestamp=t_ev,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
    )
    store.add_normalized_event(event)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res.confidence == "uncertain"


def test_evaluate_historical_alert_out_of_scope(store, engine, scenario_with_rule, completed_run):
    """Verify historical alerts outside the run time window + grace period do NOT turn

    DETECTION_NOT_TRIGGERED into ALERT_NOT_CORRELATED.
    """
    t_ev = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t_ev,
        normalized_timestamp=t_ev,
        event_category=EventCategory.PROCESS_CREATION,
        host=completed_run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    # Add historical alert for this rule from 24 hours ago
    t_historical = datetime(2026, 10, 11, 10, 5, tzinfo=timezone.utc)
    old_alert = AlertV1(
        alert_id="ALT-HISTORICAL-01",
        source_alert_id="SRC-HIST-01",
        source_type="sigma",
        alert_timestamp=t_historical,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(old_alert)

    # Engine evaluation must recognize that no alert fired for this run (ignoring old alert)
    res = engine.evaluate_run(completed_run.run_id)
    assert res.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED
    assert "did not trigger" in res.reason


def test_evaluate_alert_within_grace_period(store, engine, scenario_with_rule, completed_run):
    """Verify alert within the grace period (e.g. 20m late) is discovered and evaluated

    as ALERT_NOT_CORRELATED (since it fell outside exact run window).
    """
    t_ev = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t_ev,
        normalized_timestamp=t_ev,
        event_category=EventCategory.PROCESS_CREATION,
        host=completed_run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    # Alert fired 20 minutes after run window_end (within default 3600s grace period)
    t_late = datetime(2026, 10, 12, 10, 35, tzinfo=timezone.utc)
    late_alert = AlertV1(
        alert_id="ALT-LATE-01",
        source_alert_id="SRC-LATE-01",
        source_type="sigma",
        alert_timestamp=t_late,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(late_alert)

    res = engine.evaluate_run(completed_run.run_id)
    assert res.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert "could not be correlated" in res.reason


def test_ground_truth_independence_from_prediction(store, engine, completed_run, scenario_with_rule):
    """Verify that adding, modifying, or removing GroundTruthV1 does not affect predictions."""
    t_ev = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t_ev,
        normalized_timestamp=t_ev,
        event_category=EventCategory.PROCESS_CREATION,
        host=completed_run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    # Initial baseline without ground truth -> DETECTION_NOT_TRIGGERED
    res1 = engine.evaluate_run(completed_run.run_id)
    assert res1.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED

    # Add GroundTruth claiming PASS
    gt1 = GroundTruthV1(
        ground_truth_id="GT-TEST-01",
        run_id=completed_run.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="independent_oracle",
    )
    store.add_ground_truth(gt1)

    res2 = engine.evaluate_run(completed_run.run_id)
    assert res2.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED
    assert res2.predicted_category == res1.predicted_category

    # Mutate GroundTruth to ERROR
    store._ground_truths["GT-TEST-01"] = GroundTruthV1(
        ground_truth_id="GT-TEST-01",
        run_id=completed_run.run_id,
        expected_diagnostic_category=DiagnosticCategory.ERROR,
        verification_method="mutated",
    )
    res3 = engine.evaluate_run(completed_run.run_id)
    assert res3.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED

    # Remove GroundTruth entirely
    del store._ground_truths["GT-TEST-01"]
    res4 = engine.evaluate_run(completed_run.run_id)
    assert res4.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED


def test_alert_grace_period_exact_boundaries(store, engine, scenario_with_rule, completed_run):
    """Verify alert timestamps at exact grace period boundaries behave correctly."""
    t_ev = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t_ev,
        normalized_timestamp=t_ev,
        event_category=EventCategory.PROCESS_CREATION,
        host=completed_run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    grace = timedelta(seconds=engine.default_alert_grace_period_seconds)  # 3600s
    t_start = completed_run.window_start  # 10:00:00
    t_end = completed_run.window_end      # 10:15:00

    # 1. Exact inner boundary start (10:00:00) -> correlates -> PASS
    alert_start = AlertV1(
        alert_id="ALT-IN-START",
        source_alert_id="SRC-1",
        source_type="sigma",
        alert_timestamp=t_start,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert_start)
    assert engine.evaluate_run(completed_run.run_id).predicted_category == DiagnosticCategory.PASS
    del store._alerts["ALT-IN-START"]

    # 2. Exact inner boundary end (10:15:00) -> correlates -> PASS
    alert_end = AlertV1(
        alert_id="ALT-IN-END",
        source_alert_id="SRC-2",
        source_type="sigma",
        alert_timestamp=t_end,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert_end)
    assert engine.evaluate_run(completed_run.run_id).predicted_category == DiagnosticCategory.PASS
    del store._alerts["ALT-IN-END"]

    # 3. Exact outer boundary start (t_start - grace: 09:00:00) -> ALERT_NOT_CORRELATED
    alert_outer_start = AlertV1(
        alert_id="ALT-OUT-START",
        source_alert_id="SRC-3",
        source_type="sigma",
        alert_timestamp=t_start - grace,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert_outer_start)
    assert engine.evaluate_run(completed_run.run_id).predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    del store._alerts["ALT-OUT-START"]

    # 4. 1 second before outer boundary start (08:59:59) -> outside grace -> DETECTION_NOT_TRIGGERED
    alert_before_outer = AlertV1(
        alert_id="ALT-BEFORE-OUT",
        source_alert_id="SRC-4",
        source_type="sigma",
        alert_timestamp=t_start - grace - timedelta(seconds=1),
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert_before_outer)
    assert engine.evaluate_run(completed_run.run_id).predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED
    del store._alerts["ALT-BEFORE-OUT"]

    # 5. Exact outer boundary end (t_end + grace: 11:15:00) -> ALERT_NOT_CORRELATED
    alert_outer_end = AlertV1(
        alert_id="ALT-OUT-END",
        source_alert_id="SRC-5",
        source_type="sigma",
        alert_timestamp=t_end + grace,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert_outer_end)
    assert engine.evaluate_run(completed_run.run_id).predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    del store._alerts["ALT-OUT-END"]

    # 6. 1 second after outer boundary end (11:15:01) -> outside grace -> DETECTION_NOT_TRIGGERED
    alert_after_outer = AlertV1(
        alert_id="ALT-AFTER-OUT",
        source_alert_id="SRC-6",
        source_type="sigma",
        alert_timestamp=t_end + grace + timedelta(seconds=1),
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert_after_outer)
    assert engine.evaluate_run(completed_run.run_id).predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED


def test_missing_timestamps_and_multiple_candidate_alerts_deterministic(store, engine, scenario_with_rule, completed_run):
    """Verify missing timestamps are handled safely and multiple candidates produce deterministic results."""
    t_ev = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t_ev,
        normalized_timestamp=t_ev,
        event_category=EventCategory.PROCESS_CREATION,
        host=completed_run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    # Add an alert with missing timestamp (None)
    alert_no_ts = AlertV1(
        alert_id="ALT-NO-TS",
        source_alert_id="SRC-NO-TS",
        source_type="sigma",
        alert_timestamp=None,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert_no_ts)

    # Missing timestamp on target host prevents reliable diagnosis -> INCONCLUSIVE
    res_no_ts = engine.evaluate_run(completed_run.run_id)
    assert res_no_ts.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res_no_ts.confidence == "uncertain"

    # Now add multiple candidate alerts inserted in reverse chronological order
    t2 = datetime(2026, 10, 12, 10, 10, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 2, tzinfo=timezone.utc)
    alert2 = AlertV1(
        alert_id="ALT-02",
        source_alert_id="SRC-2",
        source_type="sigma",
        alert_timestamp=t2,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    alert1 = AlertV1(
        alert_id="ALT-01",
        source_alert_id="SRC-1",
        source_type="sigma",
        alert_timestamp=t1,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert2)
    store.add_alert(alert1)

    res_multi = engine.evaluate_run(completed_run.run_id)
    assert res_multi.predicted_category == DiagnosticCategory.PASS
    # Supporting evidence must contain both correlated alerts in deterministic chronological order
    assert res_multi.supporting_evidence_ids == ["NORM-01", "ALT-01", "ALT-02"]


def test_missing_alert_timestamp_preserves_ingestion_metadata_only(store, engine, scenario_with_rule, completed_run):
    """Verify ingestion time is stored as metadata only and missing event timestamp yields INCONCLUSIVE."""
    t_ev = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t_ev,
        normalized_timestamp=t_ev,
        event_category=EventCategory.PROCESS_CREATION,
        host=completed_run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    # Ingest alert without event timestamp
    alert = AlertV1(
        alert_id="ALT-INGESTION-ONLY",
        source_alert_id="SRC-ING-01",
        source_type="wazuh",
        alert_timestamp=None,
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert)

    # Ingestion time must be set as ingestion metadata, not alert_timestamp
    assert alert.ingested_at is not None
    assert alert.alert_timestamp is None
    assert alert.metadata.get("ingestion_time_only") is True

    # Evaluation cannot verify whether detection occurred during run window -> INCONCLUSIVE
    res = engine.evaluate_run(completed_run.run_id)
    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res.confidence == "uncertain"
    assert "cannot be reliably verified" in res.reason


def test_latency_classification_when_acceptable_threshold_exceeded(store, engine, scenario_with_rule, completed_run):
    """Verify latency classification is applied when event and raw ingestion timestamps clearly show latency exceeded."""
    t_action = datetime(2026, 10, 12, 10, 2, tzinfo=timezone.utc)
    t_ingested = datetime(2026, 10, 12, 10, 8, tzinfo=timezone.utc)  # 360s latency (threshold is 300s)

    # Create raw telemetry event with explicit ingestion timestamp
    raw_event = RawTelemetryEventV1(
        raw_event_id="RAW-LATENCY-01",
        source_event_id="SRC-SYS-01",
        source_format="sysmon",
        source_timestamp=t_action,
        ingested_at=t_ingested,
        raw_payload={"EventID": 1},
    )
    store.add_raw_event(raw_event)

    # Normalized event linking to raw event
    norm_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-LATENCY-01",
        raw_event_id="RAW-LATENCY-01",
        source_event_id="SRC-SYS-01",
        source_timestamp=t_action,
        normalized_timestamp=t_action,
        event_category=EventCategory.PROCESS_CREATION,
        host=completed_run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(norm_event)

    # Correlated alert
    alert = AlertV1(
        alert_id="ALT-PASS-01",
        source_alert_id="SRC-A-01",
        source_type="sigma",
        alert_timestamp=datetime(2026, 10, 12, 10, 4, tzinfo=timezone.utc),
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert)

    res = engine.evaluate_run(completed_run.run_id)
    # Outcome is PASS because evidence was observed and correlated
    assert res.predicted_category == DiagnosticCategory.PASS
    # Pipeline latency exceeded is classified via failure_category and metadata
    assert res.failure_category == FailureCategory.PIPELINE_LATENCY
    assert res.metadata["latency"]["latency_exceeded"] is True
    assert res.metadata["latency"]["telemetry_pipeline_latency_seconds"] == 360.0
    assert any("Telemetry pipeline latency (360.0s) exceeded" in reason for reason in res.diagnostic_reasons)


def test_latency_not_inferred_when_required_timestamps_unavailable(store, engine, scenario_with_rule, completed_run):
    """Verify latency is never inferred from unrelated timestamps when raw ingestion timestamp is unavailable."""
    t_action = datetime(2026, 10, 12, 10, 2, tzinfo=timezone.utc)

    # Event added without corresponding raw event in store
    norm_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NO-RAW",
        raw_event_id="RAW-NONEXISTENT",
        source_event_id="SRC-SYS-02",
        source_timestamp=t_action,
        normalized_timestamp=t_action,
        event_category=EventCategory.PROCESS_CREATION,
        host=completed_run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(norm_event)

    alert = AlertV1(
        alert_id="ALT-PASS-02",
        source_alert_id="SRC-A-02",
        source_type="sigma",
        alert_timestamp=datetime(2026, 10, 12, 10, 4, tzinfo=timezone.utc),
        host_id=completed_run.target_host,
        rule_reference=scenario_with_rule.expected_detection_rule_id,
    )
    store.add_alert(alert)

    res = engine.evaluate_run(completed_run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS
    # Since raw event was unavailable, latency was NOT inferred from run window or execution start
    assert res.failure_category is None
    assert res.metadata["latency"]["telemetry_pipeline_latency"]["status"] == "unavailable"
