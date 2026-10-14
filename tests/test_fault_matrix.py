"""Phase 2 Fault-Injection Benchmark Matrix (FT-01 through FT-12).

Automated verification of the deterministic Assurance Engine across nominal
and simulated failure modes, verifying each against independent ground-truth baselines.
"""

from datetime import datetime, timezone, timedelta
import pytest

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    GroundTruthLabel,
    GroundTruthV1,
    NormalizedTelemetryEventV1,
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
def base_scenario(store):
    scn = ScenarioV1(
        scenario_id="SCN-FT-BASE",
        name="FT Base Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"powershell(\.exe)?\s+.*-enc",
        expected_detection_rule_id="RULE-SIGMA-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scn)
    return scn


def _make_run(
    store,
    scenario_id: str,
    run_id: str = "RUN-FT",
    host: str = "WS-01",
    status: ExecutionStatus = ExecutionStatus.COMPLETED,
    t0: datetime = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc),
    duration_min: int = 10,
) -> TestRunV1:
    run = TestRunV1(
        run_id=run_id,
        scenario_id=scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host=host,
        target_user="CORP\\test_user",
        window_start=t0,
        window_end=t0 + timedelta(minutes=duration_min),
        executed_at=t0 + timedelta(seconds=15),
        execution_status=status,
    )
    store.add_run(run)
    return run


# ── FT-01: Nominal Baseline Detection ─────────────────────────────────────────

def test_ft_01_nominal_baseline_pass(store, engine, base_scenario):
    """FT-01: Valid execution with expected telemetry and matching alert -> PASS."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    run = _make_run(store, base_scenario.scenario_id, "RUN-FT-01", "WS-01", ExecutionStatus.COMPLETED, t0)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-FT-01",
        raw_event_id="RAW-01",
        source_event_id="S-01",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    alert = AlertV1(
        alert_id="ALT-FT-01",
        source_alert_id="WAZ-01",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=2),
        host_id="WS-01",
        rule_reference="RULE-SIGMA-01",
    )
    store.add_alert(alert)

    gt = GroundTruthV1(
        ground_truth_id="GT-FT-01",
        run_id=run.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="independent_test_harness",
    )
    store.add_ground_truth(gt)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == gt.expected_diagnostic_category
    assert result.confidence == "definitive"
    assert "EVT-FT-01" in result.supporting_evidence_ids
    assert "ALT-FT-01" in result.supporting_evidence_ids


# ── FT-02: Test Never Executed ────────────────────────────────────────────────

def test_ft_02_test_never_executed(store, engine, base_scenario):
    """FT-02: Test execution failed before payload generation -> TEST_NOT_EXECUTED."""
    run = _make_run(store, base_scenario.scenario_id, "RUN-FT-02", status=ExecutionStatus.FAILED)

    gt = GroundTruthV1(
        ground_truth_id="GT-FT-02",
        run_id=run.run_id,
        expected_diagnostic_category=DiagnosticCategory.TEST_NOT_EXECUTED,
        verification_method="runner_exit_code",
    )
    store.add_ground_truth(gt)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == gt.expected_diagnostic_category
    assert result.confidence == "definitive"


# ── FT-03: Test Still Running ─────────────────────────────────────────────────

def test_ft_03_test_still_running_inconclusive(store, engine, base_scenario):
    """FT-03: Evaluation invoked while run status is RUNNING -> INCONCLUSIVE."""
    run = _make_run(store, base_scenario.scenario_id, "RUN-FT-03", status=ExecutionStatus.RUNNING)

    gt = GroundTruthV1(
        ground_truth_id="GT-FT-03",
        run_id=run.run_id,
        expected_diagnostic_category=DiagnosticCategory.INCONCLUSIVE,
        verification_method="runtime_supervisor",
    )
    store.add_ground_truth(gt)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == gt.expected_diagnostic_category
    assert result.confidence == "uncertain"
    assert "RUNNING" in result.reason


# ── FT-04: Expected Telemetry Absent (Sensor Blackout) ────────────────────────

def test_ft_04_telemetry_absent_empty(store, engine, base_scenario):
    """FT-04: Zero telemetry observed from host during observation window -> EXPECTED_TELEMETRY_MISSING."""
    run = _make_run(store, base_scenario.scenario_id, "RUN-FT-04")

    gt = GroundTruthV1(
        ground_truth_id="GT-FT-04",
        run_id=run.run_id,
        expected_diagnostic_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        verification_method="sensor_fault_injection",
    )
    store.add_ground_truth(gt)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == gt.expected_diagnostic_category
    assert result.confidence == "likely"


# ── FT-05: Non-Matching Telemetry Signature ───────────────────────────────────

def test_ft_05_telemetry_signature_mismatch(store, engine, base_scenario):
    """FT-05: Telemetry observed in window, but process/regex signature does not match -> EXPECTED_TELEMETRY_MISSING."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    run = _make_run(store, base_scenario.scenario_id, "RUN-FT-05", t0=t0)

    # Ingest notepad.exe instead of powershell.exe
    event = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-FT-05",
        raw_event_id="RAW-05",
        source_event_id="S-05",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="notepad.exe",
        command_line="notepad.exe readme.txt",
    )
    store.add_normalized_event(event)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert "none match the expected signature" in result.reason


# ── FT-06: Detection Rule Not Triggered ───────────────────────────────────────

def test_ft_06_detection_not_triggered(store, engine, base_scenario):
    """FT-06: Matching telemetry present, but expected detection rule never fired -> DETECTION_NOT_TRIGGERED."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    run = _make_run(store, base_scenario.scenario_id, "RUN-FT-06", t0=t0)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-FT-06",
        raw_event_id="RAW-06",
        source_event_id="S-06",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    # An unrelated rule fired, but NOT RULE-SIGMA-01
    alert = AlertV1(
        alert_id="ALT-UNRELATED",
        source_alert_id="WAZ-99",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=2),
        host_id="WS-01",
        rule_reference="RULE-OTHER-99",
    )
    store.add_alert(alert)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED
    assert "did not trigger" in result.reason
    assert "EVT-FT-06" in result.supporting_evidence_ids


# ── FT-07: Alert Routing Fault (Wrong Host) ───────────────────────────────────

def test_ft_07_alert_routing_fault_wrong_host(store, engine, base_scenario):
    """FT-07: Telemetry present; rule fired in SIEM, but alert was attributed to a different host -> ALERT_NOT_CORRELATED."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    run = _make_run(store, base_scenario.scenario_id, "RUN-FT-07", host="WS-01", t0=t0)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-FT-07",
        raw_event_id="RAW-07",
        source_event_id="S-07",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    # Rule fired, but on WS-99 instead of WS-01
    alert = AlertV1(
        alert_id="ALT-FT-07",
        source_alert_id="WAZ-07",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=2),
        host_id="WS-99",
        rule_reference="RULE-SIGMA-01",
    )
    store.add_alert(alert)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert "could not be correlated" in result.reason
    assert "ALT-FT-07" in result.contradictory_evidence_ids


# ── FT-08: Alert Latency / Clock Skew (Outside Time Window) ───────────────────

def test_ft_08_alert_out_of_window(store, engine, base_scenario):
    """FT-08: Telemetry present; rule fired for target host, but alert arrived well outside window -> ALERT_NOT_CORRELATED."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    run = _make_run(store, base_scenario.scenario_id, "RUN-FT-08", host="WS-01", t0=t0, duration_min=10)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-FT-08",
        raw_event_id="RAW-08",
        source_event_id="S-08",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    # Alert timestamp is 45 minutes after window_end (10:10)
    alert = AlertV1(
        alert_id="ALT-FT-08",
        source_alert_id="WAZ-08",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=55),
        host_id="WS-01",
        rule_reference="RULE-SIGMA-01",
    )
    store.add_alert(alert)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert "could not be correlated" in result.reason
    assert "ALT-FT-08" in result.contradictory_evidence_ids


# ── FT-09: Telemetry-Only Scenario Without Detection Rule ─────────────────────

def test_ft_09_telemetry_only_scenario_pass(store, engine):
    """FT-09: Scenario configured as EXPECTED_TELEMETRY_ONLY with no rule -> PASS upon telemetry match."""
    scn = ScenarioV1(
        scenario_id="SCN-FT-09",
        name="Telemetry Health Check",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
    )
    store.add_scenario(scn)

    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    run = _make_run(store, scn.scenario_id, "RUN-FT-09", host="WS-01", t0=t0)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-FT-09",
        raw_event_id="RAW-09",
        source_event_id="S-09",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="powershell.exe",
    )
    store.add_normalized_event(event)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == DiagnosticCategory.PASS
    assert "telemetry-only scenario" in result.reason
    assert "EVT-FT-09" in result.supporting_evidence_ids


# ── FT-10: Ambiguous Criteria (Expected Alert But No Rule Specified) ─────────

def test_ft_10_missing_rule_definition_inconclusive(store, engine):
    """FT-10: Scenario expects alert, telemetry is observed, but no rule ID is defined -> INCONCLUSIVE."""
    scn = ScenarioV1(
        scenario_id="SCN-FT-10",
        name="Incomplete Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_detection_rule_id=None,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scn)

    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    run = _make_run(store, scn.scenario_id, "RUN-FT-10", host="WS-01", t0=t0)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-FT-10",
        raw_event_id="RAW-10",
        source_event_id="S-10",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="powershell.exe",
    )
    store.add_normalized_event(event)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert result.confidence == "uncertain"


# ── FT-11: IP-Based Host Boundary Isolation ───────────────────────────────────

def test_ft_11_ip_address_host_isolation(store, engine, base_scenario):
    """FT-11: Run target is 192.168.1.10; telemetry from 192.168.2.99 MUST NOT match -> EXPECTED_TELEMETRY_MISSING."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    run = _make_run(store, base_scenario.scenario_id, "RUN-FT-11", host="192.168.1.10", t0=t0)

    # Event from a DIFFERENT IP in the same /8 or /16
    event = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-FT-11",
        raw_event_id="RAW-11",
        source_event_id="S-11",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="192.168.2.99",
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
    )
    store.add_normalized_event(event)

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert "No telemetry events observed" in result.reason


# ── FT-12: Missing Entity Integrity Error ────────────────────────────────────

def test_ft_12_nonexistent_scenario_error(store, engine):
    """FT-12: Run references nonexistent scenario -> ERROR."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    run = TestRunV1(
        run_id="RUN-FT-12",
        scenario_id="SCN-NONEXISTENT",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-01",
        target_user="CORP\\test_user",
        window_start=t0,
        window_end=t0 + timedelta(minutes=10),
        executed_at=t0,
    )
    store._runs[run.run_id] = run

    result = engine.evaluate_run(run.run_id)
    assert result.predicted_category == DiagnosticCategory.ERROR
    assert "Scenario not found" in result.reason
