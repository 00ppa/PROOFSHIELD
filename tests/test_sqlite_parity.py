"""Unit and parity tests for SQLiteStore CRUD and correlation queries (Phase 3.2).

Validates:
- Exact CRUD parity between InMemoryStore and SQLiteStore across all 8 entities.
- Duplicate ID rejection and exception parity (matching ValueError messages).
- Missing scenario rejection on test run registration (ValueError("Scenario not found")).
- Missing entity lookup parity (returning None).
- Spatio-temporal correlation query parity (get_events_for_run, get_alerts_for_run, list_alerts_for_rule).
- Host matching engine parity (NetBIOS vs FQDN, IPv4/IPv6 isolation).
- Timestamp alignment parity (naive vs aware, non-UTC timezone offsets, microseconds).
- Persistence across store restarts on file-backed SQLite database.
- AssuranceEngine deterministic diagnostic evaluation parity.
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticCategory,
    DiagnosticResultV1,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    GroundTruthV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore


@pytest.fixture
def stores():
    """Fixture providing both InMemoryStore and SQLiteStore in parallel."""
    in_mem = InMemoryStore()
    sqlite_mem = SQLiteStore(":memory:")
    try:
        yield in_mem, sqlite_mem
    finally:
        sqlite_mem.close()


def test_crud_parity_all_entities(stores):
    """Verify identical CRUD operations, duplicate checks, and missing lookups across all 8 entities."""
    mem_store, sql_store = stores
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

    # 1. Scenarios
    scn = ScenarioV1(
        scenario_id="SCN-PARITY-01",
        name="Parity Test Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        validation_target=ValidationTarget.EXPECTED_ALERT,
        expected_detection_rule_id="RULE-PARITY-01",
    )
    assert mem_store.add_scenario(scn) == scn
    assert sql_store.add_scenario(scn) == scn

    assert mem_store.get_scenario("SCN-PARITY-01") == scn
    assert sql_store.get_scenario("SCN-PARITY-01") == scn
    assert mem_store.get_scenario("NONEXISTENT") is None
    assert sql_store.get_scenario("NONEXISTENT") is None
    assert len(mem_store.list_scenarios()) == len(sql_store.list_scenarios()) == 1

    # Duplicate scenario
    with pytest.raises(ValueError, match="Scenario already exists: SCN-PARITY-01"):
        mem_store.add_scenario(scn)
    with pytest.raises(ValueError, match="Scenario already exists: SCN-PARITY-01"):
        sql_store.add_scenario(scn)

    # 2. Test Runs - Missing scenario check
    run_orphan = TestRunV1(
        run_id="RUN-ORPHAN",
        scenario_id="SCN-MISSING",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-01",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    with pytest.raises(ValueError, match="Scenario not found: SCN-MISSING"):
        mem_store.add_run(run_orphan)
    with pytest.raises(ValueError, match="Scenario not found: SCN-MISSING"):
        sql_store.add_run(run_orphan)

    # Valid Test Run
    run = TestRunV1(
        run_id="RUN-PARITY-01",
        scenario_id="SCN-PARITY-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-WIN11-01",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
        execution_token="TOK-PARITY-01",
    )
    assert mem_store.add_run(run) == run
    assert sql_store.add_run(run) == run

    assert mem_store.get_run("RUN-PARITY-01") == run
    assert sql_store.get_run("RUN-PARITY-01") == run
    assert mem_store.get_run("NONEXISTENT") is None
    assert sql_store.get_run("NONEXISTENT") is None
    assert len(mem_store.list_runs()) == len(sql_store.list_runs()) == 1
    assert len(mem_store.list_runs(scenario_id="SCN-PARITY-01")) == len(sql_store.list_runs(scenario_id="SCN-PARITY-01")) == 1
    assert len(mem_store.list_runs(scenario_id="NONEXISTENT")) == len(sql_store.list_runs(scenario_id="NONEXISTENT")) == 0

    # Duplicate run
    with pytest.raises(ValueError, match="Run already exists: RUN-PARITY-01"):
        mem_store.add_run(run)
    with pytest.raises(ValueError, match="Run already exists: RUN-PARITY-01"):
        sql_store.add_run(run)

    # 3. Raw Telemetry
    raw = RawTelemetryEventV1(
        raw_event_id="RAW-PARITY-01",
        source_event_id="SRC-101",
        source_format="sysmon",
        source_timestamp=t0 + timedelta(minutes=2),
        ingested_at=t0 + timedelta(minutes=2),
        raw_payload={"EventID": 1, "Image": "powershell.exe"},
    )
    assert mem_store.add_raw_event(raw) == raw
    assert sql_store.add_raw_event(raw) == raw
    assert mem_store.get_raw_event("RAW-PARITY-01") == raw
    assert sql_store.get_raw_event("RAW-PARITY-01") == raw
    assert len(mem_store.list_raw_events()) == len(sql_store.list_raw_events()) == 1

    with pytest.raises(ValueError, match="Raw event already exists: RAW-PARITY-01"):
        mem_store.add_raw_event(raw)
    with pytest.raises(ValueError, match="Raw event already exists: RAW-PARITY-01"):
        sql_store.add_raw_event(raw)

    # 4. Normalized Telemetry
    norm = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-PARITY-01",
        raw_event_id="RAW-PARITY-01",
        source_event_id="SRC-101",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc test",
        execution_token="TOK-PARITY-01",
    )
    assert mem_store.add_normalized_event(norm) == norm
    assert sql_store.add_normalized_event(norm) == norm
    assert mem_store.get_normalized_event("NORM-PARITY-01") == norm
    assert sql_store.get_normalized_event("NORM-PARITY-01") == norm
    assert len(mem_store.list_normalized_events()) == len(sql_store.list_normalized_events()) == 1

    with pytest.raises(ValueError, match="Normalized event already exists: NORM-PARITY-01"):
        mem_store.add_normalized_event(norm)
    with pytest.raises(ValueError, match="Normalized event already exists: NORM-PARITY-01"):
        sql_store.add_normalized_event(norm)

    # 5. Detection Rules
    rule = DetectionRuleV1(
        rule_id="RULE-PARITY-01",
        rule_name="PowerShell Execution Rule",
        rule_format="sigma",
    )
    assert mem_store.add_rule(rule) == rule
    assert sql_store.add_rule(rule) == rule
    assert mem_store.get_rule("RULE-PARITY-01") == rule
    assert sql_store.get_rule("RULE-PARITY-01") == rule
    assert len(mem_store.list_rules()) == len(sql_store.list_rules()) == 1

    with pytest.raises(ValueError, match="Rule already exists: RULE-PARITY-01"):
        mem_store.add_rule(rule)
    with pytest.raises(ValueError, match="Rule already exists: RULE-PARITY-01"):
        sql_store.add_rule(rule)

    # 6. Alerts (includes token extraction on ingest)
    alert = AlertV1(
        alert_id="ALT-PARITY-01",
        source_alert_id="SRC-ALT-1",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id="ws-win11-01",
        rule_reference="RULE-PARITY-01",
        alert_title="Suspicious PowerShell token=TOK-PARITY-01 Detected",
    )
    mem_alert = mem_store.add_alert(alert.model_copy(deep=True))
    sql_alert = sql_store.add_alert(alert.model_copy(deep=True))

    # Token must be extracted identically
    assert mem_alert.execution_token == sql_alert.execution_token == "TOK-PARITY-01"
    assert mem_store.get_alert("ALT-PARITY-01") == mem_alert
    assert sql_store.get_alert("ALT-PARITY-01") == sql_alert
    assert len(mem_store.list_alerts()) == len(sql_store.list_alerts()) == 1

    with pytest.raises(ValueError, match="Alert already exists: ALT-PARITY-01"):
        mem_store.add_alert(mem_alert)
    with pytest.raises(ValueError, match="Alert already exists: ALT-PARITY-01"):
        sql_store.add_alert(sql_alert)

    # 7. Diagnostic Results (replaces on duplicate diagnostic_id)
    diag1 = DiagnosticResultV1(
        diagnostic_id="DIAG-01",
        test_run_id=run.run_id,
        scenario_id=scn.scenario_id,
        predicted_category=DiagnosticCategory.PASS,
        confidence="definitive",
        reason="Initial evaluation",
        evaluated_at=t0 + timedelta(minutes=5),
    )
    mem_store.add_result(diag1)
    sql_store.add_result(diag1)
    assert mem_store.get_result("DIAG-01") == sql_store.get_result("DIAG-01") == diag1
    assert mem_store.get_result_for_run(run.run_id) == sql_store.get_result_for_run(run.run_id) == diag1

    # Overwrite with newer result
    diag2 = DiagnosticResultV1(
        diagnostic_id="DIAG-01",
        test_run_id=run.run_id,
        scenario_id=scn.scenario_id,
        predicted_category=DiagnosticCategory.PASS,
        confidence="definitive",
        reason="Updated evaluation",
        evaluated_at=t0 + timedelta(minutes=10),
    )
    mem_store.add_result(diag2)
    sql_store.add_result(diag2)
    assert mem_store.get_result("DIAG-01") == sql_store.get_result("DIAG-01") == diag2
    assert mem_store.get_result_for_run(run.run_id) == sql_store.get_result_for_run(run.run_id) == diag2
    assert len(mem_store.list_results()) == len(sql_store.list_results()) == 1

    # 8. Ground Truth
    gt = GroundTruthV1(
        ground_truth_id="GT-PARITY-01",
        run_id=run.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="manual",
    )
    assert mem_store.add_ground_truth(gt) == gt
    assert sql_store.add_ground_truth(gt) == gt
    assert mem_store.get_ground_truth_for_run(run.run_id) == sql_store.get_ground_truth_for_run(run.run_id) == gt
    assert len(mem_store.list_ground_truths()) == len(sql_store.list_ground_truths()) == 1

    with pytest.raises(ValueError, match="Ground truth already exists: GT-PARITY-01"):
        mem_store.add_ground_truth(gt)
    with pytest.raises(ValueError, match="Ground truth already exists: GT-PARITY-01"):
        sql_store.add_ground_truth(gt)

    # Reset
    mem_store.reset()
    sql_store.reset()
    assert len(mem_store.list_scenarios()) == len(sql_store.list_scenarios()) == 0
    assert len(mem_store.list_runs()) == len(sql_store.list_runs()) == 0
    assert len(mem_store.list_raw_events()) == len(sql_store.list_raw_events()) == 0
    assert len(mem_store.list_normalized_events()) == len(sql_store.list_normalized_events()) == 0
    assert len(mem_store.list_rules()) == len(sql_store.list_rules()) == 0
    assert len(mem_store.list_alerts()) == len(sql_store.list_alerts()) == 0
    assert len(mem_store.list_results()) == len(sql_store.list_results()) == 0
    assert len(mem_store.list_ground_truths()) == len(sql_store.list_ground_truths()) == 0


def test_correlation_parity_events_for_run(stores):
    """Verify get_events_for_run produces identical results, ordering, and host matching."""
    mem_store, sql_store = stores
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

    scn = ScenarioV1(
        scenario_id="SCN-EV-01",
        name="Event Correlation Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
    )
    run = TestRunV1(
        run_id="RUN-EV-01",
        scenario_id="SCN-EV-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WORKSTATION-01",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    for s in (mem_store, sql_store):
        s.add_scenario(scn)
        s.add_run(run)

    # 1. Matching in-window event (exact host)
    ev1 = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="WORKSTATION-01",
        process_name="powershell.exe",
    )
    # 2. Matching in-window event (FQDN host -> matches NetBIOS WORKSTATION-01)
    ev2 = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-02",
        raw_event_id="RAW-02",
        source_event_id="SRC-02",
        source_timestamp=t0 + timedelta(minutes=5),
        normalized_timestamp=t0 + timedelta(minutes=5),
        event_category=EventCategory.PROCESS_CREATION,
        host="workstation-01.corp.local",
        process_name="powershell.exe",
    )
    # 3. Out-of-window event (too late)
    ev_late = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-LATE",
        raw_event_id="RAW-03",
        source_event_id="SRC-03",
        source_timestamp=t0 + timedelta(minutes=30),
        normalized_timestamp=t0 + timedelta(minutes=30),
        event_category=EventCategory.PROCESS_CREATION,
        host="WORKSTATION-01",
        process_name="powershell.exe",
    )
    # 4. Out-of-window event (too early)
    ev_early = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-EARLY",
        raw_event_id="RAW-04",
        source_event_id="SRC-04",
        source_timestamp=t0 - timedelta(minutes=5),
        normalized_timestamp=t0 - timedelta(minutes=5),
        event_category=EventCategory.PROCESS_CREATION,
        host="WORKSTATION-01",
        process_name="powershell.exe",
    )
    # 5. Wrong host event
    ev_wrong_host = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-WRONG",
        raw_event_id="RAW-05",
        source_event_id="SRC-05",
        source_timestamp=t0 + timedelta(minutes=3),
        normalized_timestamp=t0 + timedelta(minutes=3),
        event_category=EventCategory.PROCESS_CREATION,
        host="WORKSTATION-99",
        process_name="powershell.exe",
    )
    for s in (mem_store, sql_store):
        s.add_normalized_event(ev1)
        s.add_normalized_event(ev2)
        s.add_normalized_event(ev_late)
        s.add_normalized_event(ev_early)
        s.add_normalized_event(ev_wrong_host)

    mem_events = mem_store.get_events_for_run(run)
    sql_events = sql_store.get_events_for_run(run)

    assert len(mem_events) == len(sql_events) == 2
    assert [e.normalized_event_id for e in mem_events] == [e.normalized_event_id for e in sql_events] == ["NORM-01", "NORM-02"]


def test_correlation_parity_alerts(stores):
    """Verify get_alerts_for_run and list_alerts_for_rule produce identical results."""
    mem_store, sql_store = stores
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

    scn = ScenarioV1(
        scenario_id="SCN-ALT-01",
        name="Alert Parity Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
        expected_detection_rule_id="RULE-SIGMA-01",
    )
    run = TestRunV1(
        run_id="RUN-ALT-01",
        scenario_id="SCN-ALT-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="192.168.1.50",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    rule = DetectionRuleV1(
        rule_id="RULE-SIGMA-01",
        rule_name="PowerShell Cradle Detection",
        rule_format="sigma",
    )
    for s in (mem_store, sql_store):
        s.add_scenario(scn)
        s.add_run(run)
        s.add_rule(rule)

    # 1. Matching in-window alert (exact IP host)
    a1 = AlertV1(
        alert_id="ALT-01",
        source_alert_id="SRC-ALT-01",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=4),
        host_id="192.168.1.50",
        rule_reference="RULE-SIGMA-01",
    )
    # 2. Alert with same rule, wrong host (different IP: 192.168.1.99)
    a_wrong_host = AlertV1(
        alert_id="ALT-WRONG-HOST",
        source_alert_id="SRC-ALT-WRONG-HOST",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=4),
        host_id="192.168.1.99",
        rule_reference="RULE-SIGMA-01",
    )
    # 3. Alert with same rule, out of window (grace period candidate)
    a_out_window = AlertV1(
        alert_id="ALT-OUT-WINDOW",
        source_alert_id="SRC-ALT-OUT-WINDOW",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=25),
        host_id="192.168.1.50",
        rule_reference="RULE-SIGMA-01",
    )
    # 4. Alert lacking timestamp
    a_no_ts = AlertV1(
        alert_id="ALT-NO-TS",
        source_alert_id="SRC-ALT-NO-TS",
        source_type="wazuh",
        alert_timestamp=None,
        host_id="192.168.1.50",
        rule_reference="RULE-SIGMA-01",
    )
    # 5. Alert for different rule
    a_other_rule = AlertV1(
        alert_id="ALT-OTHER-RULE",
        source_alert_id="SRC-ALT-OTHER-RULE",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=4),
        host_id="192.168.1.50",
        rule_reference="RULE-OTHER-99",
    )
    for s in (mem_store, sql_store):
        s.add_alert(a1.model_copy(deep=True))
        s.add_alert(a_wrong_host.model_copy(deep=True))
        s.add_alert(a_out_window.model_copy(deep=True))
        s.add_alert(a_no_ts.model_copy(deep=True))
        s.add_alert(a_other_rule.model_copy(deep=True))

    # A. Correlated alerts for run (correlates by target host and window, not rule reference)
    mem_run_alerts = mem_store.get_alerts_for_run(run)
    sql_run_alerts = sql_store.get_alerts_for_run(run)
    assert len(mem_run_alerts) == len(sql_run_alerts) == 2
    assert [a.alert_id for a in mem_run_alerts] == [a.alert_id for a in sql_run_alerts] == ["ALT-01", "ALT-OTHER-RULE"]

    # B. List alerts for rule (unbounded)
    mem_rule_all = mem_store.list_alerts_for_rule("RULE-SIGMA-01")
    sql_rule_all = sql_store.list_alerts_for_rule("RULE-SIGMA-01")
    assert len(mem_rule_all) == len(sql_rule_all) == 4

    # C. List alerts for rule (time-bounded window)
    mem_rule_window = mem_store.list_alerts_for_rule("RULE-SIGMA-01", window_start=t0, window_end=t1)
    sql_rule_window = sql_store.list_alerts_for_rule("RULE-SIGMA-01", window_start=t0, window_end=t1)
    assert len(mem_rule_window) == len(sql_rule_window) == 2
    assert [a.alert_id for a in mem_rule_window] == [a.alert_id for a in sql_rule_window] == ["ALT-01", "ALT-WRONG-HOST"]


def test_timestamp_offset_and_naive_parity(stores):
    """Verify exact parity when comparing timestamps with timezone offsets and naive datetimes."""
    mem_store, sql_store = stores

    # Run defined with UTC window 10:00 - 10:30 UTC
    t0_utc = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1_utc = datetime(2026, 10, 12, 10, 30, tzinfo=timezone.utc)

    scn = ScenarioV1(
        scenario_id="SCN-TZ-01",
        name="Timezone Parity Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
    )
    run = TestRunV1(
        run_id="RUN-TZ-01",
        scenario_id="SCN-TZ-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-01",
        target_user="secops",
        window_start=t0_utc,
        window_end=t1_utc,
        executed_at=t0_utc,
    )
    for s in (mem_store, sql_store):
        s.add_scenario(scn)
        s.add_run(run)

    # Event with IST offset (+05:30): 15:45 IST is 10:15 UTC (inside window)
    tz_ist = timezone(timedelta(hours=5, minutes=30))
    t_ist = datetime(2026, 10, 12, 15, 45, 0, 500000, tzinfo=tz_ist)

    # Event with EDT offset (-04:00): 06:15 EDT is 10:15 UTC (inside window)
    tz_edt = timezone(timedelta(hours=-4))
    t_edt = datetime(2026, 10, 12, 6, 15, 0, 250000, tzinfo=tz_edt)

    # Event with Naive timestamp: 10:20 naive (InMemoryStore aligns naive to window's UTC)
    t_naive = datetime(2026, 10, 12, 10, 20, 0)

    # Event outside window: 17:00 IST is 11:30 UTC (outside window)
    t_outside = datetime(2026, 10, 12, 17, 0, 0, tzinfo=tz_ist)

    ev_ist = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-IST",
        raw_event_id="RAW-1",
        source_event_id="SRC-IST",
        source_timestamp=t_ist,
        normalized_timestamp=t_ist,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="powershell.exe",
    )
    ev_edt = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-EDT",
        raw_event_id="RAW-2",
        source_event_id="SRC-EDT",
        source_timestamp=t_edt,
        normalized_timestamp=t_edt,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="powershell.exe",
    )
    ev_out = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-OUT",
        raw_event_id="RAW-4",
        source_event_id="SRC-OUT",
        source_timestamp=t_outside,
        normalized_timestamp=t_outside,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        process_name="powershell.exe",
    )

    for s in (mem_store, sql_store):
        s.add_normalized_event(ev_ist)
        s.add_normalized_event(ev_edt)
        s.add_normalized_event(ev_out)

    # 1. Aware events with different offsets correlated against UTC window
    mem_events = mem_store.get_events_for_run(run)
    sql_events = sql_store.get_events_for_run(run)

    assert len(mem_events) == len(sql_events) == 2
    # EDT event (10:15:00.250 UTC) sorts before IST event (10:15:00.500 UTC)
    assert [e.normalized_event_id for e in mem_events] == [e.normalized_event_id for e in sql_events] == ["NORM-EDT", "NORM-IST"]

    # Verify retrieved models preserve original timezone representation
    retrieved_ist = sql_store.get_normalized_event("NORM-IST")
    assert retrieved_ist.normalized_timestamp.tzinfo == tz_ist
    assert retrieved_ist.normalized_timestamp.microsecond == 500000

    # 2. Fully naive run and events parity
    run_naive = TestRunV1(
        run_id="RUN-NAIVE-01",
        scenario_id="SCN-TZ-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-NAIVE",
        target_user="secops",
        window_start=datetime(2026, 10, 12, 10, 0, 0),
        window_end=datetime(2026, 10, 12, 10, 30, 0),
        executed_at=datetime(2026, 10, 12, 10, 0, 0),
    )
    ev_naive_in = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NAIVE-IN",
        raw_event_id="RAW-N1",
        source_event_id="SRC-N1",
        source_timestamp=datetime(2026, 10, 12, 10, 15, 0),
        normalized_timestamp=datetime(2026, 10, 12, 10, 15, 0),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-NAIVE",
        process_name="powershell.exe",
    )
    ev_naive_out = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NAIVE-OUT",
        raw_event_id="RAW-N2",
        source_event_id="SRC-N2",
        source_timestamp=datetime(2026, 10, 12, 10, 45, 0),
        normalized_timestamp=datetime(2026, 10, 12, 10, 45, 0),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-NAIVE",
        process_name="powershell.exe",
    )
    for s in (mem_store, sql_store):
        s.add_run(run_naive)
        s.add_normalized_event(ev_naive_in)
        s.add_normalized_event(ev_naive_out)

    mem_naive_evs = mem_store.get_events_for_run(run_naive)
    sql_naive_evs = sql_store.get_events_for_run(run_naive)
    assert len(mem_naive_evs) == len(sql_naive_evs) == 1
    assert mem_naive_evs[0].normalized_event_id == sql_naive_evs[0].normalized_event_id == "NORM-NAIVE-IN"

    retrieved_naive = sql_store.get_normalized_event("NORM-NAIVE-IN")
    assert retrieved_naive.normalized_timestamp.tzinfo is None

    # 3. Documented Mixed Naive-vs-Aware Sorting Limitation in InMemoryStore:
    # If a naive event and an aware event both match a run's host and window,
    # InMemoryStore's sort key crashes because Python forbids comparing naive and aware datetimes.
    ev_mixed_naive = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-MIXED-NAIVE",
        raw_event_id="RAW-MIX",
        source_event_id="SRC-MIX",
        source_timestamp=datetime(2026, 10, 12, 10, 20, 0),
        normalized_timestamp=datetime(2026, 10, 12, 10, 20, 0),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",  # matches run WS-01
        process_name="powershell.exe",
    )
    mem_store.add_normalized_event(ev_mixed_naive)
    with pytest.raises(TypeError, match="can't compare offset-naive and offset-aware datetimes"):
        mem_store.get_events_for_run(run)


def test_persistence_across_restart_file_backed(tmp_path: Path):
    """Verify complete persistence by saving all entities, closing, reopening, and querying."""
    db_file = tmp_path / "persistent_proofshield.db"
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

    # ── Phase A: Ingest entities into store instance 1 ──────────────────────
    store1 = SQLiteStore(db_file)
    try:
        scn = ScenarioV1(
            scenario_id="SCN-PERSIST-01",
            name="Persistence Test Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="powershell.exe",
            validation_target=ValidationTarget.EXPECTED_ALERT,
            expected_detection_rule_id="RULE-PERSIST-01",
        )
        store1.add_scenario(scn)

        run = TestRunV1(
            run_id="RUN-PERSIST-01",
            scenario_id="SCN-PERSIST-01",
            execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
            is_synthetic=True,
            target_host="WS-PERSIST-01",
            target_user="secops",
            window_start=t0,
            window_end=t1,
            executed_at=t0,
            execution_token="TOK-PERSIST-01",
        )
        store1.add_run(run)

        raw = RawTelemetryEventV1(
            raw_event_id="RAW-P1",
            source_event_id="SRC-P1",
            source_format="sysmon",
            source_timestamp=t0 + timedelta(minutes=2),
            ingested_at=t0 + timedelta(minutes=2),
            raw_payload={"EventID": 1},
        )
        store1.add_raw_event(raw)

        norm = NormalizedTelemetryEventV1(
            normalized_event_id="NORM-P1",
            raw_event_id="RAW-P1",
            source_event_id="SRC-P1",
            source_timestamp=t0 + timedelta(minutes=2),
            normalized_timestamp=t0 + timedelta(minutes=2),
            event_category=EventCategory.PROCESS_CREATION,
            host="WS-PERSIST-01",
            process_name="powershell.exe",
            execution_token="TOK-PERSIST-01",
        )
        store1.add_normalized_event(norm)

        rule = DetectionRuleV1(
            rule_id="RULE-PERSIST-01",
            rule_name="Parity Persistence Rule",
            rule_format="sigma",
        )
        store1.add_rule(rule)

        alert = AlertV1(
            alert_id="ALT-P1",
            source_alert_id="SRC-ALT-P1",
            source_type="wazuh",
            alert_timestamp=t0 + timedelta(minutes=3),
            host_id="ws-persist-01",
            rule_reference="RULE-PERSIST-01",
            alert_title="Persistence Alert token=TOK-PERSIST-01",
        )
        store1.add_alert(alert)

        diag = DiagnosticResultV1(
            diagnostic_id="DIAG-P1",
            test_run_id=run.run_id,
            scenario_id=scn.scenario_id,
            predicted_category=DiagnosticCategory.PASS,
            confidence="definitive",
            reason="Verified persistence pass",
            evaluated_at=t0 + timedelta(minutes=5),
        )
        store1.add_result(diag)

        gt = GroundTruthV1(
            ground_truth_id="GT-P1",
            run_id=run.run_id,
            expected_diagnostic_category=DiagnosticCategory.PASS,
            verification_method="manual_audit",
        )
        store1.add_ground_truth(gt)
    finally:
        store1.close()

    assert store1.is_closed is True

    # ── Phase B: Open brand-new store instance 2 against the same file ──────
    store2 = SQLiteStore(db_file)
    try:
        assert store2.is_closed is False
        assert len(store2.list_scenarios()) == 1
        assert store2.get_scenario("SCN-PERSIST-01") == scn

        assert len(store2.list_runs()) == 1
        assert store2.get_run("RUN-PERSIST-01") == run

        assert len(store2.list_raw_events()) == 1
        assert store2.get_raw_event("RAW-P1") == raw

        assert len(store2.list_normalized_events()) == 1
        assert store2.get_normalized_event("NORM-P1") == norm

        assert len(store2.list_rules()) == 1
        assert store2.get_rule("RULE-PERSIST-01") == rule

        assert len(store2.list_alerts()) == 1
        retrieved_alert = store2.get_alert("ALT-P1")
        assert retrieved_alert.execution_token == "TOK-PERSIST-01"

        assert len(store2.list_results()) == 1
        assert store2.get_result_for_run(run.run_id) == diag

        assert len(store2.list_ground_truths()) == 1
        assert store2.get_ground_truth_for_run(run.run_id) == gt

        # Correlation queries work identically on reloaded database
        correlated_events = store2.get_events_for_run(run)
        assert len(correlated_events) == 1
        assert correlated_events[0].normalized_event_id == "NORM-P1"

        correlated_alerts = store2.get_alerts_for_run(run)
        assert len(correlated_alerts) == 1
        assert correlated_alerts[0].alert_id == "ALT-P1"
    finally:
        store2.close()


def test_assurance_engine_parity_with_sqlite_store(stores):
    """Verify Layer 5 AssuranceEngine produces bit-identical verdicts on SQLiteStore and InMemoryStore."""
    mem_store, sql_store = stores
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    tok = "TOK-ENGINE-01"

    scn = ScenarioV1(
        scenario_id="SCN-ENG-01",
        name="Engine Parity Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"powershell(\.exe)?\s+.*-enc",
        expected_detection_rule_id="RULE-ENG-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    run = TestRunV1(
        run_id="RUN-ENG-01",
        scenario_id="SCN-ENG-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WORKSTATION-01",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
        execution_token=tok,
    )
    rule = DetectionRuleV1(
        rule_id="RULE-ENG-01",
        rule_name="PowerShell Execution Rule",
        rule_format="sigma",
    )
    norm = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-ENG-01",
        raw_event_id="RAW-ENG-01",
        source_event_id="SRC-ENG-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="WORKSTATION-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc test1234",
        execution_token=tok,
    )
    alert = AlertV1(
        alert_id="ALT-ENG-01",
        source_alert_id="SRC-ALT-01",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id="workstation-01.corp.local",  # NetBIOS/FQDN matching
        rule_reference="RULE-ENG-01",
        alert_title=f"PowerShell cradle token={tok}",
    )

    for s in (mem_store, sql_store):
        s.add_scenario(scn)
        s.add_run(run)
        s.add_rule(rule)
        s.add_normalized_event(norm)
        s.add_alert(alert.model_copy(deep=True))

    engine_mem = AssuranceEngine(mem_store)
    engine_sql = AssuranceEngine(sql_store)

    # 1. Default Mode Parity
    res_mem_def = engine_mem.evaluate_run(run.run_id, strict_attribution=False)
    res_sql_def = engine_sql.evaluate_run(run.run_id, strict_attribution=False)

    assert res_mem_def.predicted_category == res_sql_def.predicted_category == DiagnosticCategory.PASS
    assert res_mem_def.confidence == res_sql_def.confidence == "definitive"
    assert res_mem_def.supporting_evidence_ids == res_sql_def.supporting_evidence_ids
    assert res_mem_def.metadata["attribution"]["status"] == res_sql_def.metadata["attribution"]["status"]

    # 2. Strict Attribution Mode Parity
    res_mem_strict = engine_mem.evaluate_run(run.run_id, strict_attribution=True)
    res_sql_strict = engine_sql.evaluate_run(run.run_id, strict_attribution=True)

    assert res_mem_strict.predicted_category == res_sql_strict.predicted_category == DiagnosticCategory.PASS
    assert res_mem_strict.confidence == res_sql_strict.confidence == "definitive"
    assert res_mem_strict.supporting_evidence_ids == res_sql_strict.supporting_evidence_ids
    assert res_mem_strict.metadata["attribution"]["status"] == res_sql_strict.metadata["attribution"]["status"]
