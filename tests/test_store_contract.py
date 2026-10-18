"""Contract and integration hardening tests for PROOFSHIELD storage backends.

Runs identical contract validation tests across InMemoryStore and SQLiteStore (both
in-memory and file-backed), verifying:
1. Every StoreProtocol method: signatures, return types, ordering, duplicate handling,
   replacement behavior, missing entity behavior, and reset semantics.
2. Transaction atomicity: multi-step rollback, nested savepoint isolation, outer failure rollback.
3. Correlation queries: inclusive/exclusive time boundaries, microseconds, multiple timezone
   offsets, hostname aliases, NetBIOS/FQDN matching, and IPv4/IPv6 address normalization.
4. Lifecycle, idempotent close, repeated initialization, and file-backed database reopening.
5. Index efficiency verification using EXPLAIN QUERY PLAN.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Generator, Tuple
import pytest

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.common import (
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    ValidationTarget,
)
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1, RawTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.base_store import StoreProtocol
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore


@pytest.fixture(params=["in_memory", "sqlite_memory", "sqlite_file"])
def store(request, tmp_path: Path) -> Generator[StoreProtocol, None, None]:
    """Yield each storage backend configured under identical test conditions."""
    if request.param == "in_memory":
        s = InMemoryStore()
        yield s
        s.reset()
    elif request.param == "sqlite_memory":
        s = SQLiteStore(":memory:")
        yield s
        s.close()
    elif request.param == "sqlite_file":
        db_file = tmp_path / "contract_test.db"
        s = SQLiteStore(db_file)
        yield s
        s.close()


# ── 1. Comprehensive CRUD Contract Tests ─────────────────────────────────────


def test_contract_scenario_crud(store: StoreProtocol):
    """Test scenario registration, retrieval, listing, duplicate rejection, and not-found behavior."""
    scn = ScenarioV1(
        scenario_id="SCN-CONTRACT-01",
        name="Contract Scenario 1",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        validation_target=ValidationTarget.EXPECTED_ALERT,
        expected_detection_rule_id="RULE-SIGMA-01",
        max_acceptable_latency_seconds=120,
    )
    # Registration returns identical model
    assert store.add_scenario(scn) == scn

    # Retrieval
    assert store.get_scenario("SCN-CONTRACT-01") == scn
    assert store.get_scenario("NONEXISTENT") is None

    # Listing
    scenarios = store.list_scenarios()
    assert len(scenarios) == 1
    assert scenarios[0] == scn

    # Duplicate rejection
    with pytest.raises(ValueError, match="Scenario already exists: SCN-CONTRACT-01"):
        store.add_scenario(scn)


def test_contract_test_run_crud(store: StoreProtocol):
    """Test test run creation, foreign-key dependency on scenario, duplicate rejection, and filtering."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

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
    # Missing scenario rejection
    with pytest.raises(ValueError, match="Scenario not found: SCN-MISSING"):
        store.add_run(run_orphan)

    # Valid parent scenario
    scn = ScenarioV1(
        scenario_id="SCN-PARENT-01",
        name="Parent Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scn)

    run1 = TestRunV1(
        run_id="RUN-01",
        scenario_id="SCN-PARENT-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-01",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_token="TOK-01",
    )
    run2 = TestRunV1(
        run_id="RUN-02",
        scenario_id="SCN-PARENT-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-02",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_token="TOK-02",
    )
    assert store.add_run(run1) == run1
    assert store.add_run(run2) == run2

    # Retrieval
    assert store.get_run("RUN-01") == run1
    assert store.get_run("NONEXISTENT") is None

    # Listing and scenario filtering
    assert len(store.list_runs()) == 2
    assert len(store.list_runs(scenario_id="SCN-PARENT-01")) == 2
    assert len(store.list_runs(scenario_id="NONEXISTENT")) == 0

    # Duplicate rejection
    with pytest.raises(ValueError, match="Run already exists: RUN-01"):
        store.add_run(run1)


def test_contract_raw_and_normalized_events(store: StoreProtocol):
    """Test raw and normalized telemetry storage, retrieval, listing, and duplicate rejection."""
    t0 = datetime(2026, 10, 12, 10, 2, tzinfo=timezone.utc)

    raw = RawTelemetryEventV1(
        raw_event_id="RAW-001",
        source_event_id="SRC-SYS-01",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={"EventID": 1, "Image": "powershell.exe"},
    )
    assert store.add_raw_event(raw) == raw
    assert store.get_raw_event("RAW-001") == raw
    assert store.get_raw_event("NONEXISTENT") is None
    assert len(store.list_raw_events()) == 1

    with pytest.raises(ValueError, match="Raw event already exists: RAW-001"):
        store.add_raw_event(raw)

    norm = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-001",
        raw_event_id="RAW-001",
        source_event_id="SRC-SYS-01",
        source_timestamp=t0,
        normalized_timestamp=t0,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc dGVzdA==",
        execution_token="TOK-CONTRACT-01",
    )
    assert store.add_normalized_event(norm) == norm
    assert store.get_normalized_event("NORM-001") == norm
    assert store.get_normalized_event("NONEXISTENT") is None
    assert len(store.list_normalized_events()) == 1

    with pytest.raises(ValueError, match="Normalized event already exists: NORM-001"):
        store.add_normalized_event(norm)


def test_contract_detection_rules_and_alerts(store: StoreProtocol):
    """Test detection rules and alert CRUD, token extraction on ingest, and metadata population."""
    rule = DetectionRuleV1(
        rule_id="RULE-CONTRACT-01",
        rule_name="Encoded PowerShell Execution",
        rule_format="sigma",
    )
    assert store.add_rule(rule) == rule
    assert store.get_rule("RULE-CONTRACT-01") == rule
    assert store.get_rule("NONEXISTENT") is None
    assert len(store.list_rules()) == 1

    with pytest.raises(ValueError, match="Rule already exists: RULE-CONTRACT-01"):
        store.add_rule(rule)

    t0 = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    # Alert with explicit token in alert title and missing ingested_at
    alert = AlertV1(
        alert_id="ALT-CONTRACT-01",
        source_alert_id="SRC-ALT-01",
        source_type="wazuh",
        alert_timestamp=t0,
        host_id="ws-win11-01.corp.local",
        rule_reference="RULE-CONTRACT-01",
        alert_title="Encoded PowerShell Detected token=TOK-CONTRACT-01",
    )
    saved_alert = store.add_alert(alert)

    # Ingested_at must be populated automatically
    assert saved_alert.ingested_at is not None
    # Token must be extracted automatically
    assert saved_alert.execution_token == "TOK-CONTRACT-01"

    assert store.get_alert("ALT-CONTRACT-01") == saved_alert
    assert store.get_alert("NONEXISTENT") is None
    assert len(store.list_alerts()) == 1

    # Alert lacking timestamp gets ingestion_time_only flag
    alert_no_ts = AlertV1(
        alert_id="ALT-NO-TS",
        source_alert_id="SRC-ALT-02",
        source_type="wazuh",
        alert_timestamp=None,
        host_id="ws-win11-01.corp.local",
        rule_reference="RULE-CONTRACT-01",
    )
    saved_no_ts = store.add_alert(alert_no_ts)
    assert saved_no_ts.metadata.get("ingestion_time_only") is True

    with pytest.raises(ValueError, match="Alert already exists: ALT-CONTRACT-01"):
        store.add_alert(alert)


def test_contract_diagnostic_results_replacement_and_ordering(store: StoreProtocol):
    """Test diagnostic result overwrite semantics and most-recent retrieval for test runs."""
    t0 = datetime(2026, 10, 12, 10, 10, tzinfo=timezone.utc)

    # Result 1 for RUN-01
    res1 = DiagnosticResultV1(
        diagnostic_id="DIAG-01",
        test_run_id="RUN-01",
        scenario_id="SCN-01",
        predicted_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        confidence="likely",
        reason="Initial evaluation before logs arrived",
        evaluated_at=t0,
    )
    store.add_result(res1)
    assert store.get_result("DIAG-01") == res1
    assert store.get_result_for_run("RUN-01") == res1
    assert len(store.list_results()) == 1

    # Overwrite result with same diagnostic_id
    res1_updated = DiagnosticResultV1(
        diagnostic_id="DIAG-01",
        test_run_id="RUN-01",
        scenario_id="SCN-01",
        predicted_category=DiagnosticCategory.PASS,
        confidence="definitive",
        reason="Telemetry verified on re-check",
        evaluated_at=t0 + timedelta(minutes=2),
    )
    store.add_result(res1_updated)
    assert store.get_result("DIAG-01") == res1_updated
    assert store.get_result_for_run("RUN-01") == res1_updated
    assert len(store.list_results()) == 1

    # New result for same test run with different diagnostic_id
    res2 = DiagnosticResultV1(
        diagnostic_id="DIAG-02",
        test_run_id="RUN-01",
        scenario_id="SCN-01",
        predicted_category=DiagnosticCategory.PASS,
        confidence="definitive",
        reason="Third evaluation",
        evaluated_at=t0 + timedelta(minutes=5),
    )
    store.add_result(res2)
    assert len(store.list_results()) == 2
    # get_result_for_run must return the most recent result (DIAG-02)
    assert store.get_result_for_run("RUN-01") == res2
    assert store.get_result_for_run("NONEXISTENT") is None


def test_contract_ground_truth_crud(store: StoreProtocol):
    """Test ground truth record creation, lookup by run_id, and duplicate rejection."""
    gt = GroundTruthV1(
        ground_truth_id="GT-001",
        run_id="RUN-01",
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="manual_analyst_review",
    )
    assert store.add_ground_truth(gt) == gt
    assert store.get_ground_truth_for_run("RUN-01") == gt
    assert store.get_ground_truth_for_run("NONEXISTENT") is None
    assert len(store.list_ground_truths()) == 1

    with pytest.raises(ValueError, match="Ground truth already exists: GT-001"):
        store.add_ground_truth(gt)


def test_contract_reset_semantics(store: StoreProtocol):
    """Verify reset() empties all 8 collections and leaves backend ready for re-population."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

    scn = ScenarioV1(
        scenario_id="SCN-R",
        name="Reset Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    run = TestRunV1(
        run_id="RUN-R",
        scenario_id="SCN-R",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-01",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    store.add_scenario(scn)
    store.add_run(run)
    assert len(store.list_scenarios()) == 1
    assert len(store.list_runs()) == 1

    store.reset()

    assert len(store.list_scenarios()) == 0
    assert len(store.list_runs()) == 0
    assert len(store.list_raw_events()) == 0
    assert len(store.list_normalized_events()) == 0
    assert len(store.list_rules()) == 0
    assert len(store.list_alerts()) == 0
    assert len(store.list_results()) == 0
    assert len(store.list_ground_truths()) == 0

    # Re-inserting with same IDs must succeed without duplicate error
    store.add_scenario(scn)
    assert len(store.list_scenarios()) == 1


# ── 2. Correlation Boundary & Edge-Case Contract Tests ───────────────────────


def test_contract_correlation_time_boundaries(store: StoreProtocol):
    """Verify inclusive/exclusive time boundaries at sub-microsecond precision.

    Run window: [10:00:00.000000, 10:15:00.000000]
    - Boundary 1: 10:00:00.000000 UTC -> INCLUDED (inclusive start)
    - Boundary 2: 10:15:00.000000 UTC -> INCLUDED (inclusive end)
    - Boundary 3: 09:59:59.999999 UTC -> EXCLUDED (pre-window)
    - Boundary 4: 10:15:00.000001 UTC -> EXCLUDED (post-window)
    """
    t_start = datetime(2026, 10, 12, 10, 0, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 12, 10, 15, 0, 0, tzinfo=timezone.utc)

    scn = ScenarioV1(
        scenario_id="SCN-BOUNDARIES",
        name="Boundary Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    run = TestRunV1(
        run_id="RUN-BOUNDARIES",
        scenario_id="SCN-BOUNDARIES",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-BOUND",
        target_user="secops",
        window_start=t_start,
        window_end=t_end,
        executed_at=t_start,
    )
    store.add_scenario(scn)
    store.add_run(run)

    # 4 Telemetry Events
    e_start = NormalizedTelemetryEventV1(
        normalized_event_id="EV-START",
        raw_event_id="R-1",
        source_event_id="S-1",
        source_timestamp=t_start,
        normalized_timestamp=t_start,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-BOUND",
        process_name="powershell.exe",
    )
    e_end = NormalizedTelemetryEventV1(
        normalized_event_id="EV-END",
        raw_event_id="R-2",
        source_event_id="S-2",
        source_timestamp=t_end,
        normalized_timestamp=t_end,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-BOUND",
        process_name="powershell.exe",
    )
    e_pre = NormalizedTelemetryEventV1(
        normalized_event_id="EV-PRE",
        raw_event_id="R-3",
        source_event_id="S-3",
        source_timestamp=t_start - timedelta(microseconds=1),
        normalized_timestamp=t_start - timedelta(microseconds=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-BOUND",
        process_name="powershell.exe",
    )
    e_post = NormalizedTelemetryEventV1(
        normalized_event_id="EV-POST",
        raw_event_id="R-4",
        source_event_id="S-4",
        source_timestamp=t_end + timedelta(microseconds=1),
        normalized_timestamp=t_end + timedelta(microseconds=1),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-BOUND",
        process_name="powershell.exe",
    )

    for e in (e_start, e_end, e_pre, e_post):
        store.add_normalized_event(e)

    events = store.get_events_for_run(run)
    assert len(events) == 2
    assert [e.normalized_event_id for e in events] == ["EV-START", "EV-END"]

    # 4 Alerts
    a_start = AlertV1(
        alert_id="ALT-START",
        source_alert_id="SA-1",
        source_type="wazuh",
        alert_timestamp=t_start,
        host_id="WS-BOUND",
        rule_reference="RULE-01",
    )
    a_end = AlertV1(
        alert_id="ALT-END",
        source_alert_id="SA-2",
        source_type="wazuh",
        alert_timestamp=t_end,
        host_id="WS-BOUND",
        rule_reference="RULE-01",
    )
    a_pre = AlertV1(
        alert_id="ALT-PRE",
        source_alert_id="SA-3",
        source_type="wazuh",
        alert_timestamp=t_start - timedelta(microseconds=1),
        host_id="WS-BOUND",
        rule_reference="RULE-01",
    )
    a_post = AlertV1(
        alert_id="ALT-POST",
        source_alert_id="SA-4",
        source_type="wazuh",
        alert_timestamp=t_end + timedelta(microseconds=1),
        host_id="WS-BOUND",
        rule_reference="RULE-01",
    )
    for a in (a_start, a_end, a_pre, a_post):
        store.add_alert(a)

    alerts = store.get_alerts_for_run(run)
    assert len(alerts) == 2
    assert [a.alert_id for a in alerts] == ["ALT-START", "ALT-END"]

    # Rule bounded query
    rule_alerts = store.list_alerts_for_rule("RULE-01", window_start=t_start, window_end=t_end)
    assert len(rule_alerts) == 2
    assert [a.alert_id for a in rule_alerts] == ["ALT-START", "ALT-END"]


def test_contract_correlation_host_matching_advanced(store: StoreProtocol):
    """Verify hosts_match rules across short NetBIOS, FQDN, cross-domain, IPv4, and IPv6."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

    scn = ScenarioV1(
        scenario_id="SCN-HOSTS",
        name="Host Matching Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scn)

    # 1. Short NetBIOS target host "srv-01" matches "SRV-01.corp.internal"
    run_netbios = TestRunV1(
        run_id="RUN-NETBIOS",
        scenario_id="SCN-HOSTS",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="srv-01",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    store.add_run(run_netbios)

    ev_fqdn = NormalizedTelemetryEventV1(
        normalized_event_id="EV-FQDN",
        raw_event_id="R-F1",
        source_event_id="S-F1",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="SRV-01.corp.internal",
        process_name="cmd.exe",
    )
    store.add_normalized_event(ev_fqdn)

    assert len(store.get_events_for_run(run_netbios)) == 1

    # 2. Cross-domain collision rejection: "srv-01.prod.corp" vs "srv-01.dev.corp"
    run_prod = TestRunV1(
        run_id="RUN-PROD",
        scenario_id="SCN-HOSTS",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="srv-01.prod.corp",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    store.add_run(run_prod)

    ev_dev = NormalizedTelemetryEventV1(
        normalized_event_id="EV-DEV",
        raw_event_id="R-D1",
        source_event_id="S-D1",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="srv-01.dev.corp",
        process_name="cmd.exe",
    )
    store.add_normalized_event(ev_dev)

    assert len(store.get_events_for_run(run_prod)) == 0

    # 3. Canonical IPv6 matching: compressed vs uncompressed
    run_ipv6 = TestRunV1(
        run_id="RUN-IPV6",
        scenario_id="SCN-HOSTS",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="2001:db8::1",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    store.add_run(run_ipv6)

    ev_ipv6_uncompressed = NormalizedTelemetryEventV1(
        normalized_event_id="EV-IPV6",
        raw_event_id="R-6",
        source_event_id="S-6",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="2001:0db8:0000:0000:0000:0000:0000:0001",
        process_name="cmd.exe",
    )
    store.add_normalized_event(ev_ipv6_uncompressed)

    assert len(store.get_events_for_run(run_ipv6)) == 1

    # 4. IP vs Hostname mismatch
    run_ip = TestRunV1(
        run_id="RUN-IP",
        scenario_id="SCN-HOSTS",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="10.0.0.50",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    store.add_run(run_ip)

    ev_hostname = NormalizedTelemetryEventV1(
        normalized_event_id="EV-HOST",
        raw_event_id="R-H",
        source_event_id="S-H",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="host-10-0-0-50",
        process_name="cmd.exe",
    )
    store.add_normalized_event(ev_hostname)

    assert len(store.get_events_for_run(run_ip)) == 0


def test_contract_correlation_multi_timezone_offsets(store: StoreProtocol):
    """Verify correct correlation and chronological ordering across multiple global timezone offsets.

    Window: 10:00 - 10:30 UTC
    Event Tokyo (JST +09:00): 19:05 JST -> 10:05 UTC (1st)
    Event New York (EDT -04:00): 06:10 EDT -> 10:10 UTC (2nd)
    Event Mumbai (IST +05:30): 15:45 IST -> 10:15 UTC (3rd)
    Event Out of window (IST +05:30): 17:00 IST -> 11:30 UTC (EXCLUDED)
    """
    t0_utc = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1_utc = datetime(2026, 10, 12, 10, 30, tzinfo=timezone.utc)

    scn = ScenarioV1(
        scenario_id="SCN-TZ",
        name="Timezone Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    run = TestRunV1(
        run_id="RUN-TZ",
        scenario_id="SCN-TZ",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-GLOBAL",
        target_user="secops",
        window_start=t0_utc,
        window_end=t1_utc,
        executed_at=t0_utc,
    )
    store.add_scenario(scn)
    store.add_run(run)

    tz_jst = timezone(timedelta(hours=9))
    tz_edt = timezone(timedelta(hours=-4))
    tz_ist = timezone(timedelta(hours=5, minutes=30))

    ev_jst = NormalizedTelemetryEventV1(
        normalized_event_id="EV-JST",
        raw_event_id="R-JST",
        source_event_id="S-JST",
        source_timestamp=datetime(2026, 10, 12, 19, 5, 0, tzinfo=tz_jst),
        normalized_timestamp=datetime(2026, 10, 12, 19, 5, 0, tzinfo=tz_jst),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-GLOBAL",
        process_name="cmd.exe",
    )
    ev_edt = NormalizedTelemetryEventV1(
        normalized_event_id="EV-EDT",
        raw_event_id="R-EDT",
        source_event_id="S-EDT",
        source_timestamp=datetime(2026, 10, 12, 6, 10, 0, tzinfo=tz_edt),
        normalized_timestamp=datetime(2026, 10, 12, 6, 10, 0, tzinfo=tz_edt),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-GLOBAL",
        process_name="cmd.exe",
    )
    ev_ist = NormalizedTelemetryEventV1(
        normalized_event_id="EV-IST",
        raw_event_id="R-IST",
        source_event_id="S-IST",
        source_timestamp=datetime(2026, 10, 12, 15, 45, 0, tzinfo=tz_ist),
        normalized_timestamp=datetime(2026, 10, 12, 15, 45, 0, tzinfo=tz_ist),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-GLOBAL",
        process_name="cmd.exe",
    )
    ev_out = NormalizedTelemetryEventV1(
        normalized_event_id="EV-OUT",
        raw_event_id="R-OUT",
        source_event_id="S-OUT",
        source_timestamp=datetime(2026, 10, 12, 17, 0, 0, tzinfo=tz_ist),
        normalized_timestamp=datetime(2026, 10, 12, 17, 0, 0, tzinfo=tz_ist),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-GLOBAL",
        process_name="cmd.exe",
    )

    for e in (ev_jst, ev_edt, ev_ist, ev_out):
        store.add_normalized_event(e)

    events = store.get_events_for_run(run)
    assert len(events) == 3
    # Chronological sort across timezones: 10:05 UTC (JST), 10:10 UTC (EDT), 10:15 UTC (IST)
    assert [e.normalized_event_id for e in events] == ["EV-JST", "EV-EDT", "EV-IST"]


# ── 3. Transaction Atomicity & Integration Hardening Tests ───────────────────


def test_transaction_atomicity_multi_step_failure(tmp_path: Path):
    """Verify multi-step operations are completely rolled back when an exception occurs in SQLiteStore."""
    db_file = tmp_path / "atomic_failure.db"
    store = SQLiteStore(db_file)
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

    scn = ScenarioV1(
        scenario_id="SCN-ATOMIC",
        name="Atomic Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    run = TestRunV1(
        run_id="RUN-ATOMIC",
        scenario_id="SCN-ATOMIC",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-01",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )

    # Attempt multi-step insert with failure at the end
    try:
        with store.transaction():
            store.add_scenario(scn)
            store.add_run(run)
            raise RuntimeError("Simulated pipeline failure during multi-step write")
    except RuntimeError:
        pass

    # Verify zero records committed
    assert store.get_scenario("SCN-ATOMIC") is None
    assert store.get_run("RUN-ATOMIC") is None
    assert len(store.list_scenarios()) == 0
    assert len(store.list_runs()) == 0
    store.close()


def test_transaction_nested_savepoint_rollback_and_outer_commit(tmp_path: Path):
    """Verify an inner transaction block failure does not rollback an outer transaction if caught."""
    db_file = tmp_path / "nested_sp.db"
    store = SQLiteStore(db_file)

    scn1 = ScenarioV1(
        scenario_id="SCN-1",
        name="Scenario 1",
        mitre_technique_id="T1059",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    scn2_invalid = ScenarioV1(
        scenario_id="SCN-2",
        name="Scenario 2",
        mitre_technique_id="T1059",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    scn3 = ScenarioV1(
        scenario_id="SCN-3",
        name="Scenario 3",
        mitre_technique_id="T1059",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )

    with store.transaction():
        store.add_scenario(scn1)
        try:
            with store.transaction():
                store.add_scenario(scn2_invalid)
                raise ValueError("Inner savepoint failure")
        except ValueError:
            pass  # Caught and handled
        store.add_scenario(scn3)

    assert store.get_scenario("SCN-1") is not None
    assert store.get_scenario("SCN-2") is None  # Rolled back cleanly
    assert store.get_scenario("SCN-3") is not None
    assert len(store.list_scenarios()) == 2
    store.close()


def test_transaction_nested_outer_failure(tmp_path: Path):
    """Verify an outer transaction failure rolls back both outer writes and inner savepoints."""
    db_file = tmp_path / "nested_outer_fail.db"
    store = SQLiteStore(db_file)

    scn1 = ScenarioV1(
        scenario_id="SCN-OUTER-1",
        name="Outer Scenario 1",
        mitre_technique_id="T1059",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    scn2_inner = ScenarioV1(
        scenario_id="SCN-INNER-1",
        name="Inner Scenario 1",
        mitre_technique_id="T1059",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )

    try:
        with store.transaction():
            store.add_scenario(scn1)
            with store.transaction():
                store.add_scenario(scn2_inner)  # inner succeeds
            raise RuntimeError("Outer transaction crashes after inner succeeds")
    except RuntimeError:
        pass

    # Neither the outer nor the inner writes should remain
    assert store.get_scenario("SCN-OUTER-1") is None
    assert store.get_scenario("SCN-INNER-1") is None
    assert len(store.list_scenarios()) == 0
    store.close()


def test_sqlite_lifecycle_reopening_and_recovery(tmp_path: Path):
    """Verify file-backed database persistence across close/reopen and error recovery."""
    db_file = tmp_path / "lifecycle.db"

    # Step 1: Open, populate, close
    store1 = SQLiteStore(db_file)
    scn = ScenarioV1(
        scenario_id="SCN-LIFE",
        name="Lifecycle Test",
        mitre_technique_id="T1059",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store1.add_scenario(scn)
    store1.close()

    # Idempotent close
    store1.close()
    assert store1.is_closed is True

    # Operations on closed store raise RuntimeError
    with pytest.raises(RuntimeError, match="SQLiteStore connection is closed"):
        store1.get_scenario("SCN-LIFE")
    with pytest.raises(RuntimeError, match="SQLiteStore connection is closed"):
        with store1.transaction():
            pass

    # Step 2: Reopen from same file
    store2 = SQLiteStore(db_file)
    assert store2.is_closed is False
    assert store2.get_scenario("SCN-LIFE") == scn

    # Failed transaction does not corrupt connection or prevent future operations
    with pytest.raises(RuntimeError, match="Crash"):
        with store2.transaction():
            raise RuntimeError("Crash")

    # Connection remains fully functional after failure
    scn_after = ScenarioV1(
        scenario_id="SCN-AFTER",
        name="After Failure",
        mitre_technique_id="T1059",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store2.add_scenario(scn_after)
    assert len(store2.list_scenarios()) == 2
    store2.close()


# ── 4. EXPLAIN QUERY PLAN Verification ───────────────────────────────────────


def test_explain_query_plan_verification():
    """Verify SQL indexes are properly utilized without temporary sort B-trees."""
    store = SQLiteStore(":memory:")
    cur = store.connection.cursor()

    # 1. test_runs by scenario_id
    cur.execute("EXPLAIN QUERY PLAN SELECT payload_json FROM test_runs WHERE scenario_id = ? ORDER BY rowid;", ("SCN-1",))
    plan_runs = " ".join(row[3] for row in cur.fetchall())
    assert "USING INDEX idx_test_runs_scenario" in plan_runs

    # 2. alerts by rule_reference
    cur.execute("EXPLAIN QUERY PLAN SELECT payload_json FROM alerts WHERE rule_reference = ? ORDER BY rowid;", ("RULE-1",))
    plan_alerts_rows = [row[3] for row in cur.fetchall()]
    plan_alerts = " ".join(plan_alerts_rows)
    assert "USING INDEX idx_alerts_rule" in plan_alerts
    # Must NOT require a temporary B-tree for ORDER BY rowid
    assert not any("USE TEMP B-TREE FOR ORDER BY" in r for r in plan_alerts_rows)

    # 3. diagnostic_results by test_run_id (most recent)
    cur.execute("EXPLAIN QUERY PLAN SELECT payload_json FROM diagnostic_results WHERE test_run_id = ? ORDER BY rowid DESC LIMIT 1;", ("RUN-1",))
    plan_diag_rows = [row[3] for row in cur.fetchall()]
    plan_diag = " ".join(plan_diag_rows)
    assert "USING INDEX idx_diagnostic_results_run_id" in plan_diag
    # Must NOT require a temporary B-tree for reverse rowid ordering
    assert not any("USE TEMP B-TREE FOR ORDER BY" in r for r in plan_diag_rows)

    # 4. ground_truths by run_id
    cur.execute("EXPLAIN QUERY PLAN SELECT payload_json FROM ground_truths WHERE run_id = ? ORDER BY rowid ASC LIMIT 1;", ("RUN-1",))
    plan_gt = " ".join(row[3] for row in cur.fetchall())
    assert "USING INDEX idx_ground_truths_run" in plan_gt

    store.close()
