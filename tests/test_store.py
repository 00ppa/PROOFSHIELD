"""Unit tests for InMemoryStore."""

from datetime import datetime, timezone, timedelta
import pytest

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticCategory,
    DiagnosticResultV1,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    GroundTruthLabel,
    GroundTruthV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.store import InMemoryStore, hosts_match


@pytest.fixture
def store():
    return InMemoryStore()


@pytest.fixture
def sample_scenario():
    return ScenarioV1(
        scenario_id="SCN-T1059.001-01",
        name="PowerShell Execution Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )


@pytest.fixture
def sample_run():
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    return TestRunV1(
        run_id="RUN-001",
        scenario_id="SCN-T1059.001-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-WIN11-01",
        target_user="CORP\\alice",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
    )


def test_scenario_crud(store, sample_scenario):
    store.add_scenario(sample_scenario)
    assert store.get_scenario("SCN-T1059.001-01") == sample_scenario
    assert len(store.list_scenarios()) == 1

    with pytest.raises(ValueError, match="already exists"):
        store.add_scenario(sample_scenario)


def test_run_crud(store, sample_scenario, sample_run):
    with pytest.raises(ValueError, match="Scenario not found"):
        store.add_run(sample_run)

    store.add_scenario(sample_scenario)
    store.add_run(sample_run)
    assert store.get_run("RUN-001") == sample_run
    assert len(store.list_runs()) == 1
    assert len(store.list_runs(scenario_id="SCN-T1059.001-01")) == 1
    assert len(store.list_runs(scenario_id="NONEXISTENT")) == 0

    with pytest.raises(ValueError, match="already exists"):
        store.add_run(sample_run)


def test_raw_event_crud(store):
    t0 = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    raw = RawTelemetryEventV1(
        raw_event_id="RAW-001",
        source_event_id="SRC-SYS-101",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={"EventID": 1},
    )
    store.add_raw_event(raw)
    assert store.get_raw_event("RAW-001") == raw
    assert len(store.list_raw_events()) == 1

    with pytest.raises(ValueError, match="already exists"):
        store.add_raw_event(raw)


def test_normalized_event_correlation(store, sample_scenario, sample_run):
    store.add_scenario(sample_scenario)
    store.add_run(sample_run)

    t_in = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    t_out = datetime(2026, 10, 12, 11, 0, tzinfo=timezone.utc)

    event_in = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-001",
        raw_event_id="RAW-001",
        source_event_id="SRC-101",
        source_timestamp=t_in,
        normalized_timestamp=t_in,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
        process_name="powershell.exe",
        command_line="powershell.exe -enc test",
    )
    event_out = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-002",
        raw_event_id="RAW-002",
        source_event_id="SRC-102",
        source_timestamp=t_out,
        normalized_timestamp=t_out,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-WIN11-01",
        process_name="powershell.exe",
    )
    event_diff_host = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-003",
        raw_event_id="RAW-003",
        source_event_id="SRC-103",
        source_timestamp=t_in,
        normalized_timestamp=t_in,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-LINUX-99",
        process_name="powershell.exe",
    )

    store.add_normalized_event(event_in)
    store.add_normalized_event(event_out)
    store.add_normalized_event(event_diff_host)

    correlated = store.get_events_for_run(sample_run)
    assert len(correlated) == 1
    assert correlated[0].normalized_event_id == "NORM-001"


def test_rule_crud(store):
    rule = DetectionRuleV1(
        rule_id="RULE-01",
        rule_name="Test Rule",
        rule_format="sigma",
    )
    store.add_rule(rule)
    assert store.get_rule("RULE-01") == rule
    assert len(store.list_rules()) == 1

    with pytest.raises(ValueError, match="already exists"):
        store.add_rule(rule)


def test_alert_correlation(store, sample_scenario, sample_run):
    store.add_scenario(sample_scenario)
    store.add_run(sample_run)

    t_in = datetime(2026, 10, 12, 10, 8, tzinfo=timezone.utc)
    t_out = datetime(2026, 10, 12, 10, 30, tzinfo=timezone.utc)

    alert_match = AlertV1(
        alert_id="ALT-001",
        source_alert_id="SRC-ALT-1",
        source_type="wazuh",
        alert_timestamp=t_in,
        host_id="ws-win11-01",  # case-insensitive check
        rule_reference="RULE-01",
    )
    alert_outside = AlertV1(
        alert_id="ALT-002",
        source_alert_id="SRC-ALT-2",
        source_type="wazuh",
        alert_timestamp=t_out,
        host_id="WS-WIN11-01",
        rule_reference="RULE-01",
    )

    store.add_alert(alert_match)
    store.add_alert(alert_outside)

    alerts = store.get_alerts_for_run(sample_run)
    assert len(alerts) == 1
    assert alerts[0].alert_id == "ALT-001"


def test_result_and_ground_truth(store, sample_run):
    t0 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    res = DiagnosticResultV1(
        diagnostic_id="DIAG-01",
        test_run_id=sample_run.run_id,
        scenario_id="SCN-T1059.001-01",
        predicted_category=DiagnosticCategory.PASS,
        confidence="definitive",
        reason="Success",
        evaluated_at=t0,
    )
    store.add_result(res)
    assert store.get_result("DIAG-01") == res
    assert store.get_result_for_run(sample_run.run_id) == res

    gt = GroundTruthV1(
        ground_truth_id="GT-01",
        run_id=sample_run.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="manual",
    )
    store.add_ground_truth(gt)
    assert store.get_ground_truth_for_run(sample_run.run_id) == gt
    assert len(store.list_ground_truths()) == 1


def test_reset(store, sample_scenario):
    store.add_scenario(sample_scenario)
    assert len(store.list_scenarios()) == 1
    store.reset()
    assert len(store.list_scenarios()) == 0


def test_hosts_match_behavior():
    from proofshield.services.store import hosts_match

    # Exact match
    assert hosts_match("ws-01", "WS-01") is True
    assert hosts_match("192.168.1.50", "192.168.1.50") is True

    # NetBIOS vs FQDN match
    assert hosts_match("WORKSTATION-01", "workstation-01.corp.local") is True
    assert hosts_match("server.corp.local", "server") is True

    # IPv4 address safety: DIFFERENT IPs with same first octet MUST NOT match
    assert hosts_match("192.168.1.50", "192.168.2.99") is False
    assert hosts_match("10.0.1.1", "10.0.1.2") is False

    # IPv6 canonicalization: compressed vs expanded representation
    assert hosts_match("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001") is True
    assert hosts_match("2001:DB8::ABCD", "2001:db8::abcd") is True
    assert hosts_match("fe80::1", "fe80:0000:0000:0000:0000:0000:0000:0001") is True
    assert hosts_match("::1", "0:0:0:0:0:0:0:1") is True
    assert hosts_match("2001:db8::1", "2001:db8::2") is False

    # IP vs Hostname safety
    assert hosts_match("192.168.1.1", "host.domain.com") is False
    assert hosts_match("2001:db8::1", "ipv6host") is False

    # Cross-domain FQDN collision prevention: different domains MUST NOT match
    assert hosts_match("server.prod.corp", "server.dev.corp") is False


def test_list_alerts_for_rule(store):
    t0 = datetime(2026, 10, 12, 10, 8, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 30, tzinfo=timezone.utc)
    t_old = datetime(2026, 10, 11, 10, 0, tzinfo=timezone.utc)

    alert1 = AlertV1(
        alert_id="ALT-R1-01",
        source_alert_id="SRC-1",
        source_type="wazuh",
        alert_timestamp=t0,
        host_id="ws-01",
        rule_reference="RULE-X",
    )
    alert2 = AlertV1(
        alert_id="ALT-R2-01",
        source_alert_id="SRC-2",
        source_type="wazuh",
        alert_timestamp=t0,
        host_id="ws-02",
        rule_reference="RULE-Y",
    )
    alert3 = AlertV1(
        alert_id="ALT-R1-HISTORICAL",
        source_alert_id="SRC-3",
        source_type="wazuh",
        alert_timestamp=t_old,
        host_id="ws-01",
        rule_reference="RULE-X",
    )
    alert_no_ts = AlertV1(
        alert_id="ALT-R1-NO-TS",
        source_alert_id="SRC-4",
        source_type="wazuh",
        alert_timestamp=None,
        host_id="ws-01",
        rule_reference="RULE-X",
    )
    store.add_alert(alert1)
    store.add_alert(alert2)
    store.add_alert(alert3)
    store.add_alert(alert_no_ts)

    # Without window, returns all alerts for rule (including missing timestamp)
    rule_x_all = store.list_alerts_for_rule("RULE-X")
    assert len(rule_x_all) == 3

    # Bounded by time window: safely excludes historical and missing-timestamp alerts
    window_start = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    window_end = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)
    rule_x_window = store.list_alerts_for_rule(
        "RULE-X", window_start=window_start, window_end=window_end
    )
    assert len(rule_x_window) == 1
    assert rule_x_window[0].alert_id == "ALT-R1-01"

    rule_z_alerts = store.list_alerts_for_rule("RULE-NONEXISTENT")
    assert len(rule_z_alerts) == 0

