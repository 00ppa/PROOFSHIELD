"""Tests for campaign replay engine and evidence integrity verification."""

from datetime import datetime, timedelta, timezone
import pytest

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.campaign import (
    CampaignDefinitionV1,
    CampaignExecutionConfigV1,
    CampaignExecutionPolicy,
)
from proofshield.schemas.common import (
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    ValidationTarget,
)
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.campaign_engine import CampaignEngine
from proofshield.services.store import InMemoryStore


@pytest.fixture
def replay_setup():
    store = InMemoryStore()
    now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Scenarios
    s1 = ScenarioV1(
        scenario_id="SCN-REPLAY-01",
        name="Persistence via Cron",
        mitre_technique_id="T1053.003",
        mitre_tactic="Persistence",
        expected_event_category=EventCategory.FILE_EVENT,
        expected_file_path="/etc/cron.d/job",
        expected_detection_rule_id="RULE-CRON-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(s1)

    # 2. Rule
    rule = DetectionRuleV1(
        rule_id="RULE-CRON-01",
        rule_name="Suspicious Cron Job Created",
        rule_format="sigma",
    )
    store.add_rule(rule)

    # 3. Test Run
    run1 = TestRunV1(
        run_id="RUN-REPLAY-01",
        scenario_id="SCN-REPLAY-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="linux-srv-01",
        target_user="root",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(run1)

    # 4. Telemetry and Alert
    evt = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-FILE-01",
        raw_event_id="RAW-FILE-01",
        source_event_id="SRC-FILE-01",
        source_timestamp=now + timedelta(seconds=2),
        normalized_timestamp=now + timedelta(seconds=2),
        event_category=EventCategory.FILE_EVENT,
        host="linux-srv-01",
        user="root",
        extra_attributes={"file_path": "/etc/cron.d/job"},
    )
    store.add_normalized_event(evt)

    alt = AlertV1(
        alert_id="ALT-CRON-01",
        source_alert_id="SRC-ALT-CRON-01",
        source_type="syslog",
        rule_reference="RULE-CRON-01",
        host_id="linux-srv-01",
        alert_timestamp=now + timedelta(seconds=5),
        severity="medium",
    )
    store.add_alert(alt)

    # 5. Campaign
    campaign = CampaignDefinitionV1(
        campaign_id="CPG-REPLAY-SUITE",
        name="Cron Persistence Campaign",
        scenario_ids=["SCN-REPLAY-01"],
    )
    store.add_campaign(campaign)

    engine = CampaignEngine(store=store)
    return engine, "CPG-REPLAY-SUITE"


def test_exact_replay_matches_original_run(replay_setup):
    engine, campaign_id = replay_setup
    store = engine.store

    # Initial campaign run
    orig_run = engine.execute_campaign(campaign_id)
    assert orig_run.summary.passed_scenarios == 1
    orig_run_id = orig_run.run_id

    # Replay
    replay_result = engine.replay_campaign_run(orig_run_id)

    # Assertions
    assert replay_result.is_exact_replay is True
    assert replay_result.verdict == "EXACT_REPLAY"
    assert len(replay_result.missing_evidence) == 0
    assert len(replay_result.altered_evidence) == 0

    # Original run must remain untouched in store
    fetched_orig = store.get_campaign_run(orig_run_id)
    assert fetched_orig is not None
    assert fetched_orig.run_id == orig_run_id
    assert fetched_orig.is_replay is False

    # Replay run must have distinct ID and is_replay flag
    replay_run = replay_result.replay_run
    assert replay_run.run_id != orig_run_id
    assert replay_run.is_replay is True
    assert replay_run.source_run_id == orig_run_id
    assert replay_run.summary.passed_scenarios == 1

    # Comparison report
    comp = replay_result.comparison
    assert comp.is_equivalent_campaign is True
    assert comp.is_equivalent_evidence is True
    assert comp.comparison_verdict == "IDENTICAL"
    assert len(comp.regressions) == 0
    assert len(comp.improvements) == 0


def test_replay_detects_altered_evidence(replay_setup):
    engine, campaign_id = replay_setup
    store = engine.store

    orig_run = engine.execute_campaign(campaign_id)
    orig_run_id = orig_run.run_id

    # Alter scenario definition in store
    altered_scenario = ScenarioV1(
        scenario_id="SCN-REPLAY-01",
        name="ALTERED Scenario Definition",
        mitre_technique_id="T1053.003",
        mitre_tactic="Persistence",
        expected_event_category=EventCategory.FILE_EVENT,
        expected_file_path="/etc/cron.d/different_job",  # Path changed
        expected_detection_rule_id="RULE-CRON-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store._scenarios["SCN-REPLAY-01"] = altered_scenario

    replay_result = engine.replay_campaign_run(orig_run_id)

    assert replay_result.is_exact_replay is False
    assert len(replay_result.altered_evidence) >= 1
    assert "Scenario:SCN-REPLAY-01 (hash changed)" in replay_result.altered_evidence[0]


def test_replay_detects_missing_evidence(replay_setup):
    engine, campaign_id = replay_setup
    store = engine.store

    orig_run = engine.execute_campaign(campaign_id)
    orig_run_id = orig_run.run_id

    # Delete alert evidence from store
    del store._alerts["ALT-CRON-01"]

    replay_result = engine.replay_campaign_run(orig_run_id)

    assert replay_result.is_exact_replay is False
    assert len(replay_result.missing_evidence) >= 1
    assert any("Alert:ALT-CRON-01" in m for m in replay_result.missing_evidence)


def test_replay_nonexistent_run_raises(replay_setup):
    engine, _ = replay_setup
    with pytest.raises(ValueError) as exc:
        engine.replay_campaign_run("CRUN-NONEXISTENT")
    assert "Source campaign run not found" in str(exc.value)
