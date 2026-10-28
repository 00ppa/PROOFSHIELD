"""Tests for CampaignEngine: execution, failure isolation, determinism, and root-cause aggregation."""

from datetime import datetime, timedelta, timezone
import pytest

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.campaign import (
    CampaignDefinitionV1,
    CampaignExecutionConfigV1,
    CampaignExecutionPolicy,
    CampaignRunStatus,
    ScenarioRunStatus,
)
from proofshield.schemas.common import (
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    ValidationTarget,
)
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.campaign_engine import CampaignEngine
from proofshield.services.store import InMemoryStore


@pytest.fixture
def populated_engine():
    """Sets up an InMemoryStore with 3 scenarios:

    - SCN-01: PASS (all expected telemetry and alert present)
    - SCN-02: EXPECTED_TELEMETRY_MISSING (no telemetry present)
    - SCN-03: DETECTION_NOT_TRIGGERED (telemetry present, but alert missing)
    """
    store = InMemoryStore()
    now = datetime(2026, 10, 29, 10, 0, 0, tzinfo=timezone.utc)

    # Scenarios
    s1 = ScenarioV1(
        scenario_id="SCN-PASS",
        name="Valid Powershell Execution",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_detection_rule_id="RULE-PS-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    s2 = ScenarioV1(
        scenario_id="SCN-MISSING-TEL",
        name="Missing Telemetry Technique",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="cmd.exe",
        expected_detection_rule_id="RULE-CMD-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    s3 = ScenarioV1(
        scenario_id="SCN-NO-ALERT",
        name="Rule Did Not Fire Technique",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="bash",
        expected_detection_rule_id="RULE-BASH-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(s1)
    store.add_scenario(s2)
    store.add_scenario(s3)

    # Detection Rules
    rule1 = DetectionRuleV1(
        rule_id="RULE-PS-01",
        rule_name="Suspicious PowerShell",
        rule_format="sigma",
    )
    rule2 = DetectionRuleV1(
        rule_id="RULE-CMD-01",
        rule_name="Suspicious CMD",
        rule_format="sigma",
    )
    rule3 = DetectionRuleV1(
        rule_id="RULE-BASH-01",
        rule_name="Suspicious Bash",
        rule_format="sigma",
    )
    store.add_rule(rule1)
    store.add_rule(rule2)
    store.add_rule(rule3)

    # Runs
    r1 = TestRunV1(
        run_id="RUN-01",
        scenario_id="SCN-PASS",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="endpoint-01",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    r2 = TestRunV1(
        run_id="RUN-02",
        scenario_id="SCN-MISSING-TEL",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="endpoint-01",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    r3 = TestRunV1(
        run_id="RUN-03",
        scenario_id="SCN-NO-ALERT",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="endpoint-01",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(r1)
    store.add_run(r2)
    store.add_run(r3)

    # Evidence for RUN-01 (PASS): matching event + matching alert
    evt1 = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-EVT-01",
        source_timestamp=now + timedelta(seconds=5),
        normalized_timestamp=now + timedelta(seconds=5),
        event_category=EventCategory.PROCESS_CREATION,
        host="endpoint-01",
        user="alice",
        process_name="powershell.exe",
    )
    store.add_normalized_event(evt1)
    alt1 = AlertV1(
        alert_id="ALT-01",
        source_alert_id="SRC-ALT-01",
        source_type="wazuh",
        rule_reference="RULE-PS-01",
        host_id="endpoint-01",
        alert_timestamp=now + timedelta(seconds=10),
        severity="high",
    )
    store.add_alert(alt1)

    # Evidence for RUN-03 (NO-ALERT): matching event, but NO alert
    evt3 = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-03",
        raw_event_id="RAW-03",
        source_event_id="SRC-EVT-03",
        source_timestamp=now + timedelta(seconds=5),
        normalized_timestamp=now + timedelta(seconds=5),
        event_category=EventCategory.PROCESS_CREATION,
        host="endpoint-01",
        user="alice",
        process_name="bash",
    )
    store.add_normalized_event(evt3)

    # Ground Truths for RUN-01, RUN-02, RUN-03
    gt1 = GroundTruthV1(
        ground_truth_id="GT-01",
        run_id="RUN-01",
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="synthetic_generation",
    )
    gt2 = GroundTruthV1(
        ground_truth_id="GT-02",
        run_id="RUN-02",
        expected_diagnostic_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        verification_method="synthetic_generation",
    )
    gt3 = GroundTruthV1(
        ground_truth_id="GT-03",
        run_id="RUN-03",
        expected_diagnostic_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        verification_method="synthetic_generation",
    )
    store.add_ground_truth(gt1)
    store.add_ground_truth(gt2)
    store.add_ground_truth(gt3)

    return CampaignEngine(store=store)


def test_campaign_execution_nominal(populated_engine: CampaignEngine):
    store = populated_engine.store
    campaign = CampaignDefinitionV1(
        campaign_id="CPG-MIXED-01",
        name="Mixed Outcomes Campaign",
        scenario_ids=["SCN-PASS", "SCN-MISSING-TEL", "SCN-NO-ALERT"],
        execution_config=CampaignExecutionConfigV1(
            execution_policy=CampaignExecutionPolicy.CONTINUE_ON_ERROR
        ),
    )
    store.add_campaign(campaign)

    run = populated_engine.execute_campaign("CPG-MIXED-01")

    assert run.status == CampaignRunStatus.COMPLETED
    assert run.total_scenarios == 3
    assert len(run.scenario_results) == 3

    # Check results in declared order
    res1, res2, res3 = run.scenario_results
    assert res1.scenario_id == "SCN-PASS"
    assert res1.status == ScenarioRunStatus.PASS
    assert res1.predicted_category == DiagnosticCategory.PASS

    assert res2.scenario_id == "SCN-MISSING-TEL"
    assert res2.status == ScenarioRunStatus.FAILURE
    assert res2.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    assert res3.scenario_id == "SCN-NO-ALERT"
    assert res3.status == ScenarioRunStatus.FAILURE
    assert res3.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED

    # Check summary metrics
    summary = run.summary
    assert summary.total_scenarios == 3
    assert summary.executed_scenarios == 3
    assert summary.passed_scenarios == 1
    assert summary.failed_scenarios == 2
    assert summary.pass_rate == pytest.approx(1 / 3, 0.001)
    assert summary.execution_coverage == 1.0

    # Ground truth was provided for all 3 scenarios:
    assert summary.precision == 1.0  # 1 true positive / 1 predicted positive
    assert summary.recall == 1.0     # 1 true positive / 1 expected positive
    assert summary.f1 == 1.0

    # Check Root Cause Grouping
    assert len(run.root_cause_analysis) == 2
    rc_keys = {g.root_cause_category for g in run.root_cause_analysis}
    assert "MISSING_EXPECTED_TELEMETRY" in rc_keys
    assert "DETECTION_RULE_DID_NOT_TRIGGER" in rc_keys

    # Check Evidence Manifest
    manifest = run.evidence_manifest
    assert len(manifest.scenario_references) == 3
    assert manifest.manifest_hash is not None


def test_campaign_unexecuted_scenario(populated_engine: CampaignEngine):
    store = populated_engine.store
    # Add a scenario with no corresponding test run
    s_unexec = ScenarioV1(
        scenario_id="SCN-UNEXEC",
        name="Unexecuted Technique",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
    )
    store.add_scenario(s_unexec)

    campaign = CampaignDefinitionV1(
        campaign_id="CPG-WITH-UNEXEC",
        name="Campaign with unexecuted scenario",
        scenario_ids=["SCN-PASS", "SCN-UNEXEC"],
    )
    store.add_campaign(campaign)

    run = populated_engine.execute_campaign("CPG-WITH-UNEXEC")
    assert run.status == CampaignRunStatus.COMPLETED
    assert run.summary.total_scenarios == 2
    assert run.summary.executed_scenarios == 1
    assert run.summary.unexecuted_scenarios == 1
    assert run.summary.execution_coverage == 0.5
    assert run.summary.pass_rate == 1.0  # 1 pass / 1 executed


def test_campaign_failure_isolation_stop_on_error(populated_engine: CampaignEngine):
    store = populated_engine.store
    # Define campaign with a missing scenario ID followed by valid scenario
    campaign = CampaignDefinitionV1(
        campaign_id="CPG-STOP-ERROR",
        name="Stop on Error Campaign",
        scenario_ids=["SCN-NONEXISTENT", "SCN-PASS"],
        execution_config=CampaignExecutionConfigV1(
            execution_policy=CampaignExecutionPolicy.STOP_ON_ERROR
        ),
    )
    store.add_campaign(campaign)

    run = populated_engine.execute_campaign("CPG-STOP-ERROR")
    # SCN-NONEXISTENT triggers error, SCN-PASS is SKIPPED
    assert run.status == CampaignRunStatus.FAILED
    assert len(run.scenario_results) == 2
    assert run.scenario_results[0].status == ScenarioRunStatus.ERROR
    assert run.scenario_results[1].status == ScenarioRunStatus.SKIPPED


def test_campaign_execution_determinism(populated_engine: CampaignEngine):
    store = populated_engine.store
    campaign = CampaignDefinitionV1(
        campaign_id="CPG-DET-01",
        name="Deterministic Campaign",
        scenario_ids=["SCN-PASS", "SCN-MISSING-TEL"],
    )
    store.add_campaign(campaign)

    run1 = populated_engine.execute_campaign("CPG-DET-01")
    run2 = populated_engine.execute_campaign("CPG-DET-01")

    # Manifest hashes and summaries must be identical
    assert run1.evidence_manifest.manifest_hash == run2.evidence_manifest.manifest_hash
    assert run1.summary.pass_rate == run2.summary.pass_rate
    assert run1.summary.category_counts == run2.summary.category_counts
    assert len(run1.scenario_results) == len(run2.scenario_results)
    for res1, res2 in zip(run1.scenario_results, run2.scenario_results):
        assert res1.scenario_id == res2.scenario_id
        assert res1.predicted_category == res2.predicted_category
        assert res1.status == res2.status
