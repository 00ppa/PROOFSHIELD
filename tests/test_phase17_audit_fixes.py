"""Reproducible failure tests for Phase 17 Audit (Phase 17.1).

Validates:
1. Defect 1: Alert correlation rate false 1.0 on telemetry-only / alert-free campaigns.
2. Defect 2: Manifest hash tampering bypassing verification in assurance report.
3. Defect 3: Evidence completeness / inconclusive deterioration yielding false NO_CHANGE verdict.
4. Defect 4: Modified scenario definition between runs undetected by regression analyzer.
5. Defect 5: SQLiteStore foreign key error reporting "already exists" instead of "Campaign not found".
"""

from datetime import datetime, timedelta, timezone
import pytest

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.assurance_report import (
    AssuranceMetricV1,
    CampaignAssuranceReportV1,
    EvidenceVerificationStatus,
    FindingCategory,
    MetricStatus,
    RegressionVerdict,
)
from proofshield.schemas.campaign import (
    CampaignDefinitionV1,
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
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.assurance_report import CampaignAssuranceReportGenerator
from proofshield.services.campaign_engine import CampaignEngine
from proofshield.services.canonical import compute_canonical_hash
from proofshield.services.regression_analyzer import CampaignRegressionAnalyzer
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore


def test_defect1_alert_correlation_rate_on_telemetry_only_campaign():
    """Defect 1: A campaign with only EXPECTED_TELEMETRY_ONLY scenarios (no alerts expected)

    should NOT report alert_correlation_rate = 1.0; it should report INSUFFICIENT_DATA.
    """
    store = InMemoryStore()
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    # Scenario expects only telemetry, no alert
    s_telem_only = ScenarioV1(
        scenario_id="SCN-TELEM-ONLY",
        name="Telemetry Only Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="notepad.exe",
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
    )
    store.add_scenario(s_telem_only)

    r_telem = TestRunV1(
        run_id="TR-TELEM-ONLY",
        scenario_id="SCN-TELEM-ONLY",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="endpoint-01",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(r_telem)

    evt = NormalizedTelemetryEventV1(
        normalized_event_id="EVT-TELEM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=now + timedelta(seconds=2),
        normalized_timestamp=now + timedelta(seconds=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="endpoint-01",
        user="alice",
        process_name="notepad.exe",
    )
    store.add_normalized_event(evt)

    camp = CampaignDefinitionV1(
        campaign_id="CPG-TELEM-ONLY",
        name="Telemetry Only Campaign",
        scenario_ids=["SCN-TELEM-ONLY"],
    )
    store.add_campaign(camp)

    engine = CampaignEngine(store)
    run = engine.execute_campaign("CPG-TELEM-ONLY")
    assert run.scenario_results[0].status == ScenarioRunStatus.PASS

    report_gen = CampaignAssuranceReportGenerator(store)
    report = report_gen.generate_report(run.run_id)

    # Since no alerts were expected or candidates present, alert_correlation_rate must be INSUFFICIENT_DATA
    metric = report.assurance_metrics.alert_correlation_rate
    assert metric.status == MetricStatus.INSUFFICIENT_DATA, f"Expected INSUFFICIENT_DATA but got {metric.status} with value {metric.value}"
    assert metric.value is None


def test_defect2_tampered_manifest_hash_detected():
    """Defect 2: Changing manifest.manifest_hash without altering individual event hashes

    should be caught and result in INTEGRITY_COMPROMISED.
    """
    store = InMemoryStore()
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    s1 = ScenarioV1(
        scenario_id="SCN-D2",
        name="Defect 2 Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="test.exe",
        expected_detection_rule_id="RULE-D2",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(s1)
    store.add_rule(DetectionRuleV1(rule_id="RULE-D2", rule_name="Rule D2", rule_format="sigma"))
    r1 = TestRunV1(
        run_id="TR-D2",
        scenario_id="SCN-D2",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-1",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(r1)
    camp = CampaignDefinitionV1(
        campaign_id="CPG-D2",
        name="Campaign D2",
        scenario_ids=["SCN-D2"],
    )
    store.add_campaign(camp)

    engine = CampaignEngine(store)
    run = engine.execute_campaign("CPG-D2")

    # Deliberately corrupt the manifest_hash on the campaign run
    tampered_manifest = run.evidence_manifest.model_copy(update={"manifest_hash": "deadbeef" * 8})
    tampered_run = run.model_copy(update={"evidence_manifest": tampered_manifest})
    store._campaign_runs[run.run_id] = tampered_run

    report_gen = CampaignAssuranceReportGenerator(store)
    report = report_gen.generate_report(run.run_id, verify_manifest=True)

    assert report.evidence_quality.manifest_verification_status == EvidenceVerificationStatus.INTEGRITY_COMPROMISED, (
        f"Expected INTEGRITY_COMPROMISED but got {report.evidence_quality.manifest_verification_status}"
    )


def test_defect3_evidence_completeness_regression_verdict():
    """Defect 3: Evidence completeness degradation must result in RegressionVerdict.REGRESSION,

    NOT RegressionVerdict.NO_CHANGE.
    """
    store = InMemoryStore()
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    s1 = ScenarioV1(
        scenario_id="SCN-D3",
        name="Defect 3 Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="test.exe",
        expected_detection_rule_id="RULE-D3",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(s1)
    store.add_rule(DetectionRuleV1(rule_id="RULE-D3", rule_name="Rule D3", rule_format="sigma"))
    r1 = TestRunV1(
        run_id="TR-D3",
        scenario_id="SCN-D3",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-1",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(r1)
    # Evidence for baseline: matching event + alert
    store.add_normalized_event(NormalizedTelemetryEventV1(
        normalized_event_id="EVT-D3",
        raw_event_id="RAW-D3",
        source_event_id="SRC-D3",
        source_timestamp=now + timedelta(seconds=2),
        normalized_timestamp=now + timedelta(seconds=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="host-1",
        user="alice",
        process_name="test.exe",
    ))
    store.add_alert(AlertV1(
        alert_id="ALT-D3",
        source_alert_id="SRC-ALT-D3",
        source_type="wazuh",
        rule_reference="RULE-D3",
        host_id="host-1",
        alert_timestamp=now + timedelta(seconds=5),
        severity="high",
    ))
    camp = CampaignDefinitionV1(
        campaign_id="CPG-D3",
        name="Campaign D3",
        scenario_ids=["SCN-D3"],
    )
    store.add_campaign(camp)

    engine = CampaignEngine(store)
    base_run = engine.execute_campaign("CPG-D3")

    report_gen = CampaignAssuranceReportGenerator(store)
    base_report = report_gen.generate_report(base_run.run_id)
    assert base_report.assurance_metrics.evidence_completeness_rate.value == 1.0

    # In candidate run, simulate evidence completeness dropping to 0.0 (e.g. missing_evidence flag True)
    cand_run = base_run.model_copy(deep=True)
    cand_run.run_id = "CRUN-D3-CAND"
    cand_scen_res = cand_run.scenario_results[0].model_copy(update={"missing_evidence": True})
    cand_run.scenario_results = [cand_scen_res]
    store.add_campaign_run(cand_run)

    cand_report = report_gen.generate_report(cand_run.run_id)
    assert cand_report.assurance_metrics.evidence_completeness_rate.value == 0.0

    analyzer = CampaignRegressionAnalyzer(store)
    analysis = analyzer.analyze_reports(base_report, cand_report, base_run, cand_run)

    assert analysis.verdict == RegressionVerdict.REGRESSION, (
        f"Expected REGRESSION verdict when evidence completeness drops from 100% to 0%, but got {analysis.verdict}"
    )


def test_defect4_modified_scenario_definition_detected():
    """Defect 4: When a scenario definition changes between baseline and candidate runs

    (e.g. process name or regex changed), the regression analyzer should detect the
    scenario definition drift and flag it.
    """
    store = InMemoryStore()
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    s1 = ScenarioV1(
        scenario_id="SCN-D4",
        name="Defect 4 Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_detection_rule_id="RULE-D4",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(s1)
    store.add_rule(DetectionRuleV1(rule_id="RULE-D4", rule_name="Rule D4", rule_format="sigma"))
    r1 = TestRunV1(
        run_id="TR-D4",
        scenario_id="SCN-D4",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-1",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(r1)
    camp = CampaignDefinitionV1(
        campaign_id="CPG-D4",
        name="Campaign D4",
        scenario_ids=["SCN-D4"],
    )
    store.add_campaign(camp)

    engine = CampaignEngine(store)
    base_run = engine.execute_campaign("CPG-D4")

    # In candidate run, simulate that SCN-D4's scenario definition changed (different hash)
    cand_run = base_run.model_copy(deep=True)
    cand_run.run_id = "CRUN-D4-CAND"
    # Mutate the scenario reference's scenario_hash in the candidate run manifest
    cand_s_ref = cand_run.evidence_manifest.scenario_references[0].model_copy(
        update={"scenario_hash": "c0ffee" * 10 + "0000"}
    )
    cand_run.evidence_manifest.scenario_references = [cand_s_ref]
    store.add_campaign_run(cand_run)

    report_gen = CampaignAssuranceReportGenerator(store)
    base_report = report_gen.generate_report(base_run.run_id)
    cand_report = report_gen.generate_report(cand_run.run_id)

    analyzer = CampaignRegressionAnalyzer(store)
    analysis = analyzer.analyze_reports(base_report, cand_report, base_run, cand_run)

    # Must flag that scenario definition was modified
    scenario_drift_findings = [
        f for f in analysis.findings
        if "SCN-D4" in f.affected_target and "definition" in f.explanation.lower()
    ]
    assert len(scenario_drift_findings) >= 1, (
        f"Expected finding detecting scenario definition drift for SCN-D4, but got findings: {[f.explanation for f in analysis.findings]}"
    )


def test_defect5_sqlite_store_foreign_key_error_parity(tmp_path):
    """Defect 5: Adding an assurance report with a non-existent campaign_id must raise

    'Campaign not found', NOT 'Assurance report already exists'.
    """
    db_file = tmp_path / "fk_defect_test.db"
    sqlite_store = SQLiteStore(db_file)

    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    s = ScenarioV1(
        scenario_id="SCN-D5",
        name="Scenario D5",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_detection_rule_id="RULE-D5",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    sqlite_store.add_scenario(s)
    sqlite_store.add_rule(DetectionRuleV1(rule_id="RULE-D5", rule_name="Rule D5", rule_format="sigma"))
    c = CampaignDefinitionV1(
        campaign_id="CPG-D5",
        name="Campaign D5",
        scenario_ids=["SCN-D5"],
    )
    sqlite_store.add_campaign(c)

    engine = CampaignEngine(sqlite_store)
    run = engine.execute_campaign("CPG-D5")

    report_gen = CampaignAssuranceReportGenerator(sqlite_store)
    report = report_gen.generate_report(run.run_id)

    # Tamper the report to point to a non-existent campaign_id
    bad_campaign_report = report.model_copy(update={"campaign_id": "NON-EXISTENT-CPG"})

    with pytest.raises(ValueError, match="Campaign not found"):
        sqlite_store.add_assurance_report(bad_campaign_report)

    sqlite_store.close()
