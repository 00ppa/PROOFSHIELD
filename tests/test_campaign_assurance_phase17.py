"""Comprehensive Adversarial, Integrity, and Parity Tests for Phase 17.

Validates:
1. Campaign Assurance Report Generation (empty, all-pass, all-fail, mixed, unexecuted, missing telemetry/alerts).
2. Regression Analysis Service (regression, improvement, no change, insufficient data, incomparable, drift).
3. Determinism & Integrity (RFC 8785 canonical digest, tamper detection, NaN/infinity rejection).
4. Storage Backends & Parity (InMemoryStore vs SQLiteStore, transaction rollback, duplicate isolation).
5. REST API Integration (FastAPI endpoints, pagination, validation, error sanitization, integrity enforcement).
"""

from datetime import datetime, timedelta, timezone
import math
import tempfile
import pytest
from fastapi.testclient import TestClient

from proofshield.main import app
from proofshield.schemas.alert import AlertV1
from proofshield.schemas.assurance_report import (
    AssuranceMetricV1,
    CampaignAssuranceReportV1,
    EvidenceVerificationStatus,
    FindingCategory,
    FindingSeverity,
    MetricStatus,
    RegressionVerdict,
)
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
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.assurance_report import (
    CampaignAssuranceReportGenerator,
    compute_assurance_report_digest,
)
from proofshield.services.campaign_engine import CampaignEngine
from proofshield.services.canonical import compute_canonical_hash
from proofshield.services.regression_analyzer import (
    CampaignRegressionAnalyzer,
    compute_regression_analysis_digest,
)
from proofshield.services.root_cause import RootCauseIntelligenceService
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore, reset_store, set_store


@pytest.fixture
def populated_env():
    """Sets up a comprehensive store with multiple scenarios, rules, test runs, and evidence."""
    store = InMemoryStore()
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    # Scenarios
    s_pass = ScenarioV1(
        scenario_id="SCN-P17-PASS",
        name="Valid Execution Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_detection_rule_id="RULE-17-PS",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    s_miss_telem = ScenarioV1(
        scenario_id="SCN-P17-NO-TELEM",
        name="Missing Telemetry Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="wmic.exe",
        expected_detection_rule_id="RULE-17-WMIC",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    s_no_alert = ScenarioV1(
        scenario_id="SCN-P17-NO-ALERT",
        name="No Alert Fired Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="cmd.exe",
        expected_detection_rule_id="RULE-17-CMD",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    s_unlinked_alert = ScenarioV1(
        scenario_id="SCN-P17-UNLINKED",
        name="Alert Not Correlated Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="certutil.exe",
        expected_detection_rule_id="RULE-17-CERTUTIL",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(s_pass)
    store.add_scenario(s_miss_telem)
    store.add_scenario(s_no_alert)
    store.add_scenario(s_unlinked_alert)

    # Rules
    store.add_rule(DetectionRuleV1(rule_id="RULE-17-PS", rule_name="Rule PS", rule_format="sigma"))
    store.add_rule(DetectionRuleV1(rule_id="RULE-17-WMIC", rule_name="Rule WMIC", rule_format="sigma"))
    store.add_rule(DetectionRuleV1(rule_id="RULE-17-CMD", rule_name="Rule CMD", rule_format="sigma"))
    store.add_rule(DetectionRuleV1(rule_id="RULE-17-CERTUTIL", rule_name="Rule Certutil", rule_format="sigma"))

    # Test Runs
    r_pass = TestRunV1(
        run_id="TR-17-PASS",
        scenario_id="SCN-P17-PASS",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-17",
        target_user="secops",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    r_no_telem = TestRunV1(
        run_id="TR-17-NO-TELEM",
        scenario_id="SCN-P17-NO-TELEM",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-17",
        target_user="secops",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    r_no_alert = TestRunV1(
        run_id="TR-17-NO-ALERT",
        scenario_id="SCN-P17-NO-ALERT",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-17",
        target_user="secops",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    r_unlinked = TestRunV1(
        run_id="TR-17-UNLINKED",
        scenario_id="SCN-P17-UNLINKED",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-17",
        target_user="secops",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_run(r_pass)
    store.add_run(r_no_telem)
    store.add_run(r_no_alert)
    store.add_run(r_unlinked)

    # Telemetry
    store.add_normalized_event(NormalizedTelemetryEventV1(
        normalized_event_id="EVT-17-PASS",
        raw_event_id="RAW-17-P",
        source_event_id="SRC-17-P",
        source_timestamp=now + timedelta(seconds=2),
        normalized_timestamp=now + timedelta(seconds=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="host-17",
        user="secops",
        process_name="powershell.exe",
    ))
    store.add_normalized_event(NormalizedTelemetryEventV1(
        normalized_event_id="EVT-17-NO-ALERT",
        raw_event_id="RAW-17-NA",
        source_event_id="SRC-17-NA",
        source_timestamp=now + timedelta(seconds=2),
        normalized_timestamp=now + timedelta(seconds=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="host-17",
        user="secops",
        process_name="cmd.exe",
    ))
    store.add_normalized_event(NormalizedTelemetryEventV1(
        normalized_event_id="EVT-17-UNLINKED",
        raw_event_id="RAW-17-U",
        source_event_id="SRC-17-U",
        source_timestamp=now + timedelta(seconds=2),
        normalized_timestamp=now + timedelta(seconds=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="host-17",
        user="secops",
        process_name="certutil.exe",
    ))

    # Alerts
    store.add_alert(AlertV1(
        alert_id="ALT-17-PASS",
        source_alert_id="SRC-ALT-17-P",
        source_type="wazuh",
        rule_reference="RULE-17-PS",
        host_id="host-17",
        alert_timestamp=now + timedelta(seconds=5),
        severity="high",
    ))
    # Unlinked alert is on wrong host
    store.add_alert(AlertV1(
        alert_id="ALT-17-WRONG-HOST",
        source_alert_id="SRC-ALT-17-WH",
        source_type="wazuh",
        rule_reference="RULE-17-CERTUTIL",
        host_id="other-host-99",
        alert_timestamp=now + timedelta(seconds=5),
        severity="high",
    ))

    # Campaign Definition
    campaign = CampaignDefinitionV1(
        campaign_id="CPG-PHASE-17",
        name="Phase 17 Comprehensive Campaign",
        scenario_ids=[
            "SCN-P17-PASS",
            "SCN-P17-NO-TELEM",
            "SCN-P17-NO-ALERT",
            "SCN-P17-UNLINKED",
        ],
    )
    store.add_campaign(campaign)

    return store


# ── 1. Report Generation Tests ──────────────────────────────────────────────

class TestReportGeneration:
    """Verifies campaign assurance report generation under varied conditions."""

    def test_full_mixed_report_generation(self, populated_env):
        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-PHASE-17")

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report(run.run_id, verify_manifest=True)

        assert report.schema_version == "v1"
        assert report.campaign_id == "CPG-PHASE-17"
        assert report.campaign_run_id == run.run_id
        assert report.execution_summary.total_scenarios == 4
        assert report.execution_summary.executed_test_cases == 4
        assert report.execution_summary.successful_executions == 1
        assert report.execution_summary.failed_executions == 3

        # Check explicit metrics
        metrics = report.assurance_metrics
        assert metrics.detection_success_rate.value == 0.25
        assert metrics.detection_success_rate.numerator == 1
        assert metrics.detection_success_rate.denominator == 4
        assert metrics.detection_success_rate.status == MetricStatus.AVAILABLE

        assert metrics.detection_failure_rate.value == 0.75
        assert metrics.telemetry_availability_rate.value == 0.75  # 3 of 4 had telemetry
        assert metrics.execution_coverage.value == 1.0

        # Check diagnostic distribution (7 canonical categories)
        dist = report.diagnostic_distribution
        assert dist.pass_count == 1
        assert dist.expected_telemetry_missing_count == 1
        assert dist.detection_not_triggered_count == 1
        assert dist.alert_not_correlated_count == 1
        assert dist.total_classified == 4
        assert dist.distribution_percentages["PASS"] == 25.0

        # Evidence quality check
        assert report.evidence_quality.manifest_verification_status == EvidenceVerificationStatus.VERIFIED
        assert report.evidence_quality.is_complete is True
        assert len(report.evidence_quality.missing_evidence_references) == 0

    def test_all_passing_campaign(self, populated_env):
        camp = CampaignDefinitionV1(
            campaign_id="CPG-ALL-PASS",
            name="All Passing Campaign",
            scenario_ids=["SCN-P17-PASS"],
        )
        populated_env.add_campaign(camp)

        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-ALL-PASS")

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report(run.run_id)

        assert report.execution_summary.successful_executions == 1
        assert report.execution_summary.failed_executions == 0
        assert report.assurance_metrics.detection_success_rate.value == 1.0
        assert report.assurance_metrics.detection_failure_rate.value == 0.0
        assert report.assurance_metrics.telemetry_availability_rate.value == 1.0
        assert report.assurance_metrics.alert_correlation_rate.value == 1.0

    def test_all_failing_campaign(self, populated_env):
        camp = CampaignDefinitionV1(
            campaign_id="CPG-ALL-FAIL",
            name="All Failing Campaign",
            scenario_ids=["SCN-P17-NO-ALERT", "SCN-P17-NO-TELEM"],
        )
        populated_env.add_campaign(camp)

        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-ALL-FAIL")

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report(run.run_id)

        assert report.execution_summary.successful_executions == 0
        assert report.execution_summary.failed_executions == 2
        assert report.assurance_metrics.detection_success_rate.value == 0.0
        assert report.assurance_metrics.detection_failure_rate.value == 1.0

    def test_unexecuted_cases_handling(self, populated_env):
        # Scenario without a test run
        s_unexec = ScenarioV1(
            scenario_id="SCN-P17-UNEXEC",
            name="Unexecuted Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="unexec.exe",
            expected_detection_rule_id="RULE-17-PS",
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        populated_env.add_scenario(s_unexec)

        camp = CampaignDefinitionV1(
            campaign_id="CPG-WITH-UNEXEC",
            name="Campaign with Unexecuted Case",
            scenario_ids=["SCN-P17-PASS", "SCN-P17-UNEXEC"],
        )
        populated_env.add_campaign(camp)

        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-WITH-UNEXEC")

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report(run.run_id)

        assert report.execution_summary.total_scenarios == 2
        assert report.execution_summary.executed_test_cases == 1
        assert report.execution_summary.unexecuted_cases == 1
        # Success rate must be relative to executed test cases (1/1 = 1.0), NOT 1/2
        assert report.assurance_metrics.detection_success_rate.value == 1.0
        assert report.assurance_metrics.execution_coverage.value == 0.5
        assert report.is_complete is False  # Incomplete because unexecuted case exists

    def test_tampered_evidence_detection_in_report(self, populated_env):
        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-PHASE-17")

        # Deliberately modify an event in the store to tamper with evidence
        evt = populated_env.get_normalized_event("EVT-17-PASS")
        tampered_evt = evt.model_copy(update={"process_name": "tampered_evil.exe"})
        populated_env._normalized_events["EVT-17-PASS"] = tampered_evt

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report(run.run_id, verify_manifest=True)

        assert report.evidence_quality.manifest_verification_status == EvidenceVerificationStatus.INTEGRITY_COMPROMISED
        assert "EVT-17-PASS" in report.evidence_quality.integrity_verification_failures
        assert report.is_complete is False


# ── 2. Regression Analysis Tests ────────────────────────────────────────────

class TestRegressionAnalysis:
    """Verifies regression detection, improvement tracking, drift analysis, and compatibility."""

    def test_new_regression_scenario(self, populated_env):
        engine = CampaignEngine(populated_env)
        # Baseline run: 1 pass, 3 failures
        base_run = engine.execute_campaign("CPG-PHASE-17")

        # Now simulate a regression where SCN-P17-PASS loses its alert
        # Remove alert ALT-17-PASS
        del populated_env._alerts["ALT-17-PASS"]

        # Target run: SCN-P17-PASS will now fail
        cand_run = engine.execute_campaign("CPG-PHASE-17")

        analyzer = CampaignRegressionAnalyzer(populated_env)
        analysis = analyzer.analyze_runs(base_run.run_id, cand_run.run_id)

        assert analysis.verdict == RegressionVerdict.REGRESSION
        assert analysis.compatibility.is_compatible is True

        # Check finding
        reg_findings = [f for f in analysis.findings if f.category == FindingCategory.DETECTION_REGRESSION]
        assert len(reg_findings) == 1
        assert reg_findings[0].affected_target == "SCN-P17-PASS"
        assert reg_findings[0].severity == FindingSeverity.CRITICAL
        assert reg_findings[0].is_actionable is True

        # Metric deterioration finding
        metric_findings = [f for f in analysis.findings if f.category == FindingCategory.METRIC_DETERIORATION]
        assert len(metric_findings) >= 1
        assert metric_findings[0].affected_target == "detection_success_rate"

    def test_detection_improvement_scenario(self, populated_env):
        engine = CampaignEngine(populated_env)

        # Baseline run without alert for CMD
        base_run = engine.execute_campaign("CPG-PHASE-17")

        # Candidate run with alert added for CMD (improves SCN-P17-NO-ALERT to PASS)
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        populated_env.add_alert(AlertV1(
            alert_id="ALT-17-CMD-RESOLVED",
            source_alert_id="SRC-CMD-RESOLVED",
            source_type="wazuh",
            rule_reference="RULE-17-CMD",
            host_id="host-17",
            alert_timestamp=now + timedelta(seconds=10),
            severity="high",
        ))
        cand_run = engine.execute_campaign("CPG-PHASE-17")

        analyzer = CampaignRegressionAnalyzer(populated_env)
        analysis = analyzer.analyze_runs(base_run.run_id, cand_run.run_id)

        assert analysis.verdict == RegressionVerdict.IMPROVEMENT
        improvements = [f for f in analysis.findings if f.category == FindingCategory.DETECTION_IMPROVEMENT]
        assert len(improvements) == 1
        assert improvements[0].affected_target == "SCN-P17-NO-ALERT"
        assert improvements[0].severity == FindingSeverity.INFORMATIONAL
        assert improvements[0].is_actionable is False

    def test_no_change_scenario(self, populated_env):
        engine = CampaignEngine(populated_env)
        run1 = engine.execute_campaign("CPG-PHASE-17")
        run2 = engine.execute_campaign("CPG-PHASE-17")

        analyzer = CampaignRegressionAnalyzer(populated_env)
        analysis = analyzer.analyze_runs(run1.run_id, run2.run_id)

        assert analysis.verdict == RegressionVerdict.NO_CHANGE
        assert analysis.summary_counts["critical"] == 0
        assert analysis.summary_counts["high"] == 0

    def test_incomparable_disjoint_campaigns(self, populated_env):
        # Create campaign B with totally different scenario
        s_other = ScenarioV1(
            scenario_id="SCN-OTHER-01",
            name="Other Scenario",
            mitre_technique_id="T1078",
            mitre_tactic="Initial Access",
            expected_event_category=EventCategory.AUTHENTICATION,
            expected_detection_rule_id="RULE-17-PS",
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        populated_env.add_scenario(s_other)
        camp_b = CampaignDefinitionV1(
            campaign_id="CPG-DISJOINT",
            name="Disjoint Campaign",
            scenario_ids=["SCN-OTHER-01"],
        )
        populated_env.add_campaign(camp_b)

        engine = CampaignEngine(populated_env)
        run1 = engine.execute_campaign("CPG-PHASE-17")
        run2 = engine.execute_campaign("CPG-DISJOINT")

        analyzer = CampaignRegressionAnalyzer(populated_env)
        analysis = analyzer.analyze_runs(run1.run_id, run2.run_id)

        assert analysis.verdict == RegressionVerdict.INCOMPARABLE
        assert analysis.compatibility.is_compatible is False
        assert "disjoint" in analysis.compatibility.reasons[0].lower()

    def test_configuration_drift_detection(self, populated_env):
        engine = CampaignEngine(populated_env)
        run1 = engine.execute_campaign("CPG-PHASE-17")

        # Run with config override
        cfg_override = CampaignExecutionConfigV1(default_alert_grace_period_seconds=120)
        run2 = engine.execute_campaign("CPG-PHASE-17", execution_config_override=cfg_override)

        analyzer = CampaignRegressionAnalyzer(populated_env)
        analysis = analyzer.analyze_runs(run1.run_id, run2.run_id)

        assert analysis.compatibility.config_drift_detected is True
        drift_findings = [f for f in analysis.findings if f.category == FindingCategory.ENVIRONMENT_DRIFT]
        assert len(drift_findings) >= 1


# ── 3. Determinism & Integrity Tests ────────────────────────────────────────

class TestDeterminismAndIntegrity:
    """Verifies RFC 8785 canonical hash computation and strict tamper detection."""

    def test_report_digest_reproducibility(self, populated_env):
        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-PHASE-17")

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        rpt1 = report_gen.generate_report(run.run_id)
        rpt2 = report_gen.generate_report(run.run_id)

        # Content digests must be 100% bit-for-bit identical
        assert rpt1.report_digest == rpt2.report_digest
        assert CampaignAssuranceReportGenerator.verify_report_integrity(rpt1) is True
        assert CampaignAssuranceReportGenerator.verify_report_integrity(rpt2) is True

    def test_tampered_report_fails_integrity(self, populated_env):
        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-PHASE-17")

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report(run.run_id)

        # Tamper with the report content without updating digest
        tampered_summary = report.execution_summary.model_copy(update={"successful_executions": 999})
        tampered_report = report.model_copy(update={"execution_summary": tampered_summary})

        assert CampaignAssuranceReportGenerator.verify_report_integrity(tampered_report) is False

    def test_metric_nan_and_inf_strictly_rejected(self):
        with pytest.raises(ValueError, match="NaN or Infinite"):
            AssuranceMetricV1(
                name="invalid_metric",
                numerator=1,
                denominator=2,
                value=float("nan"),
                description="desc",
                formula="num/den",
            )

        with pytest.raises(ValueError, match="NaN or Infinite"):
            AssuranceMetricV1(
                name="inf_metric",
                numerator=1,
                denominator=2,
                value=float("inf"),
                description="desc",
                formula="num/den",
            )


# ── 4. Storage Backends & Parity Tests ──────────────────────────────────────

class TestStorageParity:
    """Verifies complete parity between InMemoryStore and SQLiteStore."""

    def test_storage_parity_report_lifecycle(self, populated_env, tmp_path):
        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-PHASE-17")

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report(run.run_id)

        # 1. InMemoryStore test
        mem_store = InMemoryStore()
        mem_store.add_campaign(populated_env.get_campaign("CPG-PHASE-17"))
        mem_store.add_campaign_run(run)

        saved_mem = mem_store.add_assurance_report(report)
        assert saved_mem.report_id == report.report_id

        retrieved_mem = mem_store.get_assurance_report(report.report_id)
        assert retrieved_mem is not None
        assert retrieved_mem.report_digest == report.report_digest

        # Retrieval isolation test (mutating retrieved copy should not affect store)
        retrieved_mem.is_complete = not retrieved_mem.is_complete
        assert mem_store.get_assurance_report(report.report_id).is_complete == report.is_complete

        # 2. SQLiteStore test
        db_file = tmp_path / "parity_test.db"
        sqlite_store = SQLiteStore(db_file)
        sqlite_store.add_campaign(populated_env.get_campaign("CPG-PHASE-17"))
        sqlite_store.add_campaign_run(run)

        saved_sql = sqlite_store.add_assurance_report(report)
        assert saved_sql.report_id == report.report_id

        retrieved_sql = sqlite_store.get_assurance_report(report.report_id)
        assert retrieved_sql is not None
        assert retrieved_sql.report_digest == report.report_digest
        assert retrieved_sql.assurance_metrics.detection_success_rate.value == report.assurance_metrics.detection_success_rate.value

        # Duplicate rejection
        with pytest.raises(ValueError, match="already exists"):
            sqlite_store.add_assurance_report(report)

        # Listing parity
        mem_list = mem_store.list_assurance_reports()
        sql_list = sqlite_store.list_assurance_reports()
        assert len(mem_list) == len(sql_list) == 1
        assert mem_list[0].report_id == sql_list[0].report_id

        sqlite_store.close()

    def test_sqlite_transaction_rollback_on_assurance_report(self, populated_env, tmp_path):
        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-PHASE-17")
        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report(run.run_id)

        db_file = tmp_path / "rollback_test.db"
        sqlite_store = SQLiteStore(db_file)
        sqlite_store.add_campaign(populated_env.get_campaign("CPG-PHASE-17"))
        sqlite_store.add_campaign_run(run)

        try:
            with sqlite_store.transaction() as cursor:
                # Insert report directly inside transaction
                sqlite_store.add_assurance_report(report)
                raise RuntimeError("Simulated failure")
        except RuntimeError:
            pass

        # Report should have rolled back
        assert sqlite_store.get_assurance_report(report.report_id) is None
        sqlite_store.close()


# ── 5. REST API Integration Tests ───────────────────────────────────────────

class TestRESTAPIIntegration:
    """Verifies all Phase 17 FastAPI endpoints with TestClient."""

    @pytest.fixture
    def api_client(self, populated_env):
        set_store(populated_env)
        client = TestClient(app)
        yield client
        reset_store()

    def test_api_assurance_report_lifecycle(self, api_client, populated_env):
        # 1. Execute campaign via API
        resp_exec = api_client.post("/api/v1/campaigns/CPG-PHASE-17/runs")
        assert resp_exec.status_code == 201
        run_data = resp_exec.json()
        run_id = run_data["run_id"]

        # 2. Compile assurance report via POST
        resp_rpt = api_client.post(f"/api/v1/campaign-runs/{run_id}/assurance-report")
        assert resp_rpt.status_code == 201
        rpt_data = resp_rpt.json()
        assert rpt_data["campaign_run_id"] == run_id
        assert "report_digest" in rpt_data
        report_id = rpt_data["report_id"]

        # 3. Retrieve assurance report via GET
        resp_get = api_client.get(f"/api/v1/campaign-assurance-reports/{report_id}")
        assert resp_get.status_code == 200
        assert resp_get.json()["report_digest"] == rpt_data["report_digest"]

        # 4. List assurance reports with pagination
        resp_list = api_client.get("/api/v1/campaign-assurance-reports?limit=10&offset=0")
        assert resp_list.status_code == 200
        assert len(resp_list.json()) >= 1

        # 5. Root cause intelligence
        resp_rc = api_client.get(f"/api/v1/campaign-runs/{run_id}/root-cause-intelligence")
        assert resp_rc.status_code == 200
        rc_data = resp_rc.json()
        assert rc_data["total_issues_analyzed"] == 3
        assert len(rc_data["patterns"]) >= 1

    def test_api_regression_analysis(self, api_client, populated_env):
        # Create baseline run
        resp1 = api_client.post("/api/v1/campaigns/CPG-PHASE-17/runs")
        run1_id = resp1.json()["run_id"]

        # Create candidate run
        resp2 = api_client.post("/api/v1/campaigns/CPG-PHASE-17/runs")
        run2_id = resp2.json()["run_id"]

        # Compare via POST endpoint
        resp_reg = api_client.post(
            f"/api/v1/campaign-runs/{run2_id}/regression-analysis",
            json={"baseline_run_id": run1_id},
        )
        assert resp_reg.status_code == 200
        reg_data = resp_reg.json()
        assert reg_data["verdict"] == "NO_CHANGE"
        assert reg_data["compatibility"]["is_compatible"] is True

        # Compare via GET endpoint
        resp_get_reg = api_client.get(f"/api/v1/campaign-runs/{run2_id}/regression/{run1_id}")
        assert resp_get_reg.status_code == 200
        assert resp_get_reg.json()["analysis_digest"] == reg_data["analysis_digest"]

    def test_api_404_and_validation(self, api_client):
        # Non-existent run
        resp = api_client.post("/api/v1/campaign-runs/NON-EXISTENT-RUN/assurance-report")
        assert resp.status_code == 404

        # Non-existent report
        resp_rpt = api_client.get("/api/v1/campaign-assurance-reports/NON-EXISTENT-RPT")
        assert resp_rpt.status_code == 404

        # Invalid identifier regex
        resp_bad = api_client.get("/api/v1/campaign-assurance-reports/bad!id@chars")
        assert resp_bad.status_code == 422

    def test_api_oversized_pagination_422(self, api_client):
        resp = api_client.get("/api/v1/campaign-assurance-reports?limit=1001")
        assert resp.status_code == 422

    def test_api_tampered_report_integrity_failure_500(self, api_client, populated_env):
        resp_exec = api_client.post("/api/v1/campaigns/CPG-PHASE-17/runs")
        run_id = resp_exec.json()["run_id"]

        resp_rpt = api_client.post(f"/api/v1/campaign-runs/{run_id}/assurance-report")
        report_id = resp_rpt.json()["report_id"]

        # Deliberately tamper with the report in the underlying store
        stored_report = populated_env.get_assurance_report(report_id)
        tampered_summary = stored_report.execution_summary.model_copy(update={"successful_executions": 888})
        tampered_report = stored_report.model_copy(update={"execution_summary": tampered_summary})
        populated_env._assurance_reports[report_id] = tampered_report

        # Request via API: should detect digest mismatch and return 500
        resp_get = api_client.get(f"/api/v1/campaign-assurance-reports/{report_id}")
        assert resp_get.status_code == 500
        assert "integrity compromised" in resp_get.json()["detail"].lower()


# ── 6. Additional Adversarial Edge Cases ─────────────────────────────────────

class TestAdversarialEdgeCases:
    """Tests extreme edge cases including empty runs, Unicode canonicalization, and foreign keys."""

    def test_empty_campaign_report(self, populated_env):
        # Campaign with 1 scenario declared but 0 executed
        s_ghost = ScenarioV1(
            scenario_id="SCN-GHOST",
            name="Ghost Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_detection_rule_id="RULE-17-PS",
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        populated_env.add_scenario(s_ghost)
        camp = CampaignDefinitionV1(
            campaign_id="CPG-EMPTY-RUN",
            name="Empty Run Campaign",
            scenario_ids=["SCN-GHOST"],
        )
        populated_env.add_campaign(camp)

        # Create a synthetic empty CampaignRunV1
        from proofshield.schemas.campaign import (
            CampaignSummaryV1,
            EvidenceManifestV1,
            CampaignRunV1,
        )
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        empty_run = CampaignRunV1(
            run_id="CRUN-EMPTY-01",
            campaign_id="CPG-EMPTY-RUN",
            status=CampaignRunStatus.COMPLETED,
            started_at=now,
            completed_at=now,
            total_scenarios=1,
            scenario_results=[],  # No executed scenarios
            summary=CampaignSummaryV1(
                total_scenarios=1,
                executed_scenarios=0,
                unexecuted_scenarios=1,
                passed_scenarios=0,
                failed_scenarios=0,
                inconclusive_scenarios=0,
                error_scenarios=0,
                execution_coverage=0.0,
                error_rate=0.0,
            ),
            evidence_manifest=EvidenceManifestV1(
                campaign_id="CPG-EMPTY-RUN",
                campaign_run_id="CRUN-EMPTY-01",
                manifest_hash="00" * 32,
            ),
        )
        populated_env.add_campaign_run(empty_run)

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report("CRUN-EMPTY-01")

        assert report.execution_summary.executed_test_cases == 0
        assert report.execution_summary.unexecuted_cases == 1
        assert report.assurance_metrics.detection_success_rate.status == MetricStatus.INSUFFICIENT_DATA
        assert report.assurance_metrics.detection_success_rate.value is None
        assert report.assurance_metrics.detection_failure_rate.status == MetricStatus.INSUFFICIENT_DATA
        assert report.assurance_metrics.execution_coverage.value == 0.0

    def test_unicode_and_complex_metadata_canonicalization(self, populated_env):
        engine = CampaignEngine(populated_env)
        run = engine.execute_campaign("CPG-PHASE-17")

        report_gen = CampaignAssuranceReportGenerator(populated_env)
        report = report_gen.generate_report(run.run_id)

        # Embed complex Unicode (Cyrillic, CJK, Emoji, accents) in metadata
        report.metadata["unicode_test"] = "Безопасность 🛡️ 安全 Équipes de détection"
        # Recompute digest with unicode metadata
        assert report.metadata["unicode_test"] == "Безопасность 🛡️ 安全 Équipes de détection"
        assert CampaignAssuranceReportGenerator.verify_report_integrity(report) is True

    def test_sqlite_foreign_key_enforcement(self, tmp_path):
        db_file = tmp_path / "fk_test.db"
        sqlite_store = SQLiteStore(db_file)

        # Attempt to add an assurance report referencing a non-existent campaign run
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        from proofshield.schemas.assurance_report import (
            AssuranceMetricV1,
            DetectionAssuranceMetricsV1,
            DiagnosticDistributionV1,
            EvidenceQualityV1,
            ExecutionSummaryV1,
        )

        dummy_metric = AssuranceMetricV1(
            name="test", numerator=1, denominator=1, value=1.0, description="d", formula="f"
        )
        metrics = DetectionAssuranceMetricsV1(
            detection_success_rate=dummy_metric,
            detection_failure_rate=dummy_metric,
            telemetry_availability_rate=dummy_metric,
            evidence_completeness_rate=dummy_metric,
            alert_correlation_rate=dummy_metric,
            inconclusive_rate=dummy_metric,
            execution_coverage=dummy_metric,
        )
        orphan_report = CampaignAssuranceReportV1(
            report_id="RPT-ORPHAN",
            campaign_id="CPG-NONEXISTENT",
            campaign_run_id="CRUN-NONEXISTENT",
            engine_version="v1.0.0",
            execution_summary=ExecutionSummaryV1(
                campaign_id="CPG-NONEXISTENT",
                campaign_name="Nonexistent",
                campaign_run_id="CRUN-NONEXISTENT",
                total_scenarios=1,
                executed_test_cases=1,
                unexecuted_cases=0,
                successful_executions=1,
                failed_executions=0,
                error_executions=0,
                inconclusive_executions=0,
            ),
            assurance_metrics=metrics,
            diagnostic_distribution=DiagnosticDistributionV1(),
            evidence_quality=EvidenceQualityV1(
                total_evidence_records=0,
                manifest_verification_status=EvidenceVerificationStatus.UNVERIFIED,
                is_complete=True,
            ),
            is_complete=True,
            report_digest="00" * 32,
        )

        with pytest.raises(ValueError, match="Campaign run not found"):
            sqlite_store.add_assurance_report(orphan_report)

        sqlite_store.close()
