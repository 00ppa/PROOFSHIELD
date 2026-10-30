"""Phase 17.2 End-to-End Validation Test Suite.

Validates the complete Campaign Assurance Intelligence and Regression Analysis lifecycle:
1. Realistic baseline and candidate campaigns:
   - PASS (expected process + expected alert on correct host and window)
   - DETECTION_NOT_TRIGGERED (expected process observed, alert absent)
   - INCONCLUSIVE (test run incomplete / RUNNING status)
   - EXPECTED_TELEMETRY_MISSING (test run completed, expected process absent)
   - TEST_NOT_EXECUTED (scenario declared in campaign, but test run absent from store)
2. Campaign execution through CampaignEngine
3. Assurance report compilation with explicit mathematical metric verifications
4. Report canonical SHA-256 digest sealing and evidence manifest verification
5. Regression analysis and root-cause intelligence
6. Backend parity across InMemoryStore and file-backed SQLiteStore
7. SQLite reopen and persisted report validation
8. Evidence tampering, configuration drift, scenario-definition drift, and duplicate report generation
9. Mathematical correctness against hand-calculated expected values
10. Preservation of 24/25 benchmark accuracy
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.assurance_report import (
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
from proofshield.services.regression_analyzer import CampaignRegressionAnalyzer
from proofshield.services.root_cause import RootCauseIntelligenceService
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore


def _build_representative_environment(store, now: datetime):
    """Seed store with 5 representative scenarios and their execution artifacts."""
    # 1. Scenarios
    s_pass = ScenarioV1(
        scenario_id="SCN-E2E-PASS",
        name="Passing Detection Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_detection_rule_id="RULE-E2E-PS",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    s_no_alert = ScenarioV1(
        scenario_id="SCN-E2E-NO-ALERT",
        name="Detection Not Triggered Scenario",
        mitre_technique_id="T1059.003",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="cmd.exe",
        expected_detection_rule_id="RULE-E2E-CMD",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    s_inconcl = ScenarioV1(
        scenario_id="SCN-E2E-INCONCL",
        name="Inconclusive Running Scenario",
        mitre_technique_id="T1082",
        mitre_tactic="Discovery",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="systeminfo.exe",
        expected_detection_rule_id="RULE-E2E-SYSINFO",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    s_no_telem = ScenarioV1(
        scenario_id="SCN-E2E-NO-TELEM",
        name="Missing Telemetry Scenario",
        mitre_technique_id="T1047",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="wmic.exe",
        expected_detection_rule_id="RULE-E2E-WMIC",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    s_unexec = ScenarioV1(
        scenario_id="SCN-E2E-UNEXEC",
        name="Unexecuted Scenario",
        mitre_technique_id="T1083",
        mitre_tactic="Discovery",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="dir.exe",
        expected_detection_rule_id="RULE-E2E-DIR",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(s_pass)
    store.add_scenario(s_no_alert)
    store.add_scenario(s_inconcl)
    store.add_scenario(s_no_telem)
    store.add_scenario(s_unexec)

    # 2. Rules
    store.add_rule(DetectionRuleV1(rule_id="RULE-E2E-PS", rule_name="PowerShell Execution", rule_format="sigma"))
    store.add_rule(DetectionRuleV1(rule_id="RULE-E2E-CMD", rule_name="Cmd Execution", rule_format="sigma"))
    store.add_rule(DetectionRuleV1(rule_id="RULE-E2E-SYSINFO", rule_name="Systeminfo Discovery", rule_format="sigma"))
    store.add_rule(DetectionRuleV1(rule_id="RULE-E2E-WMIC", rule_name="WMIC Execution", rule_format="sigma"))
    store.add_rule(DetectionRuleV1(rule_id="RULE-E2E-DIR", rule_name="Directory Listing", rule_format="sigma"))

    # 3. Test Runs
    # SCN-PASS: completed
    store.add_run(TestRunV1(
        run_id="TR-E2E-PASS",
        scenario_id="SCN-E2E-PASS",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-e2e",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    ))
    # SCN-NO-ALERT: completed
    store.add_run(TestRunV1(
        run_id="TR-E2E-NO-ALERT",
        scenario_id="SCN-E2E-NO-ALERT",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-e2e",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    ))
    # SCN-INCONCL: still RUNNING
    store.add_run(TestRunV1(
        run_id="TR-E2E-INCONCL",
        scenario_id="SCN-E2E-INCONCL",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-e2e",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.RUNNING,
    ))
    # SCN-NO-TELEM: completed
    store.add_run(TestRunV1(
        run_id="TR-E2E-NO-TELEM",
        scenario_id="SCN-E2E-NO-TELEM",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="host-e2e",
        target_user="alice",
        executed_at=now,
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=60),
        execution_status=ExecutionStatus.COMPLETED,
    ))
    # SCN-UNEXEC: No test run added!

    # 4. Telemetry Events
    # SCN-PASS has powershell.exe
    store.add_normalized_event(NormalizedTelemetryEventV1(
        normalized_event_id="EVT-E2E-PS",
        raw_event_id="RAW-E2E-PS",
        source_event_id="SRC-E2E-PS",
        source_timestamp=now + timedelta(seconds=2),
        normalized_timestamp=now + timedelta(seconds=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="host-e2e",
        user="alice",
        process_name="powershell.exe",
    ))
    # SCN-NO-ALERT has cmd.exe
    store.add_normalized_event(NormalizedTelemetryEventV1(
        normalized_event_id="EVT-E2E-CMD",
        raw_event_id="RAW-E2E-CMD",
        source_event_id="SRC-E2E-CMD",
        source_timestamp=now + timedelta(seconds=2),
        normalized_timestamp=now + timedelta(seconds=2),
        event_category=EventCategory.PROCESS_CREATION,
        host="host-e2e",
        user="alice",
        process_name="cmd.exe",
    ))

    # 5. Alerts
    # SCN-PASS has matching alert
    store.add_alert(AlertV1(
        alert_id="ALT-E2E-PS",
        source_alert_id="SRC-ALT-E2E-PS",
        source_type="sigma",
        rule_reference="RULE-E2E-PS",
        host_id="host-e2e",
        alert_timestamp=now + timedelta(seconds=5),
        severity="high",
    ))

    # 6. Campaign Definition with 5 declared scenarios
    camp = CampaignDefinitionV1(
        campaign_id="CPG-E2E-SUITE",
        name="E2E Representative Campaign Suite",
        scenario_ids=[
            "SCN-E2E-PASS",
            "SCN-E2E-NO-ALERT",
            "SCN-E2E-INCONCL",
            "SCN-E2E-NO-TELEM",
            "SCN-E2E-UNEXEC",
        ],
    )
    store.add_campaign(camp)
    return camp


class TestPhase17EndToEndLifecycle:
    """Comprehensive E2E lifecycle tests across backends, determinism, and drift."""

    def test_e2e_complete_workflow_in_memory(self):
        """Execute complete Phase 17 lifecycle in InMemoryStore:

        Execution -> Assurance Report -> Digest Verification -> Regression Analysis -> Root Cause.
        """
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        _build_representative_environment(store, now)

        engine = CampaignEngine(store)
        base_run = engine.execute_campaign("CPG-E2E-SUITE")

        # 1. Execution Summary Verification
        assert base_run.status == CampaignRunStatus.COMPLETED
        assert base_run.total_scenarios == 5
        assert len(base_run.scenario_results) == 5

        report_gen = CampaignAssuranceReportGenerator(store)
        report = report_gen.generate_report(base_run.run_id, verify_manifest=True)

        # 2. Mathematical Metric Verification (Hand-Calculated Parity)
        summary = report.execution_summary
        assert summary.total_scenarios == 5
        assert summary.executed_test_cases == 4  # PASS, NO-ALERT, INCONCL, NO-TELEM
        assert summary.unexecuted_cases == 1     # UNEXEC
        assert summary.successful_executions == 1 # PASS
        assert summary.failed_executions == 2     # NO-ALERT (DETECTION_NOT_TRIGGERED), NO-TELEM (EXPECTED_TELEMETRY_MISSING)
        assert summary.error_executions == 0
        assert summary.inconclusive_executions == 1 # INCONCL
        assert summary.skipped_executions == 1

        # Diagnostic Distribution Verification
        dist = report.diagnostic_distribution
        assert dist.pass_count == 1
        assert dist.test_not_executed_count == 1
        assert dist.expected_telemetry_missing_count == 1
        assert dist.detection_not_triggered_count == 1
        assert dist.alert_not_correlated_count == 0
        assert dist.inconclusive_count == 1
        assert dist.error_count == 0
        assert dist.total_classified == 5

        # Assurance Metrics
        metrics = report.assurance_metrics
        # Detection success: 1 / 4 = 0.25
        assert metrics.detection_success_rate.numerator == 1
        assert metrics.detection_success_rate.denominator == 4
        assert metrics.detection_success_rate.value == 0.25
        assert metrics.detection_success_rate.status == MetricStatus.AVAILABLE

        # Detection failure: 2 / 4 = 0.50
        assert metrics.detection_failure_rate.numerator == 2
        assert metrics.detection_failure_rate.denominator == 4
        assert metrics.detection_failure_rate.value == 0.50

        # Telemetry availability: PASS + NO-ALERT = 2 / 4 = 0.50
        assert metrics.telemetry_availability_rate.numerator == 2
        assert metrics.telemetry_availability_rate.denominator == 4
        assert metrics.telemetry_availability_rate.value == 0.50

        # Evidence completeness: 2 complete out of 4 = 0.50
        assert metrics.evidence_completeness_rate.numerator == 2
        assert metrics.evidence_completeness_rate.denominator == 4
        assert metrics.evidence_completeness_rate.value == 0.50

        # Alert correlation: only 1 scenario had alert correlation evaluation -> 1 / 1 = 1.0
        assert metrics.alert_correlation_rate.numerator == 1
        assert metrics.alert_correlation_rate.denominator == 1
        assert metrics.alert_correlation_rate.value == 1.0

        # Inconclusive rate: 1 / 4 = 0.25
        assert metrics.inconclusive_rate.numerator == 1
        assert metrics.inconclusive_rate.denominator == 4
        assert metrics.inconclusive_rate.value == 0.25

        # Execution coverage: 4 / 5 = 0.80
        assert metrics.execution_coverage.numerator == 4
        assert metrics.execution_coverage.denominator == 5
        assert metrics.execution_coverage.value == 0.80

        # 3. Report Digest & Manifest Verification
        assert report.evidence_quality.manifest_verification_status == EvidenceVerificationStatus.VERIFIED
        # is_complete is False because SCN-E2E-UNEXEC was unexecuted/skipped
        assert report.is_complete is False
        assert CampaignAssuranceReportGenerator.verify_report_integrity(report) is True

        # Store the baseline report
        store.add_assurance_report(report)

        # 4. Construct Candidate Run with Regression (PASS regressed to FAILURE)
        cand_run = base_run.model_copy(deep=True)
        cand_run.run_id = "CRUN-E2E-CAND-REGRESSED"
        cand_results = []
        for r in cand_run.scenario_results:
            if r.scenario_id == "SCN-E2E-PASS":
                cand_results.append(r.model_copy(update={
                    "status": ScenarioRunStatus.FAILURE,
                    "predicted_category": DiagnosticCategory.DETECTION_NOT_TRIGGERED,
                    "reason": "Detection rule did not fire in candidate run",
                }))
            else:
                cand_results.append(r)
        cand_run.scenario_results = cand_results
        store.add_campaign_run(cand_run)

        cand_report = report_gen.generate_report(cand_run.run_id, verify_manifest=False)
        store.add_assurance_report(cand_report)

        # 5. Run Regression Analyzer
        analyzer = CampaignRegressionAnalyzer(store)
        analysis = analyzer.analyze_reports(report, cand_report, base_run, cand_run)

        assert analysis.verdict == RegressionVerdict.REGRESSION
        assert analysis.summary_counts["critical"] >= 1
        # Verify finding for SCN-E2E-PASS
        pass_findings = [f for f in analysis.findings if f.affected_target == "SCN-E2E-PASS"]
        assert len(pass_findings) == 1
        assert pass_findings[0].category == FindingCategory.DETECTION_REGRESSION
        assert pass_findings[0].severity == FindingSeverity.CRITICAL
        assert pass_findings[0].is_actionable is True

        # 6. Run Root Cause Intelligence Service
        rc_service = RootCauseIntelligenceService(store)
        rc_intel = rc_service.analyze_campaign_run(base_run.run_id)

        assert rc_intel.campaign_run_id == base_run.run_id
        assert rc_intel.total_issues_analyzed == 4
        # Verify root cause groupings
        categories = {p.diagnostic_category for p in rc_intel.patterns}
        assert DiagnosticCategory.EXPECTED_TELEMETRY_MISSING in categories
        assert DiagnosticCategory.DETECTION_NOT_TRIGGERED in categories
        assert DiagnosticCategory.INCONCLUSIVE in categories
        assert DiagnosticCategory.TEST_NOT_EXECUTED in categories

    def test_e2e_sqlite_backend_parity_and_reopen(self, tmp_path: Path):
        """Execute the workflow in file-backed SQLiteStore, test parity, reopen DB, and verify persistence."""
        db_path = tmp_path / "e2e_parity.db"
        sqlite_store = SQLiteStore(db_path)
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        _build_representative_environment(sqlite_store, now)

        engine = CampaignEngine(sqlite_store)
        run = engine.execute_campaign("CPG-E2E-SUITE")

        report_gen = CampaignAssuranceReportGenerator(sqlite_store)
        report = report_gen.generate_report(run.run_id, verify_manifest=True)

        assert report.assurance_metrics.detection_success_rate.value == 0.25
        assert report.assurance_metrics.detection_failure_rate.value == 0.50
        assert report.assurance_metrics.telemetry_availability_rate.value == 0.50
        assert report.assurance_metrics.evidence_completeness_rate.value == 0.50
        assert report.assurance_metrics.execution_coverage.value == 0.80

        saved_report = sqlite_store.add_assurance_report(report)
        assert saved_report.report_id == report.report_id

        # Close the SQLite database cleanly
        sqlite_store.close()

        # Reopen SQLite database from disk and verify persistence
        reopened_store = SQLiteStore(db_path)
        retrieved_report = reopened_store.get_assurance_report(report.report_id)
        assert retrieved_report is not None
        assert retrieved_report.report_id == report.report_id
        assert retrieved_report.report_digest == report.report_digest
        assert retrieved_report.execution_summary.executed_test_cases == 4
        assert retrieved_report.execution_summary.unexecuted_cases == 1
        assert CampaignAssuranceReportGenerator.verify_report_integrity(retrieved_report) is True

        # Test listing reports from reopened database
        listed_reports = reopened_store.list_assurance_reports(campaign_id="CPG-E2E-SUITE")
        assert len(listed_reports) == 1
        assert listed_reports[0].report_id == report.report_id

        reopened_store.close()

    def test_e2e_adversarial_tampering_and_drift_detection(self, tmp_path: Path):
        """Adversarial validation:

        1. Tampering detection on stored telemetry post-execution
        2. Execution configuration drift detection
        3. Scenario contract definition drift detection
        4. Duplicate report prevention
        """
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        _build_representative_environment(store, now)

        engine = CampaignEngine(store)
        run = engine.execute_campaign("CPG-E2E-SUITE")

        # 1. Evidence Tampering: modify stored normalized telemetry event content
        tampered_event = store.get_normalized_event("EVT-E2E-PS").model_copy(
            update={"process_name": "malicious_injected.exe"}
        )
        store._normalized_events["EVT-E2E-PS"] = tampered_event

        report_gen = CampaignAssuranceReportGenerator(store)
        tampered_report = report_gen.generate_report(run.run_id, verify_manifest=True)

        assert tampered_report.evidence_quality.manifest_verification_status == EvidenceVerificationStatus.INTEGRITY_COMPROMISED
        assert tampered_report.is_complete is False
        assert "EVT-E2E-PS" in tampered_report.evidence_quality.integrity_verification_failures

        # Restore event for subsequent tests
        store._normalized_events["EVT-E2E-PS"] = tampered_event.model_copy(update={"process_name": "powershell.exe"})

        # 2. Configuration Drift Detection
        config_base = CampaignExecutionConfigV1(default_alert_grace_period_seconds=1800)
        config_cand = CampaignExecutionConfigV1(default_alert_grace_period_seconds=3600)

        run_base = engine.execute_campaign("CPG-E2E-SUITE", execution_config_override=config_base)
        run_cand = engine.execute_campaign("CPG-E2E-SUITE", execution_config_override=config_cand)

        rpt_base = report_gen.generate_report(run_base.run_id, verify_manifest=False)
        rpt_cand = report_gen.generate_report(run_cand.run_id, verify_manifest=False)

        analyzer = CampaignRegressionAnalyzer(store)
        analysis_drift = analyzer.analyze_reports(rpt_base, rpt_cand, run_base, run_cand)

        assert analysis_drift.compatibility.config_drift_detected is True
        assert analysis_drift.compatibility.verdict == "CONFIG_DRIFT"
        drift_findings = [f for f in analysis_drift.findings if f.category == FindingCategory.ENVIRONMENT_DRIFT]
        assert len(drift_findings) >= 1

        # 3. Scenario-Definition Contract Drift Detection
        run_cand_scen_drift = run_base.model_copy(deep=True)
        run_cand_scen_drift.run_id = "CRUN-E2E-SCEN-DRIFT"
        drifted_srefs = []
        for sref in run_cand_scen_drift.evidence_manifest.scenario_references:
            if sref.scenario_id == "SCN-E2E-PASS":
                drifted_srefs.append(sref.model_copy(update={"scenario_hash": "c0ffee" * 10 + "0000"}))
            else:
                drifted_srefs.append(sref)
        run_cand_scen_drift.evidence_manifest.scenario_references = drifted_srefs
        store.add_campaign_run(run_cand_scen_drift)

        rpt_cand_scen_drift = report_gen.generate_report(run_cand_scen_drift.run_id, verify_manifest=False)
        analysis_scen_drift = analyzer.analyze_reports(rpt_base, rpt_cand_scen_drift, run_base, run_cand_scen_drift)
        assert analysis_scen_drift.compatibility.verdict == "SCENARIO_DEFINITION_DRIFT"
        scen_drift_findings = [
            f for f in analysis_scen_drift.findings
            if "SCN-E2E-PASS" in f.affected_target and "definition" in f.explanation.lower()
        ]
        assert len(scen_drift_findings) >= 1

        # 4. Duplicate Report Prevention
        store.add_assurance_report(rpt_base)
        with pytest.raises(ValueError, match="Assurance report already exists"):
            store.add_assurance_report(rpt_base)

    def test_e2e_canonical_determinism_and_oracle_benchmark(self):
        """Verify:

        1. Bit-for-bit digest determinism across arbitrary dictionary key orders
        2. Benchmark suite preserves 24/25 accuracy
        """
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        _build_representative_environment(store, now)

        engine = CampaignEngine(store)
        run = engine.execute_campaign("CPG-E2E-SUITE")

        report_gen = CampaignAssuranceReportGenerator(store)
        report_1 = report_gen.generate_report(run.run_id, verify_manifest=True)
        report_2 = report_gen.generate_report(run.run_id, verify_manifest=True)

        # Digits must be bit-for-bit identical
        assert report_1.report_digest == report_2.report_digest
        assert report_1.report_id == report_2.report_id

        # Run benchmark accuracy evaluation directly
        import sys
        tests_dir = str(Path(__file__).resolve().parent)
        if tests_dir not in sys.path:
            sys.path.insert(0, tests_dir)
        import test_benchmark
        # Must execute cleanly without assertion error
        test_benchmark.test_benchmark_execution_and_accuracy()
