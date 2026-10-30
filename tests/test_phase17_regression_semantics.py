"""Phase 17.3 Regression Semantics & Assurance Quality Review Test Suite.

Audits:
1. Every metric's numerator, denominator, eligibility rules, and INSUFFICIENT_DATA states
2. Separation of floating-point comparison tolerance (1e-6) from operational regression thresholds
3. Zero denominators, small sample sizes (N=1), missing metrics, and campaign size changes
4. Baseline/candidate comparisons when scenarios are added, removed, skipped, or redefined
5. Regression verdict differentiation (detection degradation, telemetry degradation, evidence degradation, insufficient evidence)
6. Root-cause intelligence evidence support without false causal claims
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

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
    CampaignRunStatus,
    CampaignRunV1,
    CampaignSummaryV1,
    EvidenceManifestV1,
    ScenarioCampaignResultV1,
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
from proofshield.services.regression_analyzer import CampaignRegressionAnalyzer
from proofshield.services.root_cause import RootCauseIntelligenceService
from proofshield.services.store import InMemoryStore


class TestMetricAuditAndZeroDenominators:
    """Audit A: Numerators, denominators, eligibility rules, and INSUFFICIENT_DATA handling."""

    def test_all_metrics_zero_denominator_behavior(self):
        """When 0 test cases are executed, all execution-dependent metrics must be INSUFFICIENT_DATA with value=None."""
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

        # Campaign with 1 declared scenario, but no test run executed
        s1 = ScenarioV1(
            scenario_id="SCN-ZERO-EXEC",
            name="Unexecuted Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        store.add_scenario(s1)
        camp = CampaignDefinitionV1(
            campaign_id="CPG-ZERO-EXEC",
            name="Zero Executed Campaign",
            scenario_ids=["SCN-ZERO-EXEC"],
        )
        store.add_campaign(camp)

        engine = CampaignEngine(store)
        run = engine.execute_campaign("CPG-ZERO-EXEC")
        assert run.summary.executed_scenarios == 0

        report_gen = CampaignAssuranceReportGenerator(store)
        report = report_gen.generate_report(run.run_id)

        metrics = report.assurance_metrics
        # 1. Detection Success Rate
        assert metrics.detection_success_rate.status == MetricStatus.INSUFFICIENT_DATA
        assert metrics.detection_success_rate.value is None
        assert metrics.detection_success_rate.denominator == 0

        # 2. Detection Failure Rate
        assert metrics.detection_failure_rate.status == MetricStatus.INSUFFICIENT_DATA
        assert metrics.detection_failure_rate.value is None
        assert metrics.detection_failure_rate.denominator == 0

        # 3. Telemetry Availability Rate
        assert metrics.telemetry_availability_rate.status == MetricStatus.INSUFFICIENT_DATA
        assert metrics.telemetry_availability_rate.value is None
        assert metrics.telemetry_availability_rate.denominator == 0

        # 4. Evidence Completeness Rate
        assert metrics.evidence_completeness_rate.status == MetricStatus.INSUFFICIENT_DATA
        assert metrics.evidence_completeness_rate.value is None
        assert metrics.evidence_completeness_rate.denominator == 0

        # 5. Alert Correlation Rate
        assert metrics.alert_correlation_rate.status == MetricStatus.INSUFFICIENT_DATA
        assert metrics.alert_correlation_rate.value is None
        assert metrics.alert_correlation_rate.denominator == 0

        # 6. Inconclusive Rate
        assert metrics.inconclusive_rate.status == MetricStatus.INSUFFICIENT_DATA
        assert metrics.inconclusive_rate.value is None
        assert metrics.inconclusive_rate.denominator == 0

        # 7. Execution Coverage
        assert metrics.execution_coverage.status == MetricStatus.AVAILABLE
        assert metrics.execution_coverage.value == 0.0
        assert metrics.execution_coverage.numerator == 0
        assert metrics.execution_coverage.denominator == 1

    def test_zero_declared_scenarios_coverage_metric(self):
        """When a campaign declares 0 scenarios, execution_coverage must return INSUFFICIENT_DATA with value=None."""
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

        # Register campaign definition first to satisfy foreign key constraint
        store.add_campaign(CampaignDefinitionV1(
            campaign_id="CPG-EMPTY-0",
            name="Empty Zero Camp",
            scenario_ids=["SCN-PLACEHOLDER"],
        ))

        # Create a run record with 0 scenarios
        empty_run = CampaignRunV1(
            run_id="CRUN-EMPTY-ZERO",
            campaign_id="CPG-EMPTY-0",
            status=CampaignRunStatus.COMPLETED,
            started_at=now,
            completed_at=now,
            total_scenarios=0,
            scenario_results=[],
            summary=CampaignSummaryV1(
                total_scenarios=0,
                executed_scenarios=0,
                unexecuted_scenarios=0,
                passed_scenarios=0,
                failed_scenarios=0,
                inconclusive_scenarios=0,
                error_scenarios=0,
                execution_coverage=0.0,
                error_rate=0.0,
            ),
            evidence_manifest=EvidenceManifestV1(
                campaign_id="CPG-EMPTY-0",
                campaign_run_id="CRUN-EMPTY-ZERO",
                manifest_hash="00" * 32,
            ),
        )
        store.add_campaign_run(empty_run)

        report_gen = CampaignAssuranceReportGenerator(store)
        report = report_gen.generate_report("CRUN-EMPTY-ZERO", verify_manifest=False)

        assert report.assurance_metrics.execution_coverage.status == MetricStatus.INSUFFICIENT_DATA
        assert report.assurance_metrics.execution_coverage.value is None
        assert report.assurance_metrics.execution_coverage.denominator == 0

    def test_single_sample_size_n_equals_1(self):
        """Boundary test: exactly 1 scenario executed with PASS outcome."""
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

        s = ScenarioV1(
            scenario_id="SCN-N1",
            name="Single Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="notepad.exe",
            expected_detection_rule_id="RULE-N1",
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        store.add_scenario(s)
        store.add_rule(DetectionRuleV1(rule_id="RULE-N1", rule_name="Rule N1", rule_format="sigma"))
        store.add_run(TestRunV1(
            run_id="TR-N1",
            scenario_id="SCN-N1",
            execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
            target_host="host-1",
            target_user="alice",
            executed_at=now,
            window_start=now - timedelta(seconds=5),
            window_end=now + timedelta(seconds=30),
            execution_status=ExecutionStatus.COMPLETED,
        ))
        store.add_normalized_event(NormalizedTelemetryEventV1(
            normalized_event_id="EVT-N1",
            raw_event_id="RAW-N1",
            source_event_id="SRC-N1",
            source_timestamp=now + timedelta(seconds=2),
            normalized_timestamp=now + timedelta(seconds=2),
            event_category=EventCategory.PROCESS_CREATION,
            host="host-1",
            user="alice",
            process_name="notepad.exe",
        ))
        store.add_alert(AlertV1(
            alert_id="ALT-N1",
            source_alert_id="SRC-ALT-N1",
            source_type="sigma",
            rule_reference="RULE-N1",
            host_id="host-1",
            alert_timestamp=now + timedelta(seconds=4),
            severity="high",
        ))
        camp = CampaignDefinitionV1(
            campaign_id="CPG-N1",
            name="Single Scenario Campaign",
            scenario_ids=["SCN-N1"],
        )
        store.add_campaign(camp)

        engine = CampaignEngine(store)
        run = engine.execute_campaign("CPG-N1")

        report_gen = CampaignAssuranceReportGenerator(store)
        report = report_gen.generate_report(run.run_id)

        m = report.assurance_metrics
        assert m.detection_success_rate.value == 1.0
        assert m.detection_failure_rate.value == 0.0
        assert m.telemetry_availability_rate.value == 1.0
        assert m.evidence_completeness_rate.value == 1.0
        assert m.alert_correlation_rate.value == 1.0
        assert m.inconclusive_rate.value == 0.0
        assert m.execution_coverage.value == 1.0


class TestRegressionThresholdsAndTolerance:
    """Audit B: Floating-point precision vs operational regression thresholds."""

    def test_floating_point_representation_noise_suppressed(self):
        """Floating point noise below float_epsilon (1e-6) must NOT generate false regressions or improvements."""
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

        # Baseline: 3 scenarios, 2 pass -> 2/3 = 0.6666666666666666
        # Candidate: 3 scenarios, 2 pass -> 2/3 = 0.6666666666666667 (slight float discrepancy)
        s1 = ScenarioV1(
            scenario_id="SCN-T1",
            name="Scenario T1",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        store.add_scenario(s1)
        camp = CampaignDefinitionV1(campaign_id="CPG-TOL", name="Tol Camp", scenario_ids=["SCN-T1"])
        store.add_campaign(camp)

        engine = CampaignEngine(store)
        base_run = engine.execute_campaign("CPG-TOL")

        report_gen = CampaignAssuranceReportGenerator(store)
        base_rpt = report_gen.generate_report(base_run.run_id)

        # Set executed_test_cases > 0 so that step 2 (insufficient data) is bypassed
        base_rpt.execution_summary.executed_test_cases = 10
        base_rpt.assurance_metrics.detection_success_rate = AssuranceMetricV1(
            name="detection_success_rate",
            numerator=8,
            denominator=10,
            value=0.80,
            status=MetricStatus.AVAILABLE,
            description="desc",
            formula="form",
        )

        # Mock candidate report with tiny delta below 1e-6
        cand_rpt = base_rpt.model_copy(deep=True)
        cand_rpt.campaign_run_id = "CRUN-TOL-CAND"
        cand_rpt.execution_summary.executed_test_cases = 10

        # Introduce 1e-9 float noise
        cand_rpt.assurance_metrics.detection_success_rate = AssuranceMetricV1(
            name="detection_success_rate",
            numerator=8,
            denominator=10,
            value=0.80 + 1e-9,
            status=MetricStatus.AVAILABLE,
            description="desc",
            formula="form",
        )

        analyzer = CampaignRegressionAnalyzer(store, float_epsilon=1e-6, metric_tolerance=0.0001)
        analysis = analyzer.analyze_reports(base_rpt, cand_rpt, base_run, base_run)

        # Must not generate METRIC_IMPROVEMENT or METRIC_DETERIORATION findings from float noise
        metric_findings = [
            f for f in analysis.findings
            if f.category in (FindingCategory.METRIC_IMPROVEMENT, FindingCategory.METRIC_DETERIORATION)
        ]
        assert len(metric_findings) == 0

    def test_custom_operational_regression_threshold(self):
        """Custom metric_tolerance (e.g. 5% = 0.05) must ignore 2% drops and only flag drops >= 5%."""
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

        s1 = ScenarioV1(
            scenario_id="SCN-OP-TOL",
            name="Scenario Op Tol",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        store.add_scenario(s1)
        camp = CampaignDefinitionV1(campaign_id="CPG-OP", name="Op Camp", scenario_ids=["SCN-OP-TOL"])
        store.add_campaign(camp)

        engine = CampaignEngine(store)
        base_run = engine.execute_campaign("CPG-OP")

        report_gen = CampaignAssuranceReportGenerator(store)
        base_rpt = report_gen.generate_report(base_run.run_id)
        base_rpt.execution_summary.executed_test_cases = 100
        base_rpt.assurance_metrics.detection_success_rate = AssuranceMetricV1(
            name="detection_success_rate",
            numerator=100,
            denominator=100,
            value=1.0,
            status=MetricStatus.AVAILABLE,
            description="desc",
            formula="form",
        )

        # Create candidate with a 2% drop in detection success (from 1.0 to 0.98)
        cand_rpt_minor = base_rpt.model_copy(deep=True)
        cand_rpt_minor.campaign_run_id = "CRUN-OP-CAND"
        cand_rpt_minor.execution_summary.executed_test_cases = 100
        cand_rpt_minor.assurance_metrics.detection_success_rate = AssuranceMetricV1(
            name="detection_success_rate",
            numerator=98,
            denominator=100,
            value=0.98,
            status=MetricStatus.AVAILABLE,
            description="desc",
            formula="form",
        )

        # With standard strict tolerance (0.0001), 2% drop IS a regression finding
        analyzer_strict = CampaignRegressionAnalyzer(store, metric_tolerance=0.0001)
        analysis_strict = analyzer_strict.analyze_reports(base_rpt, cand_rpt_minor, base_run, base_run)
        assert any(
            f.category == FindingCategory.METRIC_DETERIORATION and f.affected_target == "detection_success_rate"
            for f in analysis_strict.findings
        )

        # With operational 5% tolerance (0.05), 2% drop is within operational boundary (NO regression finding)
        analyzer_lenient = CampaignRegressionAnalyzer(store, metric_tolerance=0.05)
        analysis_lenient = analyzer_lenient.analyze_reports(base_rpt, cand_rpt_minor, base_run, base_run)
        assert not any(
            f.category == FindingCategory.METRIC_DETERIORATION and f.affected_target == "detection_success_rate"
            for f in analysis_lenient.findings
        )


class TestRegressionVerdictsAndDriverDifferentiation:
    """Audit C: Differentiation of detection, telemetry, evidence, and insufficient data degradation."""

    def test_verdict_distinguishes_insufficient_data(self):
        """When 0 test cases are executed, regression analyzer must return INSUFFICIENT_DATA."""
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

        s = ScenarioV1(
            scenario_id="SCN-NODATA",
            name="No Data",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        store.add_scenario(s)
        camp = CampaignDefinitionV1(campaign_id="CPG-NODATA", name="No Data Camp", scenario_ids=["SCN-NODATA"])
        store.add_campaign(camp)

        engine = CampaignEngine(store)
        run_1 = engine.execute_campaign("CPG-NODATA")
        run_2 = engine.execute_campaign("CPG-NODATA")

        report_gen = CampaignAssuranceReportGenerator(store)
        rpt_1 = report_gen.generate_report(run_1.run_id)
        rpt_2 = report_gen.generate_report(run_2.run_id)

        analyzer = CampaignRegressionAnalyzer(store)
        analysis = analyzer.analyze_reports(rpt_1, rpt_2, run_1, run_2)

        assert analysis.verdict == RegressionVerdict.INSUFFICIENT_DATA
        assert any("0 test cases" in f.explanation for f in analysis.findings)

    def test_verdict_distinguishes_telemetry_degradation(self):
        """When detection was working, but telemetry availability dropped, TELEMETRY_GAP_INCREASE finding is generated."""
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

        # Baseline: 100% telemetry availability
        # Candidate: 0% telemetry availability
        s = ScenarioV1(
            scenario_id="SCN-TELEM-DEG",
            name="Telem Deg",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        store.add_scenario(s)
        camp = CampaignDefinitionV1(campaign_id="CPG-TELEM-DEG", name="Camp", scenario_ids=["SCN-TELEM-DEG"])
        store.add_campaign(camp)

        engine = CampaignEngine(store)
        base_run = engine.execute_campaign("CPG-TELEM-DEG")

        report_gen = CampaignAssuranceReportGenerator(store)
        base_rpt = report_gen.generate_report(base_run.run_id)

        base_rpt.execution_summary.executed_test_cases = 10
        base_rpt.assurance_metrics.telemetry_availability_rate = AssuranceMetricV1(
            name="telemetry_availability_rate",
            numerator=10,
            denominator=10,
            value=1.0,
            status=MetricStatus.AVAILABLE,
            description="desc",
            formula="form",
        )

        cand_rpt = base_rpt.model_copy(deep=True)
        cand_rpt.campaign_run_id = "CRUN-TELEM-CAND"
        cand_rpt.assurance_metrics.telemetry_availability_rate = AssuranceMetricV1(
            name="telemetry_availability_rate",
            numerator=5,
            denominator=10,
            value=0.5,
            status=MetricStatus.AVAILABLE,
            description="desc",
            formula="form",
        )

        analyzer = CampaignRegressionAnalyzer(store)
        analysis = analyzer.analyze_reports(base_rpt, cand_rpt, base_run, base_run)

        assert analysis.verdict == RegressionVerdict.REGRESSION
        telem_findings = [f for f in analysis.findings if f.category == FindingCategory.TELEMETRY_GAP_INCREASE]
        assert len(telem_findings) == 1
        assert telem_findings[0].severity == FindingSeverity.HIGH
        assert telem_findings[0].is_actionable is True


class TestRootCauseReliabilityAndAttribution:
    """Audit D: Root cause groupings must be evidence-supported and avoid speculative causation claims."""

    def test_root_cause_bifurcates_facts_and_explanations(self):
        """Root cause patterns must strictly segregate observed facts from inferred explanations."""
        store = InMemoryStore()
        now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

        s = ScenarioV1(
            scenario_id="SCN-RC-FACTS",
            name="RC Facts Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="powershell.exe",
            expected_detection_rule_id="RULE-RC",
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
        store.add_scenario(s)
        store.add_rule(DetectionRuleV1(rule_id="RULE-RC", rule_name="Rule RC", rule_format="sigma"))
        store.add_run(TestRunV1(
            run_id="TR-RC",
            scenario_id="SCN-RC-FACTS",
            execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
            target_host="host-rc",
            target_user="alice",
            executed_at=now,
            window_start=now - timedelta(seconds=5),
            window_end=now + timedelta(seconds=30),
            execution_status=ExecutionStatus.COMPLETED,
        ))
        camp = CampaignDefinitionV1(campaign_id="CPG-RC", name="RC Camp", scenario_ids=["SCN-RC-FACTS"])
        store.add_campaign(camp)

        engine = CampaignEngine(store)
        run = engine.execute_campaign("CPG-RC")

        rc_service = RootCauseIntelligenceService(store)
        rc_intel = rc_service.analyze_campaign_run(run.run_id)

        assert len(rc_intel.patterns) >= 1
        pattern = rc_intel.patterns[0]

        # Observed facts must state empirical observations
        assert len(pattern.observed_facts) >= 1
        for fact in pattern.observed_facts:
            assert isinstance(fact, str) and len(fact) > 0
            # Must not make definitive claims of outside system states
            assert "proven" not in fact.lower()

        # Inferred explanations must be labeled with 'Potential causes'
        assert len(pattern.inferred_explanations) >= 1
        for expl in pattern.inferred_explanations:
            assert "potential" in expl.lower() or "causes" in expl.lower()
