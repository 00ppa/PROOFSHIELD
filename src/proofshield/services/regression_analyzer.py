"""Deterministic Campaign Regression Analysis and Intelligence Service.

Phase 17 implementation providing:
- Structured comparative evaluation between baseline and candidate campaigns
- Compatibility auditing (scenario parity, configuration drift, engine version drift)
- Fine-grained finding generation with deterministic severity and actionability flags
- Verifiable classification into REGRESSION, IMPROVEMENT, NO_CHANGE, INSUFFICIENT_DATA, or INCOMPARABLE
- Canonical SHA-256 digest for audit trail integrity
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple, Union

from proofshield.schemas.assurance_report import (
    CampaignAssuranceReportV1,
    CampaignCompatibilityV1,
    CampaignRegressionAnalysisV1,
    FindingCategory,
    FindingSeverity,
    RegressionFindingV1,
    RegressionVerdict,
)
from proofshield.schemas.campaign import (
    CampaignRunV1,
    ScenarioCampaignResultV1,
    ScenarioRunStatus,
)
from proofshield.schemas.common import DiagnosticCategory
from proofshield.services.assurance_report import CampaignAssuranceReportGenerator
from proofshield.services.base_store import StoreProtocol
from proofshield.services.canonical import compute_canonical_hash


# Documented severity hierarchy for deterministic sorting
SEVERITY_ORDER: Dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFORMATIONAL: 4,
}


def compute_regression_analysis_digest(
    baseline_run_id: str,
    candidate_run_id: str,
    campaign_id: str,
    verdict: RegressionVerdict,
    compatibility: CampaignCompatibilityV1,
    findings: List[RegressionFindingV1],
    summary_counts: Dict[str, int],
) -> str:
    """Compute deterministic canonical SHA-256 digest over regression analysis content."""
    body = {
        "baseline_run_id": baseline_run_id,
        "candidate_run_id": candidate_run_id,
        "campaign_id": campaign_id,
        "verdict": verdict.value,
        "compatibility": compatibility.model_dump(mode="json"),
        "findings": [
            {
                "finding_id": f.finding_id,
                "category": f.category.value,
                "severity": f.severity.value,
                "affected_target": f.affected_target,
                "baseline_value": str(f.baseline_value),
                "candidate_value": str(f.candidate_value),
                "difference": str(f.difference),
                "supporting_evidence_references": sorted(f.supporting_evidence_references),
                "explanation": f.explanation,
                "is_actionable": f.is_actionable,
            }
            for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.finding_id))
        ],
        "summary_counts": {k: summary_counts[k] for k in sorted(summary_counts.keys())},
    }
    return compute_canonical_hash(body)


class CampaignRegressionAnalyzer:
    """Evaluates regressions and improvements across campaign runs deterministically."""

    # 1. Floating-point comparison tolerance (numerical zero guard)
    FLOAT_EPSILON: float = 1e-6
    # 2. Operational metric regression tolerance threshold (default: 0.0001 / 0.01%)
    DEFAULT_METRIC_TOLERANCE: float = 0.0001
    # Backward-compatible alias
    METRIC_REGRESSION_TOLERANCE: float = DEFAULT_METRIC_TOLERANCE

    def __init__(
        self,
        store: StoreProtocol,
        metric_tolerance: Optional[float] = None,
        float_epsilon: Optional[float] = None,
    ) -> None:
        self.store = store
        self.report_generator = CampaignAssuranceReportGenerator(store)
        self.metric_tolerance = (
            metric_tolerance if metric_tolerance is not None else self.DEFAULT_METRIC_TOLERANCE
        )
        self.float_epsilon = (
            float_epsilon if float_epsilon is not None else self.FLOAT_EPSILON
        )

    def analyze_runs(
        self,
        baseline_run_id: str,
        candidate_run_id: str,
        analysis_id: Optional[str] = None,
        metric_tolerance: Optional[float] = None,
    ) -> CampaignRegressionAnalysisV1:
        """Perform comparative regression analysis between two campaign runs.

        Raises:
            ValueError: If either campaign run is not found in the store.
        """
        base_run = self.store.get_campaign_run(baseline_run_id)
        if base_run is None:
            raise ValueError(f"Baseline campaign run not found: {baseline_run_id}")

        cand_run = self.store.get_campaign_run(candidate_run_id)
        if cand_run is None:
            raise ValueError(f"Candidate campaign run not found: {candidate_run_id}")

        # Generate or compile assurance reports for both runs
        base_report = self.report_generator.generate_report(baseline_run_id, verify_manifest=False)
        cand_report = self.report_generator.generate_report(candidate_run_id, verify_manifest=False)

        return self.analyze_reports(
            base_report,
            cand_report,
            base_run,
            cand_run,
            analysis_id=analysis_id,
            metric_tolerance=metric_tolerance,
        )

    def analyze_reports(
        self,
        base_report: CampaignAssuranceReportV1,
        cand_report: CampaignAssuranceReportV1,
        base_run: Optional[CampaignRunV1] = None,
        cand_run: Optional[CampaignRunV1] = None,
        analysis_id: Optional[str] = None,
        metric_tolerance: Optional[float] = None,
    ) -> CampaignRegressionAnalysisV1:
        """Compare two compiled CampaignAssuranceReportV1 instances."""
        campaign_id = cand_report.campaign_id

        if not base_run:
            base_run = self.store.get_campaign_run(base_report.campaign_run_id)
        if not cand_run:
            cand_run = self.store.get_campaign_run(cand_report.campaign_run_id)

        # 1. Compatibility Audit
        compatibility, is_incomparable, modified_definitions = self._audit_compatibility(
            base_report, cand_report, base_run, cand_run
        )

        findings: List[RegressionFindingV1] = []
        finding_seq = 1

        # If completely incomparable (e.g. 0 common scenarios between two runs), return INCOMPARABLE
        if is_incomparable:
            findings.append(
                RegressionFindingV1(
                    finding_id=f"FND-{finding_seq:03d}",
                    category=FindingCategory.SCENARIO_SET_CHANGE,
                    severity=FindingSeverity.CRITICAL,
                    affected_target="campaign_compatibility",
                    baseline_value=f"{compatibility.baseline_scenario_count} scenarios",
                    candidate_value=f"{compatibility.candidate_scenario_count} scenarios",
                    difference=f"0 common scenarios out of {compatibility.baseline_scenario_count + compatibility.candidate_scenario_count}",
                    supporting_evidence_references=[],
                    explanation="Baseline and candidate campaigns have disjoint scenario suites; direct comparison is invalid.",
                    is_actionable=True,
                )
            )
            finding_seq += 1

            summary_counts = self._compute_summary_counts(findings)
            verdict = RegressionVerdict.INCOMPARABLE

            if not analysis_id:
                seed = f"{base_report.campaign_run_id}:{cand_report.campaign_run_id}:INCOMPATIBLE"
                short_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
                analysis_id = f"REG-{campaign_id[:20]}-{short_hash}"

            digest = compute_regression_analysis_digest(
                baseline_run_id=base_report.campaign_run_id,
                candidate_run_id=cand_report.campaign_run_id,
                campaign_id=campaign_id,
                verdict=verdict,
                compatibility=compatibility,
                findings=findings,
                summary_counts=summary_counts,
            )

            return CampaignRegressionAnalysisV1(
                schema_version="v1",
                analysis_id=analysis_id,
                baseline_run_id=base_report.campaign_run_id,
                candidate_run_id=cand_report.campaign_run_id,
                campaign_id=campaign_id,
                verdict=verdict,
                compatibility=compatibility,
                findings=findings,
                summary_counts=summary_counts,
                analyzed_at=datetime.now(timezone.utc),
                analysis_digest=digest,
            )

        # 2. Check for Insufficient Data
        if (
            base_report.execution_summary.executed_test_cases == 0
            or cand_report.execution_summary.executed_test_cases == 0
        ):
            findings.append(
                RegressionFindingV1(
                    finding_id=f"FND-{finding_seq:03d}",
                    category=FindingCategory.METRIC_DETERIORATION,
                    severity=FindingSeverity.HIGH,
                    affected_target="executed_test_cases",
                    baseline_value=base_report.execution_summary.executed_test_cases,
                    candidate_value=cand_report.execution_summary.executed_test_cases,
                    difference=cand_report.execution_summary.executed_test_cases - base_report.execution_summary.executed_test_cases,
                    supporting_evidence_references=[],
                    explanation="One or both campaign runs executed 0 test cases, precluding conclusive regression analysis.",
                    is_actionable=True,
                )
            )
            summary_counts = self._compute_summary_counts(findings)
            verdict = RegressionVerdict.INSUFFICIENT_DATA

            if not analysis_id:
                seed = f"{base_report.campaign_run_id}:{cand_report.campaign_run_id}:NODATA"
                short_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
                analysis_id = f"REG-{campaign_id[:20]}-{short_hash}"

            digest = compute_regression_analysis_digest(
                baseline_run_id=base_report.campaign_run_id,
                candidate_run_id=cand_report.campaign_run_id,
                campaign_id=campaign_id,
                verdict=verdict,
                compatibility=compatibility,
                findings=findings,
                summary_counts=summary_counts,
            )

            return CampaignRegressionAnalysisV1(
                schema_version="v1",
                analysis_id=analysis_id,
                baseline_run_id=base_report.campaign_run_id,
                candidate_run_id=cand_report.campaign_run_id,
                campaign_id=campaign_id,
                verdict=verdict,
                compatibility=compatibility,
                findings=findings,
                summary_counts=summary_counts,
                analyzed_at=datetime.now(timezone.utc),
                analysis_digest=digest,
            )

        # 3. Environment & Configuration Drift Findings
        if compatibility.config_drift_detected:
            findings.append(
                RegressionFindingV1(
                    finding_id=f"FND-{finding_seq:03d}",
                    category=FindingCategory.ENVIRONMENT_DRIFT,
                    severity=FindingSeverity.MEDIUM,
                    affected_target="execution_config",
                    baseline_value="baseline_config",
                    candidate_value="candidate_config",
                    difference="Execution configuration parameters diverged between runs",
                    supporting_evidence_references=[],
                    explanation="Execution configuration parameters (e.g. grace period or strict attribution) differed between runs.",
                    is_actionable=False,
                )
            )
            finding_seq += 1

        # Scenario definition contract modifications
        for sid in modified_definitions:
            findings.append(
                RegressionFindingV1(
                    finding_id=f"FND-{finding_seq:03d}",
                    category=FindingCategory.ENVIRONMENT_DRIFT,
                    severity=FindingSeverity.MEDIUM,
                    affected_target=sid,
                    baseline_value="baseline_definition",
                    candidate_value="modified_definition",
                    difference="Scenario definition contract modified (canonical hash mismatch)",
                    supporting_evidence_references=[],
                    explanation=(
                        f"Scenario '{sid}' definition contract was modified between baseline and candidate runs; "
                        "outcome shifts or failures may stem from altered validation criteria rather than detection logic regression."
                    ),
                    is_actionable=True,
                )
            )
            finding_seq += 1

        if compatibility.engine_version_baseline != compatibility.engine_version_candidate:
            findings.append(
                RegressionFindingV1(
                    finding_id=f"FND-{finding_seq:03d}",
                    category=FindingCategory.ENVIRONMENT_DRIFT,
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_target="engine_version",
                    baseline_value=compatibility.engine_version_baseline,
                    candidate_value=compatibility.engine_version_candidate,
                    difference=f"{compatibility.engine_version_baseline} -> {compatibility.engine_version_candidate}",
                    supporting_evidence_references=[],
                    explanation="Assurance engine version differs between runs.",
                    is_actionable=False,
                )
            )
            finding_seq += 1

        # 4. Scenario Set Drift Findings
        if compatibility.added_scenarios:
            findings.append(
                RegressionFindingV1(
                    finding_id=f"FND-{finding_seq:03d}",
                    category=FindingCategory.SCENARIO_SET_CHANGE,
                    severity=FindingSeverity.LOW,
                    affected_target="added_scenarios",
                    baseline_value=[],
                    candidate_value=compatibility.added_scenarios,
                    difference=f"+{len(compatibility.added_scenarios)} scenarios",
                    supporting_evidence_references=[],
                    explanation=f"Candidate campaign introduced {len(compatibility.added_scenarios)} new scenarios: {compatibility.added_scenarios[:5]}",
                    is_actionable=False,
                )
            )
            finding_seq += 1

        if compatibility.removed_scenarios:
            findings.append(
                RegressionFindingV1(
                    finding_id=f"FND-{finding_seq:03d}",
                    category=FindingCategory.SCENARIO_SET_CHANGE,
                    severity=FindingSeverity.MEDIUM,
                    affected_target="removed_scenarios",
                    baseline_value=compatibility.removed_scenarios,
                    candidate_value=[],
                    difference=f"-{len(compatibility.removed_scenarios)} scenarios",
                    supporting_evidence_references=[],
                    explanation=f"Candidate campaign omitted {len(compatibility.removed_scenarios)} scenarios evaluated in baseline: {compatibility.removed_scenarios[:5]}",
                    is_actionable=True,
                )
            )
            finding_seq += 1

        # 5. Per-Scenario Transitions
        base_results_map = {r.scenario_id: r for r in (base_run.scenario_results if base_run else [])}
        cand_results_map = {r.scenario_id: r for r in (cand_run.scenario_results if cand_run else [])}

        common_ids = sorted(list(set(base_results_map.keys()) & set(cand_results_map.keys())))

        for sid in common_ids:
            b_res = base_results_map[sid]
            c_res = cand_results_map[sid]

            # Scenario Regressed: PASS -> non-PASS
            if b_res.status == ScenarioRunStatus.PASS and c_res.status != ScenarioRunStatus.PASS:
                findings.append(
                    RegressionFindingV1(
                        finding_id=f"FND-{finding_seq:03d}",
                        category=FindingCategory.DETECTION_REGRESSION,
                        severity=FindingSeverity.CRITICAL if c_res.status == ScenarioRunStatus.FAILURE else FindingSeverity.HIGH,
                        affected_target=sid,
                        baseline_value=b_res.status.value,
                        candidate_value=c_res.status.value,
                        difference=f"{b_res.status.value} -> {c_res.status.value} ({c_res.predicted_category.value if c_res.predicted_category else 'UNKNOWN'})",
                        supporting_evidence_references=c_res.supporting_evidence_ids[:5],
                        explanation=f"Detection scenario '{sid}' regressed from PASS to {c_res.status.value}: {c_res.reason}",
                        is_actionable=True,
                    )
                )
                finding_seq += 1

            # Scenario Improved: non-PASS -> PASS
            elif b_res.status != ScenarioRunStatus.PASS and c_res.status == ScenarioRunStatus.PASS:
                findings.append(
                    RegressionFindingV1(
                        finding_id=f"FND-{finding_seq:03d}",
                        category=FindingCategory.DETECTION_IMPROVEMENT,
                        severity=FindingSeverity.INFORMATIONAL,
                        affected_target=sid,
                        baseline_value=b_res.status.value,
                        candidate_value=c_res.status.value,
                        difference=f"{b_res.status.value} -> PASS",
                        supporting_evidence_references=c_res.supporting_evidence_ids[:5],
                        explanation=f"Detection scenario '{sid}' previously failing or unverified now successfully passes: {c_res.reason}",
                        is_actionable=False,
                    )
                )
                finding_seq += 1

            # Newly Introduced Execution Error
            elif b_res.status != ScenarioRunStatus.ERROR and c_res.status == ScenarioRunStatus.ERROR:
                findings.append(
                    RegressionFindingV1(
                        finding_id=f"FND-{finding_seq:03d}",
                        category=FindingCategory.EXECUTION_ERROR_INCREASE,
                        severity=FindingSeverity.HIGH,
                        affected_target=sid,
                        baseline_value=b_res.status.value,
                        candidate_value="ERROR",
                        difference=f"{b_res.status.value} -> ERROR",
                        supporting_evidence_references=[],
                        explanation=f"Scenario '{sid}' encountered an execution error: {c_res.error_message or c_res.reason}",
                        is_actionable=True,
                    )
                )
                finding_seq += 1

        # 6. Aggregate Metric Shifts
        b_metrics = base_report.assurance_metrics
        c_metrics = cand_report.assurance_metrics
        tolerance = metric_tolerance if metric_tolerance is not None else self.metric_tolerance
        epsilon = self.float_epsilon

        def _safe_delta(cand_val: Optional[float], base_val: Optional[float]) -> Optional[float]:
            """Compute metric delta, suppressing floating-point representation noise below epsilon."""
            if cand_val is None or base_val is None:
                return None
            raw = cand_val - base_val
            return 0.0 if abs(raw) < epsilon else round(raw, 4)

        # 6.1 Detection Success Rate Shift
        succ_delta = _safe_delta(c_metrics.detection_success_rate.value, b_metrics.detection_success_rate.value)
        if succ_delta is not None:
            if succ_delta <= -tolerance:
                findings.append(
                    RegressionFindingV1(
                        finding_id=f"FND-{finding_seq:03d}",
                        category=FindingCategory.METRIC_DETERIORATION,
                        severity=FindingSeverity.HIGH,
                        affected_target="detection_success_rate",
                        baseline_value=b_metrics.detection_success_rate.value,
                        candidate_value=c_metrics.detection_success_rate.value,
                        difference=succ_delta,
                        supporting_evidence_references=[],
                        explanation=f"Detection success rate deteriorated by {abs(succ_delta):.1%} ({b_metrics.detection_success_rate.value:.1%} -> {c_metrics.detection_success_rate.value:.1%}).",
                        is_actionable=True,
                    )
                )
                finding_seq += 1
            elif succ_delta >= tolerance:
                findings.append(
                    RegressionFindingV1(
                        finding_id=f"FND-{finding_seq:03d}",
                        category=FindingCategory.METRIC_IMPROVEMENT,
                        severity=FindingSeverity.INFORMATIONAL,
                        affected_target="detection_success_rate",
                        baseline_value=b_metrics.detection_success_rate.value,
                        candidate_value=c_metrics.detection_success_rate.value,
                        difference=succ_delta,
                        supporting_evidence_references=[],
                        explanation=f"Detection success rate improved by {succ_delta:.1%} ({b_metrics.detection_success_rate.value:.1%} -> {c_metrics.detection_success_rate.value:.1%}).",
                        is_actionable=False,
                    )
                )
                finding_seq += 1

        # 6.2 Telemetry Availability Shift
        telem_delta = _safe_delta(c_metrics.telemetry_availability_rate.value, b_metrics.telemetry_availability_rate.value)
        if telem_delta is not None:
            if telem_delta <= -tolerance:
                findings.append(
                    RegressionFindingV1(
                        finding_id=f"FND-{finding_seq:03d}",
                        category=FindingCategory.TELEMETRY_GAP_INCREASE,
                        severity=FindingSeverity.HIGH,
                        affected_target="telemetry_availability_rate",
                        baseline_value=b_metrics.telemetry_availability_rate.value,
                        candidate_value=c_metrics.telemetry_availability_rate.value,
                        difference=telem_delta,
                        supporting_evidence_references=[],
                        explanation=f"Telemetry availability dropped by {abs(telem_delta):.1%}; {cand_report.diagnostic_distribution.expected_telemetry_missing_count} scenarios had missing telemetry.",
                        is_actionable=True,
                    )
                )
                finding_seq += 1

        # 6.3 Alert Correlation Shift
        corr_delta = _safe_delta(c_metrics.alert_correlation_rate.value, b_metrics.alert_correlation_rate.value)
        if corr_delta is not None:
            if corr_delta <= -tolerance:
                findings.append(
                    RegressionFindingV1(
                        finding_id=f"FND-{finding_seq:03d}",
                        category=FindingCategory.ALERT_CORRELATION_DETERIORATION,
                        severity=FindingSeverity.HIGH,
                        affected_target="alert_correlation_rate",
                        baseline_value=b_metrics.alert_correlation_rate.value,
                        candidate_value=c_metrics.alert_correlation_rate.value,
                        difference=corr_delta,
                        supporting_evidence_references=[],
                        explanation=f"Alert correlation rate declined by {abs(corr_delta):.1%}; {cand_report.diagnostic_distribution.alert_not_correlated_count} alerts could not be correlated.",
                        is_actionable=True,
                    )
                )
                finding_seq += 1

        # 6.4 Inconclusive Rate Increase
        inconcl_delta = _safe_delta(c_metrics.inconclusive_rate.value, b_metrics.inconclusive_rate.value)
        if inconcl_delta is not None:
            if inconcl_delta >= tolerance:
                findings.append(
                    RegressionFindingV1(
                        finding_id=f"FND-{finding_seq:03d}",
                        category=FindingCategory.INCONCLUSIVE_RATE_INCREASE,
                        severity=FindingSeverity.MEDIUM,
                        affected_target="inconclusive_rate",
                        baseline_value=b_metrics.inconclusive_rate.value,
                        candidate_value=c_metrics.inconclusive_rate.value,
                        difference=inconcl_delta,
                        supporting_evidence_references=[],
                        explanation=f"Inconclusive verdicts increased by {inconcl_delta:.1%} ({cand_report.diagnostic_distribution.inconclusive_count} inconclusive scenarios).",
                        is_actionable=True,
                    )
                )
                finding_seq += 1

        # 6.5 Evidence Completeness Deterioration
        comp_delta = _safe_delta(c_metrics.evidence_completeness_rate.value, b_metrics.evidence_completeness_rate.value)
        if comp_delta is not None:
            if comp_delta <= -tolerance:
                findings.append(
                    RegressionFindingV1(
                        finding_id=f"FND-{finding_seq:03d}",
                        category=FindingCategory.EVIDENCE_COMPLETENESS_DETERIORATION,
                        severity=FindingSeverity.MEDIUM,
                        affected_target="evidence_completeness_rate",
                        baseline_value=b_metrics.evidence_completeness_rate.value,
                        candidate_value=c_metrics.evidence_completeness_rate.value,
                        difference=comp_delta,
                        supporting_evidence_references=[],
                        explanation=f"Evidence completeness dropped by {abs(comp_delta):.1%}; missing evidence affected one or more scenarios.",
                        is_actionable=True,
                    )
                )
                finding_seq += 1

        # 7. Overall Verdict Calculation
        summary_counts = self._compute_summary_counts(findings)

        has_critical = summary_counts.get("critical", 0) > 0
        has_high = summary_counts.get("high", 0) > 0
        has_improvements = any(f.category in (FindingCategory.DETECTION_IMPROVEMENT, FindingCategory.METRIC_IMPROVEMENT) for f in findings)
        has_regressions = any(f.category in (
            FindingCategory.DETECTION_REGRESSION,
            FindingCategory.METRIC_DETERIORATION,
            FindingCategory.TELEMETRY_GAP_INCREASE,
            FindingCategory.ALERT_CORRELATION_DETERIORATION,
            FindingCategory.EXECUTION_ERROR_INCREASE,
            FindingCategory.INCONCLUSIVE_RATE_INCREASE,
            FindingCategory.EVIDENCE_COMPLETENESS_DETERIORATION,
        ) for f in findings)

        if has_critical or has_high or has_regressions:
            verdict = RegressionVerdict.REGRESSION
        elif has_improvements:
            verdict = RegressionVerdict.IMPROVEMENT
        else:
            verdict = RegressionVerdict.NO_CHANGE

        # Deterministically sort findings by severity (CRITICAL -> INFORMATIONAL) then finding_id
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.finding_id))

        # 8. Deterministic Identifier and Canonical Digest
        if not analysis_id:
            seed = f"{base_report.campaign_run_id}:{cand_report.campaign_run_id}:{verdict.value}"
            short_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
            analysis_id = f"REG-{campaign_id[:20]}-{short_hash}"

        digest = compute_regression_analysis_digest(
            baseline_run_id=base_report.campaign_run_id,
            candidate_run_id=cand_report.campaign_run_id,
            campaign_id=campaign_id,
            verdict=verdict,
            compatibility=compatibility,
            findings=findings,
            summary_counts=summary_counts,
        )

        return CampaignRegressionAnalysisV1(
            schema_version="v1",
            analysis_id=analysis_id,
            baseline_run_id=base_report.campaign_run_id,
            candidate_run_id=cand_report.campaign_run_id,
            campaign_id=campaign_id,
            verdict=verdict,
            compatibility=compatibility,
            findings=findings,
            summary_counts=summary_counts,
            analyzed_at=datetime.now(timezone.utc),
            analysis_digest=digest,
        )

    def _audit_compatibility(
        self,
        base_report: CampaignAssuranceReportV1,
        cand_report: CampaignAssuranceReportV1,
        base_run: Optional[CampaignRunV1],
        cand_run: Optional[CampaignRunV1],
    ) -> Tuple[CampaignCompatibilityV1, bool, List[str]]:
        """Audit compatibility between two runs."""
        base_scenarios: List[str] = []
        cand_scenarios: List[str] = []

        if base_run and base_run.scenario_results:
            base_scenarios = [r.scenario_id for r in base_run.scenario_results]
        if cand_run and cand_run.scenario_results:
            cand_scenarios = [r.scenario_id for r in cand_run.scenario_results]

        base_set = set(base_scenarios)
        cand_set = set(cand_scenarios)

        added = sorted(list(cand_set - base_set))
        removed = sorted(list(base_set - cand_set))
        common = sorted(list(base_set & cand_set))

        reasons: List[str] = []
        config_drift = False

        if base_run and cand_run:
            base_cfg = base_run.evidence_manifest.execution_config_snapshot or {}
            cand_cfg = cand_run.evidence_manifest.execution_config_snapshot or {}
            if base_cfg != cand_cfg:
                config_drift = True
                reasons.append("Execution configuration parameters diverged between runs.")

        modified_definitions: List[str] = []
        if base_run and cand_run and base_run.evidence_manifest and cand_run.evidence_manifest:
            base_srefs = {
                s.scenario_id: s.scenario_hash
                for s in (base_run.evidence_manifest.scenario_references or [])
                if s.scenario_hash
            }
            cand_srefs = {
                s.scenario_id: s.scenario_hash
                for s in (cand_run.evidence_manifest.scenario_references or [])
                if s.scenario_hash
            }
            for sid in common:
                b_hash = base_srefs.get(sid)
                c_hash = cand_srefs.get(sid)
                if b_hash and c_hash and b_hash != c_hash:
                    modified_definitions.append(sid)
                    reasons.append(f"Scenario definition contract for '{sid}' was modified between runs.")

        engine_base = base_report.engine_version
        engine_cand = cand_report.engine_version
        if engine_base != engine_cand:
            reasons.append(f"Engine versions differ ({engine_base} vs {engine_cand}).")

        # Disjoint scenario suites check
        is_incomparable = False
        if len(base_scenarios) > 0 and len(cand_scenarios) > 0 and len(common) == 0:
            is_incomparable = True
            reasons.append("Runs evaluate completely disjoint scenario sets (0 common scenarios).")

        if base_report.campaign_id != cand_report.campaign_id:
            reasons.append(f"Runs evaluate different campaign IDs ({base_report.campaign_id} vs {cand_report.campaign_id}).")

        is_compatible = not is_incomparable

        verdict = "COMPATIBLE"
        if is_incomparable:
            verdict = "INCOMPATIBLE_SCENARIOS"
        elif config_drift:
            verdict = "CONFIG_DRIFT"
        elif modified_definitions:
            verdict = "SCENARIO_DEFINITION_DRIFT"
        elif engine_base != engine_cand:
            verdict = "ENGINE_DRIFT"
        elif added or removed:
            verdict = "SCENARIO_SET_DRIFT"

        compatibility = CampaignCompatibilityV1(
            is_compatible=is_compatible,
            verdict=verdict,
            baseline_scenario_count=len(base_scenarios),
            candidate_scenario_count=len(cand_scenarios),
            common_scenario_count=len(common),
            added_scenarios=added,
            removed_scenarios=removed,
            engine_version_baseline=engine_base,
            engine_version_candidate=engine_cand,
            config_drift_detected=config_drift,
            reasons=reasons,
        )

        return compatibility, is_incomparable, modified_definitions

    def _compute_summary_counts(self, findings: List[RegressionFindingV1]) -> Dict[str, int]:
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "total_findings": len(findings),
        }
        for f in findings:
            key = f.severity.value.lower()
            if key in counts:
                counts[key] += 1
        return counts

