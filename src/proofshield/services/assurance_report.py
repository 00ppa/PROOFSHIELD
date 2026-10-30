"""Deterministic Campaign Assurance Intelligence and Reporting Service.

Phase 17 implementation providing:
- Non-destructive aggregation of campaign run evidence and diagnostics
- Mathematically rigorous detection assurance metrics with explicit numerators/denominators
- Diagnostic distribution across the seven canonical categories
- Cryptographic evidence quality auditing and manifest verification against storage
- Deterministic RFC 8785 (JCS) canonical digest computation and tamper detection
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
import uuid

from proofshield.schemas.assurance_report import (
    AssuranceMetricV1,
    CampaignAssuranceReportV1,
    DetectionAssuranceMetricsV1,
    DiagnosticDistributionV1,
    EvidenceQualityV1,
    EvidenceVerificationStatus,
    ExecutionSummaryV1,
    MetricStatus,
)
from proofshield.schemas.campaign import (
    CampaignDefinitionV1,
    CampaignRunV1,
    RootCauseGroupV1,
    ScenarioCampaignResultV1,
    ScenarioRunStatus,
)
from proofshield.schemas.common import DiagnosticCategory, FailureCategory
from proofshield.services.base_store import StoreProtocol
from proofshield.services.canonical import compute_canonical_hash


def compute_assurance_report_digest(
    campaign_id: str,
    campaign_run_id: str,
    engine_version: str,
    execution_summary: ExecutionSummaryV1,
    assurance_metrics: DetectionAssuranceMetricsV1,
    diagnostic_distribution: DiagnosticDistributionV1,
    evidence_quality: EvidenceQualityV1,
    root_cause_analysis: List[RootCauseGroupV1],
    is_complete: bool,
) -> str:
    """Compute deterministic RFC 8785 canonical SHA-256 digest over core report content."""
    canonical_body = {
        "campaign_id": campaign_id,
        "campaign_run_id": campaign_run_id,
        "engine_version": engine_version,
        "execution_summary": execution_summary.model_dump(mode="json"),
        "assurance_metrics": assurance_metrics.model_dump(mode="json"),
        "diagnostic_distribution": diagnostic_distribution.model_dump(mode="json"),
        "evidence_quality": {
            "total_evidence_records": evidence_quality.total_evidence_records,
            "manifest_verification_status": evidence_quality.manifest_verification_status.value,
            "missing_evidence_references": sorted(evidence_quality.missing_evidence_references),
            "invalid_evidence_references": sorted(evidence_quality.invalid_evidence_references),
            "integrity_verification_failures": sorted(evidence_quality.integrity_verification_failures),
            "is_complete": evidence_quality.is_complete,
            "notes": sorted(evidence_quality.notes),
        },
        "root_cause_analysis": [
            {
                "root_cause_category": rc.root_cause_category,
                "scenario_count": rc.scenario_count,
                "scenario_ids": sorted(rc.scenario_ids),
                "supporting_evidence_ids": sorted(rc.supporting_evidence_ids),
                "explanation": rc.explanation,
                "confidence": rc.confidence,
            }
            for rc in sorted(root_cause_analysis, key=lambda x: x.root_cause_category)
        ],
        "is_complete": is_complete,
    }
    return compute_canonical_hash(canonical_body)


class CampaignAssuranceReportGenerator:
    """Compiles auditable, reproducible assurance reports from stored campaign executions."""

    ENGINE_VERSION = "v1.0.0"

    def __init__(self, store: StoreProtocol, engine_version: str = "v1.0.0") -> None:
        self.store = store
        self.engine_version = engine_version

    def generate_report(
        self,
        run_id: str,
        verify_manifest: bool = True,
        report_id: Optional[str] = None,
    ) -> CampaignAssuranceReportV1:
        """Generate a versioned campaign assurance report for an existing campaign run.

        Aggregates stored scenario results, audits evidence manifest against the store,
        calculates formal metrics with explicit denominators, and seals the report with
        a canonical SHA-256 digest.

        Raises:
            ValueError: If the campaign run or associated campaign definition is not found.
        """
        run = self.store.get_campaign_run(run_id)
        if run is None:
            raise ValueError(f"Campaign run not found: {run_id}")

        campaign = self.store.get_campaign(run.campaign_id)
        campaign_name = campaign.name if campaign else f"Campaign-{run.campaign_id}"
        manifest = run.evidence_manifest
        s_ref_map = {ref.scenario_id: ref for ref in (manifest.scenario_references if manifest else [])}

        # 1. Execution Summary
        total_scenarios = run.total_scenarios
        scenario_results = run.scenario_results

        successful = 0
        failed = 0
        error_cnt = 0
        inconclusive_cnt = 0
        skipped_cnt = 0

        for r in scenario_results:
            if r.status == ScenarioRunStatus.PASS:
                successful += 1
            elif r.status == ScenarioRunStatus.FAILURE:
                failed += 1
            elif r.status == ScenarioRunStatus.ERROR:
                error_cnt += 1
            elif r.status == ScenarioRunStatus.INCONCLUSIVE:
                inconclusive_cnt += 1
            elif r.status == ScenarioRunStatus.SKIPPED:
                skipped_cnt += 1

        executed = successful + failed + error_cnt + inconclusive_cnt
        unexecuted = max(0, total_scenarios - executed)

        execution_summary = ExecutionSummaryV1(
            campaign_id=run.campaign_id,
            campaign_name=campaign_name,
            campaign_run_id=run.run_id,
            total_scenarios=total_scenarios,
            executed_test_cases=executed,
            unexecuted_cases=unexecuted,
            successful_executions=successful,
            failed_executions=failed,
            error_executions=error_cnt,
            inconclusive_executions=inconclusive_cnt,
            skipped_executions=skipped_cnt,
        )

        # 2. Diagnostic Distribution (across the seven formal categories)
        diag_counts: Dict[str, int] = {
            "PASS": 0,
            "TEST_NOT_EXECUTED": 0,
            "EXPECTED_TELEMETRY_MISSING": 0,
            "DETECTION_NOT_TRIGGERED": 0,
            "ALERT_NOT_CORRELATED": 0,
            "INCONCLUSIVE": 0,
            "ERROR": 0,
        }

        for r in scenario_results:
            cat = r.predicted_category.value if r.predicted_category else None
            if cat in diag_counts:
                diag_counts[cat] += 1
            elif r.status == ScenarioRunStatus.ERROR:
                diag_counts["ERROR"] += 1
            elif r.status == ScenarioRunStatus.SKIPPED:
                diag_counts["TEST_NOT_EXECUTED"] += 1
            else:
                diag_counts["INCONCLUSIVE"] += 1

        # Include unrecorded scenarios from campaign definition in TEST_NOT_EXECUTED
        # (Scenarios already recorded in scenario_results as SKIPPED/TEST_NOT_EXECUTED are already counted above)
        unrecorded = max(0, total_scenarios - len(scenario_results))
        if unrecorded > 0:
            diag_counts["TEST_NOT_EXECUTED"] += unrecorded

        total_classified = sum(diag_counts.values())
        percentages = {}
        if total_classified > 0:
            for k, cnt in diag_counts.items():
                percentages[k] = round((cnt / total_classified) * 100.0, 2)
        else:
            percentages = {k: 0.0 for k in diag_counts}

        diagnostic_distribution = DiagnosticDistributionV1(
            pass_count=diag_counts["PASS"],
            test_not_executed_count=diag_counts["TEST_NOT_EXECUTED"],
            expected_telemetry_missing_count=diag_counts["EXPECTED_TELEMETRY_MISSING"],
            detection_not_triggered_count=diag_counts["DETECTION_NOT_TRIGGERED"],
            alert_not_correlated_count=diag_counts["ALERT_NOT_CORRELATED"],
            inconclusive_count=diag_counts["INCONCLUSIVE"],
            error_count=diag_counts["ERROR"],
            total_classified=total_classified,
            distribution_percentages=percentages,
        )

        # 3. Detection Assurance Metrics (rigorous numerators and denominators)
        # 3.1 Detection Success Rate: passed / executed
        if executed > 0:
            det_succ_val = successful / executed
            det_succ = AssuranceMetricV1(
                name="detection_success_rate",
                numerator=successful,
                denominator=executed,
                value=det_succ_val,
                status=MetricStatus.AVAILABLE,
                description="Proportion of executed scenarios where detection passed successfully",
                formula="successful_executions / executed_test_cases",
            )
        else:
            det_succ = AssuranceMetricV1(
                name="detection_success_rate",
                numerator=0,
                denominator=0,
                value=None,
                status=MetricStatus.INSUFFICIENT_DATA,
                description="Proportion of executed scenarios where detection passed successfully",
                formula="successful_executions / executed_test_cases",
                notes="No test cases were executed; metric undefined.",
            )

        # 3.2 Detection Failure Rate: failed / executed
        if executed > 0:
            det_fail_val = failed / executed
            det_fail = AssuranceMetricV1(
                name="detection_failure_rate",
                numerator=failed,
                denominator=executed,
                value=det_fail_val,
                status=MetricStatus.AVAILABLE,
                description="Proportion of executed scenarios diagnosed with detection failure",
                formula="failed_executions / executed_test_cases",
            )
        else:
            det_fail = AssuranceMetricV1(
                name="detection_failure_rate",
                numerator=0,
                denominator=0,
                value=None,
                status=MetricStatus.INSUFFICIENT_DATA,
                description="Proportion of executed scenarios diagnosed with detection failure",
                formula="failed_executions / executed_test_cases",
                notes="No test cases were executed; metric undefined.",
            )

        # 3.3 Telemetry Availability Rate:
        # Measures the proportion of executed scenarios where required telemetry was present on the endpoint.
        # Scenarios diagnosed with EXPECTED_TELEMETRY_MISSING, ERROR, or INCONCLUSIVE lacked verified expected telemetry.
        avail_telemetry_cnt = 0
        for r in scenario_results:
            if (
                r.predicted_category in (
                    DiagnosticCategory.PASS,
                    DiagnosticCategory.DETECTION_NOT_TRIGGERED,
                    DiagnosticCategory.ALERT_NOT_CORRELATED,
                )
                and r.status != ScenarioRunStatus.ERROR
            ):
                avail_telemetry_cnt += 1

        if executed > 0:
            telem_avail_val = avail_telemetry_cnt / executed
            telem_avail = AssuranceMetricV1(
                name="telemetry_availability_rate",
                numerator=avail_telemetry_cnt,
                denominator=executed,
                value=telem_avail_val,
                status=MetricStatus.AVAILABLE,
                description="Proportion of executed scenarios where required telemetry was present on the endpoint",
                formula="scenarios_with_telemetry / executed_test_cases",
            )
        else:
            telem_avail = AssuranceMetricV1(
                name="telemetry_availability_rate",
                numerator=0,
                denominator=0,
                value=None,
                status=MetricStatus.INSUFFICIENT_DATA,
                description="Proportion of executed scenarios where required telemetry was present on the endpoint",
                formula="scenarios_with_telemetry / executed_test_cases",
                notes="No test cases were executed; metric undefined.",
            )

        # 3.4 Evidence Completeness Rate: (executed - missing_evidence) / executed
        missing_evidence_cnt = sum(1 for r in scenario_results if r.missing_evidence)
        if executed > 0:
            complete_evidence_cnt = max(0, executed - missing_evidence_cnt)
            evid_comp_val = complete_evidence_cnt / executed
            evid_comp = AssuranceMetricV1(
                name="evidence_completeness_rate",
                numerator=complete_evidence_cnt,
                denominator=executed,
                value=evid_comp_val,
                status=MetricStatus.AVAILABLE,
                description="Proportion of executed scenarios whose diagnostic verdict had complete non-missing evidence",
                formula="(executed_test_cases - missing_evidence_count) / executed_test_cases",
            )
        else:
            evid_comp = AssuranceMetricV1(
                name="evidence_completeness_rate",
                numerator=0,
                denominator=0,
                value=None,
                status=MetricStatus.INSUFFICIENT_DATA,
                description="Proportion of executed scenarios whose diagnostic verdict had complete non-missing evidence",
                formula="(executed_test_cases - missing_evidence_count) / executed_test_cases",
                notes="No test cases were executed; metric undefined.",
            )

        # 3.5 Alert Correlation Rate:
        # Evaluated strictly on scenarios where alerts were expected or alert activity was detected.
        # Scenarios that expect only telemetry or benign baseline (no alerts) do not falsely count as 100% correlation.
        correlated_alerts_cnt = 0
        uncorrelated_alerts_cnt = 0
        for r in scenario_results:
            s_ref = s_ref_map.get(r.scenario_id)
            if s_ref and len(s_ref.alert_ids) > 0:
                correlated_alerts_cnt += 1
            elif r.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED:
                uncorrelated_alerts_cnt += 1

        alert_candidate_scenarios = correlated_alerts_cnt + uncorrelated_alerts_cnt
        if alert_candidate_scenarios > 0:
            alert_corr_val = correlated_alerts_cnt / alert_candidate_scenarios
            alert_corr = AssuranceMetricV1(
                name="alert_correlation_rate",
                numerator=correlated_alerts_cnt,
                denominator=alert_candidate_scenarios,
                value=alert_corr_val,
                status=MetricStatus.AVAILABLE,
                description="Proportion of alert-relevant scenarios where alerts successfully correlated to host and window",
                formula="correlated_alert_scenarios / (correlated_alert_scenarios + alert_not_correlated_scenarios)",
            )
        else:
            alert_corr = AssuranceMetricV1(
                name="alert_correlation_rate",
                numerator=0,
                denominator=0,
                value=None,
                status=MetricStatus.INSUFFICIENT_DATA,
                description="Proportion of alert-relevant scenarios where alerts successfully correlated to host and window",
                formula="correlated_alert_scenarios / (correlated_alert_scenarios + alert_not_correlated_scenarios)",
                notes="No scenarios with alert candidates or alert correlation requirements were executed.",
            )

        # 3.6 Inconclusive Rate: inconclusive / executed
        if executed > 0:
            inconcl_val = inconclusive_cnt / executed
            inconcl = AssuranceMetricV1(
                name="inconclusive_rate",
                numerator=inconclusive_cnt,
                denominator=executed,
                value=inconcl_val,
                status=MetricStatus.AVAILABLE,
                description="Proportion of executed scenarios resulting in inconclusive or ambiguous verdicts",
                formula="inconclusive_executions / executed_test_cases",
            )
        else:
            inconcl = AssuranceMetricV1(
                name="inconclusive_rate",
                numerator=0,
                denominator=0,
                value=None,
                status=MetricStatus.INSUFFICIENT_DATA,
                description="Proportion of executed scenarios resulting in inconclusive or ambiguous verdicts",
                formula="inconclusive_executions / executed_test_cases",
                notes="No test cases were executed; metric undefined.",
            )

        # 3.7 Execution Coverage: executed / total_scenarios
        if total_scenarios > 0:
            cov_val = min(1.0, executed / total_scenarios)
            exec_cov = AssuranceMetricV1(
                name="execution_coverage",
                numerator=executed,
                denominator=total_scenarios,
                value=cov_val,
                status=MetricStatus.AVAILABLE,
                description="Proportion of declared campaign scenarios evaluated against actual test runs",
                formula="executed_test_cases / total_scenarios",
            )
        else:
            exec_cov = AssuranceMetricV1(
                name="execution_coverage",
                numerator=0,
                denominator=0,
                value=None,
                status=MetricStatus.INSUFFICIENT_DATA,
                description="Proportion of declared campaign scenarios evaluated against actual test runs",
                formula="executed_test_cases / total_scenarios",
                notes="Campaign declared 0 scenarios; metric undefined.",
            )

        assurance_metrics = DetectionAssuranceMetricsV1(
            detection_success_rate=det_succ,
            detection_failure_rate=det_fail,
            telemetry_availability_rate=telem_avail,
            evidence_completeness_rate=evid_comp,
            alert_correlation_rate=alert_corr,
            inconclusive_rate=inconcl,
            execution_coverage=exec_cov,
        )

        # 4. Evidence Quality & Manifest Verification
        manifest = run.evidence_manifest
        manifest_status = EvidenceVerificationStatus.UNVERIFIED
        missing_refs: List[str] = []
        invalid_refs: List[str] = []
        integrity_failures: List[str] = []
        evidence_notes: List[str] = []

        total_evidence_records = manifest.total_evidence_count if manifest else 0

        if not manifest or not manifest.manifest_hash:
            manifest_status = EvidenceVerificationStatus.MANIFEST_ABSENT
            evidence_notes.append("No evidence manifest recorded on campaign run.")
        elif verify_manifest:
            manifest_verified = True

            # 1. Verify internal cryptographic hash of the manifest itself
            from proofshield.services.campaign_engine import compute_manifest_hash_from_manifest
            expected_manifest_hash = compute_manifest_hash_from_manifest(
                campaign_id=manifest.campaign_id,
                engine_version=manifest.engine_version,
                execution_config_hash=manifest.execution_config_hash,
                scenario_references=manifest.scenario_references,
            )
            if expected_manifest_hash != manifest.manifest_hash:
                integrity_failures.append(f"Manifest:{manifest.manifest_hash}")
                manifest_verified = False
                evidence_notes.append(
                    f"Evidence manifest internal hash mismatch: expected {expected_manifest_hash[:12]}..., got {manifest.manifest_hash[:12]}..."
                )

            for s_ref in manifest.scenario_references:
                # Check scenario definition
                scen = self.store.get_scenario(s_ref.scenario_id)
                if scen is None:
                    missing_refs.append(f"Scenario:{s_ref.scenario_id}")
                    manifest_verified = False
                else:
                    actual_scen_hash = compute_canonical_hash(scen)
                    if actual_scen_hash != s_ref.scenario_hash:
                        integrity_failures.append(f"Scenario:{s_ref.scenario_id}")
                        manifest_verified = False

                # Check ground truth if present
                if s_ref.ground_truth_id and s_ref.test_run_id:
                    gt = self.store.get_ground_truth_for_run(s_ref.test_run_id)
                    if gt is None:
                        missing_refs.append(f"GroundTruth:{s_ref.ground_truth_id}")
                        manifest_verified = False
                    elif s_ref.ground_truth_hash:
                        actual_gt_hash = compute_canonical_hash(gt)
                        if actual_gt_hash != s_ref.ground_truth_hash:
                            integrity_failures.append(f"GroundTruth:{s_ref.ground_truth_id}")
                            manifest_verified = False

                # Check normalized telemetry events
                for eid, expected_hash in s_ref.telemetry_event_hashes.items():
                    event = self.store.get_normalized_event(eid)
                    if event is None:
                        missing_refs.append(eid)
                        manifest_verified = False
                    else:
                        actual_hash = compute_canonical_hash(event)
                        if actual_hash != expected_hash:
                            integrity_failures.append(eid)
                            manifest_verified = False

                # Check alerts
                for aid, expected_hash in s_ref.alert_hashes.items():
                    alert = self.store.get_alert(aid)
                    if alert is None:
                        missing_refs.append(aid)
                        manifest_verified = False
                    else:
                        actual_hash = compute_canonical_hash(alert)
                        if actual_hash != expected_hash:
                            integrity_failures.append(aid)
                            manifest_verified = False

                # Check test runs
                if s_ref.test_run_id and s_ref.test_run_hash:
                    tr = self.store.get_run(s_ref.test_run_id)
                    if tr is None:
                        missing_refs.append(s_ref.test_run_id)
                        manifest_verified = False
                    else:
                        actual_hash = compute_canonical_hash(tr)
                        if actual_hash != s_ref.test_run_hash:
                            integrity_failures.append(s_ref.test_run_id)
                            manifest_verified = False

            if integrity_failures:
                manifest_status = EvidenceVerificationStatus.INTEGRITY_COMPROMISED
                evidence_notes.append(
                    f"Cryptographic hash mismatch for {len(integrity_failures)} evidence records."
                )
            elif missing_refs:
                manifest_status = EvidenceVerificationStatus.MISSING_EVIDENCE
                evidence_notes.append(
                    f"Store is missing {len(missing_refs)} evidence records referenced in manifest."
                )
            elif manifest_verified:
                manifest_status = EvidenceVerificationStatus.VERIFIED
                evidence_notes.append("All referenced evidence verified against store.")
        else:
            manifest_status = EvidenceVerificationStatus.UNVERIFIED
            evidence_notes.append("Evidence manifest verification bypassed by request.")

        # Overall report completeness check:
        # Report is complete only if all declared scenarios were executed, zero missing evidence references,
        # zero integrity failures, and manifest verification was successfully performed.
        is_complete = (
            unexecuted == 0
            and skipped_cnt == 0
            and len(missing_refs) == 0
            and len(integrity_failures) == 0
            and manifest_status == EvidenceVerificationStatus.VERIFIED
        )

        evidence_quality = EvidenceQualityV1(
            total_evidence_records=total_evidence_records,
            manifest_verification_status=manifest_status,
            missing_evidence_references=sorted(list(set(missing_refs))),
            invalid_evidence_references=sorted(list(set(invalid_refs))),
            integrity_verification_failures=sorted(list(set(integrity_failures))),
            is_complete=is_complete,
            notes=evidence_notes,
        )

        # 5. Root Cause Analysis (reused from CampaignRunV1 or structured groupings)
        root_causes = run.root_cause_analysis

        # 6. Report Identifier & Canonical Digest
        if not report_id:
            # Deterministic report ID based on run_id and engine version
            seed = f"{run.run_id}:{self.engine_version}"
            short_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
            report_id = f"RPT-{run.campaign_id[:24]}-{short_hash}"

        report_digest = compute_assurance_report_digest(
            campaign_id=run.campaign_id,
            campaign_run_id=run.run_id,
            engine_version=self.engine_version,
            execution_summary=execution_summary,
            assurance_metrics=assurance_metrics,
            diagnostic_distribution=diagnostic_distribution,
            evidence_quality=evidence_quality,
            root_cause_analysis=root_causes,
            is_complete=is_complete,
        )

        return CampaignAssuranceReportV1(
            schema_version="v1",
            report_id=report_id,
            campaign_id=run.campaign_id,
            campaign_run_id=run.run_id,
            generated_at=datetime.now(timezone.utc),
            engine_version=self.engine_version,
            execution_summary=execution_summary,
            assurance_metrics=assurance_metrics,
            diagnostic_distribution=diagnostic_distribution,
            evidence_quality=evidence_quality,
            root_cause_analysis=root_causes,
            is_complete=is_complete,
            report_digest=report_digest,
            metadata={
                "source_run_status": run.status.value,
                "is_replay": run.is_replay,
                "manifest_verified": verify_manifest,
            },
        )

    @classmethod
    def verify_report_integrity(cls, report: CampaignAssuranceReportV1) -> bool:
        """Validate whether a stored CampaignAssuranceReportV1 matches its computed canonical digest.

        Detects accidental bit rot, silent corruption, or manual data modifications.
        """
        expected_digest = compute_assurance_report_digest(
            campaign_id=report.campaign_id,
            campaign_run_id=report.campaign_run_id,
            engine_version=report.engine_version,
            execution_summary=report.execution_summary,
            assurance_metrics=report.assurance_metrics,
            diagnostic_distribution=report.diagnostic_distribution,
            evidence_quality=report.evidence_quality,
            root_cause_analysis=report.root_cause_analysis,
            is_complete=report.is_complete,
        )
        return expected_digest == report.report_digest
