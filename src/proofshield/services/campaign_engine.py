"""Deterministic Campaign Execution & Replay Engine.

Architecture Layer 5 extension providing:
- Deterministic campaign scenario resolution and execution.
- Failure isolation policies (CONTINUE_ON_ERROR vs STOP_ON_ERROR).
- Auditable evidence manifests with canonical SHA-256 integrity verification.
- Replay engine against captured evidence with immutability guarantees.
- Root-cause diagnostic aggregation across campaign results.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from proofshield.schemas.campaign import (
    CampaignComparisonV1,
    CampaignDefinitionV1,
    CampaignExecutionConfigV1,
    CampaignExecutionPolicy,
    CampaignReplayResultV1,
    CampaignRunStatus,
    CampaignRunV1,
    CampaignSummaryV1,
    EvidenceManifestV1,
    ReplayClassification,
    RootCauseGroupV1,
    ScenarioCampaignResultV1,
    ScenarioEvidenceRefV1,
    ScenarioRunStatus,
)
from proofshield.schemas.common import (
    AttributionStatus,
    DiagnosticCategory,
    ExecutionStatus,
    FailureCategory,
)
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.base_store import StoreProtocol, to_comparable_utc
from proofshield.services.canonical import compute_canonical_hash
from proofshield.services.campaign_comparison import compare_campaign_runs
from proofshield.services.evaluation import AssuranceEngine


def compute_manifest_hash_from_manifest(
    campaign_id: str,
    engine_version: str,
    execution_config_hash: Optional[str],
    scenario_references: List[ScenarioEvidenceRefV1],
) -> str:
    """Compute the deterministic canonical SHA-256 hash of an EvidenceManifestV1's source inputs."""
    sorted_refs = sorted(scenario_references, key=lambda r: r.scenario_id)
    source_evidence_for_hash = {
        "campaign_id": campaign_id,
        "engine_version": engine_version,
        "execution_config_hash": execution_config_hash,
        "scenarios": [
            {
                "scenario_id": ref.scenario_id,
                "scenario_hash": ref.scenario_hash,
                "test_run_id": ref.test_run_id,
                "test_run_hash": ref.test_run_hash,
                "telemetry_event_hashes": {
                    k: ref.telemetry_event_hashes[k]
                    for k in sorted(ref.telemetry_event_hashes.keys())
                },
                "alert_hashes": {
                    k: ref.alert_hashes[k]
                    for k in sorted(ref.alert_hashes.keys())
                },
                "ground_truth_id": ref.ground_truth_id,
                "ground_truth_hash": ref.ground_truth_hash,
            }
            for ref in sorted_refs
        ],
    }
    return compute_canonical_hash(source_evidence_for_hash)


class CampaignEngine:
    """Deterministic detection validation campaign engine.

    Executes campaign definitions against the existing AssuranceEngine,
    captures diagnostic results and evidence manifests, aggregates metrics,
    and supports deterministic replay against preserved evidence.
    """

    VERSION = "v1.0.0"

    def __init__(self, store: StoreProtocol, engine_version: str = "v0.1.0") -> None:
        self.store = store
        self.engine_version = engine_version

    def execute_campaign(
        self,
        campaign_id: str,
        execution_config_override: Optional[CampaignExecutionConfigV1] = None,
        scenario_run_map: Optional[Dict[str, str]] = None,
        is_replay: bool = False,
        source_run_id: Optional[str] = None,
    ) -> CampaignRunV1:
        """Execute a validation campaign deterministically.

        Steps:
        1. Resolve campaign definition from store.
        2. Apply execution configuration and error policy.
        3. Evaluate each scenario in declared order using AssuranceEngine.
        4. Capture diagnostics and build canonical evidence manifest.
        5. Aggregate results, calculate summary metrics, and group root causes.
        6. Persist campaign run record in store.
        """
        campaign = self.store.get_campaign(campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign not found: {campaign_id}")

        config = execution_config_override or campaign.execution_config
        started_at = datetime.now(timezone.utc)
        run_id = f"CRUN-{started_at.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

        scenario_results: List[ScenarioCampaignResultV1] = []
        scenario_evidence_refs: List[ScenarioEvidenceRefV1] = []
        errors: List[str] = []
        warnings: List[str] = []

        total_scenarios = len(campaign.scenario_ids)
        halted_early = False

        assurance_engine = AssuranceEngine(
            self.store,
            default_alert_grace_period_seconds=config.default_alert_grace_period_seconds,
            strict_attribution=config.strict_attribution if config.strict_attribution is not None else False,
        )

        for order, scenario_id in enumerate(campaign.scenario_ids):
            if halted_early:
                scenario_results.append(
                    ScenarioCampaignResultV1(
                        scenario_id=scenario_id,
                        execution_order=order,
                        status=ScenarioRunStatus.SKIPPED,
                        reason="Execution halted early due to STOP_ON_ERROR policy on previous scenario failure",
                        confidence="definitive",
                    )
                )
                continue

            scenario = self.store.get_scenario(scenario_id)
            if scenario is None:
                err_msg = f"Scenario definition not found in store: {scenario_id}"
                errors.append(err_msg)
                res = ScenarioCampaignResultV1(
                    scenario_id=scenario_id,
                    execution_order=order,
                    predicted_category=DiagnosticCategory.ERROR,
                    status=ScenarioRunStatus.ERROR,
                    reason=err_msg,
                    confidence="definitive",
                    error_message=err_msg,
                    error_classification="SCENARIO_NOT_FOUND",
                )
                scenario_results.append(res)
                if config.execution_policy == CampaignExecutionPolicy.STOP_ON_ERROR:
                    halted_early = True
                continue

            scenario_hash = compute_canonical_hash(scenario)

            # Resolve associated TestRun
            test_run: Optional[TestRunV1] = None
            if scenario_run_map and scenario_id in scenario_run_map:
                mapped_run_id = scenario_run_map[scenario_id]
                test_run = self.store.get_run(mapped_run_id)
                if test_run is None:
                    warnings.append(f"Mapped test run '{mapped_run_id}' for scenario '{scenario_id}' not found.")
            else:
                candidate_runs = self.store.list_runs(scenario_id=scenario_id)
                if candidate_runs:
                    # Deterministically pick the latest run by executed_at
                    candidate_runs.sort(key=lambda r: to_comparable_utc(r.executed_at), reverse=True)
                    test_run = candidate_runs[0]

            if test_run is None:
                # Scenario has not been executed
                res = ScenarioCampaignResultV1(
                    scenario_id=scenario_id,
                    execution_order=order,
                    predicted_category=DiagnosticCategory.TEST_NOT_EXECUTED,
                    status=ScenarioRunStatus.SKIPPED,
                    reason=f"No recorded test run found in store for scenario: {scenario_id}",
                    confidence="definitive",
                    error_classification="TEST_NOT_EXECUTED",
                )
                scenario_results.append(res)
                scenario_evidence_refs.append(
                    ScenarioEvidenceRefV1(
                        scenario_id=scenario_id,
                        scenario_hash=scenario_hash,
                    )
                )
                continue

            test_run_hash = compute_canonical_hash(test_run)

            # Execute evaluation via AssuranceEngine
            try:
                diag = assurance_engine.evaluate_run(
                    test_run.run_id,
                    strict_attribution=config.strict_attribution,
                )
                self.store.add_result(diag)

                # Map diagnostic verdict to scenario campaign status
                if diag.predicted_category == DiagnosticCategory.PASS:
                    scen_status = ScenarioRunStatus.PASS
                elif diag.predicted_category == DiagnosticCategory.INCONCLUSIVE:
                    scen_status = ScenarioRunStatus.INCONCLUSIVE
                elif diag.predicted_category == DiagnosticCategory.ERROR:
                    scen_status = ScenarioRunStatus.ERROR
                else:
                    scen_status = ScenarioRunStatus.FAILURE

                attr_meta = diag.metadata.get("attribution", {})
                attr_status_val = attr_meta.get("status")
                attr_status = None
                if attr_status_val:
                    try:
                        attr_status = AttributionStatus(attr_status_val)
                    except ValueError:
                        pass

                res = ScenarioCampaignResultV1(
                    scenario_id=scenario_id,
                    execution_order=order,
                    test_run_id=test_run.run_id,
                    diagnostic_id=diag.diagnostic_id,
                    predicted_category=diag.predicted_category,
                    failure_category=diag.failure_category,
                    status=scen_status,
                    confidence=diag.confidence,
                    reason=diag.reason,
                    diagnostic_reasons=diag.diagnostic_reasons,
                    supporting_evidence_ids=diag.supporting_evidence_ids,
                    contradictory_evidence_ids=diag.contradictory_evidence_ids,
                    checks_performed=diag.checks_performed,
                    alternative_eliminations=diag.alternative_eliminations,
                    missing_evidence=diag.missing_evidence,
                    attribution_status=attr_status,
                )
                scenario_results.append(res)

                # Ground truth check
                gt = self.store.get_ground_truth_for_run(test_run.run_id)
                gt_hash = compute_canonical_hash(gt) if gt else None

                # Accurately partition evidence IDs into telemetry events vs alerts and capture content hashes
                all_evidence_ids = set(diag.supporting_evidence_ids + diag.contradictory_evidence_ids)
                telemetry_ids = []
                telemetry_hashes = {}
                alert_ids = []
                alert_hashes = {}
                for eid in sorted(all_evidence_ids):
                    ev = self.store.get_normalized_event(eid)
                    if ev is not None:
                        telemetry_ids.append(eid)
                        telemetry_hashes[eid] = compute_canonical_hash(ev)
                    else:
                        alt = self.store.get_alert(eid)
                        if alt is not None:
                            alert_ids.append(eid)
                            alert_hashes[eid] = compute_canonical_hash(alt)

                scenario_evidence_refs.append(
                    ScenarioEvidenceRefV1(
                        scenario_id=scenario_id,
                        scenario_hash=scenario_hash,
                        test_run_id=test_run.run_id,
                        test_run_hash=test_run_hash,
                        telemetry_event_ids=telemetry_ids,
                        telemetry_event_hashes=telemetry_hashes,
                        alert_ids=alert_ids,
                        alert_hashes=alert_hashes,
                        ground_truth_id=gt.ground_truth_id if gt else None,
                        ground_truth_hash=gt_hash,
                        diagnostic_id=diag.diagnostic_id,
                    )
                )

                if scen_status == ScenarioRunStatus.ERROR and config.execution_policy == CampaignExecutionPolicy.STOP_ON_ERROR:
                    halted_early = True

            except Exception as exc:
                err_msg = f"Evaluation exception on scenario '{scenario_id}': {str(exc)}"
                errors.append(err_msg)
                res = ScenarioCampaignResultV1(
                    scenario_id=scenario_id,
                    execution_order=order,
                    test_run_id=test_run.run_id,
                    predicted_category=DiagnosticCategory.ERROR,
                    status=ScenarioRunStatus.ERROR,
                    reason=err_msg,
                    confidence="definitive",
                    error_message=err_msg,
                    error_classification="EVALUATION_EXCEPTION",
                )
                scenario_results.append(res)
                scenario_evidence_refs.append(
                    ScenarioEvidenceRefV1(
                        scenario_id=scenario_id,
                        scenario_hash=scenario_hash,
                        test_run_id=test_run.run_id,
                        test_run_hash=test_run_hash,
                    )
                )
                if config.execution_policy == CampaignExecutionPolicy.STOP_ON_ERROR:
                    halted_early = True

        completed_at = datetime.now(timezone.utc)

        # ── 4. Build Evidence Manifest ─────────────────────────────────────────
        scenario_evidence_refs.sort(key=lambda r: r.scenario_id)
        config_hash = compute_canonical_hash(config)
        config_snapshot = config.model_dump(mode="json")

        manifest_hash = compute_manifest_hash_from_manifest(
            campaign_id=campaign_id,
            engine_version=assurance_engine.VERSION,
            execution_config_hash=config_hash,
            scenario_references=scenario_evidence_refs,
        )

        total_evidence_count = 0
        for r in scenario_evidence_refs:
            total_evidence_count += len(r.telemetry_event_ids) + len(r.alert_ids)

        evidence_manifest = EvidenceManifestV1(
            campaign_id=campaign_id,
            campaign_run_id=run_id,
            canonical_hash_algorithm="sha256",
            execution_config_hash=config_hash,
            execution_config_snapshot=config_snapshot,
            manifest_hash=manifest_hash,
            scenario_references=scenario_evidence_refs,
            total_evidence_count=total_evidence_count,
            engine_version=assurance_engine.VERSION,
            schema_version="v1",
            generated_at=completed_at,
        )

        # ── 5. Build Root Cause Analysis ───────────────────────────────────────
        root_cause_analysis = self._aggregate_root_causes(scenario_results)

        # ── 6. Aggregate Summary Metrics ───────────────────────────────────────
        summary = self._calculate_summary(scenario_results, total_scenarios)

        # Determine overall run status
        if halted_early or (errors and len(scenario_results) == len(errors)):
            run_status = CampaignRunStatus.FAILED
        elif errors or summary.error_scenarios > 0:
            run_status = CampaignRunStatus.COMPLETED_WITH_ERRORS
        else:
            run_status = CampaignRunStatus.COMPLETED

        campaign_run = CampaignRunV1(
            run_id=run_id,
            campaign_id=campaign_id,
            campaign_version="v1",
            status=run_status,
            started_at=started_at,
            completed_at=completed_at,
            total_scenarios=total_scenarios,
            scenario_results=scenario_results,
            summary=summary,
            evidence_manifest=evidence_manifest,
            root_cause_analysis=root_cause_analysis,
            errors=errors,
            warnings=warnings,
            is_replay=is_replay,
            source_run_id=source_run_id,
            metadata={
                "execution_policy": config.execution_policy.value,
                "strict_attribution": config.strict_attribution,
                "default_alert_grace_period_seconds": config.default_alert_grace_period_seconds,
            },
        )

        with self.store.transaction():
            self.store.add_campaign_run(campaign_run)

        return campaign_run

    def replay_campaign_run(
        self,
        source_run_id: str,
        execution_config_override: Optional[CampaignExecutionConfigV1] = None,
    ) -> CampaignReplayResultV1:
        """Replay a previously executed campaign run against preserved evidence.

        Guarantees:
        - Never mutates or overwrites the original campaign run.
        - Verifies that all referenced evidence and scenario definitions still exist
          and match their original canonical hashes.
        - Identifies missing or altered evidence without fabricating records.
        - Re-executes the campaign against original evidence inputs.
        - Generates a newly identified replay run and deterministic comparison.
        """
        source_run = self.store.get_campaign_run(source_run_id)
        if source_run is None:
            raise ValueError(f"Source campaign run not found: {source_run_id}")

        missing_evidence: List[str] = []
        altered_evidence: List[str] = []
        scenario_run_map: Dict[str, str] = {}

        manifest = source_run.evidence_manifest

        # 1. Verify Manifest Internal Cryptographic Integrity
        expected_manifest_hash = compute_manifest_hash_from_manifest(
            campaign_id=manifest.campaign_id,
            engine_version=manifest.engine_version,
            execution_config_hash=manifest.execution_config_hash,
            scenario_references=manifest.scenario_references,
        )
        manifest_valid = (expected_manifest_hash == manifest.manifest_hash)
        if not manifest_valid:
            altered_evidence.append(
                f"EvidenceManifest:{manifest.campaign_run_id} (internal manifest_hash mismatch: computed {expected_manifest_hash[:8]}..., recorded {manifest.manifest_hash[:8]}...)"
            )

        # 2. Verify all referenced evidence in store
        for ref in manifest.scenario_references:
            # Scenario definition
            scenario = self.store.get_scenario(ref.scenario_id)
            if scenario is None:
                missing_evidence.append(f"Scenario:{ref.scenario_id}")
            else:
                curr_scen_hash = compute_canonical_hash(scenario)
                if curr_scen_hash != ref.scenario_hash:
                    altered_evidence.append(f"Scenario:{ref.scenario_id} (hash changed)")

            # Test run
            if ref.test_run_id:
                test_run = self.store.get_run(ref.test_run_id)
                if test_run is None:
                    missing_evidence.append(f"TestRun:{ref.test_run_id}")
                else:
                    curr_run_hash = compute_canonical_hash(test_run)
                    if ref.test_run_hash and curr_run_hash != ref.test_run_hash:
                        altered_evidence.append(f"TestRun:{ref.test_run_id} (hash changed)")
                    scenario_run_map[ref.scenario_id] = ref.test_run_id

            # Telemetry events (content verification)
            if ref.telemetry_event_hashes:
                for ev_id, expected_hash in ref.telemetry_event_hashes.items():
                    ev = self.store.get_normalized_event(ev_id)
                    if ev is None:
                        missing_evidence.append(f"NormalizedEvent:{ev_id}")
                    else:
                        curr_ev_hash = compute_canonical_hash(ev)
                        if curr_ev_hash != expected_hash:
                            altered_evidence.append(
                                f"NormalizedEvent:{ev_id} (hash changed: expected {expected_hash[:8]}..., got {curr_ev_hash[:8]}...)"
                            )
            else:
                for ev_id in ref.telemetry_event_ids:
                    if self.store.get_normalized_event(ev_id) is None:
                        missing_evidence.append(f"NormalizedEvent:{ev_id}")

            # Alerts (content verification)
            if ref.alert_hashes:
                for alt_id, expected_hash in ref.alert_hashes.items():
                    alt = self.store.get_alert(alt_id)
                    if alt is None:
                        missing_evidence.append(f"Alert:{alt_id}")
                    else:
                        curr_alt_hash = compute_canonical_hash(alt)
                        if curr_alt_hash != expected_hash:
                            altered_evidence.append(
                                f"Alert:{alt_id} (hash changed: expected {expected_hash[:8]}..., got {curr_alt_hash[:8]}...)"
                            )
            else:
                for alt_id in ref.alert_ids:
                    if self.store.get_alert(alt_id) is None:
                        missing_evidence.append(f"Alert:{alt_id}")

            # Ground truth
            if ref.ground_truth_id and ref.test_run_id:
                gt = self.store.get_ground_truth_for_run(ref.test_run_id)
                if gt is None:
                    missing_evidence.append(f"GroundTruth:{ref.ground_truth_id}")
                elif ref.ground_truth_hash:
                    curr_gt_hash = compute_canonical_hash(gt)
                    if curr_gt_hash != ref.ground_truth_hash:
                        altered_evidence.append(f"GroundTruth:{ref.ground_truth_id} (hash changed)")

        # 3. Determine Replay Classification
        assurance_engine = AssuranceEngine(self.store)
        is_same_engine = (manifest.engine_version == assurance_engine.VERSION)

        # Resolve effective execution configuration for replay
        if execution_config_override is not None:
            effective_config = execution_config_override
        else:
            effective_config = CampaignExecutionConfigV1(
                execution_policy=CampaignExecutionPolicy(
                    source_run.metadata.get("execution_policy", CampaignExecutionPolicy.CONTINUE_ON_ERROR.value)
                ),
                strict_attribution=source_run.metadata.get("strict_attribution"),
                default_alert_grace_period_seconds=source_run.metadata.get("default_alert_grace_period_seconds", 3600),
            )

        replay_config_hash = compute_canonical_hash(effective_config)
        is_same_config = (
            manifest.execution_config_hash is None
            or replay_config_hash == manifest.execution_config_hash
        )

        if not manifest_valid:
            classification = ReplayClassification.INVALID_MANIFEST
            verdict = "INVALID_MANIFEST"
        elif len(missing_evidence) > 0 or len(altered_evidence) > 0:
            classification = ReplayClassification.EVIDENCE_REEVALUATION
            verdict = "PARTIAL_REPLAY" if len(missing_evidence) < len(manifest.scenario_references) else "INVALID_REPLAY"
        elif not is_same_engine or not is_same_config:
            classification = ReplayClassification.ENGINE_COMPARISON
            verdict = "ENGINE_COMPARISON"
        else:
            classification = ReplayClassification.EXACT_REPLAY
            verdict = "EXACT_REPLAY"

        # Re-execute campaign with scenario_run_map preserving exact historical bindings
        replay_run = self.execute_campaign(
            campaign_id=source_run.campaign_id,
            execution_config_override=effective_config,
            scenario_run_map=scenario_run_map,
            is_replay=True,
            source_run_id=source_run_id,
        )

        comparison = compare_campaign_runs(base_run=source_run, target_run=replay_run)

        is_exact = (
            classification == ReplayClassification.EXACT_REPLAY
            and comparison.comparison_verdict == "IDENTICAL"
        )

        return CampaignReplayResultV1(
            replay_run=replay_run,
            source_run=source_run,
            comparison=comparison,
            is_exact_replay=is_exact,
            replay_classification=classification,
            manifest_valid=manifest_valid,
            missing_evidence=missing_evidence,
            altered_evidence=altered_evidence,
            verdict=verdict,
        )

    def compare_runs(self, run_id_a: str, run_id_b: str) -> CampaignComparisonV1:
        """Compare two campaign runs retrieved by identifier."""
        run_a = self.store.get_campaign_run(run_id_a)
        if run_a is None:
            raise ValueError(f"Baseline campaign run not found: {run_id_a}")
        run_b = self.store.get_campaign_run(run_id_b)
        if run_b is None:
            raise ValueError(f"Target campaign run not found: {run_id_b}")
        return compare_campaign_runs(base_run=run_a, target_run=run_b)

    def _calculate_summary(
        self, scenario_results: List[ScenarioCampaignResultV1], total_scenarios: int
    ) -> CampaignSummaryV1:
        """Aggregate statistical summary metrics with explicit denominators."""
        category_counts: Dict[str, int] = {}
        passed = 0
        failed = 0
        inconclusive = 0
        error_cnt = 0
        executed = 0
        complete_evidence_count = 0

        # Ground truth tracking for precision/recall/F1
        tp = 0
        fp = 0
        fn = 0
        gt_available_count = 0

        for r in scenario_results:
            cat_name = r.predicted_category.value if r.predicted_category else "NOT_EVALUATED"
            category_counts[cat_name] = category_counts.get(cat_name, 0) + 1

            is_unexecuted = (
                r.status == ScenarioRunStatus.SKIPPED
                or r.predicted_category == DiagnosticCategory.TEST_NOT_EXECUTED
            )
            if not is_unexecuted:
                executed += 1
                if not r.missing_evidence and r.predicted_category is not None:
                    complete_evidence_count += 1

            if r.status == ScenarioRunStatus.PASS:
                passed += 1
            elif r.status == ScenarioRunStatus.FAILURE:
                failed += 1
            elif r.status == ScenarioRunStatus.INCONCLUSIVE:
                inconclusive += 1
            elif r.status == ScenarioRunStatus.ERROR:
                error_cnt += 1

            # Check ground truth if test_run_id is available
            if r.test_run_id:
                gt = self.store.get_ground_truth_for_run(r.test_run_id)
                if gt:
                    gt_available_count += 1
                    is_pred_pass = (r.predicted_category == DiagnosticCategory.PASS)
                    is_expected_pass = (gt.expected_diagnostic_category == DiagnosticCategory.PASS)
                    if is_pred_pass and is_expected_pass:
                        tp += 1
                    elif is_pred_pass and not is_expected_pass:
                        fp += 1
                    elif not is_pred_pass and is_expected_pass:
                        fn += 1

        unexecuted = total_scenarios - executed
        coverage = round(executed / total_scenarios, 4) if total_scenarios > 0 else 0.0
        pass_rate = round(passed / executed, 4) if executed > 0 else None
        inconclusive_rate = round(inconclusive / executed, 4) if executed > 0 else None
        error_rate = round(error_cnt / total_scenarios, 4) if total_scenarios > 0 else 0.0
        completeness = round(complete_evidence_count / executed, 4) if executed > 0 else None

        precision = None
        recall = None
        f1 = None
        metrics_notes: List[str] = [
            f"Pass rate denominator: {executed} executed scenarios (passed_scenarios / executed_scenarios).",
            f"Execution coverage denominator: {total_scenarios} total declared scenarios.",
        ]

        if executed > 0 and gt_available_count == executed:
            if (tp + fp) > 0:
                precision = round(tp / (tp + fp), 4)
            if (tp + fn) > 0:
                recall = round(tp / (tp + fn), 4)
            if precision is not None and recall is not None and (precision + recall) > 0:
                f1 = round(2 * (precision * recall) / (precision + recall), 4)
            metrics_notes.append(
                f"Precision/Recall/F1 computed against {gt_available_count} verified independent ground truth records."
            )
        else:
            metrics_notes.append(
                f"Precision/Recall/F1 unavailable: only {gt_available_count}/{executed} executed scenarios have independent ground truth."
            )

        return CampaignSummaryV1(
            total_scenarios=total_scenarios,
            executed_scenarios=executed,
            unexecuted_scenarios=unexecuted,
            passed_scenarios=passed,
            failed_scenarios=failed,
            inconclusive_scenarios=inconclusive,
            error_scenarios=error_cnt,
            category_counts=category_counts,
            pass_rate=pass_rate,
            execution_coverage=coverage,
            inconclusive_rate=inconclusive_rate,
            error_rate=error_rate,
            evidence_completeness=completeness,
            precision=precision,
            recall=recall,
            f1=f1,
            metrics_notes=metrics_notes,
        )

    def _aggregate_root_causes(
        self, scenario_results: List[ScenarioCampaignResultV1]
    ) -> List[RootCauseGroupV1]:
        """Group non-passing scenarios deterministically by primary underlying diagnostic cause."""
        groups: Dict[str, Dict[str, Any]] = {}

        for r in scenario_results:
            if r.status == ScenarioRunStatus.PASS:
                continue

            # Classify cause deterministically based on predicted_category, failure_category, and reason
            cat = r.predicted_category
            if cat == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING:
                cause_key = "MISSING_EXPECTED_TELEMETRY"
                explanation = "Sensor pipeline failed to collect or ingest expected security telemetry matching scenario signature."
            elif cat == DiagnosticCategory.DETECTION_NOT_TRIGGERED:
                cause_key = "DETECTION_RULE_DID_NOT_TRIGGER"
                explanation = "Normalized telemetry matched scenario signature, but expected SIEM/EDR detection rule did not fire an alert."
            elif cat == DiagnosticCategory.ALERT_NOT_CORRELATED:
                cause_key = "ALERT_CORRELATION_FAILURE"
                explanation = "Alert was generated but could not be correlated to test run due to host, window, or token boundary mismatch."
            elif cat == DiagnosticCategory.INCONCLUSIVE:
                if r.missing_evidence:
                    cause_key = "INCOMPLETE_EVIDENCE"
                    explanation = "Diagnostic evaluation could not conclude due to missing or ambiguous telemetry evidence."
                else:
                    cause_key = "AMBIGUOUS_EVIDENCE"
                    explanation = "Evidence contained conflicting data points or unresolved provenance attribution."
            elif cat == DiagnosticCategory.TEST_NOT_EXECUTED:
                cause_key = "UNEXECUTED_SCENARIO"
                explanation = "Scenario has no corresponding test run execution recorded in storage."
            elif cat == DiagnosticCategory.ERROR or r.status == ScenarioRunStatus.ERROR:
                cause_key = "EXECUTION_OR_EVALUATION_ERROR"
                explanation = f"Scenario failed during execution or resolution: {r.reason}"
            elif r.failure_category == FailureCategory.PIPELINE_LATENCY:
                cause_key = "PIPELINE_LATENCY_EXCEEDED"
                explanation = "Telemetry arrived with pipeline latency exceeding the scenario acceptable latency window."
            else:
                cause_key = "UNCLASSIFIED_FAILURE"
                explanation = f"Diagnostic verdict classified as failure: {r.reason}"

            if cause_key not in groups:
                groups[cause_key] = {
                    "scenario_ids": [],
                    "evidence_ids": set(),
                    "explanation": explanation,
                }
            groups[cause_key]["scenario_ids"].append(r.scenario_id)
            for eid in r.supporting_evidence_ids[:3]:
                groups[cause_key]["evidence_ids"].add(eid)

        result: List[RootCauseGroupV1] = []
        for cause_key in sorted(groups.keys()):
            g = groups[cause_key]
            result.append(
                RootCauseGroupV1(
                    root_cause_category=cause_key,
                    scenario_count=len(g["scenario_ids"]),
                    scenario_ids=g["scenario_ids"],
                    supporting_evidence_ids=sorted(list(g["evidence_ids"])),
                    explanation=g["explanation"],
                    confidence="definitive",
                )
            )

        return result
