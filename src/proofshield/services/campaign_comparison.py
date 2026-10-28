"""Deterministic comparison and regression analysis between campaign runs.

Identifies regressions, improvements, inconclusive transitions, evidence variance,
and attribution shifts between baseline and target campaign runs.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from proofshield.schemas.campaign import (
    CampaignComparisonV1,
    CampaignRunV1,
    ScenarioCampaignResultV1,
    ScenarioRegressionV1,
    ScenarioRunStatus,
)
from proofshield.schemas.common import DiagnosticCategory


def compare_campaign_runs(
    base_run: CampaignRunV1, target_run: CampaignRunV1
) -> CampaignComparisonV1:
    """Compare two campaign runs deterministically.

    Identifies:
    1. Regressions (PASS -> non-PASS).
    2. Improvements (non-PASS -> PASS).
    3. Inconclusive transitions.
    4. Added and removed scenarios.
    5. Aggregate metric deltas.
    6. Evidence manifest differences.
    7. Attribution status shifts.

    Distinguishes genuine detection logic shifts from differences caused by
    changed scenario definitions, modified engine versions, or altered evidence.
    """
    comparison_id = f"CMP-{uuid.uuid4().hex[:12].upper()}"

    # Index scenarios by ID for both runs
    base_results: Dict[str, ScenarioCampaignResultV1] = {
        r.scenario_id: r for r in base_run.scenario_results
    }
    target_results: Dict[str, ScenarioCampaignResultV1] = {
        r.scenario_id: r for r in target_run.scenario_results
    }

    base_ids = set(base_results.keys())
    target_ids = set(target_results.keys())

    added_scenarios = sorted(list(target_ids - base_ids))
    removed_scenarios = sorted(list(base_ids - target_ids))
    common_scenarios = sorted(list(base_ids & target_ids))

    is_equivalent_campaign = (
        base_run.campaign_id == target_run.campaign_id
        and [r.scenario_id for r in base_run.scenario_results] == [r.scenario_id for r in target_run.scenario_results]
    )

    is_equivalent_evidence = (
        base_run.evidence_manifest.manifest_hash == target_run.evidence_manifest.manifest_hash
    )

    regressions: List[ScenarioRegressionV1] = []
    improvements: List[ScenarioRegressionV1] = []
    inconclusive_transitions: List[ScenarioRegressionV1] = []
    attribution_changes: List[Dict[str, Any]] = []

    for s_id in common_scenarios:
        b_res = base_results[s_id]
        t_res = target_results[s_id]

        b_cat = b_res.predicted_category
        t_cat = t_res.predicted_category

        # Check attribution changes
        if b_res.attribution_status != t_res.attribution_status:
            attribution_changes.append({
                "scenario_id": s_id,
                "previous_attribution": b_res.attribution_status.value if b_res.attribution_status else None,
                "current_attribution": t_res.attribution_status.value if t_res.attribution_status else None,
            })

        # Scenario outcome transition
        if b_res.status == ScenarioRunStatus.PASS and t_res.status != ScenarioRunStatus.PASS:
            regressions.append(
                ScenarioRegressionV1(
                    scenario_id=s_id,
                    previous_category=b_cat,
                    current_category=t_cat,
                    previous_status=b_res.status,
                    current_status=t_res.status,
                    transition_type="REGRESSION",
                    reason=(
                        f"Scenario regressed from PASS ({b_cat.value if b_cat else 'PASS'}) "
                        f"to {t_res.status.value} ({t_cat.value if t_cat else 'UNKNOWN'}): {t_res.reason}"
                    ),
                )
            )
        elif b_res.status != ScenarioRunStatus.PASS and t_res.status == ScenarioRunStatus.PASS:
            improvements.append(
                ScenarioRegressionV1(
                    scenario_id=s_id,
                    previous_category=b_cat,
                    current_category=t_cat,
                    previous_status=b_res.status,
                    current_status=t_res.status,
                    transition_type="IMPROVEMENT",
                    reason=(
                        f"Scenario improved from {b_res.status.value} ({b_cat.value if b_cat else 'UNKNOWN'}) "
                        f"to PASS: {t_res.reason}"
                    ),
                )
            )
        elif (
            b_res.status == ScenarioRunStatus.INCONCLUSIVE
            and t_res.status != ScenarioRunStatus.INCONCLUSIVE
        ) or (
            b_res.status != ScenarioRunStatus.INCONCLUSIVE
            and t_res.status == ScenarioRunStatus.INCONCLUSIVE
        ):
            inconclusive_transitions.append(
                ScenarioRegressionV1(
                    scenario_id=s_id,
                    previous_category=b_cat,
                    current_category=t_cat,
                    previous_status=b_res.status,
                    current_status=t_res.status,
                    transition_type="INCONCLUSIVE_SHIFT",
                    reason=(
                        f"Scenario inconclusive transition from {b_res.status.value} "
                        f"to {t_res.status.value}: {t_res.reason}"
                    ),
                )
            )

    # Metric deltas
    b_sum = base_run.summary
    t_sum = target_run.summary

    def _delta(val1: Optional[float], val2: Optional[float]) -> Optional[float]:
        if val1 is None or val2 is None:
            return None
        return round(val2 - val1, 4)

    metric_deltas: Dict[str, Optional[float]] = {
        "pass_rate_delta": _delta(b_sum.pass_rate, t_sum.pass_rate),
        "execution_coverage_delta": round(t_sum.execution_coverage - b_sum.execution_coverage, 4),
        "inconclusive_rate_delta": _delta(b_sum.inconclusive_rate, t_sum.inconclusive_rate),
        "error_rate_delta": round(t_sum.error_rate - b_sum.error_rate, 4),
        "passed_scenarios_delta": float(t_sum.passed_scenarios - b_sum.passed_scenarios),
        "failed_scenarios_delta": float(t_sum.failed_scenarios - b_sum.failed_scenarios),
    }

    # Evidence changes
    base_manifest_refs = {
        r.scenario_id: r for r in base_run.evidence_manifest.scenario_references
    }
    target_manifest_refs = {
        r.scenario_id: r for r in target_run.evidence_manifest.scenario_references
    }

    evidence_changes: Dict[str, Any] = {
        "manifest_hash_match": is_equivalent_evidence,
        "base_manifest_hash": base_run.evidence_manifest.manifest_hash,
        "target_manifest_hash": target_run.evidence_manifest.manifest_hash,
        "scenarios_with_evidence_variance": [],
    }

    for s_id in common_scenarios:
        b_ref = base_manifest_refs.get(s_id)
        t_ref = target_manifest_refs.get(s_id)
        if b_ref and t_ref:
            if b_ref.scenario_hash != t_ref.scenario_hash or b_ref.test_run_hash != t_ref.test_run_hash:
                evidence_changes["scenarios_with_evidence_variance"].append({
                    "scenario_id": s_id,
                    "scenario_def_changed": b_ref.scenario_hash != t_ref.scenario_hash,
                    "test_run_changed": b_ref.test_run_hash != t_ref.test_run_hash,
                })

    # Explanations
    explanations: List[str] = []
    if not is_equivalent_campaign:
        explanations.append(
            f"Campaign definitions differ: {len(added_scenarios)} added, {len(removed_scenarios)} removed."
        )

    if not is_equivalent_evidence:
        explanations.append(
            "Evidence manifests differ between runs; outcome changes may stem from altered telemetry or test runs rather than detection rule changes."
        )
    else:
        explanations.append(
            "Evidence manifests are identical (matching SHA-256 hash); outcome differences reflect deterministic detection logic or attribution configuration shifts."
        )

    if regressions:
        explanations.append(f"Detected {len(regressions)} detection regressions (PASS -> non-PASS).")
    if improvements:
        explanations.append(f"Detected {len(improvements)} detection improvements (non-PASS -> PASS).")

    # Verdict
    if not regressions and not improvements and not added_scenarios and not removed_scenarios and is_equivalent_evidence:
        verdict = "IDENTICAL"
    elif regressions and not improvements:
        verdict = "REGRESSION"
    elif improvements and not regressions:
        verdict = "IMPROVEMENT"
    elif regressions and improvements:
        verdict = "MIXED"
    elif not is_equivalent_evidence:
        verdict = "DIVERGENT_INPUTS"
    else:
        verdict = "STABLE"

    return CampaignComparisonV1(
        comparison_id=comparison_id,
        base_run_id=base_run.run_id,
        target_run_id=target_run.run_id,
        campaign_id=base_run.campaign_id,
        is_equivalent_campaign=is_equivalent_campaign,
        is_equivalent_evidence=is_equivalent_evidence,
        comparison_verdict=verdict,
        regressions=regressions,
        improvements=improvements,
        inconclusive_transitions=inconclusive_transitions,
        added_scenarios=added_scenarios,
        removed_scenarios=removed_scenarios,
        metric_deltas=metric_deltas,
        evidence_changes=evidence_changes,
        attribution_changes=attribution_changes,
        explanations=explanations,
        compared_at=datetime.now(timezone.utc),
    )
