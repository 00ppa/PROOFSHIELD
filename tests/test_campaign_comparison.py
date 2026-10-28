"""Tests for deterministic campaign comparison and regression analysis."""

from datetime import datetime, timezone
import pytest

from proofshield.schemas.campaign import (
    CampaignRunStatus,
    CampaignRunV1,
    CampaignSummaryV1,
    EvidenceManifestV1,
    ScenarioCampaignResultV1,
    ScenarioEvidenceRefV1,
    ScenarioRunStatus,
)
from proofshield.schemas.common import AttributionStatus, DiagnosticCategory
from proofshield.services.campaign_comparison import compare_campaign_runs


def _build_dummy_run(
    run_id: str,
    results: list,
    manifest_hash: str = "hash123",
) -> CampaignRunV1:
    now = datetime.now(timezone.utc)
    passed = sum(1 for r in results if r.status == ScenarioRunStatus.PASS)
    summary = CampaignSummaryV1(
        total_scenarios=len(results),
        executed_scenarios=len(results),
        unexecuted_scenarios=0,
        passed_scenarios=passed,
        failed_scenarios=len(results) - passed,
        inconclusive_scenarios=0,
        error_scenarios=0,
        category_counts={"PASS": passed},
        pass_rate=passed / len(results) if results else 0.0,
        execution_coverage=1.0,
        inconclusive_rate=0.0,
        error_rate=0.0,
        evidence_completeness=1.0,
    )
    manifest = EvidenceManifestV1(
        campaign_id="CPG-COMPARE",
        campaign_run_id=run_id,
        canonical_hash_algorithm="sha256",
        manifest_hash=manifest_hash,
        scenario_references=[
            ScenarioEvidenceRefV1(
                scenario_id=r.scenario_id,
                scenario_hash=f"hash_{r.scenario_id}",
                test_run_id=f"RUN_{r.scenario_id}",
                test_run_hash=f"runhash_{r.scenario_id}",
            )
            for r in results
        ],
        total_evidence_count=len(results),
        engine_version="v0.1.0",
        schema_version="v1",
        generated_at=now,
    )
    return CampaignRunV1(
        run_id=run_id,
        campaign_id="CPG-COMPARE",
        campaign_version="v1",
        status=CampaignRunStatus.COMPLETED,
        started_at=now,
        completed_at=now,
        total_scenarios=len(results),
        scenario_results=results,
        summary=summary,
        evidence_manifest=manifest,
    )


def test_comparison_identical_runs():
    r1 = ScenarioCampaignResultV1(
        scenario_id="SCN-01",
        execution_order=0,
        status=ScenarioRunStatus.PASS,
        predicted_category=DiagnosticCategory.PASS,
        reason="Success",
    )
    run_a = _build_dummy_run("RUN-A", [r1], manifest_hash="manifest_A")
    run_b = _build_dummy_run("RUN-B", [r1], manifest_hash="manifest_A")

    comp = compare_campaign_runs(base_run=run_a, target_run=run_b)
    assert comp.is_equivalent_campaign is True
    assert comp.is_equivalent_evidence is True
    assert comp.comparison_verdict == "IDENTICAL"
    assert len(comp.regressions) == 0
    assert len(comp.improvements) == 0
    assert comp.metric_deltas["pass_rate_delta"] == 0.0


def test_comparison_detects_regression():
    r_pass = ScenarioCampaignResultV1(
        scenario_id="SCN-01",
        execution_order=0,
        status=ScenarioRunStatus.PASS,
        predicted_category=DiagnosticCategory.PASS,
        reason="Success",
    )
    r_fail = ScenarioCampaignResultV1(
        scenario_id="SCN-01",
        execution_order=0,
        status=ScenarioRunStatus.FAILURE,
        predicted_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        reason="Telemetry dropped",
    )
    run_a = _build_dummy_run("RUN-A", [r_pass], manifest_hash="manifest_same")
    run_b = _build_dummy_run("RUN-B", [r_fail], manifest_hash="manifest_same")

    comp = compare_campaign_runs(base_run=run_a, target_run=run_b)
    assert comp.comparison_verdict == "REGRESSION"
    assert len(comp.regressions) == 1
    assert comp.regressions[0].scenario_id == "SCN-01"
    assert comp.regressions[0].transition_type == "REGRESSION"
    assert comp.metric_deltas["pass_rate_delta"] == -1.0


def test_comparison_detects_improvement():
    r_fail = ScenarioCampaignResultV1(
        scenario_id="SCN-01",
        execution_order=0,
        status=ScenarioRunStatus.FAILURE,
        predicted_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        reason="Rule did not fire",
    )
    r_pass = ScenarioCampaignResultV1(
        scenario_id="SCN-01",
        execution_order=0,
        status=ScenarioRunStatus.PASS,
        predicted_category=DiagnosticCategory.PASS,
        reason="Rule fired alert",
    )
    run_a = _build_dummy_run("RUN-A", [r_fail], manifest_hash="manifest_same")
    run_b = _build_dummy_run("RUN-B", [r_pass], manifest_hash="manifest_same")

    comp = compare_campaign_runs(base_run=run_a, target_run=run_b)
    assert comp.comparison_verdict == "IMPROVEMENT"
    assert len(comp.improvements) == 1
    assert comp.improvements[0].scenario_id == "SCN-01"
    assert comp.improvements[0].transition_type == "IMPROVEMENT"
    assert comp.metric_deltas["pass_rate_delta"] == 1.0


def test_comparison_detects_attribution_shift():
    r_attr_verified = ScenarioCampaignResultV1(
        scenario_id="SCN-01",
        execution_order=0,
        status=ScenarioRunStatus.PASS,
        predicted_category=DiagnosticCategory.PASS,
        attribution_status=AttributionStatus.VERIFIED,
        reason="Token matched",
    )
    r_attr_unattributed = ScenarioCampaignResultV1(
        scenario_id="SCN-01",
        execution_order=0,
        status=ScenarioRunStatus.PASS,
        predicted_category=DiagnosticCategory.PASS,
        attribution_status=AttributionStatus.UNATTRIBUTED,
        reason="Token absent",
    )
    run_a = _build_dummy_run("RUN-A", [r_attr_verified], manifest_hash="manifest_same")
    run_b = _build_dummy_run("RUN-B", [r_attr_unattributed], manifest_hash="manifest_same")

    comp = compare_campaign_runs(base_run=run_a, target_run=run_b)
    assert len(comp.attribution_changes) == 1
    assert comp.attribution_changes[0]["scenario_id"] == "SCN-01"
    assert comp.attribution_changes[0]["previous_attribution"] == "VERIFIED"
    assert comp.attribution_changes[0]["current_attribution"] == "UNATTRIBUTED"


def test_comparison_detects_added_and_removed_scenarios():
    r1 = ScenarioCampaignResultV1(
        scenario_id="SCN-01",
        execution_order=0,
        status=ScenarioRunStatus.PASS,
        predicted_category=DiagnosticCategory.PASS,
        reason="Success",
    )
    r2 = ScenarioCampaignResultV1(
        scenario_id="SCN-02",
        execution_order=1,
        status=ScenarioRunStatus.PASS,
        predicted_category=DiagnosticCategory.PASS,
        reason="Success",
    )
    run_a = _build_dummy_run("RUN-A", [r1], manifest_hash="manifest_A")
    run_b = _build_dummy_run("RUN-B", [r2], manifest_hash="manifest_B")

    comp = compare_campaign_runs(base_run=run_a, target_run=run_b)
    assert comp.added_scenarios == ["SCN-02"]
    assert comp.removed_scenarios == ["SCN-01"]
    assert comp.is_equivalent_campaign is False
    assert comp.is_equivalent_evidence is False
