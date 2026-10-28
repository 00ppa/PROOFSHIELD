"""Unit tests for Phase 16 campaign domain models and schemas."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

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
    RootCauseGroupV1,
    ScenarioCampaignResultV1,
    ScenarioEvidenceRefV1,
    ScenarioRegressionV1,
    ScenarioRunStatus,
)
from proofshield.schemas.common import (
    AttributionStatus,
    DiagnosticCategory,
    FailureCategory,
)
from proofshield.services.canonical import compute_canonical_hash


def test_valid_campaign_definition():
    campaign = CampaignDefinitionV1(
        campaign_id="CPG-LINUX-PERSISTENCE-01",
        name="Linux Persistence Validation Campaign",
        description="Validates cron and systemd persistence detections",
        scenario_ids=["SCN-CRON-01", "SCN-SYSTEMD-01"],
        tags=["persistence", "linux"],
        execution_config=CampaignExecutionConfigV1(
            execution_policy=CampaignExecutionPolicy.CONTINUE_ON_ERROR,
            strict_attribution=True,
        ),
    )
    assert campaign.campaign_id == "CPG-LINUX-PERSISTENCE-01"
    assert len(campaign.scenario_ids) == 2
    assert campaign.execution_config.strict_attribution is True


def test_campaign_rejects_empty_scenario_ids():
    with pytest.raises(ValidationError) as exc:
        CampaignDefinitionV1(
            campaign_id="CPG-EMPTY-01",
            name="Empty Campaign",
            scenario_ids=[],
        )
    assert "at least 1 item" in str(exc.value) or "at least one scenario" in str(exc.value)


def test_campaign_rejects_duplicate_scenario_ids():
    with pytest.raises(ValidationError) as exc:
        CampaignDefinitionV1(
            campaign_id="CPG-DUP-01",
            name="Duplicate Campaign",
            scenario_ids=["SCN-01", "SCN-02", "SCN-01"],
        )
    assert "Duplicate scenario identifiers" in str(exc.value)


def test_campaign_rejects_whitespace_or_empty_scenario_id():
    with pytest.raises(ValidationError) as exc:
        CampaignDefinitionV1(
            campaign_id="CPG-EMPTY-STR-01",
            name="Invalid Scenario ID",
            scenario_ids=["SCN-01", "   "],
        )
    assert "Scenario identifier cannot be empty or whitespace" in str(exc.value)


def test_campaign_rejects_more_than_max_scenarios():
    large_list = [f"SCN-{i:04d}" for i in range(501)]
    with pytest.raises(ValidationError) as exc:
        CampaignDefinitionV1(
            campaign_id="CPG-TOO-LARGE",
            name="Too Large Campaign",
            scenario_ids=large_list,
        )
    assert "exceeds maximum allowed" in str(exc.value)


def test_campaign_rejects_arbitrary_code_injection_patterns():
    with pytest.raises(ValidationError) as exc:
        CampaignDefinitionV1(
            campaign_id="CPG-INJECT",
            name="Malicious Campaign",
            description="Attempting __import__('os').system('ls')",
            scenario_ids=["SCN-01"],
        )
    assert "Potentially hazardous or executable instruction pattern detected" in str(exc.value)


def test_campaign_summary_metrics_and_denominators():
    summary = CampaignSummaryV1(
        total_scenarios=5,
        executed_scenarios=4,
        unexecuted_scenarios=1,
        passed_scenarios=3,
        failed_scenarios=1,
        inconclusive_scenarios=0,
        error_scenarios=0,
        category_counts={"PASS": 3, "EXPECTED_TELEMETRY_MISSING": 1, "TEST_NOT_EXECUTED": 1},
        pass_rate=0.75,  # 3 / 4
        execution_coverage=0.8,  # 4 / 5
        inconclusive_rate=0.0,
        error_rate=0.0,
        evidence_completeness=1.0,
        metrics_notes=["Pass rate denominator is 4 executed scenarios"],
    )
    assert summary.total_scenarios == 5
    assert summary.executed_scenarios == 4
    assert summary.pass_rate == 0.75
    assert summary.execution_coverage == 0.8


def test_campaign_summary_undefined_rates_when_zero_executed():
    summary = CampaignSummaryV1(
        total_scenarios=3,
        executed_scenarios=0,
        unexecuted_scenarios=3,
        passed_scenarios=0,
        failed_scenarios=0,
        inconclusive_scenarios=0,
        error_scenarios=0,
        category_counts={"TEST_NOT_EXECUTED": 3},
        pass_rate=None,
        execution_coverage=0.0,
        inconclusive_rate=None,
        error_rate=0.0,
        evidence_completeness=None,
        metrics_notes=["Zero scenarios were executed."],
    )
    assert summary.pass_rate is None
    assert summary.inconclusive_rate is None
    assert summary.evidence_completeness is None
    assert summary.execution_coverage == 0.0


def test_canonical_hash_stability():
    ref1 = ScenarioEvidenceRefV1(
        scenario_id="SCN-01",
        scenario_hash="abc123hash",
        test_run_id="RUN-01",
        test_run_hash="runhash456",
        telemetry_event_ids=["EVT-01", "EVT-02"],
        alert_ids=["ALT-01"],
    )
    ref2 = ScenarioEvidenceRefV1(
        scenario_id="SCN-01",
        scenario_hash="abc123hash",
        test_run_id="RUN-01",
        test_run_hash="runhash456",
        telemetry_event_ids=["EVT-01", "EVT-02"],
        alert_ids=["ALT-01"],
    )
    hash1 = compute_canonical_hash(ref1)
    hash2 = compute_canonical_hash(ref2)
    assert hash1 == hash2
    assert len(hash1) == 64
