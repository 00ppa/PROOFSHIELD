"""Storage contract and parity tests for campaign definitions and runs.

Runs identical contract validation tests across InMemoryStore and SQLiteStore
(both in-memory and file-backed), verifying:
1. add_campaign, get_campaign, list_campaigns with ordering and duplicate rejection.
2. add_campaign_run, get_campaign_run, list_campaign_runs with filtering and foreign key checks.
3. Transaction rollback guarantees: no partial or corrupted records on failure.
4. Reset semantics: clearing campaign data on reset.
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator
import pytest

from proofshield.schemas.campaign import (
    CampaignDefinitionV1,
    CampaignExecutionConfigV1,
    CampaignExecutionPolicy,
    CampaignRunStatus,
    CampaignRunV1,
    CampaignSummaryV1,
    EvidenceManifestV1,
    ScenarioCampaignResultV1,
    ScenarioEvidenceRefV1,
    ScenarioRunStatus,
)
from proofshield.schemas.common import DiagnosticCategory
from proofshield.services.base_store import StoreProtocol
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore


@pytest.fixture(params=["in_memory", "sqlite_memory", "sqlite_file"])
def store(request, tmp_path: Path) -> Generator[StoreProtocol, None, None]:
    """Yield each storage backend configured under identical test conditions."""
    if request.param == "in_memory":
        s = InMemoryStore()
        yield s
        s.reset()
    elif request.param == "sqlite_memory":
        s = SQLiteStore(":memory:")
        yield s
        s.close()
    elif request.param == "sqlite_file":
        db_file = tmp_path / "campaign_store_test.db"
        s = SQLiteStore(db_file)
        yield s
        s.close()


def _make_sample_campaign(campaign_id: str = "CPG-TEST-01") -> CampaignDefinitionV1:
    return CampaignDefinitionV1(
        campaign_id=campaign_id,
        name="Persistence Evaluation Suite",
        description="Comprehensive persistence checks",
        scenario_ids=["SCN-01", "SCN-02"],
        tags=["persistence", "unit-test"],
        execution_config=CampaignExecutionConfigV1(
            execution_policy=CampaignExecutionPolicy.CONTINUE_ON_ERROR,
            strict_attribution=False,
        ),
    )


def _make_sample_run(run_id: str, campaign_id: str) -> CampaignRunV1:
    now = datetime.now(timezone.utc)
    summary = CampaignSummaryV1(
        total_scenarios=2,
        executed_scenarios=2,
        unexecuted_scenarios=0,
        passed_scenarios=2,
        failed_scenarios=0,
        inconclusive_scenarios=0,
        error_scenarios=0,
        category_counts={"PASS": 2},
        pass_rate=1.0,
        execution_coverage=1.0,
        inconclusive_rate=0.0,
        error_rate=0.0,
        evidence_completeness=1.0,
    )
    manifest = EvidenceManifestV1(
        campaign_id=campaign_id,
        campaign_run_id=run_id,
        canonical_hash_algorithm="sha256",
        manifest_hash="samplemanifesthash1234567890abcdef1234567890abcdef1234567890abcdef",
        scenario_references=[
            ScenarioEvidenceRefV1(
                scenario_id="SCN-01",
                scenario_hash="scnhash1",
                test_run_id="RUN-01",
                test_run_hash="runhash1",
            ),
            ScenarioEvidenceRefV1(
                scenario_id="SCN-02",
                scenario_hash="scnhash2",
                test_run_id="RUN-02",
                test_run_hash="runhash2",
            ),
        ],
        total_evidence_count=2,
        engine_version="v0.1.0",
        schema_version="v1",
        generated_at=now,
    )
    return CampaignRunV1(
        run_id=run_id,
        campaign_id=campaign_id,
        campaign_version="v1",
        status=CampaignRunStatus.COMPLETED,
        started_at=now,
        completed_at=now + timedelta(seconds=1),
        total_scenarios=2,
        scenario_results=[
            ScenarioCampaignResultV1(
                scenario_id="SCN-01",
                execution_order=0,
                test_run_id="RUN-01",
                predicted_category=DiagnosticCategory.PASS,
                status=ScenarioRunStatus.PASS,
                reason="All telemetry matched",
            ),
            ScenarioCampaignResultV1(
                scenario_id="SCN-02",
                execution_order=1,
                test_run_id="RUN-02",
                predicted_category=DiagnosticCategory.PASS,
                status=ScenarioRunStatus.PASS,
                reason="Alert correlated successfully",
            ),
        ],
        summary=summary,
        evidence_manifest=manifest,
    )


def test_contract_campaign_crud(store: StoreProtocol):
    c1 = _make_sample_campaign("CPG-01")
    store.add_campaign(c1)

    fetched = store.get_campaign("CPG-01")
    assert fetched is not None
    assert fetched.campaign_id == "CPG-01"
    assert fetched.name == c1.name
    assert fetched.scenario_ids == ["SCN-01", "SCN-02"]

    # Duplicate rejected
    with pytest.raises(ValueError) as exc:
        store.add_campaign(c1)
    assert "already exists" in str(exc.value)

    # Missing returns None
    assert store.get_campaign("CPG-NONEXISTENT") is None

    # List campaigns
    c2 = _make_sample_campaign("CPG-02")
    store.add_campaign(c2)
    campaigns = store.list_campaigns()
    assert len(campaigns) == 2
    ids = [c.campaign_id for c in campaigns]
    assert "CPG-01" in ids and "CPG-02" in ids


def test_contract_campaign_run_crud(store: StoreProtocol):
    c1 = _make_sample_campaign("CPG-RUN-TEST")
    store.add_campaign(c1)

    # Missing campaign foreign key check
    orphan_run = _make_sample_run("CRUN-ORPHAN", "CPG-UNKNOWN")
    with pytest.raises(ValueError) as exc:
        store.add_campaign_run(orphan_run)
    assert "Campaign not found" in str(exc.value)

    # Valid run
    run1 = _make_sample_run("CRUN-001", "CPG-RUN-TEST")
    store.add_campaign_run(run1)

    fetched = store.get_campaign_run("CRUN-001")
    assert fetched is not None
    assert fetched.run_id == "CRUN-001"
    assert fetched.campaign_id == "CPG-RUN-TEST"
    assert fetched.summary.passed_scenarios == 2

    # Duplicate run rejected
    with pytest.raises(ValueError) as exc:
        store.add_campaign_run(run1)
    assert "already exists" in str(exc.value)

    # List runs filtered by campaign
    run2 = _make_sample_run("CRUN-002", "CPG-RUN-TEST")
    store.add_campaign_run(run2)

    c2 = _make_sample_campaign("CPG-OTHER")
    store.add_campaign(c2)
    run3 = _make_sample_run("CRUN-003", "CPG-OTHER")
    store.add_campaign_run(run3)

    all_runs = store.list_campaign_runs()
    assert len(all_runs) == 3

    filtered = store.list_campaign_runs(campaign_id="CPG-RUN-TEST")
    assert len(filtered) == 2
    assert {r.run_id for r in filtered} == {"CRUN-001", "CRUN-002"}


def test_contract_campaign_transaction_rollback(store: StoreProtocol):
    c = _make_sample_campaign("CPG-TX-TEST")
    store.add_campaign(c)

    # Attempt atomic transaction that fails halfway
    with pytest.raises(RuntimeError):
        with store.transaction():
            r1 = _make_sample_run("CRUN-TX-01", "CPG-TX-TEST")
            store.add_campaign_run(r1)
            raise RuntimeError("Simulated failure in transaction")

    # r1 must not be persisted
    assert store.get_campaign_run("CRUN-TX-01") is None
    assert len(store.list_campaign_runs(campaign_id="CPG-TX-TEST")) == 0


def test_contract_campaign_reset(store: StoreProtocol):
    c = _make_sample_campaign("CPG-RESET-TEST")
    store.add_campaign(c)
    run = _make_sample_run("CRUN-RESET-01", "CPG-RESET-TEST")
    store.add_campaign_run(run)

    assert store.get_campaign("CPG-RESET-TEST") is not None
    assert store.get_campaign_run("CRUN-RESET-01") is not None

    store.reset()

    assert store.get_campaign("CPG-RESET-TEST") is None
    assert store.get_campaign_run("CRUN-RESET-01") is None
    assert len(store.list_campaigns()) == 0
    assert len(store.list_campaign_runs()) == 0
