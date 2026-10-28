"""Adversarial and boundary condition tests for Campaign Validation & Replay Engine."""

import pytest
from fastapi.testclient import TestClient

from proofshield.schemas.campaign import CampaignDefinitionV1, CampaignExecutionConfigV1
from proofshield.services.campaign_engine import CampaignEngine
from proofshield.services.store import get_store


@pytest.fixture(autouse=True)
def clean_store():
    store = get_store()
    store.reset()
    yield
    store.reset()


def test_adversarial_deeply_nested_metadata():
    deep_dict = {"level": 1}
    curr = deep_dict
    for i in range(2, 35):
        curr["nested"] = {"level": i}
        curr = curr["nested"]

    with pytest.raises(Exception) as exc:
        CampaignDefinitionV1(
            campaign_id="CPG-NESTED-BOMB",
            name="Nesting Bomb Campaign",
            scenario_ids=["SCN-01"],
            metadata=deep_dict,
        )
    assert "nesting depth exceeds" in str(exc.value).lower()


def test_adversarial_command_injection_rejected():
    injection_strings = [
        "Campaign with __import__('os').system('id')",
        "Run; subprocess.Popen(['calc.exe'])",
        "Test with /bin/sh -c whoami",
        "powershell -enc JABhID0A...",
    ]
    for inject in injection_strings:
        with pytest.raises(Exception) as exc:
            CampaignDefinitionV1(
                campaign_id="CPG-INJECT",
                name="Injection Test",
                description=inject,
                scenario_ids=["SCN-01"],
            )
        assert "hazardous or executable instruction pattern detected" in str(exc.value).lower()


def test_adversarial_sql_injection_in_identifiers(test_client: TestClient):
    sql_injection_id = "CPG-SQL' OR '1'='1"
    # Should be rejected by regex validator pattern ^[A-Za-z0-9_\-\.]+$
    res = test_client.post(
        "/api/v1/campaigns",
        json={
            "campaign_id": sql_injection_id,
            "name": "SQLi Test",
            "scenario_ids": ["SCN-01"],
        },
    )
    assert res.status_code == 422


def test_adversarial_execution_of_missing_campaign(test_client: TestClient):
    res = test_client.post("/api/v1/campaigns/NONEXISTENT-CAMPAIGN/runs", json={})
    assert res.status_code == 404
    assert "Campaign not found" in res.json()["detail"]


def test_adversarial_replay_missing_run(test_client: TestClient):
    res = test_client.post("/api/v1/campaign-runs/NONEXISTENT-RUN/replay")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_adversarial_compare_missing_runs(test_client: TestClient):
    res = test_client.get("/api/v1/campaign-runs/RUN-A/compare/RUN-B")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_adversarial_duplicate_runs_idempotency_protection():
    store = get_store()
    engine = CampaignEngine(store)

    c = CampaignDefinitionV1(
        campaign_id="CPG-DUP-RUN",
        name="Dup Run Test",
        scenario_ids=["SCN-01"],
    )
    store.add_campaign(c)

    run = engine.execute_campaign("CPG-DUP-RUN")
    # Trying to add the exact same run again must raise ValueError, not silently overwrite
    with pytest.raises(ValueError) as exc:
        store.add_campaign_run(run)
    assert "already exists" in str(exc.value).lower()
