"""Integration tests for Campaign Validation & Replay Engine API endpoints."""

import pytest
from fastapi.testclient import TestClient

from proofshield.schemas.common import EventCategory, ExecutionMode, ExecutionStatus, ValidationTarget
from proofshield.services.store import get_store


@pytest.fixture(autouse=True)
def clean_store():
    store = get_store()
    store.reset()
    yield
    store.reset()


def _populate_api_scenario_and_run(client: TestClient):
    # Create scenario
    scen_payload = {
        "scenario_id": "SCN-API-01",
        "name": "API Validation Scenario",
        "description": "Tests process execution via API",
        "mitre_technique_id": "T1059.001",
        "mitre_tactic": "Execution",
        "expected_event_category": "PROCESS_CREATION",
        "expected_process_name": "powershell.exe",
        "expected_detection_rule_id": "RULE-API-01",
        "validation_target": "EXPECTED_ALERT",
    }
    res = client.post("/api/v1/scenarios", json=scen_payload)
    assert res.status_code == 200

    # Create detection rule
    rule_payload = {
        "rule_id": "RULE-API-01",
        "rule_name": "API Detection Rule",
        "rule_format": "sigma",
    }
    res = client.post("/api/v1/rules", json=rule_payload)
    assert res.status_code == 200

    # Create test run
    run_payload = {
        "run_id": "RUN-API-01",
        "scenario_id": "SCN-API-01",
        "execution_mode": "SYNTHETIC_SIMULATION",
        "target_host": "api-host",
        "target_user": "tester",
        "executed_at": "2026-10-29T10:00:00Z",
        "window_start": "2026-10-29T09:59:50Z",
        "window_end": "2026-10-29T10:01:00Z",
        "execution_status": "COMPLETED",
    }
    res = client.post("/api/v1/runs", json=run_payload)
    assert res.status_code == 200

    # Add telemetry event
    evt_payload = {
        "normalized_event_id": "EVT-API-01",
        "raw_event_id": "RAW-API-01",
        "source_event_id": "SRC-API-01",
        "source_timestamp": "2026-10-29T10:00:05Z",
        "normalized_timestamp": "2026-10-29T10:00:05Z",
        "event_category": "PROCESS_CREATION",
        "host": "api-host",
        "user": "tester",
        "process_name": "powershell.exe",
    }
    store = get_store()
    from proofshield.schemas.telemetry import NormalizedTelemetryEventV1
    store.add_normalized_event(NormalizedTelemetryEventV1(**evt_payload))

    # Add alert
    alt_payload = {
        "alert_id": "ALT-API-01",
        "source_alert_id": "SRC-ALT-API-01",
        "source_type": "wazuh",
        "rule_reference": "RULE-API-01",
        "host_id": "api-host",
        "alert_timestamp": "2026-10-29T10:00:10Z",
        "severity": "high",
    }
    res = client.post("/api/v1/alerts", json=alt_payload)
    assert res.status_code == 200


def test_api_campaign_lifecycle(test_client: TestClient):
    _populate_api_scenario_and_run(test_client)

    # 1. POST /api/v1/campaigns
    camp_payload = {
        "campaign_id": "CPG-API-01",
        "name": "API Test Campaign",
        "description": "Validation campaign over API",
        "scenario_ids": ["SCN-API-01"],
        "tags": ["api", "integration"],
        "execution_config": {
            "execution_policy": "CONTINUE_ON_ERROR",
            "strict_attribution": False,
        },
    }
    res = test_client.post("/api/v1/campaigns", json=camp_payload)
    assert res.status_code == 201
    camp_data = res.json()
    assert camp_data["campaign_id"] == "CPG-API-01"

    # Duplicate rejected with 409 Conflict
    res_dup = test_client.post("/api/v1/campaigns", json=camp_payload)
    assert res_dup.status_code == 409
    assert "already exists" in res_dup.json()["detail"]

    # 2. GET /api/v1/campaigns
    res_list = test_client.get("/api/v1/campaigns?limit=10&offset=0")
    assert res_list.status_code == 200
    assert len(res_list.json()) == 1

    # 3. GET /api/v1/campaigns/{id}
    res_get = test_client.get("/api/v1/campaigns/CPG-API-01")
    assert res_get.status_code == 200
    assert res_get.json()["campaign_id"] == "CPG-API-01"

    # Missing campaign returns 404
    assert test_client.get("/api/v1/campaigns/CPG-MISSING").status_code == 404

    # 4. POST /api/v1/campaigns/{id}/runs
    res_run = test_client.post("/api/v1/campaigns/CPG-API-01/runs", json={})
    assert res_run.status_code == 201
    run_data = res_run.json()
    run_id = run_data["run_id"]
    assert run_data["status"] == "COMPLETED"
    assert run_data["summary"]["passed_scenarios"] == 1
    assert run_data["summary"]["pass_rate"] == 1.0

    # 5. GET /api/v1/campaign-runs
    res_runs = test_client.get("/api/v1/campaign-runs")
    assert res_runs.status_code == 200
    assert len(res_runs.json()) == 1

    # 6. GET /api/v1/campaign-runs/{run_id}
    res_single_run = test_client.get(f"/api/v1/campaign-runs/{run_id}")
    assert res_single_run.status_code == 200
    assert res_single_run.json()["run_id"] == run_id

    # 7. GET /api/v1/campaign-runs/{run_id}/report
    res_report = test_client.get(f"/api/v1/campaign-runs/{run_id}/report")
    assert res_report.status_code == 200
    report_data = res_report.json()
    assert report_data["report_schema_version"] == "v1"
    assert "evidence_manifest" in report_data
    assert "summary" in report_data
    assert "scenario_results" in report_data

    # 8. POST /api/v1/campaign-runs/{run_id}/replay
    res_replay = test_client.post(f"/api/v1/campaign-runs/{run_id}/replay")
    assert res_replay.status_code == 201
    replay_data = res_replay.json()
    assert replay_data["is_exact_replay"] is True
    assert replay_data["verdict"] == "EXACT_REPLAY"
    replay_run_id = replay_data["replay_run"]["run_id"]
    assert replay_run_id != run_id

    # 9. GET /api/v1/campaign-runs/{run_id}/compare/{other_run_id}
    res_comp = test_client.get(f"/api/v1/campaign-runs/{run_id}/compare/{replay_run_id}")
    assert res_comp.status_code == 200
    comp_data = res_comp.json()
    assert comp_data["comparison_verdict"] == "IDENTICAL"
    assert comp_data["is_equivalent_evidence"] is True
