"""Unit tests for API endpoints, JSONL ingestion, and diagnostic evaluation."""

import json
from pathlib import Path
from fastapi.testclient import TestClient

from proofshield.services.store import get_store


def test_api_schemas_info(test_client: TestClient):
    """Verify GET /api/v1/schemas/info returns all 8 registered schemas."""
    res = test_client.get("/api/v1/schemas/info")
    assert res.status_code == 200
    data = res.json()
    assert "version" in data
    assert "ScenarioV1" in data["schemas"]
    assert "TestRunV1" in data["schemas"]
    assert "RawTelemetryEventV1" in data["schemas"]
    assert "NormalizedTelemetryEventV1" in data["schemas"]
    assert "DetectionRuleV1" in data["schemas"]
    assert "AlertV1" in data["schemas"]
    assert "DiagnosticResultV1" in data["schemas"]
    assert "GroundTruthV1" in data["schemas"]


def test_api_telemetry_normalize(test_client: TestClient, raw_telemetry_valid_path: Path):
    """Verify POST /api/v1/telemetry/normalize normalises incoming payload."""
    with open(raw_telemetry_valid_path, "r", encoding="utf-8") as f:
        first_line = f.readline()

    raw_event_dict = json.loads(first_line)

    res = test_client.post("/api/v1/telemetry/normalize", json=raw_event_dict)
    assert res.status_code == 200
    normalized_list = res.json()
    assert len(normalized_list) == 1
    assert normalized_list[0]["process_name"] == "powershell.exe"
    assert normalized_list[0]["source_event_id"] == "98214"


def test_api_ingest_jsonl_valid(test_client: TestClient, scenarios_jsonl_path: Path):
    """Verify POST /api/v1/ingest/jsonl validates scenario dataset successfully."""
    content = scenarios_jsonl_path.read_text(encoding="utf-8")
    payload = {
        "schema_type": "scenario",
        "content": content,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is True
    assert data["valid_count"] == 3
    assert data["error_count"] == 0
    assert len(data["sample_valid_records"]) == 3


def test_api_ingest_jsonl_detection_rules(
    test_client: TestClient, detection_rules_jsonl_path: Path
):
    """Verify POST /api/v1/ingest/jsonl validates detection rule dataset."""
    content = detection_rules_jsonl_path.read_text(encoding="utf-8")
    payload = {
        "schema_type": "detection_rule",
        "content": content,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is True
    assert data["valid_count"] == 2


def test_api_ingest_jsonl_alerts(test_client: TestClient, alerts_jsonl_path: Path):
    """Verify POST /api/v1/ingest/jsonl validates alerts dataset."""
    content = alerts_jsonl_path.read_text(encoding="utf-8")
    payload = {
        "schema_type": "alert",
        "content": content,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is True
    assert data["valid_count"] == 3


def test_api_ingest_jsonl_ground_truth(
    test_client: TestClient, ground_truth_jsonl_path: Path
):
    """Verify POST /api/v1/ingest/jsonl validates ground truth dataset."""
    content = ground_truth_jsonl_path.read_text(encoding="utf-8")
    payload = {
        "schema_type": "ground_truth",
        "content": content,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is True
    assert data["valid_count"] == 3


def test_api_ingest_jsonl_malformed(test_client: TestClient, raw_telemetry_malformed_path: Path):
    """Verify POST /api/v1/ingest/jsonl isolates errors and reports line details."""
    content = raw_telemetry_malformed_path.read_text(encoding="utf-8")
    payload = {
        "schema_type": "raw_telemetry",
        "content": content,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is False
    assert data["valid_count"] == 2
    assert data["error_count"] == 3
    assert len(data["errors"]) == 3


def test_api_scenario_endpoints(test_client: TestClient):
    """Test scenario creation, retrieval, and duplicate error handling."""
    get_store().reset()
    payload = {
        "schema_version": "v1",
        "scenario_id": "SCN-API-TEST-01",
        "name": "API Scenario Test",
        "mitre_technique_id": "T1059.001",
        "mitre_tactic": "Execution",
        "expected_event_category": "PROCESS_CREATION",
        "validation_target": "EXPECTED_ALERT",
    }
    # Create
    res = test_client.post("/api/v1/scenarios", json=payload)
    assert res.status_code == 200
    assert res.json()["scenario_id"] == "SCN-API-TEST-01"
    assert res.json()["validation_target"] == "EXPECTED_ALERT"

    # Duplicate conflict
    res = test_client.post("/api/v1/scenarios", json=payload)
    assert res.status_code == 409

    # List
    res = test_client.get("/api/v1/scenarios")
    assert res.status_code == 200
    assert len(res.json()) >= 1

    # Get by ID
    res = test_client.get("/api/v1/scenarios/SCN-API-TEST-01")
    assert res.status_code == 200
    assert res.json()["name"] == "API Scenario Test"

    # Get non-existent
    res = test_client.get("/api/v1/scenarios/SCN-NONEXISTENT")
    assert res.status_code == 404


def test_api_run_endpoints(test_client: TestClient):
    """Test run registration with valid scenario and missing scenario error."""
    get_store().reset()
    # Attempt run without scenario -> 404
    run_payload = {
        "schema_version": "v1",
        "run_id": "RUN-API-01",
        "scenario_id": "SCN-NOT-FOUND",
        "execution_mode": "SYNTHETIC_SIMULATION",
        "is_synthetic": True,
        "target_host": "WS-01",
        "target_user": "user1",
        "window_start": "2026-10-12T10:00:00Z",
        "window_end": "2026-10-12T10:10:00Z",
        "executed_at": "2026-10-12T10:01:00Z",
    }
    res = test_client.post("/api/v1/runs", json=run_payload)
    assert res.status_code == 404

    # Create scenario first
    scn_payload = {
        "schema_version": "v1",
        "scenario_id": "SCN-FOR-RUN",
        "name": "Scenario for Run",
        "mitre_technique_id": "T1059.001",
        "mitre_tactic": "Execution",
        "expected_event_category": "PROCESS_CREATION",
        "validation_target": "EXPECTED_ALERT",
    }
    test_client.post("/api/v1/scenarios", json=scn_payload)

    # Now create run with existing scenario
    run_payload["scenario_id"] = "SCN-FOR-RUN"
    res = test_client.post("/api/v1/runs", json=run_payload)
    assert res.status_code == 200
    assert res.json()["run_id"] == "RUN-API-01"

    # Get run
    res = test_client.get("/api/v1/runs/RUN-API-01")
    assert res.status_code == 200
    assert res.json()["target_host"] == "WS-01"


def test_api_rule_and_alert_endpoints(test_client: TestClient):
    """Test rule and alert ingestion and listing endpoints."""
    get_store().reset()
    rule_payload = {
        "schema_version": "v1",
        "rule_id": "RULE-API-01",
        "rule_name": "API Test Rule",
        "rule_format": "sigma",
    }
    res = test_client.post("/api/v1/rules", json=rule_payload)
    assert res.status_code == 200

    res = test_client.get("/api/v1/rules/RULE-API-01")
    assert res.status_code == 200

    alert_payload = {
        "schema_version": "v1",
        "alert_id": "ALT-API-01",
        "source_alert_id": "SRC-01",
        "source_type": "wazuh",
        "alert_timestamp": "2026-10-12T10:05:00Z",
        "host_id": "WS-01",
        "rule_reference": "RULE-API-01",
    }
    res = test_client.post("/api/v1/alerts", json=alert_payload)
    assert res.status_code == 200
    assert len(res.json()) == 1

    res = test_client.get("/api/v1/alerts")
    assert res.status_code == 200
    assert len(res.json()) == 1


def test_api_ground_truth_endpoints(test_client: TestClient):
    """Test ground truth registration and query."""
    get_store().reset()
    gt_payload = {
        "schema_version": "v1",
        "ground_truth_id": "GT-API-01",
        "run_id": "RUN-API-01",
        "expected_diagnostic_category": "PASS",
        "verification_method": "manual_inspection",
    }
    res = test_client.post("/api/v1/ground-truth", json=gt_payload)
    assert res.status_code == 200

    res = test_client.get("/api/v1/ground-truth/RUN-API-01")
    assert res.status_code == 200
    assert res.json()["expected_diagnostic_category"] == "PASS"


def test_api_diagnostic_evaluation_workflow(test_client: TestClient):
    """End-to-end evaluation via API: scenario + run + telemetry missing -> EXPECTED_TELEMETRY_MISSING."""
    get_store().reset()
    scn_payload = {
        "schema_version": "v1",
        "scenario_id": "SCN-EVAL-01",
        "name": "Evaluation Test",
        "mitre_technique_id": "T1059.001",
        "mitre_tactic": "Execution",
        "expected_event_category": "PROCESS_CREATION",
        "expected_detection_rule_id": "RULE-EVAL-01",
        "validation_target": "EXPECTED_ALERT",
    }
    test_client.post("/api/v1/scenarios", json=scn_payload)

    run_payload = {
        "schema_version": "v1",
        "run_id": "RUN-EVAL-01",
        "scenario_id": "SCN-EVAL-01",
        "execution_mode": "SYNTHETIC_SIMULATION",
        "is_synthetic": True,
        "target_host": "WS-01",
        "target_user": "user1",
        "window_start": "2026-10-12T10:00:00Z",
        "window_end": "2026-10-12T10:10:00Z",
        "executed_at": "2026-10-12T10:01:00Z",
        "execution_status": "COMPLETED",
    }
    test_client.post("/api/v1/runs", json=run_payload)

    # Trigger diagnostic evaluation
    res = test_client.post("/api/v1/evaluation/RUN-EVAL-01")
    assert res.status_code == 200
    diag = res.json()
    assert diag["predicted_category"] == "EXPECTED_TELEMETRY_MISSING"
    assert diag["confidence"] == "likely"
    assert diag["scenario_id"] == "SCN-EVAL-01"

    # Fetch stored evaluation
    res = test_client.get("/api/v1/evaluation/RUN-EVAL-01")
    assert res.status_code == 200
    assert res.json()["predicted_category"] == "EXPECTED_TELEMETRY_MISSING"

    # List all evaluations
    res = test_client.get("/api/v1/evaluation")
    assert res.status_code == 200
    assert len(res.json()) == 1
