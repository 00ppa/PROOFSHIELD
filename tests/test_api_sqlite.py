"""FastAPI integration and application restart persistence tests with SQLite backend.

Verifies:
1. Full API endpoint workflow functioning over SQLite persistent storage.
2. Lifespan startup failure when invalid storage configuration is provided.
3. Complete cross-process / application restart persistence across separate FastAPI app instances.
"""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from proofshield.config import reset_settings
from proofshield.main import create_application
from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    GroundTruthV1,
    ScenarioV1,
    TestRunV1,
)
from proofshield.schemas.common import (
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    ValidationTarget,
)
from proofshield.services.store import close_store, get_store, reset_store


@pytest.fixture
def sqlite_api_env(tmp_path: Path):
    """Set up temporary SQLite environment for FastAPI testing."""
    db_file = tmp_path / "api_test.db"
    reset_store()
    reset_settings()
    old_backend = os.environ.get("PROOFSHIELD_STORAGE_BACKEND")
    old_path = os.environ.get("PROOFSHIELD_SQLITE_PATH")

    os.environ["PROOFSHIELD_STORAGE_BACKEND"] = "sqlite"
    os.environ["PROOFSHIELD_SQLITE_PATH"] = str(db_file)

    yield db_file

    close_store()
    reset_settings()
    if old_backend is not None:
        os.environ["PROOFSHIELD_STORAGE_BACKEND"] = old_backend
    else:
        os.environ.pop("PROOFSHIELD_STORAGE_BACKEND", None)

    if old_path is not None:
        os.environ["PROOFSHIELD_SQLITE_PATH"] = old_path
    else:
        os.environ.pop("PROOFSHIELD_SQLITE_PATH", None)


def test_api_sqlite_crud_and_evaluation_workflow(sqlite_api_env: Path):
    """Verify all REST API routes function properly when SQLite backend is active."""
    app = create_application()
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

    with TestClient(app) as client:
        # 1. Register Scenario
        scn_payload = {
            "scenario_id": "SCN-API-SQLITE",
            "name": "SQLite API Validation Scenario",
            "mitre_technique_id": "T1059.001",
            "mitre_tactic": "Execution",
            "expected_event_category": "PROCESS_CREATION",
            "expected_process_name": "powershell.exe",
            "validation_target": "EXPECTED_ALERT",
            "expected_detection_rule_id": "RULE-API-01",
        }
        res_scn = client.post("/api/v1/scenarios", json=scn_payload)
        assert res_scn.status_code == 200
        assert res_scn.json()["scenario_id"] == "SCN-API-SQLITE"

        # Duplicate scenario -> 409 Conflict
        res_scn_dup = client.post("/api/v1/scenarios", json=scn_payload)
        assert res_scn_dup.status_code == 409

        # Fetch scenario
        res_get_scn = client.get("/api/v1/scenarios/SCN-API-SQLITE")
        assert res_get_scn.status_code == 200
        assert res_get_scn.json()["name"] == "SQLite API Validation Scenario"

        # List scenarios
        res_list_scns = client.get("/api/v1/scenarios")
        assert res_list_scns.status_code == 200
        assert len(res_list_scns.json()) == 1

        # 2. Register Test Run
        run_payload = {
            "run_id": "RUN-API-SQLITE",
            "scenario_id": "SCN-API-SQLITE",
            "execution_mode": "SYNTHETIC_SIMULATION",
            "is_synthetic": True,
            "target_host": "WS-API-01",
            "target_user": "secops",
            "window_start": t0.isoformat(),
            "window_end": t1.isoformat(),
            "executed_at": t0.isoformat(),
            "execution_status": "COMPLETED",
            "execution_token": "TOK-API-01",
        }
        res_run = client.post("/api/v1/runs", json=run_payload)
        assert res_run.status_code == 200
        assert res_run.json()["run_id"] == "RUN-API-SQLITE"

        # Fetch and list runs
        assert client.get("/api/v1/runs/RUN-API-SQLITE").status_code == 200
        assert len(client.get("/api/v1/runs?scenario_id=SCN-API-SQLITE").json()) == 1

        # 3. Register Detection Rule
        rule_payload = {
            "rule_id": "RULE-API-01",
            "rule_name": "PowerShell API Detection",
            "rule_format": "sigma",
        }
        res_rule = client.post("/api/v1/rules", json=rule_payload)
        assert res_rule.status_code == 200
        assert client.get("/api/v1/rules/RULE-API-01").status_code == 200
        assert len(client.get("/api/v1/rules").json()) == 1

        # 4. Ingest Alert
        alert_payload = {
            "alert_id": "ALT-API-01",
            "source_alert_id": "SRC-ALT-01",
            "source_type": "wazuh",
            "alert_timestamp": (t0 + timedelta(minutes=3)).isoformat(),
            "host_id": "ws-api-01",
            "rule_reference": "RULE-API-01",
            "alert_title": "Suspicious PowerShell token=TOK-API-01",
        }
        res_alert = client.post("/api/v1/alerts", json=alert_payload)
        assert res_alert.status_code == 200
        assert len(client.get("/api/v1/alerts").json()) == 1

        # 5. Ingest Normalized Telemetry via Store
        # (directly populated for diagnostic evaluation)
        store = get_store()
        norm = {
            "normalized_event_id": "NORM-API-01",
            "raw_event_id": "RAW-API-01",
            "source_event_id": "SRC-01",
            "source_timestamp": t0 + timedelta(minutes=2),
            "normalized_timestamp": t0 + timedelta(minutes=2),
            "event_category": EventCategory.PROCESS_CREATION,
            "host": "WS-API-01",
            "process_name": "powershell.exe",
            "execution_token": "TOK-API-01",
        }
        from proofshield.schemas import NormalizedTelemetryEventV1
        store.add_normalized_event(NormalizedTelemetryEventV1(**norm))

        # 6. Execute Diagnostic Evaluation via API
        res_eval = client.post("/api/v1/evaluation/RUN-API-SQLITE")
        assert res_eval.status_code == 200
        eval_data = res_eval.json()
        assert eval_data["predicted_category"] == "PASS"
        assert eval_data["confidence"] == "definitive"

        # 7. Fetch Diagnostic Evaluation
        res_get_eval = client.get("/api/v1/evaluation/RUN-API-SQLITE")
        assert res_get_eval.status_code == 200
        assert res_get_eval.json()["predicted_category"] == "PASS"

        # 8. Ground Truth API
        gt_payload = {
            "ground_truth_id": "GT-API-01",
            "run_id": "RUN-API-SQLITE",
            "expected_diagnostic_category": "PASS",
            "verification_method": "manual_review",
        }
        res_gt = client.post("/api/v1/ground-truth", json=gt_payload)
        assert res_gt.status_code == 200
        assert client.get("/api/v1/ground-truth/RUN-API-SQLITE").status_code == 200


def test_persistence_across_application_restart(sqlite_api_env: Path):
    """Verify that shutting down FastAPI app and starting a new app against the same file preserves all data."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc)

    # ── Phase 1: Application Instance 1 Ingests Records ────────────────────────
    app1 = create_application()
    with TestClient(app1) as client1:
        res = client1.post(
            "/api/v1/scenarios",
            json={
                "scenario_id": "SCN-PERSIST-API",
                "name": "Persistence Scenario",
                "mitre_technique_id": "T1059.001",
                "mitre_tactic": "Execution",
                "expected_event_category": "PROCESS_CREATION",
                "expected_process_name": "powershell.exe",
                "validation_target": "EXPECTED_ALERT",
            },
        )
        assert res.status_code == 200

        res_run = client1.post(
            "/api/v1/runs",
            json={
                "run_id": "RUN-PERSIST-API",
                "scenario_id": "SCN-PERSIST-API",
                "execution_mode": "SYNTHETIC_SIMULATION",
                "is_synthetic": True,
                "target_host": "WS-RESTART-01",
                "target_user": "secops",
                "window_start": t0.isoformat(),
                "window_end": t1.isoformat(),
                "executed_at": t0.isoformat(),
            },
        )
        assert res_run.status_code == 200

        res_rule = client1.post(
            "/api/v1/rules",
            json={
                "rule_id": "RULE-PERSIST-API",
                "rule_name": "Persistence Rule",
                "rule_format": "sigma",
            },
        )
        assert res_rule.status_code == 200

    # Simulate server shutdown: close store and reset in-memory reference
    close_store()
    reset_store()
    reset_settings()

    # ── Phase 2: Application Instance 2 Reopens Database File ─────────────────
    # Ensure environment is configured to point to the exact same file
    os.environ["PROOFSHIELD_STORAGE_BACKEND"] = "sqlite"
    os.environ["PROOFSHIELD_SQLITE_PATH"] = str(sqlite_api_env)

    app2 = create_application()
    with TestClient(app2) as client2:
        # Scenario must be present without re-ingestion
        res_scn2 = client2.get("/api/v1/scenarios/SCN-PERSIST-API")
        assert res_scn2.status_code == 200
        assert res_scn2.json()["name"] == "Persistence Scenario"

        # Test Run must be present
        res_run2 = client2.get("/api/v1/runs/RUN-PERSIST-API")
        assert res_run2.status_code == 200
        assert res_run2.json()["target_host"] == "WS-RESTART-01"

        # Rule must be present
        res_rule2 = client2.get("/api/v1/rules/RULE-PERSIST-API")
        assert res_rule2.status_code == 200
        assert res_rule2.json()["rule_name"] == "Persistence Rule"


def test_api_startup_fails_fast_on_invalid_storage_config(tmp_path: Path):
    """Verify that an invalid storage backend configuration causes startup to fail immediately."""
    reset_store()
    reset_settings()
    old_backend = os.environ.get("PROOFSHIELD_STORAGE_BACKEND")
    os.environ["PROOFSHIELD_STORAGE_BACKEND"] = "unsupported_storage_backend"

    try:
        app = create_application()
        with pytest.raises(ValueError, match="Unsupported storage backend"):
            with TestClient(app):
                pass
    finally:
        reset_store()
        reset_settings()
        if old_backend is not None:
            os.environ["PROOFSHIELD_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("PROOFSHIELD_STORAGE_BACKEND", None)
