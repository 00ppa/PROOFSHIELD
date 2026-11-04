"""Phase 24 report, export, and connected UI tests."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from proofshield.main import create_application
from proofshield.schemas.common import DiagnosticCategory, EventCategory, ExecutionMode, ExecutionStatus, ValidationTarget
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.store import InMemoryStore, set_store


def _setup():
    store = InMemoryStore()
    now = datetime(2026, 11, 3, 14, 0, tzinfo=timezone.utc)
    store.add_scenario(
        ScenarioV1(
            scenario_id="SCN-REPORT-01",
            name="Report scenario",
            mitre_technique_id="T1082",
            mitre_tactic="Discovery",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
        )
    )
    store.add_run(TestRunV1(
        run_id="RUN-REPORT-01", scenario_id="SCN-REPORT-01", target_host="REPORT-HOST", target_user="tester",
        execution_mode=ExecutionMode.EMULATED_AGENT, executed_at=now, window_start=now, window_end=now,
        execution_status=ExecutionStatus.COMPLETED,
    ))
    store.add_result(DiagnosticResultV1(
        diagnostic_id="DIAG-REPORT-01", test_run_id="RUN-REPORT-01", scenario_id="SCN-REPORT-01",
        predicted_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        reason="Expected telemetry was not observed.", evaluated_at=now,
    ))
    set_store(store)
    return store


def test_report_endpoint_and_csv_export_use_real_diagnostic_evidence():
    _setup()
    client = TestClient(create_application())
    response = client.get("/api/v1/reports/runs/RUN-REPORT-01")
    assert response.status_code == 200
    body = response.json()
    assert body["deterministic_category"] == "EXPECTED_TELEMETRY_MISSING"
    assert body["report_hash"]
    csv_response = client.get("/api/v1/reports/runs/RUN-REPORT-01/export.csv")
    assert csv_response.status_code == 200
    assert "deterministic_category" in csv_response.text


def test_ui_is_connected_to_backend_routes():
    _setup()
    client = TestClient(create_application())
    response = client.get("/ui")
    assert response.status_code == 200
    assert '/ui/assets/app.js' in response.text
    script = client.get('/ui/assets/app.js')
    assert script.status_code == 200
    assert "/api/v1/evaluation/" in script.text
    assert "/api/v1/explanations/" in script.text
    assert "strict_attribution=true" in script.text
