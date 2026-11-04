"""Phase 21 Splunk connector, persistence, and shared-assurance integration tests."""

from datetime import datetime, timedelta, timezone

import pytest

from proofshield.connectors.splunk import (
    SplunkClient,
    SplunkClientError,
    SplunkConnectorSettings,
    map_splunk_alert,
    map_splunk_result_to_raw,
)
from proofshield.schemas.common import DiagnosticCategory, EventCategory, ExecutionMode, ExecutionStatus, ValidationTarget
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.splunk_orchestrator import SplunkAssuranceOrchestrator
from proofshield.services.store import InMemoryStore
from tests.mock_splunk_server import run_mock_splunk_server


def _telemetry(token: str = "tok-splunk-01"):
    return {
        "_cd": "tel-splunk-01",
        "_time": "2026-11-03T10:00:01Z",
        "event.id": "tel-splunk-01",
        "event.category": "process",
        "event.action": "start",
        "host.name": "HOST-SPLUNK-01",
        "process.name": "whoami",
        "process.command_line": f"whoami TOKEN={token}",
        "execution_token": token,
    }


def _alert(token: str = "tok-splunk-01"):
    return {
        "event_id": "alert-splunk-01",
        "_time": "2026-11-03T10:00:02Z",
        "host": "HOST-SPLUNK-01",
        "rule_id": "RULE-SPLUNK-01",
        "title": "Splunk controlled validation alert",
        "severity": "medium",
        "execution_token": token,
    }


def _context(store: InMemoryStore):
    start = datetime(2026, 11, 3, 10, 0, 0, tzinfo=timezone.utc)
    store.add_scenario(
        ScenarioV1(
            scenario_id="SCN-SPLUNK-01",
            name="Splunk controlled process validation",
            mitre_technique_id="T1082",
            mitre_tactic="Discovery",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="whoami",
            expected_detection_rule_id="RULE-SPLUNK-01",
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
    )
    store.add_run(
        TestRunV1(
            run_id="RUN-SPLUNK-01",
            scenario_id="SCN-SPLUNK-01",
            target_host="HOST-SPLUNK-01",
            target_user="tester",
            execution_mode=ExecutionMode.EMULATED_AGENT,
            is_synthetic=False,
            executed_at=start,
            window_start=start - timedelta(seconds=1),
            window_end=start + timedelta(seconds=10),
            execution_status=ExecutionStatus.COMPLETED,
            execution_token="tok-splunk-01",
        )
    )
    store.add_rule(DetectionRuleV1(rule_id="RULE-SPLUNK-01", rule_name="Splunk test rule", rule_format="splunk"))


def test_splunk_settings_redact_token_and_validate_bounds(monkeypatch):
    monkeypatch.setenv("PROOFSHIELD_SPLUNK_URL", "https://splunk.local:8089")
    monkeypatch.setenv("PROOFSHIELD_SPLUNK_TOKEN", "secret-token")
    settings = SplunkConnectorSettings.from_env()
    assert "secret-token" not in repr(settings)
    assert "REDACTED" in repr(settings)
    with pytest.raises(ValueError):
        SplunkConnectorSettings("http://x", "t", max_results=0)


def test_splunk_mapping_preserves_raw_source_and_attribution_token():
    raw = map_splunk_result_to_raw(_telemetry())
    assert raw.source_format == "splunk"
    assert raw.source_event_id == "tel-splunk-01"
    assert raw.raw_payload["process.name"] == "whoami"
    alert = map_splunk_alert(_alert())
    assert alert.source_type == "splunk"
    assert alert.rule_reference == "RULE-SPLUNK-01"
    assert alert.execution_token == "tok-splunk-01"


def test_splunk_client_retrieves_bounded_results_and_authenticates():
    with run_mock_splunk_server() as mock:
        mock.server.telemetry = [_telemetry(), {**_telemetry(), "_cd": "tel-splunk-02"}]
        client = mock.get_client(max_results=1)
        batch = client.search_telemetry(limit=1)
        assert len(batch.results) == 1
        assert batch.is_truncated is True
        request = mock.server.requests[0]
        assert request["headers"]["Authorization"] == "Bearer splunk-test-token"
        assert "earliest_time" in request["body"]
        assert "latest_time" in request["body"]


def test_splunk_client_surfaces_authentication_errors():
    with run_mock_splunk_server() as mock:
        client = SplunkClient(SplunkConnectorSettings(
            base_url=mock.base_url,
            token="wrong-token",
            telemetry_index="telemetry",
            alert_index="alerts",
            verify_tls=False,
        ))
        with pytest.raises(SplunkClientError) as exc:
            client.search_telemetry()
        assert exc.value.status_code == 401


def test_splunk_orchestrator_persists_evidence_and_uses_shared_assurance_engine():
    store = InMemoryStore()
    _context(store)
    with run_mock_splunk_server() as mock:
        mock.server.telemetry = [_telemetry()]
        mock.server.alerts = [_alert()]
        result, report = SplunkAssuranceOrchestrator(mock.get_client(), store).evaluate_run_with_orchestration(
            "RUN-SPLUNK-01", strict_attribution=True
        )
    assert report.raw_telemetry_persisted == 1
    assert report.normalized_telemetry_persisted == 1
    assert report.alerts_persisted == 1
    assert result.predicted_category == DiagnosticCategory.PASS
    assert store.get_raw_event("splunk:raw:tel-splunk-01") is not None


def test_splunk_retrieval_failure_is_error_not_missing_telemetry():
    store = InMemoryStore()
    _context(store)
    with run_mock_splunk_server() as mock:
        mock.server.fail_status = 503
        result, report = SplunkAssuranceOrchestrator(mock.get_client(), store).evaluate_run_with_orchestration(
            "RUN-SPLUNK-01", strict_attribution=True
        )
    assert report.is_complete is False
    assert result.predicted_category == DiagnosticCategory.ERROR
