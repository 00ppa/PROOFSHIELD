"""Complete controlled execution -> Splunk -> assurance -> report workflow."""

from datetime import datetime, timezone

from proofshield.execution.runner import ControlledExecutionRunner
from proofshield.schemas.common import DiagnosticCategory, EventCategory, ValidationTarget
from proofshield.schemas.execution import ExecutionRequestV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.services.explanation import EvidenceGroundedExplanationService
from proofshield.services.report import RunReportService
from proofshield.services.splunk_orchestrator import SplunkAssuranceOrchestrator
from proofshield.services.store import InMemoryStore
from tests.mock_splunk_server import run_mock_splunk_server


def test_end_to_end_controlled_execution_splunk_assurance_report():
    store = InMemoryStore()
    store.add_scenario(
        ScenarioV1(
            scenario_id="SCN-E2E-24-01",
            name="End-to-end benign process assurance",
            mitre_technique_id="T1082",
            mitre_tactic="Discovery",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="whoami",
            expected_detection_rule_id="RULE-E2E-24-01",
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
    )
    runner = ControlledExecutionRunner(store=store, settling_time_seconds=0.1)
    store.add_rule(DetectionRuleV1(rule_id="RULE-E2E-24-01", rule_name="Controlled test rule", rule_format="splunk"))
    evidence, test_run = runner.execute(
        ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCN-E2E-24-01",
            target_host="E2E-HOST",
            action_parameters={"profile": "whoami"},
        )
    )
    assert test_run is not None
    assert evidence.verify_integrity()
    store.add_ground_truth(GroundTruthV1(ground_truth_id="GT-E2E-24-01", run_id=test_run.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS, verification_method="Independent synthetic fixture design"))

    telemetry = {
        "_cd": "e2e-telemetry-01",
        "_time": evidence.completed_at.isoformat(),
        "event.id": "e2e-telemetry-01",
        "event.category": "process",
        "event.action": "start",
        "host.name": "E2E-HOST",
        "process.name": "whoami",
        "process.command_line": f"whoami TOKEN={evidence.execution_token}",
        "execution_token": evidence.execution_token,
    }
    alert = {
        "event_id": "e2e-alert-01",
        "_time": evidence.completed_at.isoformat(),
        "host": "E2E-HOST",
        "rule_id": "RULE-E2E-24-01",
        "title": "E2E controlled validation",
        "execution_token": evidence.execution_token,
    }
    with run_mock_splunk_server() as mock:
        mock.server.telemetry = [telemetry]
        mock.server.alerts = [alert]
        result, orchestration = SplunkAssuranceOrchestrator(mock.get_client(), store).evaluate_run_with_orchestration(
            test_run.run_id, strict_attribution=True
        )
    assert orchestration.is_complete is True
    assert result.predicted_category == DiagnosticCategory.PASS
    assert store.get_result_for_run(test_run.run_id).diagnostic_id == result.diagnostic_id
    explanation = EvidenceGroundedExplanationService(store).explain(result)
    store.add_explanation(explanation)
    report = RunReportService(store).build(test_run.run_id)
    assert report.deterministic_category == DiagnosticCategory.PASS
    assert report.integrity_verified is True
    assert EvidenceGroundedExplanationService.verify(explanation) is True
