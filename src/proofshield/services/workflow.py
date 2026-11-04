"""One explicit execution-to-report lifecycle using configured SIEM adapters."""

from datetime import datetime, timezone
import time

from proofshield.connectors.elastic import ElasticAlertClient, ElasticConnectorSettings
from proofshield.connectors.splunk import SplunkClient, SplunkConnectorSettings
from proofshield.execution.runner import ControlledExecutionRunner
from proofshield.services.elastic_orchestrator import ElasticAssuranceOrchestrator
from proofshield.services.splunk_orchestrator import SplunkAssuranceOrchestrator
from proofshield.services.report import RunReportService


def configured_orchestrator(source, store):
    if source == "elastic":
        settings = ElasticConnectorSettings.from_env()
        if not settings.enabled:
            raise ValueError("Elasticsearch integration is disabled")
        return ElasticAssuranceOrchestrator(ElasticAlertClient(settings), store)
    if source == "splunk":
        settings = SplunkConnectorSettings.from_env()
        if not settings.enabled:
            raise ValueError("Splunk integration is disabled")
        return SplunkAssuranceOrchestrator(SplunkClient(settings), store)
    raise ValueError("Unknown telemetry source")


class AssuranceWorkflow:
    def __init__(self, store, sleep_fn=time.sleep):
        self.store = store
        self.sleep_fn = sleep_fn

    def collect(self, run_id, source, orchestrator=None):
        if self.store.get_run(run_id) is None:
            raise ValueError("Test run does not exist")
        coordinator = orchestrator or configured_orchestrator(source, self.store)
        result, collection = coordinator.evaluate_run_with_orchestration(run_id, strict_attribution=True)
        self.store.add_result(result)
        report = RunReportService(self.store).build(run_id)
        return {"diagnostic": result, "collection": collection, "report": report}

    def execute(self, request, source, orchestrator=None):
        if not request.scenario_id:
            raise ValueError("A scenario is required for the assurance workflow")
        coordinator = orchestrator or configured_orchestrator(source, self.store)
        runner = ControlledExecutionRunner(self.store)
        if request.dry_run:
            return {"validation": runner.validate_request(request)}
        evidence, run = runner.execute(request)
        remaining = (run.window_end - datetime.now(timezone.utc)).total_seconds()
        if remaining > 0:
            self.sleep_fn(remaining)
        result = self.collect(run.run_id, source, coordinator)
        result.update(execution=evidence, test_run=run)
        return result
