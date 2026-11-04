"""Splunk adapter reusing the established evidence orchestration and engine."""

from proofshield.connectors.elastic import ElasticTelemetryBatch, TelemetryRetrievalStatus
from proofshield.connectors.splunk import map_splunk_result_to_raw
from proofshield.services.elastic_orchestrator import (
    ElasticAssuranceOrchestrator, ElasticOrchestrationReport,
    ElasticOrchestratorSettings, NormalizationStatus,
)

SplunkNormalizationStatus = NormalizationStatus
SplunkOrchestrationReport = ElasticOrchestrationReport
SplunkOrchestratorSettings = ElasticOrchestratorSettings


class _SplunkEvidenceAdapter:
    def __init__(self, client):
        self.client = client

    def search_telemetry(self, start_time=None, end_time=None, host=None, limit=None, **kwargs):
        batch = self.client.search_telemetry(start_time=start_time, end_time=end_time, host=host, limit=limit)
        return ElasticTelemetryBatch(batch.results, batch.total_matched, "gte" if batch.is_truncated else "eq",
                                     batch.is_truncated, TelemetryRetrievalStatus(batch.status), batch.query_window)

    @staticmethod
    def map_hits_to_raw_telemetry(hits):
        return [map_splunk_result_to_raw(hit) for hit in hits]

    def fetch_and_map_alerts(self, start_time=None, end_time=None, host=None, rule_ids=None, limit=None, **kwargs):
        return self.client.fetch_and_map_alerts(start_time=start_time, end_time=end_time, host=host, rule_ids=rule_ids, limit=limit)

    @property
    def last_search_total(self):
        return self.client.last_search_total

    @property
    def last_search_truncated(self):
        return self.client.last_search_truncated


class SplunkAssuranceOrchestrator(ElasticAssuranceOrchestrator):
    source_name = "Splunk"

    def __init__(self, client, store, **kwargs):
        super().__init__(client=_SplunkEvidenceAdapter(client), store=store, **kwargs)


SplunkOrchestrator = SplunkAssuranceOrchestrator
