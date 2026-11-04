"""PROOFSHIELD Connectors for external monitoring systems and SIEMs."""

from proofshield.connectors.elastic import (
    ElasticAlertClient,
    ElasticAlertMappingError,
    ElasticClient,
    ElasticClientError,
    ElasticConnectorSettings,
    ElasticTelemetryBatch,
    ElasticTelemetryHit,
    TelemetryRetrievalStatus,
    map_elastic_alert,
    map_elastic_alerts_batch,
)
from proofshield.connectors.splunk import (
    SplunkClient,
    SplunkClientError,
    SplunkConnectorSettings,
    SplunkMappingError,
    SplunkRetrievalStatus,
    SplunkTelemetryBatch,
    map_splunk_alert,
    map_splunk_result_to_raw,
)

__all__ = [
    "ElasticAlertClient",
    "ElasticAlertMappingError",
    "ElasticClient",
    "ElasticClientError",
    "ElasticConnectorSettings",
    "ElasticTelemetryBatch",
    "ElasticTelemetryHit",
    "TelemetryRetrievalStatus",
    "map_elastic_alert",
    "map_elastic_alerts_batch",
    "SplunkClient",
    "SplunkClientError",
    "SplunkConnectorSettings",
    "SplunkMappingError",
    "SplunkRetrievalStatus",
    "SplunkTelemetryBatch",
    "map_splunk_alert",
    "map_splunk_result_to_raw",
]
