"""Live integration tests for Elasticsearch connector.

Opt-in test suite requiring an accessible Elasticsearch 8.x instance.
Execute with:
    PROOFSHIELD_ELASTIC_LIVE=true PROOFSHIELD_ELASTIC_URL=https://... PROOFSHIELD_ELASTIC_API_KEY=... pytest tests/test_elastic_live.py
"""

from datetime import datetime, timedelta, timezone
import os
import pytest

from proofshield.connectors.elastic import (
    ElasticAlertClient,
    ElasticConnectorSettings,
    TelemetryRetrievalStatus,
)
from proofshield.normalisation.ecs import ECSNormaliser
from proofshield.schemas.telemetry import RawTelemetryEventV1

LIVE_OPT_IN = os.environ.get("PROOFSHIELD_ELASTIC_LIVE", "").strip().lower() in ("true", "1", "yes")

pytestmark = pytest.mark.skipif(
    not LIVE_OPT_IN,
    reason="Live Elasticsearch integration tests disabled (set PROOFSHIELD_ELASTIC_LIVE=true to enable)",
)


def test_live_elastic_connection():
    """Verify live connectivity and settings loaded from environment."""
    settings = ElasticConnectorSettings.from_env()
    client = ElasticAlertClient(settings=settings)

    # Basic alert search in a bounded 1-hour window
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)

    hits = client.search_alerts(start_time=start_time, end_time=end_time, limit=5)
    assert isinstance(hits, list)


def test_live_telemetry_search_and_normalize():
    """Verify live telemetry query and subsequent ECS normalization."""
    settings = ElasticConnectorSettings.from_env()
    client = ElasticAlertClient(settings=settings)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=2)

    batch = client.search_telemetry(start_time=start_time, end_time=end_time, limit=10)
    assert batch.status in (
        TelemetryRetrievalStatus.COMPLETE,
        TelemetryRetrievalStatus.EMPTY,
        TelemetryRetrievalStatus.TRUNCATED,
    )

    if batch.hits:
        raw_events = client.map_hits_to_raw_telemetry(batch.hits)
        assert len(raw_events) == len(batch.hits)
        normaliser = ECSNormaliser()
        for rev in raw_events:
            assert normaliser.can_handle(rev)
            norm = normaliser.normalize(rev)
            assert norm.normalized_event_id.startswith("NORM-ECS-")
            assert norm.host is not None

