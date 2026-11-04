"""Opt-in read-only live Splunk smoke test; no live claims from mock tests."""

from datetime import datetime, timedelta, timezone
import os
import pytest

from proofshield.connectors.splunk import SplunkClient, SplunkConnectorSettings


@pytest.mark.skipif(os.environ.get("PROOFSHIELD_SPLUNK_LIVE") != "1", reason="Explicit live Splunk opt-in and credentials required")
def test_live_bounded_splunk_search():
    client = SplunkClient(SplunkConnectorSettings.from_env())
    end = datetime.now(timezone.utc)
    batch = client.search_telemetry(start_time=end - timedelta(minutes=1), end_time=end, limit=10)
    assert len(batch.results) <= 10
    assert batch.status in {"COMPLETE", "EMPTY", "TRUNCATED"}
