"""Adversarial reliability tests for the Elasticsearch connector boundary."""

from datetime import datetime, timezone
import json
from typing import Any
import urllib.request

import pytest

from proofshield.connectors.elastic import (
    ElasticAlertClient,
    ElasticAlertMappingError,
    ElasticClientError,
    ElasticConnectorSettings,
)


class _Response:
    def __init__(self, payload: bytes, content_length: Any = None):
        self.payload = payload
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            return self.payload
        return self.payload[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


def _client(**kwargs) -> ElasticAlertClient:
    settings = ElasticConnectorSettings(
        base_url="https://elastic.test:9200",
        api_key="test-key",
        **kwargs,
    )
    return ElasticAlertClient(settings)


def _search_response(hits, total=None):
    result = {"hits": {"hits": hits}}
    if total is not None:
        result["hits"]["total"] = total
    return result


def _telemetry_hit(hit_id="event-1", timestamp="2026-11-04T10:00:00Z"):
    source = {"host": {"name": "WS-01"}}
    if timestamp is not None:
        source["@timestamp"] = timestamp
    return {"_id": hit_id, "_source": source}


def test_response_byte_limit_rejects_content_length_and_chunked_overflow(monkeypatch):
    client = _client(max_response_bytes=32)
    oversized = b"{" + b"x" * 64

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: _Response(oversized, content_length=len(oversized)),
    )
    with pytest.raises(ElasticClientError, match="byte limit"):
        client.search_alerts()

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: _Response(oversized),
    )
    with pytest.raises(ElasticClientError, match="byte limit"):
        client.search_alerts()


@pytest.mark.parametrize(
    "payload, message",
    [
        (b"not-json", "invalid JSON"),
        (json.dumps(["not", "an", "object"]).encode(), "top-level JSON"),
        (json.dumps({"hits": []}).encode(), "'hits' must be an object"),
        (json.dumps({"hits": {"hits": {}}}).encode(), "'hits.hits' must be an array"),
        (json.dumps(_search_response(["not-a-hit"])).encode(), "hit 0 must be an object"),
        (json.dumps(_search_response([{"_id": "id-without-source"}])).encode(), "lacks '_source'"),
    ],
)
def test_malformed_json_and_response_shapes_are_controlled(monkeypatch, payload, message):
    client = _client()
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: _Response(payload),
    )
    with pytest.raises(ElasticClientError, match=message):
        client.search_alerts()


def test_invalid_hit_identifiers_and_timestamps_are_rejected_without_fabrication(monkeypatch):
    client = _client()
    missing_id = _telemetry_hit(hit_id=None)
    missing_id.pop("_id", None)
    response = json.dumps(_search_response([missing_id])).encode()
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: _Response(response))
    with pytest.raises(ElasticClientError, match="lacks a valid identifier"):
        client.search_telemetry()

    for timestamp, expected in ((None, "lacks a telemetry timestamp"), ("not-a-time", "invalid telemetry timestamp")):
        response = json.dumps(_search_response([_telemetry_hit(timestamp=timestamp)])).encode()
        monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: _Response(response))
        with pytest.raises(ElasticClientError, match=expected):
            client.search_telemetry()

    with pytest.raises(ElasticAlertMappingError, match="lacks a source timestamp"):
        ElasticAlertClient.map_hits_to_raw_telemetry([_telemetry_hit(timestamp=None)])
    with pytest.raises(ElasticAlertMappingError, match="lacks a valid identifier"):
        ElasticAlertClient.map_hits_to_raw_telemetry([{"_source": {"@timestamp": "2026-11-04T10:00:00Z"}}])


def test_valid_telemetry_preserves_source_id_and_timestamp():
    hit = _telemetry_hit(hit_id="event-stable", timestamp="2026-11-04T10:00:00+00:00")
    event = ElasticAlertClient.map_hits_to_raw_telemetry([hit])[0]
    assert event.source_event_id == "event-stable"
    assert event.raw_event_id == "elastic:raw:event-stable"
    assert event.source_timestamp == datetime(2026, 11, 4, 10, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"limit": 0}, "limit"),
        ({"limit": -1}, "limit"),
        ({"batch_size": 0}, "batch_size"),
        ({"batch_size": -2}, "batch_size"),
        ({"max_retries": -1}, "max_retries"),
        ({"max_retries": 11}, "max_retries"),
        ({"rule_ids": "RULE-1"}, "rule_ids"),
        ({"host": 42}, "host"),
    ],
)
def test_invalid_pagination_and_request_parameters_fail_before_network(kwargs, message):
    client = _client()
    with pytest.raises(ElasticClientError, match=message):
        if "rule_ids" in kwargs:
            client.search_alerts(**kwargs)
        else:
            client.search_telemetry(**kwargs)

    with pytest.raises(ElasticClientError, match="start_time"):
        client.search_alerts(
            start_time=datetime(2026, 11, 4, 11, tzinfo=timezone.utc),
            end_time=datetime(2026, 11, 4, 10, tzinfo=timezone.utc),
        )


def test_invalid_response_totals_are_rejected(monkeypatch):
    client = _client()
    cases = [
        {"value": -1, "relation": "eq"},
        {"value": 1, "relation": "unknown"},
        {"value": "1", "relation": "eq"},
        True,
    ]
    for total in cases:
        payload = json.dumps(_search_response([_telemetry_hit()], total=total)).encode()
        monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: _Response(payload))
        with pytest.raises(ElasticClientError, match="hits.total"):
            client.search_telemetry()
