"""Comprehensive offline tests for the Elastic Security alert connector."""

from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
from typing import Any, Dict
import urllib.error
import urllib.request

import pytest

from proofshield.connectors.elastic import (
    ElasticAlertClient,
    ElasticAlertMappingError,
    ElasticClientError,
    ElasticConnectorSettings,
    map_elastic_alert,
    map_elastic_alerts_batch,
)
from proofshield.schemas import (
    AlertV1,
    AttributionStatus,
    DetectionRuleV1,
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    NormalizedTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore


# ── Sample Fixture Generators ───────────────────────────────────────────────

def make_modern_elastic_hit(
    hit_id: str = "hit-modern-001",
    index: str = ".alerts-security.alerts-default",
    timestamp: str = "2026-10-25T14:30:00.000Z",
    hostname: str = "WS-PROD-01",
    rule_id: str = "rule-cred-dump-01",
    rule_name: str = "Credential Dumping Activity",
    severity: str = "high",
    command_line: str = "mimikatz.exe privilege::debug",
    token: str = None,
) -> Dict[str, Any]:
    cmd = command_line
    if token:
        cmd += f" --execution-token={token}"

    return {
        "_index": index,
        "_id": hit_id,
        "_source": {
            "@timestamp": timestamp,
            "kibana.alert.uuid": f"uuid-{hit_id}",
            "kibana.alert.rule.rule_id": rule_id,
            "kibana.alert.rule.uuid": f"rule-uuid-{rule_id}",
            "kibana.alert.rule.name": rule_name,
            "kibana.alert.rule.severity": severity,
            "host": {
                "name": hostname,
                "hostname": f"{hostname}.corp.internal",
                "id": "host-guid-9999",
                "ip": ["10.1.2.3"],
            },
            "process": {
                "name": "mimikatz.exe",
                "command_line": cmd,
                "args": cmd.split(),
            },
            "message": f"Rule '{rule_name}' alerted on host {hostname}",
        },
    }


def make_legacy_signal_hit(
    hit_id: str = "sig-legacy-002",
    index: str = ".siem-signals-default",
    timestamp: str = "2026-10-25T15:00:00Z",
    hostname: str = "SRV-FILE-01",
    rule_id: str = "rule-legacy-ps-01",
    token: str = None,
) -> Dict[str, Any]:
    cmd = "powershell.exe -NoP -W Hidden -Enc AAA=="
    if token:
        cmd += f" [TOKEN: {token}]"

    return {
        "_index": index,
        "_id": hit_id,
        "_source": {
            "@timestamp": timestamp,
            "signal": {
                "id": f"signal-id-{hit_id}",
                "rule": {
                    "id": rule_id,
                    "rule_id": rule_id,
                    "name": "PowerShell Encoded Execution",
                    "severity": "medium",
                },
            },
            "host": {
                "hostname": hostname,
            },
            "process": {
                "command_line": cmd,
            },
        },
    }


# ── 1. Pure Alert Mapping Tests ─────────────────────────────────────────────

def test_map_modern_kibana_alert():
    hit = make_modern_elastic_hit(token="TOK-MODERN-777")
    alert = map_elastic_alert(hit)

    assert alert.schema_version == "v1"
    assert alert.alert_id == "elastic:hit-modern-001"
    assert alert.source_alert_id == "hit-modern-001"
    assert alert.source_type == "elastic"
    assert alert.host_id == "WS-PROD-01.corp.internal"
    assert alert.rule_reference == "rule-cred-dump-01"
    assert alert.alert_title == "Credential Dumping Activity"
    assert alert.severity == "high"
    assert alert.raw_record_reference == ".alerts-security.alerts-default/hit-modern-001"
    assert alert.execution_token == "TOK-MODERN-777"
    assert alert.alert_timestamp == datetime(2026, 10, 25, 14, 30, 0, tzinfo=timezone.utc)
    assert alert.ingested_at is not None


def test_map_legacy_signal_alert():
    hit = make_legacy_signal_hit(token="TOK-LEGACY-888")
    alert = map_elastic_alert(hit)

    assert alert.alert_id == "elastic:sig-legacy-002"
    assert alert.source_alert_id == "sig-legacy-002"
    assert alert.host_id == "SRV-FILE-01"
    assert alert.rule_reference == "rule-legacy-ps-01"
    assert alert.alert_title == "PowerShell Encoded Execution"
    assert alert.severity == "medium"
    assert alert.execution_token == "TOK-LEGACY-888"
    assert alert.alert_timestamp == datetime(2026, 10, 25, 15, 0, 0, tzinfo=timezone.utc)


def test_map_nested_and_dotted_fields():
    doc = {
        "_id": "nested-alert-01",
        "_source": {
            "@timestamp": "2026-10-25T16:00:00Z",
            "kibana": {
                "alert": {
                    "rule": {
                        "rule_id": "rule-nested-01",
                        "name": "Nested Rule Name",
                        "severity": "CRITICAL",
                    }
                }
            },
            "host": {
                "name": "WS-NESTED-01",
            },
        },
    }
    alert = map_elastic_alert(doc)
    assert alert.rule_reference == "rule-nested-01"
    assert alert.alert_title == "Nested Rule Name"
    assert alert.severity == "critical"
    assert alert.host_id == "WS-NESTED-01"


def test_map_host_fallbacks():
    # Fallback to host.id
    doc1 = {"_id": "alt-host-id", "_source": {"host": {"id": "endpoint-uuid-1234"}, "@timestamp": "2026-10-25T10:00:00Z"}}
    assert map_elastic_alert(doc1).host_id == "endpoint-uuid-1234"

    # Fallback to agent.hostname
    doc2 = {"_id": "alt-agent-host", "_source": {"agent": {"hostname": "agent-host-99"}, "@timestamp": "2026-10-25T10:00:00Z"}}
    assert map_elastic_alert(doc2).host_id == "agent-host-99"

    # Fallback to host.ip list
    doc3 = {"_id": "alt-host-ip", "_source": {"host": {"ip": ["192.168.1.55", "10.0.0.1"]}, "@timestamp": "2026-10-25T10:00:00Z"}}
    assert map_elastic_alert(doc3).host_id == "192.168.1.55"


def test_map_timestamp_variations():
    # 1. ISO string with UTC offset (+05:30)
    doc_offset = {
        "_id": "ts-offset",
        "_source": {
            "host": {"name": "WS-01"},
            "@timestamp": "2026-10-25T20:30:00+05:30",
        },
    }
    alert = map_elastic_alert(doc_offset)
    assert alert.alert_timestamp == datetime(2026, 10, 25, 15, 0, 0, tzinfo=timezone.utc)

    # 2. Epoch seconds (numeric)
    doc_epoch_s = {
        "_id": "ts-epoch-s",
        "_source": {
            "host": {"name": "WS-01"},
            "@timestamp": 1792940400,  # 2026-10-25 15:00:00 UTC
        },
    }
    alert_s = map_elastic_alert(doc_epoch_s)
    assert alert_s.alert_timestamp == datetime(2026, 10, 25, 15, 0, 0, tzinfo=timezone.utc)

    # 3. Epoch milliseconds (numeric)
    doc_epoch_ms = {
        "_id": "ts-epoch-ms",
        "_source": {
            "host": {"name": "WS-01"},
            "@timestamp": 1792940400000,
        },
    }
    alert_ms = map_elastic_alert(doc_epoch_ms)
    assert alert_ms.alert_timestamp == datetime(2026, 10, 25, 15, 0, 0, tzinfo=timezone.utc)

    # 4. Missing timestamp (None)
    doc_none = {
        "_id": "ts-none",
        "_source": {
            "host": {"name": "WS-01"},
        },
    }
    assert map_elastic_alert(doc_none).alert_timestamp is None


def test_map_execution_tokens_structured_and_unstructured():
    # 1. Token in process.command_line
    hit1 = make_modern_elastic_hit(token="TOK-CMD-123")
    assert map_elastic_alert(hit1).execution_token == "TOK-CMD-123"

    # 2. Token in tags list
    hit2 = make_modern_elastic_hit()
    hit2["_source"]["tags"] = ["production", "TOKEN:TOK-TAG-456"]
    assert map_elastic_alert(hit2).execution_token == "TOK-TAG-456"

    # 3. Token in labels dict
    hit3 = make_modern_elastic_hit()
    hit3["_source"]["labels"] = {"execution_token": "TOK-LABEL-789"}
    assert map_elastic_alert(hit3).execution_token == "TOK-LABEL-789"

    # 4. Token absent
    hit4 = make_modern_elastic_hit()
    assert map_elastic_alert(hit4).execution_token is None

    # 5. Conflicting tokens between command_line and structured field
    hit5 = make_modern_elastic_hit(token="TOK-ONE")
    hit5["_source"]["labels"] = {"execution_token": "TOK-TWO"}
    assert map_elastic_alert(hit5).execution_token == "CONFLICT"


def test_map_metadata_secret_sanitization():
    hit = make_modern_elastic_hit()
    # Actual secrets that must be redacted
    hit["_source"]["api_key"] = "secret-api-key-12345"
    hit["_source"]["user_password"] = "SuperSecretPassword!"
    hit["_source"]["private_key"] = "-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASC..."
    hit["_source"]["headers"] = {"Authorization": "Bearer confidential_token"}
    hit["_source"]["custom_auth"] = "ApiKey ES_SECRET_KEY_999"

    # Legitimate forensic fields that MUST be preserved for investigation integrity
    hit["_source"]["password_reset"] = True
    hit["_source"]["secret_scope"] = "global_tenant"
    hit["_source"]["auth_token_id"] = "token-uuid-12345"
    hit["_source"]["password_hash"] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    hit["_source"]["password_change_count"] = 3
    hit["_source"]["user"] = {"password_last_changed": "2026-10-25T12:00:00Z"}

    alert = map_elastic_alert(hit)
    meta = alert.metadata

    # Assert secrets are redacted
    assert meta["api_key"] == "[REDACTED]"
    assert meta["user_password"] == "[REDACTED]"
    assert meta["private_key"] == "[REDACTED]"
    assert meta["headers"]["Authorization"] == "[REDACTED]"
    assert meta["custom_auth"] == "[REDACTED]"

    # Assert forensic non-secret attributes are safely preserved
    assert meta["password_reset"] is True
    assert meta["secret_scope"] == "global_tenant"
    assert meta["auth_token_id"] == "token-uuid-12345"
    assert meta["password_hash"] == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    assert meta["password_change_count"] == 3
    assert meta["user"]["password_last_changed"] == "2026-10-25T12:00:00Z"


def test_map_explicit_rejection_of_malformed_records():
    # Missing ID
    with pytest.raises(ElasticAlertMappingError, match="lacks a valid identifier"):
        map_elastic_alert({"_source": {"host": {"name": "WS-01"}}})

    # Missing Host
    with pytest.raises(ElasticAlertMappingError, match="lacks host identity"):
        map_elastic_alert({"_id": "alt-nohost", "_source": {"@timestamp": "2026-10-25T10:00:00Z"}})

    # Malformed timestamp
    with pytest.raises(ElasticAlertMappingError, match="Malformed alert timestamp"):
        map_elastic_alert({"_id": "alt-bad-ts", "_source": {"host": {"name": "WS-01"}, "@timestamp": "not-a-timestamp"}})

    # Non-dict record
    with pytest.raises(ElasticAlertMappingError, match="Expected alert document as dict"):
        map_elastic_alert("this-is-a-string")


def test_map_batch_and_deduplication():
    hit1 = make_modern_elastic_hit(hit_id="dup-01")
    hit2 = make_modern_elastic_hit(hit_id="dup-01")  # Duplicate
    hit3 = make_modern_elastic_hit(hit_id="unique-02")

    batch = [hit1, hit2, hit3]

    # With deduplicate=True (default)
    res_dedup = map_elastic_alerts_batch(batch, deduplicate=True)
    assert len(res_dedup) == 2
    assert [a.source_alert_id for a in res_dedup] == ["dup-01", "unique-02"]

    # With deduplicate=False
    res_all = map_elastic_alerts_batch(batch, deduplicate=False)
    assert len(res_all) == 3


# ── 2. Connector Settings & Redaction ────────────────────────────────────────

def test_settings_validation_and_secret_redaction(tmp_path: Path):
    # Valid settings
    ca_file = tmp_path / "ca.crt"
    ca_file.write_text("dummy-cert")

    settings = ElasticConnectorSettings(
        base_url="https://elastic.corp.internal:9200/",
        api_key="my-super-secret-api-key",
        ca_cert_path=ca_file,
        request_timeout=5.5,
        max_results=500,
        enabled=True,
    )
    assert settings.base_url == "https://elastic.corp.internal:9200"
    assert settings.api_key == "my-super-secret-api-key"
    assert settings.ca_cert_path == str(ca_file.resolve())
    assert settings.request_timeout == 5.5
    assert settings.max_results == 500
    assert settings.enabled is True

    # repr must redact api_key
    repr_str = repr(settings)
    assert "***REDACTED***" in repr_str
    assert "my-super-secret-api-key" not in repr_str

    # Invalid URL scheme
    with pytest.raises(ValueError, match="must start with 'http://' or 'https://'"):
        ElasticConnectorSettings(base_url="ftp://elastic.corp:9200", api_key="abc")

    # Empty API key
    with pytest.raises(ValueError, match="Elastic API key cannot be empty"):
        ElasticConnectorSettings(base_url="https://elastic:9200", api_key="")

    # Missing CA file
    with pytest.raises(ValueError, match="Specified Elastic CA certificate file does not exist"):
        ElasticConnectorSettings(
            base_url="https://elastic:9200",
            api_key="abc",
            ca_cert_path="/non/existent/ca.crt",
        )

    # Invalid timeout
    with pytest.raises(ValueError, match="timeout must be a positive float"):
        ElasticConnectorSettings(base_url="https://elastic:9200", api_key="abc", request_timeout=-1)


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROOFSHIELD_ELASTIC_URL", "https://env-elastic:9200")
    monkeypatch.setenv("PROOFSHIELD_ELASTIC_API_KEY", "env-api-key-999")
    monkeypatch.setenv("PROOFSHIELD_ELASTIC_TIMEOUT", "15.0")
    monkeypatch.setenv("PROOFSHIELD_ELASTIC_MAX_RESULTS", "250")
    monkeypatch.setenv("PROOFSHIELD_ELASTIC_ENABLED", "true")

    s = ElasticConnectorSettings.from_env()
    assert s.base_url == "https://env-elastic:9200"
    assert s.api_key == "env-api-key-999"
    assert s.request_timeout == 15.0
    assert s.max_results == 250
    assert s.enabled is True


# ── 3. Read-Only Polling Client (Mocked Network) ─────────────────────────────

class MockHTTPResponse:
    def __init__(self, status: int, data: bytes):
        self.status = status
        self.data = data

    def read(self) -> bytes:
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


def test_client_search_success(monkeypatch: pytest.MonkeyPatch):
    settings = ElasticConnectorSettings(
        base_url="https://elastic.test:9200",
        api_key="test-api-key",
        index_pattern=".alerts-security.alerts-*",
    )
    client = ElasticAlertClient(settings)

    sample_hit = make_modern_elastic_hit(hit_id="hit-search-01")
    es_response = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [sample_hit],
        }
    }

    captured_req = {}

    def mock_urlopen(req: urllib.request.Request, timeout: float = None, context: Any = None):
        captured_req["url"] = req.full_url
        captured_req["headers"] = dict(req.headers)
        captured_req["data"] = json.loads(req.data.decode("utf-8"))
        captured_req["timeout"] = timeout
        return MockHTTPResponse(200, json.dumps(es_response).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    t_start = datetime(2026, 10, 25, 10, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 25, 11, 0, tzinfo=timezone.utc)

    alerts = client.fetch_and_map_alerts(
        start_time=t_start,
        end_time=t_end,
        rule_ids=["rule-cred-dump-01"],
        host="WS-PROD-01",
        limit=50,
    )

    assert len(alerts) == 1
    assert alerts[0].alert_id == "elastic:hit-search-01"

    # Verify query DSL and request parameters
    assert captured_req["url"] == "https://elastic.test:9200/.alerts-security.alerts-*/_search"
    assert captured_req["headers"]["Authorization"] == "ApiKey test-api-key"
    assert captured_req["headers"]["Content-type"] == "application/json"
    assert captured_req["data"]["size"] == 50
    assert captured_req["data"]["sort"] == [
        {"@timestamp": {"order": "asc"}},
        {"_id": {"order": "asc"}},
    ]


def test_client_http_errors_redaction(monkeypatch: pytest.MonkeyPatch):
    settings = ElasticConnectorSettings(
        base_url="https://elastic.test:9200",
        api_key="super-secret-key-to-protect",
    )
    client = ElasticAlertClient(settings)

    # Test HTTP 401 Unauthorized with secret redaction
    def mock_urlopen_401(req, *args, **kwargs):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=io.BytesIO(b'{"error": "invalid api key: super-secret-key-to-protect"}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen_401)
    with pytest.raises(ElasticClientError) as exc_info:
        client.search_alerts()

    assert "HTTP 401 (Unauthorized)" in str(exc_info.value)
    # Crucial security check: API key must NOT be leaked into the error
    assert "super-secret-key-to-protect" not in str(exc_info.value)
    assert "[REDACTED]" in str(exc_info.value)

    # Test HTTP 400 with Elasticsearch structured error diagnostic
    def mock_urlopen_400(req, *args, **kwargs):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=io.BytesIO(b'{"error": {"type": "parsing_exception", "reason": "Unknown key [bad_field]"}}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen_400)
    with pytest.raises(ElasticClientError) as exc_info_400:
        client.search_alerts()
    assert "HTTP 400 (Bad Request)" in str(exc_info_400.value)
    assert "[parsing_exception] Unknown key [bad_field]" in str(exc_info_400.value)

    # Test HTTP 500 with non-JSON HTML body
    def mock_urlopen_500_html(req, *args, **kwargs):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=io.BytesIO(b"<html><body>500 Internal Error from Proxy</body></html>"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen_500_html)
    with pytest.raises(ElasticClientError) as exc_info_500:
        client.search_alerts()
    assert "HTTP 500 (Internal Server Error)" in str(exc_info_500.value)
    assert "500 Internal Error from Proxy" in str(exc_info_500.value)

    # Test Timeout
    def mock_urlopen_timeout(req, *args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen_timeout)
    with pytest.raises(ElasticClientError, match="timed out"):
        client.search_alerts()


def test_client_truncation_detection_and_pagination(monkeypatch: pytest.MonkeyPatch):
    settings = ElasticConnectorSettings(
        base_url="https://elastic.test:9200",
        api_key="test-api-key",
        max_results=200,
    )
    client = ElasticAlertClient(settings)

    # 1. Truncation detection when total exceeds returned batch
    hit_1 = make_modern_elastic_hit(hit_id="hit-p1-01")
    es_response_truncated = {
        "hits": {
            "total": {"value": 250, "relation": "eq"},
            "hits": [hit_1],
        }
    }
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, *args, **kwargs: MockHTTPResponse(200, json.dumps(es_response_truncated).encode("utf-8")),
    )

    hits = client.search_alerts(limit=50)
    assert len(hits) == 1
    assert client.last_search_total == 250
    assert client.last_search_truncated is True

    # 2. Raise on truncation when explicitly requested
    with pytest.raises(ElasticClientError, match="search results truncated: matched 250 alerts"):
        client.search_alerts(limit=50, raise_on_truncation=True)

    # 3. Paging via search_after across 2 requests
    req_history = []
    hit_page1 = make_modern_elastic_hit(hit_id="hit-pg-01")
    hit_page1["sort"] = [1792940400000, "hit-pg-01"]
    hit_page2 = make_modern_elastic_hit(hit_id="hit-pg-02")
    hit_page2["sort"] = [1792940401000, "hit-pg-02"]

    def mock_urlopen_paged(req, *args, **kwargs):
        body = json.loads(req.data.decode("utf-8"))
        req_history.append(body)
        if "search_after" not in body:
            # First page
            resp_obj = {"hits": {"total": {"value": 2}, "hits": [hit_page1]}}
        else:
            # Second page
            resp_obj = {"hits": {"total": {"value": 2}, "hits": [hit_page2]}}
        return MockHTTPResponse(200, json.dumps(resp_obj).encode("utf-8"))

    # Set page size to 1 artificially by setting settings max_results
    settings_paged = ElasticConnectorSettings(base_url="https://elastic.test:9200", api_key="k", max_results=10)
    client_paged = ElasticAlertClient(settings_paged)
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen_paged)

    paged_hits = client_paged.search_alerts(limit=2, batch_size=1)
    assert len(paged_hits) == 2
    assert client_paged.last_search_truncated is False
    assert client_paged.last_search_total == 2
    assert len(req_history) == 2
    assert "search_after" not in req_history[0]
    assert req_history[1]["search_after"] == [1792940400000, "hit-pg-01"]


# ── 4. Store Ingestion & Non-Aborting Duplicate Handling ────────────────────

def test_poll_and_ingest_duplicate_handling_non_aborting(monkeypatch: pytest.MonkeyPatch):
    """Verify that an existing alert does NOT abort ingestion of subsequent novel alerts."""
    store = InMemoryStore()
    settings = ElasticConnectorSettings(base_url="https://elastic.test:9200", api_key="key")
    client = ElasticAlertClient(settings)

    # Pre-populate store with alert 'elastic:hit-existing'
    existing_alert = AlertV1(
        alert_id="elastic:hit-existing",
        source_alert_id="hit-existing",
        source_type="elastic",
        host_id="WS-01",
    )
    store.add_alert(existing_alert)

    # Batch contains: [hit-existing (dup), hit-novel-1 (new), hit-novel-2 (new)]
    hit_dup = make_modern_elastic_hit(hit_id="hit-existing")
    hit_new1 = make_modern_elastic_hit(hit_id="hit-novel-1")
    hit_new2 = make_modern_elastic_hit(hit_id="hit-novel-2")
    es_response = {"hits": {"hits": [hit_dup, hit_new1, hit_new2]}}

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, *args, **kwargs: MockHTTPResponse(200, json.dumps(es_response).encode("utf-8")),
    )

    # 1. With skip_duplicates=False:
    # Must ingest novel alerts into store AND raise ValueError identifying duplicate
    with pytest.raises(ValueError, match="Duplicate alert.*elastic:hit-existing"):
        client.poll_and_ingest(store, skip_duplicates=False)

    assert client.last_ingest_duplicates == ["elastic:hit-existing"]
    # Novel alerts MUST have been successfully ingested despite the duplicate!
    assert store.get_alert("elastic:hit-novel-1") is not None
    assert store.get_alert("elastic:hit-novel-2") is not None

    # 2. With skip_duplicates=True:
    # Should skip duplicate idempotently without error
    hit_new3 = make_modern_elastic_hit(hit_id="hit-novel-3")
    es_response_2 = {"hits": {"hits": [hit_dup, hit_new3]}}
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, *args, **kwargs: MockHTTPResponse(200, json.dumps(es_response_2).encode("utf-8")),
    )

    ingested = client.poll_and_ingest(store, skip_duplicates=True)
    assert len(ingested) == 1
    assert ingested[0].alert_id == "elastic:hit-novel-3"
    assert store.get_alert("elastic:hit-novel-3") is not None


def test_poll_and_ingest_sqlite_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_path = tmp_path / "test_elastic.db"
    store = SQLiteStore(db_path)
    settings = ElasticConnectorSettings(base_url="https://elastic.test:9200", api_key="key")
    client = ElasticAlertClient(settings)

    hit = make_modern_elastic_hit(hit_id="sqlite-hit-01")
    es_response = {"hits": {"hits": [hit]}}

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, *args, **kwargs: MockHTTPResponse(200, json.dumps(es_response).encode("utf-8")),
    )

    ingested = client.poll_and_ingest(store)
    assert len(ingested) == 1

    stored_alert = store.get_alert("elastic:sqlite-hit-01")
    assert stored_alert is not None
    assert stored_alert.source_type == "elastic"


# ── 5. Strict Attribution Engine Behavioral Verification ────────────────────

def test_strict_attribution_untokenized_elastic_alert_is_inconclusive():
    """Verify that an untokenized Elastic alert inside the execution window
    yields INCONCLUSIVE (never false PASS) when evaluated under strict attribution.
    """
    store = InMemoryStore()
    engine = AssuranceEngine(store)

    t0 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    token = "TOK-RUN-STRICT-99"

    scenario = ScenarioV1(
        scenario_id="SCN-ELASTIC-01",
        name="LSASS Access via Elastic Security",
        mitre_technique_id="T1003.001",
        mitre_tactic="Credential Access",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="mimikatz.exe",
        expected_command_pattern=r"privilege::debug",
        expected_detection_rule_id="RULE-ELASTIC-LSASS-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    rule = DetectionRuleV1(
        rule_id="RULE-ELASTIC-LSASS-01",
        rule_name="LSASS Memory Read",
        rule_format="elastic",
    )
    run = TestRunV1(
        run_id="RUN-ELASTIC-01",
        scenario_id=scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-PROD-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=5),
        executed_at=t0,
        execution_token=token,  # Strict mode active
    )

    # Telemetry observed with matching token
    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-ELASTIC-01",
        raw_event_id="RAW-ELASTIC-01",
        source_event_id="SRC-ELASTIC-01",
        source_timestamp=t0 + timedelta(seconds=15),
        normalized_timestamp=t0 + timedelta(seconds=15),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="mimikatz.exe",
        command_line=f"mimikatz.exe privilege::debug --token {token}",
        execution_token=token,
    )

    store.add_scenario(scenario)
    store.add_rule(rule)
    store.add_run(run)
    store.add_normalized_event(norm_ev)

    # 1. Ingest Elastic alert with NO execution token (ordinary detection)
    raw_hit_no_token = make_modern_elastic_hit(
        hit_id="elastic-alert-no-token",
        rule_id="RULE-ELASTIC-LSASS-01",
        hostname="WS-PROD-01",
        timestamp=(t0 + timedelta(seconds=30)).isoformat(),
        token=None,  # No token
    )
    alert_no_token = map_elastic_alert(raw_hit_no_token)
    assert alert_no_token.execution_token is None
    store.add_alert(alert_no_token)

    # Strict evaluation must yield INCONCLUSIVE (missing causal link), NOT PASS
    result = engine.evaluate_run(run.run_id, strict_attribution=True)
    assert result.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert "lacks execution token" in result.reason
    assert result.metadata["attribution"]["status"] == AttributionStatus.INCONCLUSIVE.value


def test_strict_attribution_tokenized_elastic_alert_is_pass():
    """Verify that when an Elastic alert contains the matching execution token,
    it yields DiagnosticCategory.PASS under strict attribution.
    """
    store = InMemoryStore()
    engine = AssuranceEngine(store)

    t0 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    token = "TOK-RUN-STRICT-99"

    scenario = ScenarioV1(
        scenario_id="SCN-ELASTIC-02",
        name="LSASS Access via Elastic Security Verified",
        mitre_technique_id="T1003.001",
        mitre_tactic="Credential Access",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="mimikatz.exe",
        expected_command_pattern=r"privilege::debug",
        expected_detection_rule_id="RULE-ELASTIC-LSASS-02",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    rule = DetectionRuleV1(
        rule_id="RULE-ELASTIC-LSASS-02",
        rule_name="LSASS Memory Read Verified",
        rule_format="elastic",
    )
    run = TestRunV1(
        run_id="RUN-ELASTIC-02",
        scenario_id=scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-PROD-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=5),
        executed_at=t0,
        execution_token=token,
    )

    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-ELASTIC-02",
        raw_event_id="RAW-ELASTIC-02",
        source_event_id="SRC-ELASTIC-02",
        source_timestamp=t0 + timedelta(seconds=15),
        normalized_timestamp=t0 + timedelta(seconds=15),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="mimikatz.exe",
        command_line=f"mimikatz.exe privilege::debug --token {token}",
        execution_token=token,
    )

    store.add_scenario(scenario)
    store.add_rule(rule)
    store.add_run(run)
    store.add_normalized_event(norm_ev)

    # Ingest Elastic alert WITH matching execution token embedded in command_line
    raw_hit_with_token = make_modern_elastic_hit(
        hit_id="elastic-alert-with-token",
        rule_id="RULE-ELASTIC-LSASS-02",
        hostname="WS-PROD-01",
        timestamp=(t0 + timedelta(seconds=30)).isoformat(),
        token=token,
    )
    alert_with_token = map_elastic_alert(raw_hit_with_token)
    assert alert_with_token.execution_token == token
    store.add_alert(alert_with_token)

    result = engine.evaluate_run(run.run_id, strict_attribution=True)
    assert result.predicted_category == DiagnosticCategory.PASS
    assert result.metadata["attribution"]["status"] == AttributionStatus.VERIFIED.value


# ── 6. Incomplete Results & Transaction Hardening Tests ─────────────────────

def test_client_truncation_with_gte_relation(monkeypatch: pytest.MonkeyPatch):
    """Verify hits.total.relation == 'gte' is treated as incomplete even when hit count equals total."""
    settings = ElasticConnectorSettings(base_url="https://elastic.test:9200", api_key="test-key", max_results=100)
    client = ElasticAlertClient(settings)

    hit = make_modern_elastic_hit(hit_id="hit-gte-01")
    es_response = {
        "hits": {
            "total": {"value": 1, "relation": "gte"},
            "hits": [hit],
        }
    }
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, *args, **kwargs: MockHTTPResponse(200, json.dumps(es_response).encode("utf-8")),
    )

    # Retrieval of 1 hit when limit=1 and relation='gte' must NOT claim completeness
    hits = client.search_alerts(limit=1, batch_size=1)
    assert len(hits) == 1
    assert client.last_search_total == 1
    assert client.last_search_relation == "gte"
    assert client.last_search_truncated is True

    # raise_on_truncation must raise ElasticClientError citing relation 'gte'
    with pytest.raises(ElasticClientError, match="relation 'gte'"):
        client.search_alerts(limit=1, batch_size=1, raise_on_truncation=True)


def test_client_truncation_missing_or_invalid_sort(monkeypatch: pytest.MonkeyPatch):
    """Verify missing/invalid sort values in search_after pagination trigger truncation."""
    settings = ElasticConnectorSettings(base_url="https://elastic.test:9200", api_key="test-key", max_results=50)
    client = ElasticAlertClient(settings)

    # Hit lacks 'sort' field
    hit_nosort = make_modern_elastic_hit(hit_id="hit-nosort")
    hit_nosort.pop("sort", None)

    es_response = {
        "hits": {
            "total": {"value": 10},
            "hits": [hit_nosort],
        }
    }
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, *args, **kwargs: MockHTTPResponse(200, json.dumps(es_response).encode("utf-8")),
    )

    # When pagination is needed (batch_size=1, limit=5), missing sort prevents continuing
    with pytest.raises(ElasticClientError, match="missing valid 'sort' values"):
        client.search_alerts(limit=5, batch_size=1, raise_on_truncation=True)


def test_poll_and_ingest_truncation_rejects_before_ingestion(monkeypatch: pytest.MonkeyPatch):
    """Verify that truncation errors trigger before any alert is written to the store."""
    store = InMemoryStore()
    settings = ElasticConnectorSettings(base_url="https://elastic.test:9200", api_key="test-key", max_results=50)
    client = ElasticAlertClient(settings)

    hit = make_modern_elastic_hit(hit_id="hit-trunc-store")
    es_response = {
        "hits": {
            "total": {"value": 500, "relation": "eq"},
            "hits": [hit],
        }
    }
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, *args, **kwargs: MockHTTPResponse(200, json.dumps(es_response).encode("utf-8")),
    )

    with pytest.raises(ElasticClientError, match="search results truncated"):
        client.poll_and_ingest(store, limit=1, raise_on_truncation=True)

    # Store must remain completely empty (zero writes occurred)
    assert len(store.list_alerts()) == 0


def test_poll_and_ingest_atomic_rollback_vs_partial_success(monkeypatch: pytest.MonkeyPatch):
    """Verify atomic=True rolls back novel alerts on conflict, while atomic=False preserves partial success."""
    # Setup initial store with 1 pre-existing alert
    hit_existing = make_modern_elastic_hit(hit_id="hit-preexisting")
    hit_novel_1 = make_modern_elastic_hit(hit_id="hit-novel-atomic-1")
    hit_novel_2 = make_modern_elastic_hit(hit_id="hit-novel-atomic-2")

    es_response = {"hits": {"hits": [hit_novel_1, hit_existing, hit_novel_2]}}
    settings = ElasticConnectorSettings(base_url="https://elastic.test:9200", api_key="k")
    client = ElasticAlertClient(settings)

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, *args, **kwargs: MockHTTPResponse(200, json.dumps(es_response).encode("utf-8")),
    )

    # Case 1: atomic=True -> rollback on duplicate error
    store_atomic = InMemoryStore()
    store_atomic.add_alert(map_elastic_alert(hit_existing))

    with pytest.raises(ValueError, match="Duplicate alert.*elastic:hit-preexisting"):
        client.poll_and_ingest(store_atomic, skip_duplicates=False, atomic=True)

    # In atomic mode, novel alert 1 was rolled back; only preexisting remains
    assert store_atomic.get_alert("elastic:hit-novel-atomic-1") is None
    assert len(store_atomic.list_alerts()) == 1

    # Case 2: atomic=False -> partial success preserved
    store_non_atomic = InMemoryStore()
    store_non_atomic.add_alert(map_elastic_alert(hit_existing))

    with pytest.raises(ValueError, match="Duplicate alert.*elastic:hit-preexisting"):
        client.poll_and_ingest(store_non_atomic, skip_duplicates=False, atomic=False)

    # In non-atomic mode, both novel alert 1 and novel alert 2 remain committed
    assert store_non_atomic.get_alert("elastic:hit-novel-atomic-1") is not None
    assert store_non_atomic.get_alert("elastic:hit-novel-atomic-2") is not None
    assert len(store_non_atomic.list_alerts()) == 3


def test_poll_and_ingest_sqlite_store_atomic_rollback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Verify atomic=True rolls back SQLiteStore insertions on duplicate conflict."""
    db_file = tmp_path / "test_sqlite_atomic.db"
    store = SQLiteStore(db_file)

    hit_existing = make_modern_elastic_hit(hit_id="sqlite-preexisting")
    hit_novel_1 = make_modern_elastic_hit(hit_id="sqlite-novel-atomic-1")

    # Seed pre-existing alert
    store.add_alert(map_elastic_alert(hit_existing))
    assert len(store.list_alerts()) == 1

    es_response = {"hits": {"hits": [hit_novel_1, hit_existing]}}
    settings = ElasticConnectorSettings(base_url="https://elastic.test:9200", api_key="k")
    client = ElasticAlertClient(settings)

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, *args, **kwargs: MockHTTPResponse(200, json.dumps(es_response).encode("utf-8")),
    )

    with pytest.raises(ValueError, match="Duplicate alert.*sqlite-preexisting"):
        client.poll_and_ingest(store, skip_duplicates=False, atomic=True)

    # In SQLiteStore, atomic=True rolls back the transaction: novel alert must not persist
    assert store.get_alert("elastic:sqlite-novel-atomic-1") is None
    assert len(store.list_alerts()) == 1


def test_client_pagination_tied_timestamps(monkeypatch: pytest.MonkeyPatch):
    """Verify search_after handles exact timestamp collisions deterministically via _id tie-breaker."""
    # Two distinct alerts with identical @timestamp
    same_ts = "2026-10-25T14:30:00.000Z"
    same_epoch = 1792940400000

    hit_tie_1 = make_modern_elastic_hit(hit_id="hit-tie-1", timestamp=same_ts)
    hit_tie_1["sort"] = [same_epoch, "hit-tie-1"]

    hit_tie_2 = make_modern_elastic_hit(hit_id="hit-tie-2", timestamp=same_ts)
    hit_tie_2["sort"] = [same_epoch, "hit-tie-2"]

    req_bodies = []

    def mock_urlopen_tied(req, *args, **kwargs):
        body = json.loads(req.data.decode("utf-8"))
        req_bodies.append(body)
        if "search_after" not in body:
            resp_obj = {"hits": {"total": {"value": 2}, "hits": [hit_tie_1]}}
        else:
            resp_obj = {"hits": {"total": {"value": 2}, "hits": [hit_tie_2]}}
        return MockHTTPResponse(200, json.dumps(resp_obj).encode("utf-8"))

    settings = ElasticConnectorSettings(base_url="https://elastic.test:9200", api_key="k", max_results=10)
    client = ElasticAlertClient(settings)
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen_tied)

    hits = client.search_alerts(limit=2, batch_size=1)
    assert len(hits) == 2
    assert hits[0]["_id"] == "hit-tie-1"
    assert hits[1]["_id"] == "hit-tie-2"

    # Verify search_after used the tied timestamp and unique ID
    assert req_bodies[1]["search_after"] == [same_epoch, "hit-tie-1"]


def test_strict_attribution_conflicting_token_elastic_alert_is_inconclusive():
    """Verify an Elastic alert with conflicting execution tokens produces INCONCLUSIVE under strict attribution."""
    store = InMemoryStore()
    engine = AssuranceEngine(store)

    t0 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    token = "TOK-RUN-STRICT-99"

    scenario = ScenarioV1(
        scenario_id="SCN-ELASTIC-CONFLICT",
        name="LSASS Access Conflict",
        mitre_technique_id="T1003.001",
        mitre_tactic="Credential Access",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="mimikatz.exe",
        expected_command_pattern=r"privilege::debug",
        expected_detection_rule_id="RULE-ELASTIC-CONFLICT-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    rule = DetectionRuleV1(
        rule_id="RULE-ELASTIC-CONFLICT-01",
        rule_name="LSASS Memory Read Conflict",
        rule_format="elastic",
    )
    run = TestRunV1(
        run_id="RUN-ELASTIC-CONFLICT",
        scenario_id=scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-PROD-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=5),
        executed_at=t0,
        execution_token=token,
    )
    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-ELASTIC-CONF",
        raw_event_id="RAW-CONF",
        source_event_id="SRC-CONF",
        source_timestamp=t0 + timedelta(seconds=15),
        normalized_timestamp=t0 + timedelta(seconds=15),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="mimikatz.exe",
        command_line=f"mimikatz.exe privilege::debug --token {token}",
        execution_token=token,
    )
    store.add_scenario(scenario)
    store.add_rule(rule)
    store.add_run(run)
    store.add_normalized_event(norm_ev)

    # Elastic alert with internal token conflict (command_line vs labels)
    raw_hit_conflict = make_modern_elastic_hit(
        hit_id="elastic-alert-conflict",
        rule_id="RULE-ELASTIC-CONFLICT-01",
        hostname="WS-PROD-01",
        timestamp=(t0 + timedelta(seconds=30)).isoformat(),
        token="TOK-DISAGREE-1",
    )
    raw_hit_conflict["_source"]["labels"] = {"execution_token": "TOK-DISAGREE-2"}

    alert_conflict = map_elastic_alert(raw_hit_conflict)
    assert alert_conflict.execution_token == "CONFLICT"
    store.add_alert(alert_conflict)

    result = engine.evaluate_run(run.run_id, strict_attribution=True)
    assert result.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert result.predicted_category != DiagnosticCategory.PASS
    assert result.metadata["attribution"]["status"] == AttributionStatus.CONFLICT.value



