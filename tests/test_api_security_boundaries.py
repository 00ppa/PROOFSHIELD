"""Phase 15: API Security & Trust-Boundary Hardening Regression Tests.

Validates:
1. CORS trust boundaries (blocks untrusted cross-origin requests, disallows wildcard with credentials).
2. OpenAPI documentation of single-tenant architecture and unauthenticated trust boundaries.
3. Resource exhaustion & DoS protections:
   - JSONL max payload size (10 MB).
   - JSONL max lines (10,000 lines).
   - Bulk raw telemetry max batch size (5,000 items).
   - Bulk normalization max batch size (5,000 items).
   - Bulk alerts max batch size (5,000 items).
4. Deep nesting / recursion bomb protections on metadata and raw payloads (max depth 32).
5. Information disclosure prevention (sanitization of internal host filesystem paths).
6. Configuration safety (null-byte rejection in SQLite database paths).
7. Bounded query pagination and parameter limits.
8. Storage transaction atomicity on alert batch failure.
"""

from datetime import datetime, timezone
import json
import os
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from proofshield.config import validate_sqlite_path
from proofshield.main import create_application
from proofshield.schemas import (
    AlertV1,
    EventCategory,
    RawTelemetryEventV1,
    ScenarioV1,
    ValidationTarget,
)
from proofshield.services.store import InMemoryStore, get_store, reset_store


# ── 1. CORS Security & Trust Boundary Tests ────────────────────────────────────


def test_cors_rejects_untrusted_cross_origin():
    """Untrusted web origins must NOT receive Access-Control-Allow-Origin headers."""
    app = create_application()
    client = TestClient(app)

    # Request from an untrusted web origin
    resp = client.get(
        "/api/v1/health",
        headers={"Origin": "https://malicious-attacker.com"},
    )
    assert resp.status_code == 200
    # Starlette CORSMiddleware must not reflect untrusted origin
    assert "access-control-allow-origin" not in resp.headers


def test_cors_allows_configured_local_origin():
    """Permitted local origins receive Access-Control-Allow-Origin with credentials."""
    app = create_application()
    client = TestClient(app)

    resp = client.get(
        "/api/v1/health",
        headers={"Origin": "http://localhost:3000"},
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert resp.headers.get("access-control-allow-credentials") == "true"


def test_cors_wildcard_disables_credentials(monkeypatch):
    """When wildcard CORS origin is explicitly configured, credentials MUST be disabled."""
    monkeypatch.setenv("PROOFSHIELD_CORS_ORIGINS", "*")
    app = create_application()
    client = TestClient(app)

    resp = client.get(
        "/api/v1/health",
        headers={"Origin": "https://example.com"},
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "*"
    # Must NOT permit credentials with wildcard per CORS specification
    assert resp.headers.get("access-control-allow-credentials") != "true"


def test_openapi_documents_single_tenant_and_unauthenticated_trust_boundary():
    """OpenAPI schema must explicitly document the absence of internal auth and single-tenant scope."""
    app = create_application()
    client = TestClient(app)

    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    data = resp.json()
    desc = data.get("info", {}).get("description", "")

    assert "Single-Tenant Architecture" in desc
    assert "Authentication Boundary" in desc
    assert "Ingestion Limits" in desc


# ── 2. Resource Exhaustion & Denial-of-Service Limits ──────────────────────────


def test_jsonl_content_oversized_rejected():
    """A JSONL payload exceeding MAX_JSONL_CONTENT_BYTES (10MB) must be rejected with HTTP 422."""
    app = create_application()
    client = TestClient(app)

    # Exceed 10MB limit (10MB + 1KB)
    huge_content = " " * (10 * 1024 * 1024 + 1024)
    resp = client.post(
        "/api/v1/ingest/jsonl",
        json={"schema_type": "scenario", "content": huge_content},
    )
    assert resp.status_code == 422
    assert "content" in str(resp.json())


def test_jsonl_content_oversized_in_bytes_with_multibyte_characters():
    """Verify that multi-byte UTF-8 payloads exceeding 10 MB in bytes are rejected
    even if their character count is well below 10,000,000.
    """
    app = create_application()
    client = TestClient(app)

    # 3,000,000 4-byte characters = 12,000,000 bytes (11.44 MB), character count is only 3,000,000
    multibyte_huge = "🔥" * (3 * 1024 * 1024)
    resp = client.post(
        "/api/v1/ingest/jsonl",
        json={"schema_type": "scenario", "content": multibyte_huge},
    )
    assert resp.status_code == 422
    body = str(resp.json())
    assert "exceeds maximum limit of 10485760 bytes" in body


def test_jsonl_line_count_exceeded_rejected():
    """A JSONL stream exceeding MAX_JSONL_LINES (10,000 lines) must be rejected with HTTP 413."""
    app = create_application()
    client = TestClient(app)

    # 10,001 lines
    lines = ["{}\n"] * 10_001
    content = "".join(lines)
    resp = client.post(
        "/api/v1/ingest/jsonl",
        json={"schema_type": "scenario", "content": content},
    )
    assert resp.status_code == 413
    assert "exceeds maximum batch limit of 10000 lines" in resp.json()["detail"]


def test_raw_telemetry_batch_size_exceeded_rejected():
    """A batch of raw telemetry events exceeding MAX_BATCH_RECORDS (5,000) must be rejected with HTTP 413."""
    app = create_application()
    client = TestClient(app)

    # 5,001 dummy events
    now_iso = datetime.now(timezone.utc).isoformat()
    dummy_event = {
        "raw_event_id": "RAW-001",
        "source_event_id": "SRC-001",
        "source_format": "sysmon",
        "source_timestamp": now_iso,
        "ingested_at": now_iso,
        "raw_payload": {"EventID": 1},
    }
    oversized_batch = [dummy_event] * 5_001

    resp = client.post("/api/v1/telemetry/raw", json=oversized_batch)
    assert resp.status_code == 413
    assert "exceeds maximum limit of 5000 events" in resp.json()["detail"]


def test_normalize_telemetry_batch_size_exceeded_rejected():
    """A batch for normalization exceeding MAX_BATCH_RECORDS (5,000) must be rejected with HTTP 413."""
    app = create_application()
    client = TestClient(app)

    now_iso = datetime.now(timezone.utc).isoformat()
    dummy_event = {
        "raw_event_id": "RAW-001",
        "source_event_id": "SRC-001",
        "source_format": "sysmon",
        "source_timestamp": now_iso,
        "ingested_at": now_iso,
        "raw_payload": {"EventID": 1},
    }
    oversized_batch = [dummy_event] * 5_001

    resp = client.post("/api/v1/telemetry/normalize", json=oversized_batch)
    assert resp.status_code == 413
    assert "exceeds maximum limit of 5000 events" in resp.json()["detail"]


def test_alerts_batch_size_exceeded_rejected():
    """A batch of alerts exceeding MAX_ALERT_BATCH_SIZE (5,000) must be rejected with HTTP 413."""
    app = create_application()
    client = TestClient(app)

    dummy_alert = {
        "alert_id": "ALT-001",
        "source_alert_id": "SRC-A01",
        "source_type": "sigma",
        "host_id": "WS-01",
    }
    oversized_batch = [dummy_alert] * 5_001

    resp = client.post("/api/v1/alerts", json=oversized_batch)
    assert resp.status_code == 413
    assert "exceeds maximum limit of 5000 alerts" in resp.json()["detail"]


# ── 3. Nesting Depth / Recursion Bomb Protections ──────────────────────────────


def test_alert_deeply_nested_metadata_rejected():
    """Deeply nested metadata in AlertV1 (>32 levels) must be rejected by Pydantic validation."""
    nested = {"val": "leaf"}
    for _ in range(35):
        nested = {"level": nested}

    with pytest.raises(ValidationError) as exc_info:
        AlertV1(
            alert_id="ALT-NEST-01",
            source_alert_id="SRC-N1",
            source_type="sigma",
            host_id="WS-01",
            metadata=nested,
        )
    assert "nesting depth exceeds maximum allowed limit of 32" in str(exc_info.value)


def test_raw_telemetry_deeply_nested_payload_rejected():
    """Deeply nested raw_payload in RawTelemetryEventV1 (>32 levels) must be rejected."""
    nested = {"val": "leaf"}
    for _ in range(35):
        nested = {"level": nested}

    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError) as exc_info:
        RawTelemetryEventV1(
            raw_event_id="RAW-NEST-01",
            source_event_id="SRC-N1",
            source_format="sysmon",
            source_timestamp=now,
            ingested_at=now,
            raw_payload=nested,
        )
    assert "nesting depth exceeds maximum allowed limit of 32" in str(exc_info.value)


def test_safe_nested_metadata_accepted():
    """Reasonably nested structures (<=32 levels) must be accepted normally."""
    nested = {"val": "leaf"}
    for _ in range(5):
        nested = {"level": nested}

    alert = AlertV1(
        alert_id="ALT-SAFE-01",
        source_alert_id="SRC-S1",
        source_type="sigma",
        host_id="WS-01",
        metadata=nested,
    )
    assert alert.metadata["level"]["level"]["level"]["level"]["level"]["val"] == "leaf"


# ── 4. Information Disclosure & Path Sanitization ──────────────────────────────


def test_jsonl_storage_error_sanitizes_absolute_filesystem_paths():
    """Internal server filesystem paths must be redacted in client-facing storage error messages."""
    reset_store()
    app = create_application()
    client = TestClient(app)
    store = get_store()
    store.reset()

    # Pre-populate scenario
    store.add_scenario(
        ScenarioV1(
            scenario_id="SCN-EXISTING",
            name="Existing Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
    )

    # Attempt to ingest duplicate scenario in atomic mode
    rec = '{"scenario_id": "SCN-EXISTING", "name": "Dup", "mitre_technique_id": "T1059.001", "mitre_tactic": "Execution", "expected_event_category": "PROCESS_CREATION", "validation_target": "EXPECTED_ALERT"}'
    resp = client.post(
        "/api/v1/ingest/jsonl",
        json={"schema_type": "scenario", "content": rec, "store": True, "atomic": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["stored"] is False
    assert len(data["errors"]) == 1
    err_msg = data["errors"][0]["error_message"]
    # Verify no raw Windows or UNIX paths are exposed
    assert not any(p in err_msg for p in ("D:\\", "C:\\", "/var/", "/home/"))


# ── 5. Configuration Safety ───────────────────────────────────────────────────


def test_sqlite_path_rejects_null_bytes():
    """SQLite paths containing null bytes must be rejected immediately."""
    with pytest.raises(ValueError, match="SQLite database path cannot contain null bytes"):
        validate_sqlite_path("proofshield.db\0evil.db")


# ── 6. Query Pagination & Result Bounds ────────────────────────────────────────


def test_list_endpoints_support_bounded_pagination():
    """List endpoints must support limit and offset parameters."""
    reset_store()
    app = create_application()
    client = TestClient(app)
    store = get_store()
    store.reset()

    for i in range(5):
        store.add_scenario(
            ScenarioV1(
                scenario_id=f"SCN-PAG-{i:02d}",
                name=f"Scenario {i}",
                mitre_technique_id="T1059.001",
                mitre_tactic="Execution",
                expected_event_category=EventCategory.PROCESS_CREATION,
                validation_target=ValidationTarget.EXPECTED_ALERT,
            )
        )

    # Page 1: limit 2, offset 0
    resp1 = client.get("/api/v1/scenarios?limit=2&offset=0")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert len(data1) == 2
    assert data1[0]["scenario_id"] == "SCN-PAG-00"
    assert data1[1]["scenario_id"] == "SCN-PAG-01"

    # Page 2: limit 2, offset 2
    resp2 = client.get("/api/v1/scenarios?limit=2&offset=2")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2) == 2
    assert data2[0]["scenario_id"] == "SCN-PAG-02"
    assert data2[1]["scenario_id"] == "SCN-PAG-03"


def test_list_endpoints_reject_excessive_limit():
    """Querying list endpoints with an unconstrained limit (>1000) must return HTTP 422."""
    app = create_application()
    client = TestClient(app)

    resp = client.get("/api/v1/scenarios?limit=5000")
    assert resp.status_code == 422


# ── 7. Atomic Rollback in Bulk Alerts ──────────────────────────────────────────


def test_bulk_alerts_atomic_rollback():
    """When one alert in a bulk batch conflicts, the entire batch must roll back atomically."""
    reset_store()
    app = create_application()
    client = TestClient(app)
    store = get_store()
    store.reset()

    # Pre-add alert 1
    store.add_alert(
        AlertV1(
            alert_id="ALT-BATCH-01",
            source_alert_id="SRC-A1",
            source_type="sigma",
            host_id="WS-01",
        )
    )

    # Ingest batch of 2 alerts: ALT-BATCH-NEW and duplicate ALT-BATCH-01
    batch = [
        {
            "alert_id": "ALT-BATCH-NEW",
            "source_alert_id": "SRC-ANEW",
            "source_type": "sigma",
            "host_id": "WS-01",
        },
        {
            "alert_id": "ALT-BATCH-01",
            "source_alert_id": "SRC-A1-DUP",
            "source_type": "sigma",
            "host_id": "WS-01",
        },
    ]

    resp = client.post("/api/v1/alerts", json=batch)
    assert resp.status_code == 409

    # Verify ALT-BATCH-NEW was rolled back and is not in store
    assert store.get_alert("ALT-BATCH-NEW") is None
