"""Integration tests for Phase 9B API Telemetry Persistence Bridge.

Verifies:
1. With store=false, endpoints do not persist telemetry.
2. With store=true, expected records are persisted into the active store.
3. Persisted records can be retrieved through normal service/store queries.
4. Assurance engine can evaluate persisted normalized evidence through normal store path.
5. JSONL ingest reports accurate total_lines, valid_count, error_count, stored, and persisted_count.
6. Fault-isolated partial batch import persists valid lines and records line-level StorageError for duplicates.
7. Atomic mode rolls back all insertions if any parsing or storage error occurs.
8. Duplicate IDs return HTTP 409 on raw endpoints or StorageError in JSONL streams.
9. Parity across both InMemoryStore and SQLiteStore.
10. Existing endpoints and evaluation workflows remain unaffected.
"""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from proofshield.config import reset_settings
from proofshield.main import create_application
from proofshield.schemas import (
    AlertV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
)
from proofshield.schemas.common import (
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    ValidationTarget,
)
from proofshield.services.store import close_store, get_store, reset_store


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_memory_store():
    """Ensure clean store before each test."""
    reset_store()
    yield
    reset_store()


@pytest.fixture
def sqlite_client(tmp_path: Path):
    """Yield a TestClient configured with a persistent SQLite database backend."""
    db_file = tmp_path / "telemetry_persistence_test.db"
    reset_store()
    reset_settings()
    old_backend = os.environ.get("PROOFSHIELD_STORAGE_BACKEND")
    old_path = os.environ.get("PROOFSHIELD_SQLITE_PATH")

    os.environ["PROOFSHIELD_STORAGE_BACKEND"] = "sqlite"
    os.environ["PROOFSHIELD_SQLITE_PATH"] = str(db_file)

    test_app = create_application()
    with TestClient(test_app) as client:
        yield client

    close_store()
    reset_settings()
    if old_backend is not None:
        os.environ["PROOFSHIELD_STORAGE_BACKEND"] = old_backend
    else:
        os.environ.pop("PROOFSHIELD_STORAGE_BACKEND", None)
    if old_path is not None:
        os.environ["PROOFSHIELD_SQLITE_PATH"] = old_path
    else:
        os.environ.pop("PROOFSHIELD_SQLITE_PATH", None)


# ── 1. Raw Telemetry Persistence Tests ────────────────────────────────────────

def test_raw_telemetry_store_false_default_does_not_persist(test_client: TestClient):
    """1. Verify store=False (default) validates raw event without persisting to store."""
    payload = {
        "schema_version": "v1",
        "raw_event_id": "RAW-PERSIST-01",
        "source_event_id": "101",
        "source_format": "sysmon_json",
        "source_timestamp": "2026-10-24T10:00:00Z",
        "ingested_at": "2026-10-24T10:00:05Z",
        "raw_payload": {"CommandLine": "whoami.exe"},
    }
    res = test_client.post("/api/v1/telemetry/raw", json=payload)
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["raw_event_id"] == "RAW-PERSIST-01"

    # Store must NOT contain the event
    assert len(get_store().list_raw_events()) == 0
    assert get_store().get_raw_event("RAW-PERSIST-01") is None


def test_raw_telemetry_store_true_persists_record(test_client: TestClient):
    """2. Verify store=True persists raw event and it is retrievable via get_store()."""
    payload = {
        "schema_version": "v1",
        "raw_event_id": "RAW-PERSIST-02",
        "source_event_id": "102",
        "source_format": "sysmon_json",
        "source_timestamp": "2026-10-24T10:00:00Z",
        "ingested_at": "2026-10-24T10:00:05Z",
        "raw_payload": {"CommandLine": "net user"},
    }
    res = test_client.post("/api/v1/telemetry/raw?store=true", json=payload)
    assert res.status_code == 200
    assert res.json()[0]["raw_event_id"] == "RAW-PERSIST-02"

    stored = get_store().get_raw_event("RAW-PERSIST-02")
    assert stored is not None
    assert stored.raw_event_id == "RAW-PERSIST-02"
    assert stored.source_event_id == "102"


def test_raw_telemetry_duplicate_with_store_true_returns_409(test_client: TestClient):
    """3. Verify duplicate raw event with store=True raises HTTP 409 Conflict."""
    payload = {
        "schema_version": "v1",
        "raw_event_id": "RAW-PERSIST-DUP",
        "source_event_id": "103",
        "source_format": "sysmon_json",
        "source_timestamp": "2026-10-24T10:00:00Z",
        "ingested_at": "2026-10-24T10:00:05Z",
        "raw_payload": {},
    }
    res1 = test_client.post("/api/v1/telemetry/raw?store=true", json=payload)
    assert res1.status_code == 200

    res2 = test_client.post("/api/v1/telemetry/raw?store=true", json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"].lower()


# ── 2. Normalized Telemetry Persistence Tests ─────────────────────────────────

def test_normalize_store_false_default_does_not_persist(
    test_client: TestClient, raw_telemetry_valid_path: Path
):
    """4. Verify store=False (default) normalizes events in-memory without persisting."""
    with open(raw_telemetry_valid_path, "r", encoding="utf-8") as f:
        first_line = json.loads(f.readline())

    res = test_client.post("/api/v1/telemetry/normalize", json=first_line)
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["process_name"] == "powershell.exe"

    # Store must NOT contain normalized events
    assert len(get_store().list_normalized_events()) == 0


def test_normalize_store_true_persists_canonical_event(
    test_client: TestClient, raw_telemetry_valid_path: Path
):
    """5. Verify store=True normalizes and persists canonical NormalizedTelemetryEventV1."""
    with open(raw_telemetry_valid_path, "r", encoding="utf-8") as f:
        first_line = json.loads(f.readline())

    res = test_client.post("/api/v1/telemetry/normalize?store=true", json=first_line)
    assert res.status_code == 200
    data = res.json()
    norm_id = data[0]["normalized_event_id"]

    stored = get_store().get_normalized_event(norm_id)
    assert stored is not None
    assert stored.process_name == "powershell.exe"
    assert stored.raw_event_id == first_line["raw_event_id"]


def test_normalized_telemetry_duplicate_in_jsonl_returns_storage_error(test_client: TestClient):
    """6. Verify duplicate normalized_event_id in JSONL ingestion produces StorageError."""
    norm_event = {
        "schema_version": "v1",
        "normalized_event_id": "NORM-PERSIST-DUP",
        "raw_event_id": "RAW-01",
        "source_event_id": "1",
        "source_timestamp": "2026-10-24T10:00:00Z",
        "normalized_timestamp": "2026-10-24T10:00:00Z",
        "event_category": "PROCESS_CREATION",
        "host": "HOST-01",
        "process_name": "cmd.exe",
    }
    line = json.dumps(norm_event)
    payload = {
        "schema_type": "normalized_telemetry",
        "content": f"{line}\n{line}",
        "store": True,
        "atomic": False,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["valid_count"] == 1
    assert data["error_count"] == 1
    assert data["persisted_count"] == 1
    assert data["errors"][0]["error_type"] == "StorageError"


# ── 3. JSONL Batch Ingest Persistence Tests ───────────────────────────────────

def test_jsonl_ingest_store_false_no_persistence(
    test_client: TestClient, raw_telemetry_valid_path: Path
):
    """7. Verify JSONL ingest with store=False validates records without writing to store."""
    content = raw_telemetry_valid_path.read_text(encoding="utf-8")
    payload = {
        "schema_type": "raw_telemetry",
        "content": content,
        "store": False,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["valid_count"] == 4
    assert data["stored"] is False
    assert data["persisted_count"] == 0
    assert len(get_store().list_raw_events()) == 0


def test_jsonl_ingest_store_true_persists_records(
    test_client: TestClient, raw_telemetry_valid_path: Path
):
    """8. Verify JSONL ingest with store=True validates and persists all records."""
    content = raw_telemetry_valid_path.read_text(encoding="utf-8")
    payload = {
        "schema_type": "raw_telemetry",
        "content": content,
        "store": True,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["valid_count"] == 4
    assert data["stored"] is True
    assert data["persisted_count"] == 4

    stored_events = get_store().list_raw_events()
    assert len(stored_events) == 4
    assert {e.raw_event_id for e in stored_events} == {
        "RAW-SYS-20261012-001",
        "RAW-SYS-20261012-002",
        "RAW-EDR-20261012-003",
        "RAW-EDR-20261012-004",
    }


def test_jsonl_ingest_fault_isolated_partial_failure(
    test_client: TestClient, raw_telemetry_malformed_path: Path
):
    """9. Verify fault-isolated batch import (atomic=False) saves valid lines while isolating errors."""
    content = raw_telemetry_malformed_path.read_text(encoding="utf-8")
    payload = {
        "schema_type": "raw_telemetry",
        "content": content,
        "store": True,
        "atomic": False,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is False
    assert data["valid_count"] == 2
    assert data["error_count"] == 3
    assert data["stored"] is True
    assert data["persisted_count"] == 2

    # Exactly the 2 valid records were saved into the database
    stored_events = get_store().list_raw_events()
    assert len(stored_events) == 2
    ids = {e.raw_event_id for e in stored_events}
    assert "RAW-SYS-OK-01" in ids
    assert "RAW-SYS-OK-02" in ids


def test_jsonl_ingest_duplicate_records_line_level_storage_error(test_client: TestClient):
    """10. Verify duplicate record in JSONL stream generates StorageError with accurate line number."""
    line1 = json.dumps({
        "schema_version": "v1",
        "raw_event_id": "RAW-STREAM-DUP",
        "source_event_id": "1",
        "source_format": "sysmon",
        "source_timestamp": "2026-10-24T10:00:00Z",
        "ingested_at": "2026-10-24T10:00:05Z",
        "raw_payload": {},
    })
    line2 = json.dumps({
        "schema_version": "v1",
        "raw_event_id": "RAW-STREAM-DUP",
        "source_event_id": "2",
        "source_format": "sysmon",
        "source_timestamp": "2026-10-24T10:01:00Z",
        "ingested_at": "2026-10-24T10:01:05Z",
        "raw_payload": {},
    })
    payload = {
        "schema_type": "raw_telemetry",
        "content": f"{line1}\n{line2}",
        "store": True,
        "atomic": False,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_lines"] == 2
    assert data["valid_count"] == 1
    assert data["error_count"] == 1
    assert data["persisted_count"] == 1
    assert data["stored"] is True

    # Error must indicate StorageError on line 2
    err = data["errors"][0]
    assert err["line_number"] == 2
    assert err["error_type"] == "StorageError"
    assert "already exists" in err["error_message"].lower()

    # Exactly 1 record in store
    assert len(get_store().list_raw_events()) == 1


def test_jsonl_ingest_atomic_mode_rolls_back_on_parsing_error(
    test_client: TestClient, raw_telemetry_malformed_path: Path
):
    """11. Verify atomic=True persists ZERO records if any line parsing or schema error occurs."""
    content = raw_telemetry_malformed_path.read_text(encoding="utf-8")
    payload = {
        "schema_type": "raw_telemetry",
        "content": content,
        "store": True,
        "atomic": True,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["stored"] is False
    assert data["persisted_count"] == 0
    assert len(get_store().list_raw_events()) == 0


def test_jsonl_ingest_atomic_mode_rolls_back_on_duplicate_error(test_client: TestClient):
    """12. Verify atomic=True rolls back transaction and persists ZERO records on duplicate key."""
    line1 = json.dumps({
        "schema_version": "v1",
        "raw_event_id": "RAW-ATOMIC-01",
        "source_event_id": "1",
        "source_format": "sysmon",
        "source_timestamp": "2026-10-24T10:00:00Z",
        "ingested_at": "2026-10-24T10:00:05Z",
        "raw_payload": {},
    })
    line2 = json.dumps({
        "schema_version": "v1",
        "raw_event_id": "RAW-ATOMIC-01",  # duplicate ID
        "source_event_id": "2",
        "source_format": "sysmon",
        "source_timestamp": "2026-10-24T10:01:00Z",
        "ingested_at": "2026-10-24T10:01:05Z",
        "raw_payload": {},
    })
    payload = {
        "schema_type": "raw_telemetry",
        "content": f"{line1}\n{line2}",
        "store": True,
        "atomic": True,
    }
    res = test_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["stored"] is False
    assert data["persisted_count"] == 0
    assert any("Atomic batch insertion aborted" in e["error_message"] for e in data["errors"])

    # Zero records in store due to transaction rollback
    assert len(get_store().list_raw_events()) == 0


# ── 4. End-to-End Evaluation of Persisted Evidence ───────────────────────────

def test_end_to_end_persisted_evidence_evaluated_by_assurance_engine(test_client: TestClient):
    """13. Verify persisted normalized telemetry is queried and evaluated by AssuranceEngine."""
    t0 = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)

    # 1. Register scenario
    scn_res = test_client.post(
        "/api/v1/scenarios",
        json={
            "schema_version": "v1",
            "scenario_id": "SCN-E2E-PERSIST",
            "name": "End-to-End Persistence Evaluation",
            "mitre_technique_id": "T1059.001",
            "mitre_tactic": "Execution",
            "expected_event_category": "PROCESS_CREATION",
            "expected_process_name": "cmd.exe",
            "expected_command_pattern": "whoami",
            "expected_detection_rule_id": "RULE-E2E",
            "validation_target": "EXPECTED_ALERT",
        },
    )
    assert scn_res.status_code == 200

    # 2. Register test run
    run_res = test_client.post(
        "/api/v1/runs",
        json={
            "schema_version": "v1",
            "run_id": "RUN-E2E-PERSIST",
            "scenario_id": "SCN-E2E-PERSIST",
            "execution_mode": "SYNTHETIC_SIMULATION",
            "is_synthetic": True,
            "target_host": "WS-E2E",
            "target_user": "corp\\admin",
            "window_start": t0.isoformat(),
            "window_end": (t0 + timedelta(minutes=10)).isoformat(),
            "executed_at": t0.isoformat(),
        },
    )
    assert run_res.status_code == 200

    # 3. Ingest raw telemetry and persist as normalized via API bridge
    raw_payload = {
        "schema_version": "v1",
        "raw_event_id": "RAW-E2E-01",
        "source_event_id": "4688",
        "source_format": "sysmon_json",
        "source_timestamp": (t0 + timedelta(minutes=2)).isoformat(),
        "ingested_at": (t0 + timedelta(minutes=2)).isoformat(),
        "raw_payload": {
            "EventID": 1,
            "Computer": "WS-E2E",
            "UtcTime": (t0 + timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S.000"),
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c whoami /all",
        },
    }
    norm_res = test_client.post("/api/v1/telemetry/normalize?store=true", json=raw_payload)
    assert norm_res.status_code == 200
    norm_events = norm_res.json()
    assert len(norm_events) == 1
    norm_id = norm_events[0]["normalized_event_id"]

    # 4. Ingest security alert referencing rule
    alert_res = test_client.post(
        "/api/v1/alerts",
        json={
            "schema_version": "v1",
            "alert_id": "ALT-E2E-01",
            "source_alert_id": "SRC-ALT-01",
            "source_type": "wazuh",
            "alert_timestamp": (t0 + timedelta(minutes=3)).isoformat(),
            "host_id": "WS-E2E",
            "rule_reference": "RULE-E2E",
        },
    )
    assert alert_res.status_code == 200

    # 5. Evaluate the run via diagnostic evaluation endpoint
    eval_res = test_client.post("/api/v1/evaluation/RUN-E2E-PERSIST")
    assert eval_res.status_code == 200
    result = eval_res.json()
    assert result["predicted_category"] == DiagnosticCategory.PASS.value
    assert norm_id in result["supporting_evidence_ids"]
    assert "ALT-E2E-01" in result["supporting_evidence_ids"]


# ── 5. SQLite Storage Backend Parity Tests ────────────────────────────────────

def test_sqlite_backend_raw_and_normalize_persistence(sqlite_client: TestClient):
    """14. Verify raw and normalized telemetry persistence under persistent SQLiteStore."""
    raw_payload = {
        "schema_version": "v1",
        "raw_event_id": "RAW-SQLITE-01",
        "source_event_id": "5001",
        "source_format": "sysmon_json",
        "source_timestamp": "2026-10-24T10:00:00Z",
        "ingested_at": "2026-10-24T10:00:05Z",
        "raw_payload": {
            "EventID": 1,
            "Computer": "SQLITE-HOST",
            "UtcTime": "2026-10-24 10:00:00.000",
            "Image": r"C:\Windows\System32\notepad.exe",
            "CommandLine": "notepad.exe",
        },
    }

    # Normalize with store=true
    norm_res = sqlite_client.post("/api/v1/telemetry/normalize?store=true", json=raw_payload)
    assert norm_res.status_code == 200
    norm_id = norm_res.json()[0]["normalized_event_id"]

    # Retrieve directly from active SQLite store
    stored = get_store().get_normalized_event(norm_id)
    assert stored is not None
    assert stored.process_name == "notepad.exe"
    assert stored.host == "SQLITE-HOST"


def test_sqlite_backend_jsonl_atomic_rollback(sqlite_client: TestClient):
    """15. Verify SQLite transaction rollback under atomic JSONL ingest with duplicate keys."""
    line1 = json.dumps({
        "schema_version": "v1",
        "raw_event_id": "RAW-SQLITE-ATOMIC",
        "source_event_id": "1",
        "source_format": "sysmon",
        "source_timestamp": "2026-10-24T10:00:00Z",
        "ingested_at": "2026-10-24T10:00:05Z",
        "raw_payload": {},
    })
    line2 = json.dumps({
        "schema_version": "v1",
        "raw_event_id": "RAW-SQLITE-ATOMIC",  # duplicate ID
        "source_event_id": "2",
        "source_format": "sysmon",
        "source_timestamp": "2026-10-24T10:01:00Z",
        "ingested_at": "2026-10-24T10:01:05Z",
        "raw_payload": {},
    })
    payload = {
        "schema_type": "raw_telemetry",
        "content": f"{line1}\n{line2}",
        "store": True,
        "atomic": True,
    }
    res = sqlite_client.post("/api/v1/ingest/jsonl", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["stored"] is False
    assert data["persisted_count"] == 0

    # Ensure zero records remain in SQLite
    assert len(get_store().list_raw_events()) == 0
