"""Comprehensive tests for Phase 19.1: Telemetry Ingestion & Persistence.

Verifies:
1. Explicit persistent ingestion persists raw and normalized telemetry.
2. Non-persistent API behavior (store=False default) remains completely backward compatible.
3. SQLite persistence survives closing and reopening the database.
4. InMemoryStore and SQLiteStore produce equivalent ingestion results.
5. Failed or partial ingestion is reported accurately with zero silent drops.
6. Downstream get_events_for_run() reliably retrieves persisted telemetry.
7. Bulk ingestion utilities (bulk_ingest_telemetry and ingest_jsonl_file_to_store)
   support atomic rollback and fault-isolated modes.
"""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import List, Optional
import pytest
from fastapi.testclient import TestClient

from proofshield.config import reset_settings
from proofshield.main import create_application
from proofshield.schemas import (
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore, close_store, get_store, reset_store
from proofshield.storage import (
    BulkIngestReport,
    bulk_ingest_telemetry,
    ingest_jsonl_file_to_store,
)


@pytest.fixture(autouse=True)
def clean_store():
    """Ensure clean store before and after each test."""
    reset_store()
    yield
    reset_store()


@pytest.fixture
def sqlite_client(tmp_path: Path):
    """Yield a TestClient configured with a temporary persistent SQLiteStore."""
    db_file = tmp_path / "telemetry_test_p19.db"
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


# ── 1. API Route Persistence & Backward Compatibility ────────────────────────

def test_raw_telemetry_backward_compatibility_store_false(test_client: TestClient):
    """Verify store=False (default) validates raw event without persisting to store."""
    payload = {
        "schema_version": "v1",
        "raw_event_id": "RAW-P19-01",
        "source_event_id": "1001",
        "source_format": "sysmon_json",
        "source_timestamp": "2026-11-01T10:00:00Z",
        "ingested_at": "2026-11-01T10:00:05Z",
        "raw_payload": {"CommandLine": "whoami.exe"},
    }
    res = test_client.post("/api/v1/telemetry/raw", json=payload)
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["raw_event_id"] == "RAW-P19-01"

    # Store must be empty
    assert get_store().get_raw_event("RAW-P19-01") is None
    assert len(get_store().list_raw_events()) == 0


def test_raw_telemetry_explicit_persistence_store_true(test_client: TestClient):
    """Verify store=True persists raw event into active store."""
    payload = {
        "schema_version": "v1",
        "raw_event_id": "RAW-P19-02",
        "source_event_id": "1002",
        "source_format": "sysmon_json",
        "source_timestamp": "2026-11-01T10:00:00Z",
        "ingested_at": "2026-11-01T10:00:05Z",
        "raw_payload": {"CommandLine": "net user /domain"},
    }
    res = test_client.post("/api/v1/telemetry/raw?store=true", json=payload)
    assert res.status_code == 200
    assert len(res.json()) == 1

    stored = get_store().get_raw_event("RAW-P19-02")
    assert stored is not None
    assert stored.raw_event_id == "RAW-P19-02"
    assert stored.source_event_id == "1002"


def test_normalize_telemetry_store_raw_and_normalized_atomically(test_client: TestClient):
    """Verify store=True with store_raw=True persists both raw and normalized telemetry atomically."""
    t0 = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    raw_payload = {
        "schema_version": "v1",
        "raw_event_id": "RAW-P19-DUAL-01",
        "source_event_id": "4688",
        "source_format": "sysmon_json",
        "source_timestamp": t0.isoformat(),
        "ingested_at": t0.isoformat(),
        "raw_payload": {
            "EventID": 1,
            "Computer": "HOST-P19",
            "UtcTime": t0.strftime("%Y-%m-%d %H:%M:%S.000"),
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        },
    }

    res = test_client.post("/api/v1/telemetry/normalize?store=true&store_raw=true", json=raw_payload)
    assert res.status_code == 200
    norm_events = res.json()
    assert len(norm_events) == 1
    norm_id = norm_events[0]["normalized_event_id"]

    # Both raw and normalized events must now exist in store
    raw_stored = get_store().get_raw_event("RAW-P19-DUAL-01")
    assert raw_stored is not None
    assert raw_stored.raw_event_id == "RAW-P19-DUAL-01"

    norm_stored = get_store().get_normalized_event(norm_id)
    assert norm_stored is not None
    assert norm_stored.raw_event_id == "RAW-P19-DUAL-01"
    assert norm_stored.host == "HOST-P19"


def test_normalized_telemetry_direct_endpoint(test_client: TestClient):
    """Verify POST /api/v1/telemetry/normalized validates and persists normalized records."""
    t0 = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    norm_payload = {
        "schema_version": "v1",
        "normalized_event_id": "NORM-P19-DIRECT-01",
        "raw_event_id": "RAW-P19-01",
        "source_event_id": "1001",
        "source_timestamp": t0.isoformat(),
        "normalized_timestamp": t0.isoformat(),
        "event_category": "PROCESS_CREATION",
        "host": "WS-SEC-01",
        "process_name": "mimikatz.exe",
        "command_line": "mimikatz.exe privilege::debug",
        "execution_token": "TOK-P19-99",
    }

    # 1. store=False (default) does not persist
    res1 = test_client.post("/api/v1/telemetry/normalized", json=norm_payload)
    assert res1.status_code == 200
    assert len(res1.json()) == 1
    assert get_store().get_normalized_event("NORM-P19-DIRECT-01") is None

    # 2. store=True persists record
    res2 = test_client.post("/api/v1/telemetry/normalized?store=true", json=norm_payload)
    assert res2.status_code == 200
    stored = get_store().get_normalized_event("NORM-P19-DIRECT-01")
    assert stored is not None
    assert stored.process_name == "mimikatz.exe"
    assert stored.execution_token == "TOK-P19-99"

    # 3. Duplicate with store=True raises HTTP 409
    res3 = test_client.post("/api/v1/telemetry/normalized?store=true", json=norm_payload)
    assert res3.status_code == 409
    assert "already exists" in res3.json()["detail"].lower()


# ── 2. Bulk Ingestion Utilities & Parity ──────────────────────────────────────

def _make_sample_raw_event(event_id: str, host: str = "WS-01", ts: Optional[datetime] = None) -> RawTelemetryEventV1:
    t = ts or datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    return RawTelemetryEventV1(
        schema_version="v1",
        raw_event_id=event_id,
        source_event_id=f"SRC-{event_id}",
        source_format="sysmon_json",
        source_timestamp=t,
        ingested_at=t,
        raw_payload={
            "EventID": 1,
            "Computer": host,
            "UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.000"),
            "Image": r"C:\Windows\System32\powershell.exe",
            "CommandLine": f"powershell.exe -Command Test-{event_id}",
        },
    )


def _make_sample_norm_event(event_id: str, raw_id: str, host: str = "WS-01", ts: Optional[datetime] = None) -> NormalizedTelemetryEventV1:
    t = ts or datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    return NormalizedTelemetryEventV1(
        schema_version="v1",
        normalized_event_id=event_id,
        raw_event_id=raw_id,
        source_event_id=f"SRC-{event_id}",
        source_timestamp=t,
        normalized_timestamp=t,
        event_category=EventCategory.PROCESS_CREATION,
        host=host,
        process_name="powershell.exe",
        command_line=f"powershell.exe -Command Test-{event_id}",
        execution_token="TOK-SAMPLE",
    )


def test_bulk_ingest_telemetry_inmemory_and_sqlite_parity(tmp_path: Path):
    """Verify bulk_ingest_telemetry works identically on InMemoryStore and SQLiteStore."""
    db_path = tmp_path / "parity_test.db"
    stores = [InMemoryStore(), SQLiteStore(db_path)]

    raw_events = [_make_sample_raw_event(f"RAW-PARITY-{i}") for i in range(5)]
    norm_events = [_make_sample_norm_event(f"NORM-PARITY-{i}", f"RAW-PARITY-{i}") for i in range(5)]

    for store in stores:
        report = bulk_ingest_telemetry(
            store=store,
            raw_events=raw_events,
            normalized_events=norm_events,
            atomic=True,
        )
        assert report.is_success is True
        assert report.persisted_raw_count == 5
        assert report.persisted_normalized_count == 5
        assert report.failed_count == 0
        assert len(report.errors) == 0

        # Verify retrieval parity
        assert len(store.list_raw_events()) == 5
        assert len(store.list_normalized_events()) == 5
        for i in range(5):
            assert store.get_raw_event(f"RAW-PARITY-{i}") is not None
            assert store.get_normalized_event(f"NORM-PARITY-{i}") is not None

    stores[1].close()


def test_sqlite_persistence_survives_close_and_reopen(tmp_path: Path):
    """Verify that records persisted into SQLiteStore persist after close and reopen."""
    db_path = tmp_path / "survives_restart.db"
    store1 = SQLiteStore(db_path)

    raw_ev = _make_sample_raw_event("RAW-PERSIST-DURABLE-01")
    norm_ev = _make_sample_norm_event("NORM-PERSIST-DURABLE-01", "RAW-PERSIST-DURABLE-01")

    rep = bulk_ingest_telemetry(store1, raw_events=[raw_ev], normalized_events=[norm_ev], atomic=True)
    assert rep.is_success is True

    # Close store
    store1.close()

    # Reopen brand new SQLiteStore on same file
    store2 = SQLiteStore(db_path)
    try:
        raw_reloaded = store2.get_raw_event("RAW-PERSIST-DURABLE-01")
        assert raw_reloaded is not None
        assert raw_reloaded.raw_event_id == "RAW-PERSIST-DURABLE-01"

        norm_reloaded = store2.get_normalized_event("NORM-PERSIST-DURABLE-01")
        assert norm_reloaded is not None
        assert norm_reloaded.normalized_event_id == "NORM-PERSIST-DURABLE-01"
        assert norm_reloaded.process_name == "powershell.exe"
    finally:
        store2.close()


def test_bulk_ingest_telemetry_with_normalize_raw():
    """Verify bulk_ingest_telemetry normalizes raw events and persists both."""
    store = InMemoryStore()
    raw_ev = _make_sample_raw_event("RAW-AUTO-NORM-01")

    rep = bulk_ingest_telemetry(store, raw_events=[raw_ev], normalize_raw=True, atomic=True)
    assert rep.is_success is True
    assert rep.persisted_raw_count == 1
    assert rep.persisted_normalized_count == 1

    stored_raw = store.get_raw_event("RAW-AUTO-NORM-01")
    assert stored_raw is not None

    stored_norm = store.list_normalized_events()
    assert len(stored_norm) == 1
    assert stored_norm[0].raw_event_id == "RAW-AUTO-NORM-01"
    assert stored_norm[0].process_name == "powershell.exe"


def test_bulk_ingest_atomic_rollback_on_duplicate():
    """Verify atomic=True aborts and persists zero records if a duplicate exists."""
    store = InMemoryStore()
    raw1 = _make_sample_raw_event("RAW-DUP-01")
    raw2 = _make_sample_raw_event("RAW-DUP-01")  # duplicate

    rep = bulk_ingest_telemetry(store, raw_events=[raw1, raw2], atomic=True)
    assert rep.is_success is False
    assert rep.persisted_raw_count == 0
    assert rep.failed_count == 2
    assert len(rep.errors) == 1
    assert "already exists" in rep.errors[0].lower()

    # Zero records in store
    assert len(store.list_raw_events()) == 0


def test_bulk_ingest_fault_isolated_mode_partial_success():
    """Verify atomic=False persists valid records while isolating duplicates."""
    store = InMemoryStore()
    raw1 = _make_sample_raw_event("RAW-ISO-01")
    store.add_raw_event(raw1)  # pre-existing

    raw2 = _make_sample_raw_event("RAW-ISO-02")
    raw_dup = _make_sample_raw_event("RAW-ISO-01")  # duplicate

    rep = bulk_ingest_telemetry(store, raw_events=[raw2, raw_dup], atomic=False)
    assert rep.is_success is False
    assert rep.persisted_raw_count == 1
    assert rep.failed_count == 1
    assert len(rep.errors) == 1
    assert "already exists" in rep.errors[0].lower()

    # Store contains original + novel one
    assert len(store.list_raw_events()) == 2
    assert store.get_raw_event("RAW-ISO-02") is not None


# ── 3. Downstream Correlation with AssuranceEngine ────────────────────────────

def test_downstream_get_events_for_run_retrieves_persisted_telemetry():
    """Verify that persisted normalized events are correctly correlated to test runs."""
    store = InMemoryStore()
    t0 = datetime(2026, 11, 1, 14, 0, tzinfo=timezone.utc)

    scenario = ScenarioV1(
        scenario_id="SCN-P19-01",
        name="Telemetry Correlation Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-P19-CORR-01",
        scenario_id=scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="SRV-CORR-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=5),
        executed_at=t0,
    )
    store.add_run(run)

    # 1. Event inside window on matching host
    ev_in = _make_sample_norm_event("NORM-IN-WINDOW", "RAW-01", host="SRV-CORR-01", ts=t0 + timedelta(minutes=2))
    # 2. Event outside window on matching host
    ev_out = _make_sample_norm_event("NORM-OUT-WINDOW", "RAW-02", host="SRV-CORR-01", ts=t0 + timedelta(minutes=15))
    # 3. Event inside window on different host
    ev_wrong_host = _make_sample_norm_event("NORM-WRONG-HOST", "RAW-03", host="SRV-OTHER", ts=t0 + timedelta(minutes=2))

    rep = bulk_ingest_telemetry(store, normalized_events=[ev_in, ev_out, ev_wrong_host], atomic=True)
    assert rep.is_success is True

    matched_events = store.get_events_for_run(run)
    assert len(matched_events) == 1
    assert matched_events[0].normalized_event_id == "NORM-IN-WINDOW"


# ── 4. File-Based JSONL Ingestion to Store ─────────────────────────────────────

def test_ingest_jsonl_file_to_store_raw_with_normalization(raw_telemetry_valid_path: Path):
    """Verify ingest_jsonl_file_to_store persists raw events and generates normalized events."""
    store = InMemoryStore()

    report = ingest_jsonl_file_to_store(
        filepath=raw_telemetry_valid_path,
        schema_cls=RawTelemetryEventV1,
        store=store,
        atomic=True,
        normalize_if_raw=True,
    )

    assert report.is_success is True
    assert report.persisted_raw_count == 4
    assert report.persisted_normalized_count == 4
    assert report.total_persisted == 8
    assert report.source_records == 4
    assert report.total_operations_attempted == 8
    assert report.total_records == 8
    assert report.failed_count == 0

    assert len(store.list_raw_events()) == 4
    assert len(store.list_normalized_events()) == 4


def test_ingest_jsonl_file_to_store_atomic_rollback_on_malformed_file(raw_telemetry_malformed_path: Path):
    """Verify atomic=True rolls back and writes zero records on malformed JSONL files."""
    store = InMemoryStore()

    report = ingest_jsonl_file_to_store(
        filepath=raw_telemetry_malformed_path,
        schema_cls=RawTelemetryEventV1,
        store=store,
        atomic=True,
    )

    assert report.is_success is False
    assert report.persisted_raw_count == 0
    assert report.failed_count > 0
    assert len(report.errors) > 0

    # Store must remain completely empty
    assert len(store.list_raw_events()) == 0


# ── 5. Phase 19.1.1 Adversarial Regression Tests ──────────────────────────────

def test_audit_finding_1_store_raw_without_store_persists_raw_only(test_client: TestClient):
    """Audit Finding 1: verify POST /telemetry/normalize?store_raw=true persists raw telemetry

    even when store=False (omitted default). Must not silently drop raw telemetry.
    """
    t0 = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    raw_payload = {
        "schema_version": "v1",
        "raw_event_id": "RAW-F1-01",
        "source_event_id": "999",
        "source_format": "sysmon_json",
        "source_timestamp": t0.isoformat(),
        "ingested_at": t0.isoformat(),
        "raw_payload": {
            "EventID": 1,
            "Computer": "HOST-F1",
            "CommandLine": "cmd.exe /c echo finding_1",
        },
    }

    # store_raw=true, store omitted (defaults to False)
    res = test_client.post("/api/v1/telemetry/normalize?store_raw=true", json=raw_payload)
    assert res.status_code == 200
    norm_events = res.json()
    assert len(norm_events) == 1
    norm_id = norm_events[0]["normalized_event_id"]

    # RAW event MUST be persisted in store
    raw_stored = get_store().get_raw_event("RAW-F1-01")
    assert raw_stored is not None
    assert raw_stored.raw_event_id == "RAW-F1-01"

    # NORMALIZED event MUST NOT be persisted because store=False
    norm_stored = get_store().get_normalized_event(norm_id)
    assert norm_stored is None


def test_normalize_telemetry_all_four_flag_combinations(test_client: TestClient):
    """Verify all four boolean combinations of (store, store_raw) on /telemetry/normalize."""
    t0 = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)

    def _make_payload(idx: int):
        return {
            "schema_version": "v1",
            "raw_event_id": f"RAW-COMBO-{idx}",
            "source_event_id": f"{1000 + idx}",
            "source_format": "sysmon_json",
            "source_timestamp": t0.isoformat(),
            "ingested_at": t0.isoformat(),
            "raw_payload": {
                "EventID": 1,
                "Computer": "HOST-COMBO",
                "CommandLine": f"test-combo-{idx}.exe",
            },
        }

    # Combo 1: store=false, store_raw=false -> neither persisted
    res1 = test_client.post("/api/v1/telemetry/normalize?store=false&store_raw=false", json=_make_payload(1))
    assert res1.status_code == 200
    norm1_id = res1.json()[0]["normalized_event_id"]
    assert get_store().get_raw_event("RAW-COMBO-1") is None
    assert get_store().get_normalized_event(norm1_id) is None

    # Combo 2: store=true, store_raw=false -> only normalized persisted
    res2 = test_client.post("/api/v1/telemetry/normalize?store=true&store_raw=false", json=_make_payload(2))
    assert res2.status_code == 200
    norm2_id = res2.json()[0]["normalized_event_id"]
    assert get_store().get_raw_event("RAW-COMBO-2") is None
    assert get_store().get_normalized_event(norm2_id) is not None

    # Combo 3: store=false, store_raw=true -> only raw persisted
    res3 = test_client.post("/api/v1/telemetry/normalize?store=false&store_raw=true", json=_make_payload(3))
    assert res3.status_code == 200
    norm3_id = res3.json()[0]["normalized_event_id"]
    assert get_store().get_raw_event("RAW-COMBO-3") is not None
    assert get_store().get_normalized_event(norm3_id) is None

    # Combo 4: store=true, store_raw=true -> both persisted atomically
    res4 = test_client.post("/api/v1/telemetry/normalize?store=true&store_raw=true", json=_make_payload(4))
    assert res4.status_code == 200
    norm4_id = res4.json()[0]["normalized_event_id"]
    assert get_store().get_raw_event("RAW-COMBO-4") is not None
    assert get_store().get_normalized_event(norm4_id) is not None


def test_audit_finding_2_accounting_parity_with_derived_normalized(raw_telemetry_valid_path: Path):
    """Audit Finding 2: verify accounting parity when normalize_if_raw=True."""
    store = InMemoryStore()
    report = ingest_jsonl_file_to_store(
        filepath=raw_telemetry_valid_path,
        schema_cls=RawTelemetryEventV1,
        store=store,
        atomic=True,
        normalize_if_raw=True,
    )

    # Invariants that must strictly hold:
    assert report.source_records == 4
    assert report.persisted_raw_count == 4
    assert report.persisted_normalized_count == 4
    assert report.total_persisted == 8
    assert report.total_operations_attempted == 8
    assert report.total_records == 8
    assert report.failed_count == 0
    assert report.total_persisted == report.total_operations_attempted
    assert report.is_success is True


def test_audit_finding_3_normalization_exception_before_persistence(monkeypatch: pytest.MonkeyPatch):
    """Audit Finding 3: verify unhandled normalisation exception produces accurate accounting."""
    store = InMemoryStore()
    raw_events = [_make_sample_raw_event("RAW-NORM-FAIL-01"), _make_sample_raw_event("RAW-NORM-FAIL-02")]

    from proofshield.normalisation.engine import NormalisationEngine

    def mock_fail(self, events):
        raise RuntimeError("Simulated normalisation engine parser crash")

    monkeypatch.setattr(NormalisationEngine, "normalize_batch", mock_fail)

    report = bulk_ingest_telemetry(store, raw_events=raw_events, normalize_raw=True, atomic=True)

    assert report.is_success is False
    assert report.source_records == 2
    assert report.total_records == 2
    assert report.total_operations_attempted == 2
    assert report.failed_count == 2
    assert report.persisted_raw_count == 0
    assert report.persisted_normalized_count == 0
    assert len(report.errors) == 1
    assert "Normalisation failure" in report.errors[0]
    assert "Simulated normalisation engine parser crash" in report.errors[0]

    # Store must have zero records
    assert len(store.list_raw_events()) == 0
    assert len(store.list_normalized_events()) == 0


def test_audit_finding_4_blank_lines_ignored_in_accounting(tmp_path: Path):
    """Audit Finding 4: verify blank lines at beginning, middle, and end do not inflate counts."""
    store = InMemoryStore()
    target_file = tmp_path / "blank_lines.jsonl"

    raw1 = _make_sample_raw_event("RAW-BLANK-01").model_dump_json()
    raw2 = _make_sample_raw_event("RAW-BLANK-02").model_dump_json()

    # File with blank lines at beginning, middle, and end
    content = f"\n   \n{raw1}\n\n   \t\n{raw2}\n\n"
    target_file.write_text(content, encoding="utf-8")

    report = ingest_jsonl_file_to_store(
        filepath=target_file,
        schema_cls=RawTelemetryEventV1,
        store=store,
        atomic=True,
        normalize_if_raw=False,
    )

    assert report.is_success is True
    assert report.physical_lines_read > 2
    assert report.blank_lines_skipped > 0
    assert report.source_records == 2
    assert report.persisted_raw_count == 2
    assert report.total_persisted == 2
    assert report.total_operations_attempted == 2
    assert report.total_records == 2
    assert report.failed_count == 0

    assert len(store.list_raw_events()) == 2
    assert store.get_raw_event("RAW-BLANK-01") is not None
    assert store.get_raw_event("RAW-BLANK-02") is not None


def test_atomic_rollback_duplicate_midway_through_batch():
    """Verify duplicate ID midway through batch rolls back all records in atomic mode."""
    store = InMemoryStore()
    raw_list = [
        _make_sample_raw_event("RAW-ATOMIC-MID-01"),
        _make_sample_raw_event("RAW-ATOMIC-MID-02"),
        _make_sample_raw_event("RAW-ATOMIC-MID-03"),
        _make_sample_raw_event("RAW-ATOMIC-MID-02"),  # Duplicate of 02
        _make_sample_raw_event("RAW-ATOMIC-MID-05"),
    ]

    report = bulk_ingest_telemetry(store, raw_events=raw_list, atomic=True)

    assert report.is_success is False
    assert report.persisted_raw_count == 0
    assert report.total_persisted == 0
    assert report.failed_count == 5
    assert len(report.errors) == 1
    assert "already exists" in report.errors[0].lower()

    # Assert actual store contents: exactly ZERO events exist
    assert len(store.list_raw_events()) == 0


def test_fault_isolated_jsonl_file_mixed_valid_corrupt_duplicate(tmp_path: Path):
    """Verify fault-isolated mode (atomic=False) persists valid records while isolating syntax errors and duplicates."""
    store = InMemoryStore()

    # Pre-populate store with an existing record to cause a duplicate conflict
    pre_existing = _make_sample_raw_event("RAW-PRE-EXISTING")
    store.add_raw_event(pre_existing)

    target_file = tmp_path / "mixed_records.jsonl"
    line_ok1 = _make_sample_raw_event("RAW-MIXED-OK-01").model_dump_json()
    line_corrupted = "{ corrupted json line !!"
    line_dup = _make_sample_raw_event("RAW-PRE-EXISTING").model_dump_json()
    line_ok2 = _make_sample_raw_event("RAW-MIXED-OK-02").model_dump_json()

    content = f"{line_ok1}\n{line_corrupted}\n{line_dup}\n{line_ok2}\n"
    target_file.write_text(content, encoding="utf-8")

    report = ingest_jsonl_file_to_store(
        filepath=target_file,
        schema_cls=RawTelemetryEventV1,
        store=store,
        atomic=False,
    )

    assert report.is_success is False
    assert report.source_records == 3  # 3 syntactically valid records read
    assert report.persisted_raw_count == 2  # OK-01 and OK-02 succeeded
    assert report.total_persisted == 2
    assert report.failed_count == 2  # 1 corrupted line + 1 duplicate conflict
    assert len(report.errors) == 2

    # Assert actual store contents: exactly 3 records (pre-existing + OK-01 + OK-02)
    assert len(store.list_raw_events()) == 3
    assert store.get_raw_event("RAW-MIXED-OK-01") is not None
    assert store.get_raw_event("RAW-MIXED-OK-02") is not None
    assert store.get_raw_event("RAW-PRE-EXISTING") is not None


def test_sqlite_durability_rollback_and_reopen_after_failure(tmp_path: Path):
    """Verify SQLiteStore transaction rollback persists zero writes across close and reopen."""
    db_file = tmp_path / "sqlite_rollback_test.db"
    store1 = SQLiteStore(db_file)

    # 1. Successfully store an initial anchor record
    anchor = _make_sample_raw_event("RAW-ANCHOR-01")
    store1.add_raw_event(anchor)

    # 2. Attempt an atomic batch with a duplicate of anchor
    batch = [
        _make_sample_raw_event("RAW-SHOULD-ROLLBACK-01"),
        _make_sample_raw_event("RAW-ANCHOR-01"),  # Duplicate conflict!
        _make_sample_raw_event("RAW-SHOULD-ROLLBACK-02"),
    ]
    report = bulk_ingest_telemetry(store1, raw_events=batch, atomic=True)
    assert report.is_success is False

    # Close store1
    store1.close()

    # 3. Reopen store2 on the same database file
    store2 = SQLiteStore(db_file)
    try:
        stored = store2.list_raw_events()
        assert len(stored) == 1
        assert stored[0].raw_event_id == "RAW-ANCHOR-01"
        assert store2.get_raw_event("RAW-SHOULD-ROLLBACK-01") is None
        assert store2.get_raw_event("RAW-SHOULD-ROLLBACK-02") is None
    finally:
        store2.close()


def test_non_telemetry_schema_jsonl_file_ingestion(scenarios_jsonl_path: Path):
    """Verify ingest_jsonl_file_to_store works cleanly with non-telemetry schemas (ScenarioV1)."""
    store = InMemoryStore()

    report = ingest_jsonl_file_to_store(
        filepath=scenarios_jsonl_path,
        schema_cls=ScenarioV1,
        store=store,
        atomic=True,
    )

    assert report.is_success is True
    assert report.persisted_other_count == 3
    assert report.total_persisted == 3
    assert report.failed_count == 0
    assert len(store.list_scenarios()) == 3
    assert store.get_scenario("SCN-T1059.001-01") is not None

