"""Phase 4.1 SQLite Integration Audit Regression Tests.

Validates:
1. Multi-threaded concurrent writes and reads against SQLiteStore without savepoint collisions or API misuse.
2. Concurrent FastAPI requests with SQLite backend.
3. Resource cleanup on set_store() overriding an existing store.
4. Synchronization of reset_store() with settings caching.
5. Path validation for uncreatable parent directories and URI memory databases.
"""

import concurrent.futures
import os
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from proofshield.config import (
    StorageBackend,
    get_settings,
    reset_settings,
    validate_sqlite_path,
)
from proofshield.main import create_application
from proofshield.schemas import ScenarioV1
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import (
    InMemoryStore,
    close_store,
    get_store,
    reset_store,
    set_store,
)


def _make_scenario(idx: int) -> ScenarioV1:
    return ScenarioV1(
        scenario_id=f"SCN-AUDIT-{idx:04d}",
        name=f"Audit Scenario {idx}",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category="PROCESS_CREATION",
        validation_target="EXPECTED_ALERT",
        expected_process_name="powershell.exe",
    )


def test_concurrent_multithreaded_sqlite_writes_and_reads(tmp_path: Path):
    """Verify that multiple threads concurrently writing and reading do not corrupt savepoints or cursors."""
    db_file = tmp_path / "concurrent_audit.db"
    store = SQLiteStore(db_file)

    def worker(i: int):
        scn = _make_scenario(i)
        store.add_scenario(scn)
        fetched = store.get_scenario(scn.scenario_id)
        assert fetched is not None
        assert fetched.scenario_id == scn.scenario_id
        return fetched.scenario_id

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(worker, range(40)))

        assert len(results) == 40
        assert len(store.list_scenarios()) == 40
    finally:
        store.close()


def test_concurrent_fastapi_requests_with_sqlite(tmp_path: Path, monkeypatch):
    """Verify that concurrent FastAPI API requests over SQLite succeed without savepoint errors."""
    db_file = tmp_path / "concurrent_api.db"
    monkeypatch.setenv("PROOFSHIELD_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("PROOFSHIELD_SQLITE_PATH", str(db_file))
    reset_store()

    app = create_application()
    client = TestClient(app)

    def send_request(i: int):
        payload = {
            "scenario_id": f"SCN-API-CONC-{i:03d}",
            "name": f"API Scenario {i}",
            "mitre_technique_id": "T1059.001",
            "mitre_tactic": "Execution",
            "expected_event_category": "PROCESS_CREATION",
            "validation_target": "EXPECTED_ALERT",
            "expected_process_name": "powershell.exe",
        }
        res = client.post("/api/v1/scenarios", json=payload)
        get_res = client.get(f"/api/v1/scenarios/{payload['scenario_id']}")
        return (res.status_code, get_res.status_code)

    try:
        with client:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                statuses = list(executor.map(send_request, range(25)))

        assert set(statuses) == {(200, 200)}
        assert len(get_store().list_scenarios()) == 25
    finally:
        reset_store()


def test_set_store_closes_prior_active_store(tmp_path: Path):
    """Verify that set_store closes the previous store if it was open, preventing leaks."""
    db_file = tmp_path / "prior_store.db"
    store1 = SQLiteStore(db_file)
    set_store(store1)
    assert not store1.is_closed

    store2 = InMemoryStore()
    set_store(store2)
    # store1 should be closed automatically upon being replaced
    assert store1.is_closed

    # Reset cleans up store2
    reset_store()


def test_reset_store_clears_settings_cache(monkeypatch, tmp_path: Path):
    """Verify that reset_store also invalidates the cached settings singleton."""
    monkeypatch.delenv("PROOFSHIELD_STORAGE_BACKEND", raising=False)
    reset_store()

    # Initially default in-memory
    store1 = get_store()
    assert isinstance(store1, InMemoryStore)

    # Change env to sqlite and call reset_store()
    db_file = tmp_path / "reconfigured.db"
    monkeypatch.setenv("PROOFSHIELD_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("PROOFSHIELD_SQLITE_PATH", str(db_file))
    reset_store()

    # get_store() should reflect the new env because reset_store cleared the cached settings
    store2 = get_store()
    try:
        assert isinstance(store2, SQLiteStore)
    finally:
        reset_store()


def test_validate_sqlite_path_uncreatable_parent(tmp_path: Path):
    """Verify that path validation rejects paths whose parent directory cannot be created."""
    regular_file = tmp_path / "existing_file.txt"
    regular_file.write_text("not a directory", encoding="utf-8")

    # Trying to create a file inside an existing regular file component
    invalid_path = regular_file / "uncreatable.db"
    with pytest.raises(ValueError, match="Cannot create directory"):
        validate_sqlite_path(invalid_path)


def test_uri_memory_path_support():
    """Verify that SQLite URI memory strings are permitted and initialized properly."""
    uri_path = "file:memdb_audit?mode=memory&cache=shared"
    validated = validate_sqlite_path(uri_path)
    assert validated == uri_path

    store = SQLiteStore(uri_path)
    try:
        assert not store.is_file_backed
        scn = _make_scenario(1)
        store.add_scenario(scn)
        assert store.get_scenario(scn.scenario_id) is not None
    finally:
        store.close()
