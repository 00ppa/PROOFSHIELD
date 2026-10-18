"""Tests for storage backend configuration, factory selection, and operational safety.

Verifies:
1. Default backend is InMemoryStore when no configuration is specified.
2. Explicit configuration selects SQLiteStore with configured path.
3. Invalid backend names and paths are rejected with clear, actionable ValueErrors.
4. No silent fallback to InMemoryStore when SQLite configuration or initialization fails.
5. Store singleton reuse, lifecycle cleanup, and manual override capabilities.
"""

import os
from pathlib import Path
import pytest

from proofshield.config import (
    StorageBackend,
    StorageSettings,
    get_settings,
    parse_storage_backend,
    reset_settings,
    validate_sqlite_path,
)
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import (
    InMemoryStore,
    close_store,
    get_store,
    reset_store,
    set_store,
)


@pytest.fixture(autouse=True)
def clean_storage_env_and_state():
    """Ensure clean environment and reset singleton store/settings before and after each test."""
    reset_store()
    reset_settings()
    old_backend = os.environ.pop("PROOFSHIELD_STORAGE_BACKEND", None)
    old_path = os.environ.pop("PROOFSHIELD_SQLITE_PATH", None)
    old_db_path = os.environ.pop("PROOFSHIELD_DB_PATH", None)

    yield

    reset_store()
    reset_settings()
    if old_backend is not None:
        os.environ["PROOFSHIELD_STORAGE_BACKEND"] = old_backend
    else:
        os.environ.pop("PROOFSHIELD_STORAGE_BACKEND", None)

    if old_path is not None:
        os.environ["PROOFSHIELD_SQLITE_PATH"] = old_path
    else:
        os.environ.pop("PROOFSHIELD_SQLITE_PATH", None)

    if old_db_path is not None:
        os.environ["PROOFSHIELD_DB_PATH"] = old_db_path
    else:
        os.environ.pop("PROOFSHIELD_DB_PATH", None)


def test_default_storage_backend_is_in_memory():
    """Verify that omitting configuration defaults to InMemoryStore."""
    settings = get_settings()
    assert settings.storage_backend == StorageBackend.MEMORY

    store = get_store()
    assert isinstance(store, InMemoryStore)
    assert not isinstance(store, SQLiteStore)


def test_explicit_in_memory_configurations():
    """Verify various aliases for in-memory backend are parsed correctly."""
    for alias in ["memory", "MEMORY", "in_memory", "IN-MEMORY", "  memory  "]:
        os.environ["PROOFSHIELD_STORAGE_BACKEND"] = alias
        reset_settings()
        reset_store()
        assert get_settings().storage_backend == StorageBackend.MEMORY
        assert isinstance(get_store(), InMemoryStore)


def test_explicit_sqlite_configuration(tmp_path: Path):
    """Verify configuring sqlite backend initializes SQLiteStore with the specified path."""
    db_file = tmp_path / "configured_store.db"
    os.environ["PROOFSHIELD_STORAGE_BACKEND"] = "sqlite"
    os.environ["PROOFSHIELD_SQLITE_PATH"] = str(db_file)
    reset_settings()
    reset_store()

    settings = get_settings()
    assert settings.storage_backend == StorageBackend.SQLITE
    assert settings.sqlite_path == str(db_file)

    store = get_store()
    assert isinstance(store, SQLiteStore)
    assert store.db_path == str(db_file)
    assert store.is_file_backed is True
    assert db_file.exists()


def test_reject_invalid_storage_backend_name():
    """Verify invalid backend names raise clear ValueErrors on startup."""
    invalid_backends = ["postgres", "postgresql", "mysql", "redis", "dynamodb", "invalid_backend"]
    for inv in invalid_backends:
        os.environ["PROOFSHIELD_STORAGE_BACKEND"] = inv
        reset_settings()
        reset_store()
        with pytest.raises(ValueError, match="Unsupported storage backend"):
            get_store()


def test_reject_empty_or_whitespace_sqlite_path():
    """Verify empty or whitespace SQLite path is rejected with ValueError."""
    os.environ["PROOFSHIELD_STORAGE_BACKEND"] = "sqlite"
    for empty in ["", "   ", "\t\n"]:
        os.environ["PROOFSHIELD_SQLITE_PATH"] = empty
        reset_settings()
        reset_store()
        with pytest.raises(ValueError, match="SQLite database path cannot be empty"):
            get_store()


def test_reject_sqlite_path_pointing_to_existing_directory(tmp_path: Path):
    """Verify an existing directory cannot be specified as SQLite database file."""
    existing_dir = tmp_path / "an_actual_folder"
    existing_dir.mkdir()

    os.environ["PROOFSHIELD_STORAGE_BACKEND"] = "sqlite"
    os.environ["PROOFSHIELD_SQLITE_PATH"] = str(existing_dir)
    reset_settings()
    reset_store()

    with pytest.raises(ValueError, match="SQLite database path cannot be an existing directory"):
        get_store()


def test_never_silent_fallback_on_sqlite_failure(monkeypatch):
    """Verify that failure during SQLite store initialization NEVER falls back to InMemoryStore."""
    os.environ["PROOFSHIELD_STORAGE_BACKEND"] = "sqlite"
    os.environ["PROOFSHIELD_SQLITE_PATH"] = ":memory:"
    reset_settings()
    reset_store()

    # Simulate an initialization failure (e.g., driver or OS failure)
    def fail_init(*args, **kwargs):
        raise RuntimeError("Simulated unrecoverable SQLite init failure")

    from proofshield.services import sqlite_store
    monkeypatch.setattr(sqlite_store, "SQLiteStore", fail_init)

    with pytest.raises(RuntimeError, match="Simulated unrecoverable SQLite init failure"):
        get_store()


def test_store_singleton_reuse_and_reset():
    """Verify get_store returns the same instance across multiple calls and resets properly."""
    store1 = get_store()
    store2 = get_store()
    assert store1 is store2

    reset_store()
    store3 = get_store()
    assert store3 is not store1


def test_set_store_override():
    """Verify set_store allows manual injection of store instance."""
    custom_store = InMemoryStore()
    set_store(custom_store)
    assert get_store() is custom_store


def test_close_store_idempotency(tmp_path: Path):
    """Verify close_store safely closes active SQLite store and is idempotent."""
    db_file = tmp_path / "close_test.db"
    os.environ["PROOFSHIELD_STORAGE_BACKEND"] = "sqlite"
    os.environ["PROOFSHIELD_SQLITE_PATH"] = str(db_file)
    reset_settings()
    reset_store()

    store = get_store()
    assert isinstance(store, SQLiteStore)
    assert store.is_closed is False

    close_store()
    assert store.is_closed is True

    # Repeated calls must not raise errors
    close_store()
    close_store()
