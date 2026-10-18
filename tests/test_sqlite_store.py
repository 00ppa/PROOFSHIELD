"""Unit tests for SQLite persistent storage adapter foundation (Phase 3.1).

Validates:
- StoreProtocol conformance for InMemoryStore and SQLiteStore.
- Connection lifecycle management and idempotent cleanup.
- Schema initialization across all 8 entity tables and indexes.
- Foreign-key enforcement (PRAGMA foreign_keys = ON).
- WAL mode and busy timeout on file-backed databases.
- Atomic transaction commit, rollback, and nested savepoint semantics.
- Timezone-aware timestamp serialization semantics (naive, non-UTC offsets, microseconds).
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
import pytest

from proofshield.services.base_store import StoreProtocol
from proofshield.services.store import InMemoryStore
from proofshield.services.sqlite_store import (
    SQLiteStore,
    deserialize_timestamp,
    serialize_timestamp,
    to_canonical_utc_iso,
)


def test_store_protocol_conformance():
    """Verify both InMemoryStore and SQLiteStore satisfy StoreProtocol."""
    in_mem = InMemoryStore()
    assert isinstance(in_mem, StoreProtocol)

    sqlite_mem = SQLiteStore()
    try:
        assert isinstance(sqlite_mem, StoreProtocol)
    finally:
        sqlite_mem.close()


def test_sqlite_in_memory_initialization():
    """Verify in-memory SQLite store initializes all 8 tables and indexes."""
    with SQLiteStore(":memory:") as store:
        assert store.is_closed is False
        assert store.is_file_backed is False

        cur = store.connection.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cur.fetchall()}

        expected_tables = {
            "scenarios",
            "test_runs",
            "raw_telemetry",
            "normalized_telemetry",
            "detection_rules",
            "alerts",
            "diagnostic_results",
            "ground_truths",
        }
        assert expected_tables.issubset(tables)

        # Check indexes exist
        cur.execute("SELECT name FROM sqlite_master WHERE type='index';")
        indexes = {row[0] for row in cur.fetchall()}
        expected_indexes = {
            "idx_test_runs_scenario",
            "idx_test_runs_host_window",
            "idx_normalized_telemetry_host_ts",
            "idx_alerts_rule_ts",
            "idx_alerts_host_ts",
            "idx_diagnostic_results_run",
        }
        assert expected_indexes.issubset(indexes)


def test_sqlite_file_backed_wal_and_pragmas(tmp_path: Path):
    """Verify file-backed SQLite store configures WAL mode, busy timeout, and foreign keys."""
    db_file = tmp_path / "nested" / "proofshield_test.db"
    assert not db_file.exists()

    with SQLiteStore(db_file) as store:
        assert store.is_file_backed is True
        assert db_file.exists()

        cur = store.connection.cursor()

        # WAL mode must be active on file-backed database
        cur.execute("PRAGMA journal_mode;")
        journal_mode = cur.fetchone()[0].lower()
        assert journal_mode == "wal"

        # Foreign keys must be ON
        cur.execute("PRAGMA foreign_keys;")
        foreign_keys = cur.fetchone()[0]
        assert foreign_keys == 1

        # Busy timeout must be >= 5000 ms
        cur.execute("PRAGMA busy_timeout;")
        busy_timeout = cur.fetchone()[0]
        assert busy_timeout >= 5000


def test_sqlite_foreign_key_enforcement():
    """Verify foreign key constraint rejects test_runs with nonexistent scenario_id."""
    with SQLiteStore(":memory:") as store:
        # Attempt to insert a test_run referencing a nonexistent scenario
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
            with store.transaction() as cur:
                cur.execute(
                    """
                    INSERT INTO test_runs (
                        run_id, scenario_id, execution_mode, is_synthetic,
                        target_host, target_user, window_start, window_end,
                        executed_at, execution_status, payload_json
                    ) VALUES (
                        'RUN-01', 'NONEXISTENT-SCENARIO', 'synthetic_simulation', 1,
                        'WS-01', 'secops', '2026-10-12T10:00:00Z', '2026-10-12T10:15:00Z',
                        '2026-10-12T10:00:00Z', 'COMPLETED', '{}'
                    );
                    """
                )

        # Insert valid parent scenario first
        with store.transaction() as cur:
            cur.execute(
                """
                INSERT INTO scenarios (
                    scenario_id, name, mitre_technique_id, mitre_tactic,
                    expected_event_category, validation_target, payload_json
                ) VALUES (
                    'SCN-01', 'Test Scenario', 'T1059.001', 'Execution',
                    'PROCESS_CREATION', 'EXPECTED_ALERT', '{}'
                );
                """
            )

        # Now inserting child test_run succeeds
        with store.transaction() as cur:
            cur.execute(
                """
                INSERT INTO test_runs (
                    run_id, scenario_id, execution_mode, is_synthetic,
                    target_host, target_user, window_start, window_end,
                    executed_at, execution_status, payload_json
                ) VALUES (
                    'RUN-01', 'SCN-01', 'synthetic_simulation', 1,
                    'WS-01', 'secops', '2026-10-12T10:00:00Z', '2026-10-12T10:15:00Z',
                    '2026-10-12T10:00:00Z', 'COMPLETED', '{}'
                );
                """
            )

        cur = store.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM test_runs;")
        assert cur.fetchone()[0] == 1


def test_sqlite_transaction_commit_and_rollback():
    """Verify transaction commits changes on success and rolls back on exception."""
    with SQLiteStore(":memory:") as store:
        # Successful commit
        with store.transaction() as cur:
            cur.execute(
                """
                INSERT INTO scenarios (
                    scenario_id, name, mitre_technique_id, mitre_tactic,
                    expected_event_category, validation_target, payload_json
                ) VALUES ('SCN-COMMIT', 'Commit Test', 'T1059', 'Execution', 'PROCESS_CREATION', 'EXPECTED_ALERT', '{}');
                """
            )

        cur = store.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM scenarios WHERE scenario_id='SCN-COMMIT';")
        assert cur.fetchone()[0] == 1

        # Rollback on exception
        with pytest.raises(ValueError, match="Simulated failure"):
            with store.transaction() as cur_tx:
                cur_tx.execute(
                    """
                    INSERT INTO scenarios (
                        scenario_id, name, mitre_technique_id, mitre_tactic,
                        expected_event_category, validation_target, payload_json
                    ) VALUES ('SCN-ROLLBACK', 'Rollback Test', 'T1059', 'Execution', 'PROCESS_CREATION', 'EXPECTED_ALERT', '{}');
                    """
                )
                raise ValueError("Simulated failure")

        cur_check = store.connection.cursor()
        cur_check.execute("SELECT COUNT(*) FROM scenarios WHERE scenario_id='SCN-ROLLBACK';")
        assert cur_check.fetchone()[0] == 0
        cur_check.close()


def test_sqlite_nested_transaction_savepoints():
    """Verify nested transactions use SAVEPOINTs to roll back inner block without rolling back outer block."""
    with SQLiteStore(":memory:") as store:
        with store.transaction() as cur_outer:
            cur_outer.execute(
                """
                INSERT INTO scenarios (
                    scenario_id, name, mitre_technique_id, mitre_tactic,
                    expected_event_category, validation_target, payload_json
                ) VALUES ('SCN-OUTER', 'Outer Test', 'T1059', 'Execution', 'PROCESS_CREATION', 'EXPECTED_ALERT', '{}');
                """
            )

            # Inner transaction that fails and rolls back
            try:
                with store.transaction() as cur_inner:
                    cur_inner.execute(
                        """
                        INSERT INTO scenarios (
                            scenario_id, name, mitre_technique_id, mitre_tactic,
                            expected_event_category, validation_target, payload_json
                        ) VALUES ('SCN-INNER', 'Inner Test', 'T1059', 'Execution', 'PROCESS_CREATION', 'EXPECTED_ALERT', '{}');
                        """
                    )
                    raise RuntimeError("Inner transaction error")
            except RuntimeError:
                pass  # Handled error in caller

            # Inner transaction that succeeds
            with store.transaction() as cur_inner2:
                cur_inner2.execute(
                    """
                    INSERT INTO scenarios (
                        scenario_id, name, mitre_technique_id, mitre_tactic,
                        expected_event_category, validation_target, payload_json
                    ) VALUES ('SCN-INNER2', 'Inner Test 2', 'T1059', 'Execution', 'PROCESS_CREATION', 'EXPECTED_ALERT', '{}');
                    """
                )

        cur = store.connection.cursor()
        cur.execute("SELECT scenario_id FROM scenarios ORDER BY scenario_id;")
        persisted = [row[0] for row in cur.fetchall()]
        assert persisted == ["SCN-INNER2", "SCN-OUTER"]


def test_sqlite_reset():
    """Verify reset() empties all tables respecting foreign keys."""
    with SQLiteStore(":memory:") as store:
        with store.transaction() as cur:
            cur.execute(
                """
                INSERT INTO scenarios (
                    scenario_id, name, mitre_technique_id, mitre_tactic,
                    expected_event_category, validation_target, payload_json
                ) VALUES ('SCN-RESET', 'Reset Test', 'T1059', 'Execution', 'PROCESS_CREATION', 'EXPECTED_ALERT', '{}');
                """
            )
            cur.execute(
                """
                INSERT INTO test_runs (
                    run_id, scenario_id, execution_mode, is_synthetic,
                    target_host, target_user, window_start, window_end,
                    executed_at, execution_status, payload_json
                ) VALUES (
                    'RUN-RESET', 'SCN-RESET', 'synthetic_simulation', 1,
                    'WS-01', 'secops', '2026-10-12T10:00:00Z', '2026-10-12T10:15:00Z',
                    '2026-10-12T10:00:00Z', 'COMPLETED', '{}'
                );
                """
            )

        cur = store.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM scenarios;")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT COUNT(*) FROM test_runs;")
        assert cur.fetchone()[0] == 1

        store.reset()

        cur.execute("SELECT COUNT(*) FROM scenarios;")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM test_runs;")
        assert cur.fetchone()[0] == 0


def test_sqlite_lifecycle_and_idempotent_close():
    """Verify connection closure, exception handling after close, and idempotent close."""
    store = SQLiteStore(":memory:")
    assert store.is_closed is False

    store.close()
    assert store.is_closed is True

    # Idempotent close
    store.close()
    assert store.is_closed is True

    # Operations after close must raise RuntimeError
    with pytest.raises(RuntimeError, match="connection is closed"):
        store._check_open()

    with pytest.raises(RuntimeError, match="connection is closed"):
        _ = store.connection

    with pytest.raises(RuntimeError, match="connection is closed"):
        with store.transaction():
            pass


def test_timestamp_serialization_semantics():
    """Verify preservation of naive datetimes, non-UTC timezone offsets, and microsecond precision."""
    # 1. None and empty handling
    assert serialize_timestamp(None) is None
    assert deserialize_timestamp(None) is None
    assert deserialize_timestamp("") is None
    assert deserialize_timestamp("   ") is None

    # 2. Naive datetime preserves naive status and exact microseconds
    dt_naive = datetime(2026, 10, 17, 10, 30, 45, 123456)
    serialized_naive = serialize_timestamp(dt_naive)
    assert serialized_naive == "2026-10-17T10:30:45.123456"

    deserialized_naive = deserialize_timestamp(serialized_naive)
    assert deserialized_naive == dt_naive
    assert deserialized_naive.tzinfo is None
    assert deserialized_naive.microsecond == 123456

    # 3. Timezone-aware datetime with non-UTC offset preserves offset and microseconds
    tz_ist = timezone(timedelta(hours=5, minutes=30))
    dt_ist = datetime(2026, 10, 17, 16, 0, 0, 987654, tzinfo=tz_ist)
    serialized_ist = serialize_timestamp(dt_ist)
    assert serialized_ist == "2026-10-17T16:00:00.987654+05:30"

    deserialized_ist = deserialize_timestamp(serialized_ist)
    assert deserialized_ist == dt_ist
    assert deserialized_ist.tzinfo == tz_ist
    assert deserialized_ist.hour == 16
    assert deserialized_ist.microsecond == 987654

    # 4. Standard ISO string with 'Z' suffix deserializes as UTC aware
    dt_z = deserialize_timestamp("2026-10-17T10:30:00Z")
    assert dt_z.tzinfo == timezone.utc
    assert dt_z.hour == 10
    assert dt_z == datetime(2026, 10, 17, 10, 30, 0, tzinfo=timezone.utc)

    # 5. Canonical UTC conversion for SQLite index comparison
    assert to_canonical_utc_iso(None) is None
    assert to_canonical_utc_iso(dt_naive) == "2026-10-17T10:30:45.123456+00:00"
    assert to_canonical_utc_iso(dt_ist) == "2026-10-17T10:30:00.987654+00:00"
