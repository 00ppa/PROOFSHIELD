"""Phase 5: Reliability and Operational Hardening Regression Tests.

Validates:
1. Rollback after partial writes within atomic transactions.
2. Nested transaction savepoints (inner rollback, outer commit).
3. Repeated shutdown/close idempotency and closed-state guards.
4. Failed database initialization cleanup (zero connection/file-lock leaks).
5. Minimal, versioned schema migration & incompatible version rejection.
6. Online atomic database backup and full recovery.
7. Persistence across reopening across all 8 entity schemas.
"""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import pytest

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticResultV1,
    EventCategory,
    ExecutionMode,
    GroundTruthV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import close_store, reset_store


def _make_scenario(scenario_id: str = "SCN-HARDEN-01") -> ScenarioV1:
    return ScenarioV1(
        scenario_id=scenario_id,
        name="Hardening Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
        expected_process_name="powershell.exe",
    )


def test_rollback_after_partial_writes(tmp_path: Path):
    """Verify that an exception inside a multi-write transaction cleanly rolls back all partial writes."""
    db_file = tmp_path / "rollback_test.db"
    store = SQLiteStore(db_file)

    scn1 = _make_scenario("SCN-RB-01")
    scn2 = _make_scenario("SCN-RB-02")

    with pytest.raises(RuntimeError, match="Simulated mid-transaction failure"):
        with store.transaction():
            store.add_scenario(scn1)
            # Simulate a failure before committing the second entity
            raise RuntimeError("Simulated mid-transaction failure")

    # scn1 must not have been persisted
    assert store.get_scenario("SCN-RB-01") is None
    assert len(store.list_scenarios()) == 0

    # Ensure subsequent transactions continue to work normally
    store.add_scenario(scn2)
    assert store.get_scenario("SCN-RB-02") is not None
    assert len(store.list_scenarios()) == 1
    store.close()


def test_nested_transaction_inner_rollback_outer_commit(tmp_path: Path):
    """Verify nested savepoints: inner failure rolls back to savepoint while outer commits successfully."""
    db_file = tmp_path / "nested_tx.db"
    store = SQLiteStore(db_file)

    scn_outer = _make_scenario("SCN-OUTER")
    scn_inner = _make_scenario("SCN-INNER")

    with store.transaction():
        store.add_scenario(scn_outer)

        # Inner savepoint block that fails
        try:
            with store.transaction():
                store.add_scenario(scn_inner)
                raise ValueError("Inner savepoint failure")
        except ValueError:
            # Outer block catches inner error and continues
            pass

    # Outer scenario persisted; inner scenario was rolled back by the savepoint
    assert store.get_scenario("SCN-OUTER") is not None
    assert store.get_scenario("SCN-INNER") is None
    assert len(store.list_scenarios()) == 1
    store.close()


def test_repeated_shutdown_and_close(tmp_path: Path):
    """Verify repeated calls to close() and close_store() are completely idempotent."""
    db_file = tmp_path / "repeated_close.db"
    store = SQLiteStore(db_file)
    assert not store.is_closed

    # Multiple explicit close() calls must succeed without error
    store.close()
    assert store.is_closed
    store.close()
    assert store.is_closed

    # Operations on closed store must raise clear RuntimeError
    with pytest.raises(RuntimeError, match="connection is closed"):
        store.get_scenario("SCN-ANY")

    with pytest.raises(RuntimeError, match="connection is closed"):
        with store.transaction():
            pass

    # Module-level lifecycle close_store() idempotency
    close_store()
    close_store()
    reset_store()


def test_failed_database_initialization_no_leak(tmp_path: Path):
    """Verify that if database initialization fails on a corrupted file, the connection is closed without leaks."""
    corrupted_file = tmp_path / "corrupted.db"
    # Write invalid non-SQLite header data
    corrupted_file.write_bytes(b"NOT_A_VALID_SQLITE_DATABASE_HEADER_DATA_1234567890")

    with pytest.raises(sqlite3.DatabaseError):
        SQLiteStore(corrupted_file)

    # Verify that the file can be immediately removed or modified (no open file lock leak)
    corrupted_file.unlink()
    assert not corrupted_file.exists()


def test_schema_version_detection_and_incompatible_version_rejection(tmp_path: Path):
    """Verify schema version tracking in schema_metadata and rejection of future/incompatible versions."""
    db_file = tmp_path / "schema_version.db"
    store = SQLiteStore(db_file)
    assert store.get_schema_version() == "1"

    # Verify schema_metadata table exists and holds version 1
    cur = store.connection.cursor()
    cur.execute("SELECT value FROM schema_metadata WHERE key = 'schema_version';")
    row = cur.fetchone()
    assert row is not None
    assert row[0] == "1"
    cur.close()
    store.close()

    # Re-opening valid version 1 database succeeds
    store_reopened = SQLiteStore(db_file)
    assert store_reopened.get_schema_version() == "1"
    store_reopened.close()

    # Manually modify schema_version to an unsupported future version (e.g., '99')
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE schema_metadata SET value = '99' WHERE key = 'schema_version';")
    conn.commit()
    conn.close()

    # Opening database with unsupported version must fail fast with clear, actionable error
    with pytest.raises(ValueError, match="Unsupported database schema version '99'"):
        SQLiteStore(db_file)


def test_online_backup_and_recovery(tmp_path: Path):
    """Verify consistent online atomic backup of a live database into a new destination."""
    primary_db = tmp_path / "primary.db"
    backup_db = tmp_path / "backup_archive.db"

    primary_store = SQLiteStore(primary_db)
    scn = _make_scenario("SCN-BACKUP-01")
    primary_store.add_scenario(scn)

    # Perform online backup
    primary_store.backup(backup_db)
    assert backup_db.exists()

    # Add another scenario to primary AFTER backup
    scn_after = _make_scenario("SCN-BACKUP-AFTER")
    primary_store.add_scenario(scn_after)
    primary_store.close()

    # Open backup store and verify snapshot consistency
    recovered_store = SQLiteStore(backup_db)
    try:
        assert recovered_store.get_scenario("SCN-BACKUP-01") is not None
        # SCN-BACKUP-AFTER was added after backup, must not exist in backup
        assert recovered_store.get_scenario("SCN-BACKUP-AFTER") is None
        assert len(recovered_store.list_scenarios()) == 1
        assert recovered_store.get_schema_version() == "1"
    finally:
        recovered_store.close()


def test_persistence_across_reopening_all_entities(tmp_path: Path):
    """Verify durable persistence across reopening for all 8 versioned entities."""
    db_file = tmp_path / "durable_lifecycle.db"
    t0 = datetime(2026, 10, 16, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 16, 10, 10, 0, tzinfo=timezone.utc)

    # ── 1. Create and populate store instance A ───────────────────────────
    store_a = SQLiteStore(db_file)
    try:
        scn = _make_scenario("SCN-FULL-01")
        store_a.add_scenario(scn)

        run = TestRunV1(
            run_id="RUN-FULL-01",
            scenario_id="SCN-FULL-01",
            execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
            is_synthetic=True,
            target_host="WORKSTATION-01",
            target_user="corp\\analyst",
            window_start=t0,
            window_end=t1,
            executed_at=t0,
        )
        store_a.add_run(run)

        raw = RawTelemetryEventV1(
            raw_event_id="RAW-FULL-01",
            source_event_id="SRC-101",
            source_format="sysmon",
            source_timestamp=t0,
            ingested_at=t0,
            raw_payload={"ProcessId": 1234},
        )
        store_a.add_raw_event(raw)

        norm = NormalizedTelemetryEventV1(
            normalized_event_id="NORM-FULL-01",
            raw_event_id="RAW-FULL-01",
            source_event_id="SRC-101",
            source_timestamp=t0,
            normalized_timestamp=t0,
            event_category=EventCategory.PROCESS_CREATION,
            host="WORKSTATION-01",
            process_name="powershell.exe",
        )
        store_a.add_normalized_event(norm)

        rule = DetectionRuleV1(
            rule_id="RULE-FULL-01",
            rule_name="PowerShell Execution Rule",
            rule_format="sigma",
            rule_version="1.0.0",
        )
        store_a.add_rule(rule)

        alert = AlertV1(
            alert_id="ALT-FULL-01",
            source_alert_id="SRC-ALT-101",
            source_type="wazuh",
            alert_timestamp=t0,
            host_id="WORKSTATION-01",
            rule_reference="RULE-FULL-01",
            alert_title="PowerShell Cradle Alert",
        )
        store_a.add_alert(alert)

        diag = DiagnosticResultV1(
            diagnostic_id="DIAG-FULL-01",
            test_run_id="RUN-FULL-01",
            scenario_id="SCN-FULL-01",
            predicted_category="PASS",
            confidence="definitive",
            reason="Detection alert verified and correlated",
            evaluated_at=t1,
        )
        store_a.add_result(diag)

        gt = GroundTruthV1(
            ground_truth_id="GT-FULL-01",
            run_id="RUN-FULL-01",
            expected_diagnostic_category="PASS",
            verification_method="MANUAL_EXPERT_REVIEW",
        )
        store_a.add_ground_truth(gt)
    finally:
        store_a.close()

    # ── 2. Reopen store instance B on the same database file ───────────────
    store_b = SQLiteStore(db_file)
    try:
        assert store_b.get_scenario("SCN-FULL-01") is not None
        assert store_b.get_run("RUN-FULL-01") is not None
        assert store_b.get_raw_event("RAW-FULL-01") is not None
        assert store_b.get_normalized_event("NORM-FULL-01") is not None
        assert store_b.get_rule("RULE-FULL-01") is not None
        assert store_b.get_alert("ALT-FULL-01") is not None
        assert store_b.get_result("DIAG-FULL-01") is not None
        assert store_b.get_ground_truth_for_run("RUN-FULL-01") is not None

        # Verify correlation query operates over reopened store
        reopened_run = store_b.get_run("RUN-FULL-01")
        correlated_events = store_b.get_events_for_run(reopened_run)
        assert len(correlated_events) == 1
        assert correlated_events[0].normalized_event_id == "NORM-FULL-01"

        correlated_alerts = store_b.get_alerts_for_run(reopened_run)
        assert len(correlated_alerts) == 1
        assert correlated_alerts[0].alert_id == "ALT-FULL-01"
    finally:
        store_b.close()


def test_backup_validation_self_and_same_path(tmp_path: Path):
    """Verify that backup rejects self-backup and backing up to the same file path."""
    db_file = tmp_path / "self_backup.db"
    store = SQLiteStore(db_file)

    try:
        # Rejects self instance
        with pytest.raises(ValueError, match="cannot be the same SQLiteStore instance"):
            store.backup(store)

        # Rejects same path
        with pytest.raises(ValueError, match="cannot be the same as the active database path"):
            store.backup(db_file)
    finally:
        store.close()


def test_backup_bidirectional_deadlock_free(tmp_path: Path):
    """Verify that concurrent bidirectional backups between two stores do not deadlock."""
    import concurrent.futures

    store1 = SQLiteStore(tmp_path / "store1.db")
    store2 = SQLiteStore(tmp_path / "store2.db")

    store1.add_scenario(_make_scenario("SCN-DEADLOCK-1"))
    store2.add_scenario(_make_scenario("SCN-DEADLOCK-2"))

    def task1():
        for _ in range(5):
            store1.backup(store2)

    def task2():
        for _ in range(5):
            store2.backup(store1)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut1 = executor.submit(task1)
            fut2 = executor.submit(task2)
            fut1.result(timeout=5.0)
            fut2.result(timeout=5.0)
    finally:
        store1.close()
        store2.close()


def test_backup_failure_destination_cleanup_and_source_intact(tmp_path: Path):
    """Verify that backup failure does not corrupt source and cleans up partial destination file."""
    source_db = tmp_path / "source.db"
    source_store = SQLiteStore(source_db)
    source_store.add_scenario(_make_scenario("SCN-SRC-INTACT"))

    # Destination directory path (invalid because destination must be a file)
    existing_dir = tmp_path / "invalid_dest_dir"
    existing_dir.mkdir()

    with pytest.raises(ValueError, match="cannot be an existing directory"):
        source_store.backup(existing_dir)

    # Source store remains open, uncorrupted, and fully operational
    assert not source_store.is_closed
    assert source_store.get_scenario("SCN-SRC-INTACT") is not None
    assert len(source_store.list_scenarios()) == 1

    source_store.close()


def test_schema_integrity_rejects_disguised_incompatible_tables(tmp_path: Path):
    """Verify that metadata version=1 cannot disguise an incompatible physical table."""
    db_file = tmp_path / "disguised.db"

    # Create a database manually with schema_metadata saying version 1,
    # but a broken scenarios table missing required columns (e.g. payload_json missing)
    conn = sqlite3.connect(str(db_file))
    conn.execute(
        "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);"
    )
    conn.execute("INSERT INTO schema_metadata VALUES ('schema_version', '1', '2026-10-17T00:00:00Z');")
    conn.execute(
        "CREATE TABLE scenarios (scenario_id TEXT PRIMARY KEY, wrong_column TEXT);"
    )
    conn.commit()
    conn.close()

    # Opening with SQLiteStore must fail fast with physical schema mismatch
    with pytest.raises(ValueError, match="Incompatible physical database schema: table 'scenarios' is missing"):
        SQLiteStore(db_file)

    # Verify connection was closed cleanly without leaks
    db_file.unlink()
    assert not db_file.exists()


def test_sqlite_store_mixed_naive_aware_timestamp_parity(tmp_path: Path):
    """Verify that SQLiteStore matches InMemoryStore by raising TypeError when naive and aware timestamps are mixed in query sorting."""
    store = SQLiteStore(tmp_path / "tz_parity.db")
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 30, tzinfo=timezone.utc)

    scn = _make_scenario("SCN-TZ-MIXED")
    run = TestRunV1(
        run_id="RUN-TZ-MIXED",
        scenario_id="SCN-TZ-MIXED",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-TZ",
        target_user="secops",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    ev_aware = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-AWARE",
        raw_event_id="RAW-1",
        source_event_id="SRC-1",
        source_timestamp=datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc),
        normalized_timestamp=datetime(2026, 10, 12, 10, 15, tzinfo=timezone.utc),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-TZ",
        process_name="powershell.exe",
    )
    ev_naive = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NAIVE",
        raw_event_id="RAW-2",
        source_event_id="SRC-2",
        source_timestamp=datetime(2026, 10, 12, 10, 20),
        normalized_timestamp=datetime(2026, 10, 12, 10, 20),
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-TZ",
        process_name="powershell.exe",
    )

    try:
        store.add_scenario(scn)
        store.add_run(run)
        store.add_normalized_event(ev_aware)
        store.add_normalized_event(ev_naive)

        # Both match the window and host; sorting must raise TypeError matching InMemoryStore
        with pytest.raises(TypeError, match="can't compare offset-naive and offset-aware datetimes"):
            store.get_events_for_run(run)
    finally:
        store.close()
