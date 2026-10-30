"""SQLite persistent storage adapter for PROOFSHIELD entities.

Architecture Layer 2 — persistent storage foundation providing:
- Connection lifecycle management (:memory: and file-backed databases).
- WAL journal mode for file-backed instances and busy timeout for concurrent access.
- Foreign key enforcement (PRAGMA foreign_keys = ON).
- Explicit transaction management (atomic commit / rollback with savepoint nesting).
- Schema initialization and parameterized CRUD for all 8 versioned entities.
- Preservation of timestamp serialization semantics (naive, non-UTC, and microseconds).
- Spatio-temporal and token correlation queries matching InMemoryStore semantics.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

from proofshield.config import validate_sqlite_path
from proofshield.normalisation.engine import extract_execution_token
from proofshield.schemas.alert import AlertV1
from proofshield.schemas.assurance_report import CampaignAssuranceReportV1
from proofshield.schemas.campaign import CampaignDefinitionV1, CampaignRunV1
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1, RawTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.store import hosts_match


def serialize_timestamp(ts: Optional[datetime]) -> Optional[str]:
    """Serialize datetime to ISO 8601 string preserving original timezone or naive status.

    Preserves naive datetimes as naive ISO strings (e.g. 2026-10-17T10:30:00.123456),
    timezone-aware datetimes with their original offset (e.g. 2026-10-17T16:00:00.123456+05:30),
    and microsecond precision without loss.
    """
    if ts is None:
        return None
    return ts.isoformat()


def deserialize_timestamp(val: Optional[str]) -> Optional[datetime]:
    """Deserialize ISO 8601 string preserving original timezone or naive status.

    Returns:
        - None if val is None or empty.
        - Naive datetime if val contains no timezone offset.
        - Timezone-aware datetime with original offset if val contains an offset or 'Z'.
    """
    if val is None or not val.strip():
        return None
    return datetime.fromisoformat(val)


def to_canonical_utc_iso(ts: Optional[datetime]) -> Optional[str]:
    """Convert datetime to canonical UTC ISO 8601 string for relational index comparison.

    Ensures consistent lexicographical string ordering in SQLite queries.
    If ts is naive, treats it as UTC for indexing comparison.
    """
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)
    return ts.isoformat()


def _is_in_window(ts: Optional[datetime], w_start: datetime, w_end: datetime) -> bool:
    """Check if timestamp falls within [w_start, w_end] accounting for timezone differences.

    Matches InMemoryStore and AssuranceEngine semantics exactly:
    - If ts is aware and window is naive, window is aligned to ts.tzinfo.
    - If ts is naive and window is aware, ts is aligned to window.tzinfo.
    """
    if ts is None:
        return False
    if ts.tzinfo is not None and w_start.tzinfo is None:
        w_start = w_start.replace(tzinfo=ts.tzinfo)
        w_end = w_end.replace(tzinfo=ts.tzinfo)
    elif ts.tzinfo is None and w_start.tzinfo is not None:
        ts = ts.replace(tzinfo=w_start.tzinfo)
    return w_start <= ts <= w_end


def _matches_rule_window(
    ts: Optional[datetime],
    window_start: Optional[datetime],
    window_end: Optional[datetime],
) -> bool:
    """Check if timestamp satisfies optional rule query boundaries.

    Matches InMemoryStore.list_alerts_for_rule semantics exactly:
    - Alerts lacking timestamps cannot satisfy bounded queries.
    - Boundary comparisons align naive and aware datetimes if mixed.
    """
    if ts is None:
        return window_start is None and window_end is None
    if window_start is not None:
        w_start = window_start
        if ts.tzinfo is not None and w_start.tzinfo is None:
            w_start = w_start.replace(tzinfo=ts.tzinfo)
        elif ts.tzinfo is None and w_start.tzinfo is not None:
            ts = ts.replace(tzinfo=w_start.tzinfo)
        if ts < w_start:
            return False
    if window_end is not None:
        w_end = window_end
        if ts.tzinfo is not None and w_end.tzinfo is None:
            w_end = w_end.replace(tzinfo=ts.tzinfo)
        elif ts.tzinfo is None and w_end.tzinfo is not None:
            ts = ts.replace(tzinfo=w_end.tzinfo)
        if ts > w_end:
            return False
    return True


class SQLiteStore:
    """SQLite-backed persistent entity store for PROOFSHIELD.

    Implements StoreProtocol with relational schema, ACID transactions,
    WAL mode, foreign key integrity, and exact semantic parity with InMemoryStore.
    """

    SCHEMA_VERSION = "1"

    def __init__(
        self,
        db_path: Union[str, Path] = ":memory:",
        timeout: float = 5.0,
    ) -> None:
        self.db_path = str(db_path)
        self.timeout = timeout
        self._savepoint_counter = 0
        self._lock = threading.RLock()

        # Ensure parent directory exists for file-backed storage
        if self.is_file_backed:
            Path(self.db_path).resolve().parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            self.db_path,
            timeout=self.timeout,
            check_same_thread=False,
            isolation_level=None,
            uri=True,
        )
        self._conn.row_factory = sqlite3.Row

        try:
            self._configure_pragmas()
            self._init_schema()
        except Exception:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
            raise

    def _check_open(self) -> None:
        if self._conn is None:
            raise RuntimeError("SQLiteStore connection is closed")

    @property
    def is_file_backed(self) -> bool:
        """True if the store is backed by a persistent file on disk rather than in-memory."""
        if self.db_path == ":memory:":
            return False
        if self.db_path.startswith("file:") and "mode=memory" in self.db_path:
            return False
        return True

    @property
    def is_closed(self) -> bool:
        """True if the database connection has been closed."""
        return self._conn is None

    @property
    def connection(self) -> sqlite3.Connection:
        """Direct access to the underlying sqlite3 connection."""
        self._check_open()
        assert self._conn is not None
        return self._conn

    def _configure_pragmas(self) -> None:
        """Configure essential SQLite pragmas for safety, concurrency, and integrity."""
        self._check_open()
        cursor = self.connection.cursor()
        try:
            # Foreign keys must be explicitly enabled per connection in SQLite
            cursor.execute("PRAGMA foreign_keys = ON;")
            cursor.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)};")

            if self.is_file_backed:
                cursor.execute("PRAGMA journal_mode = WAL;")
                cursor.execute("PRAGMA synchronous = NORMAL;")
        finally:
            cursor.close()

    def _init_schema(self) -> None:
        """Create relational tables and indexes for all 8 PROOFSHIELD entities."""
        self._check_open()
        with self.transaction() as cursor:
            # 0. Schema Version Metadata
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                "SELECT value FROM schema_metadata WHERE key = 'schema_version';"
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute(
                    """
                    INSERT INTO schema_metadata (key, value, updated_at)
                    VALUES ('schema_version', ?, ?);
                    """,
                    (self.SCHEMA_VERSION, datetime.now(timezone.utc).isoformat()),
                )
            else:
                existing_ver = str(row[0])
                if existing_ver != self.SCHEMA_VERSION:
                    raise ValueError(
                        f"Unsupported database schema version '{existing_ver}'. "
                        f"This version of PROOFSHIELD supports schema version '{self.SCHEMA_VERSION}'."
                    )

            # 1. Scenarios
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scenarios (
                    scenario_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    mitre_technique_id TEXT NOT NULL,
                    mitre_tactic TEXT NOT NULL,
                    expected_event_category TEXT NOT NULL,
                    validation_target TEXT NOT NULL,
                    expected_process_name TEXT,
                    expected_command_pattern TEXT,
                    expected_detection_rule_id TEXT,
                    max_acceptable_latency_seconds INTEGER,
                    payload_json TEXT NOT NULL
                );
                """
            )

            # 2. Test Runs (Foreign key to scenarios)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS test_runs (
                    run_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL REFERENCES scenarios(scenario_id) ON DELETE RESTRICT,
                    execution_mode TEXT NOT NULL,
                    is_synthetic INTEGER NOT NULL,
                    target_host TEXT NOT NULL,
                    target_user TEXT NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    execution_status TEXT NOT NULL,
                    execution_token TEXT,
                    payload_json TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_test_runs_scenario ON test_runs(scenario_id);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_test_runs_host_window ON test_runs(target_host, window_start, window_end);"
            )

            # 3. Raw Telemetry
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS raw_telemetry (
                    raw_event_id TEXT PRIMARY KEY,
                    source_event_id TEXT,
                    source_format TEXT NOT NULL,
                    source_timestamp TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )

            # 4. Normalized Telemetry
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS normalized_telemetry (
                    normalized_event_id TEXT PRIMARY KEY,
                    raw_event_id TEXT NOT NULL,
                    source_event_id TEXT,
                    source_timestamp TEXT NOT NULL,
                    normalized_timestamp TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    host TEXT NOT NULL,
                    process_name TEXT,
                    command_line TEXT,
                    execution_token TEXT,
                    payload_json TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_normalized_telemetry_host_ts ON normalized_telemetry(host, normalized_timestamp);"
            )

            # 5. Detection Rules
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS detection_rules (
                    rule_id TEXT PRIMARY KEY,
                    rule_name TEXT NOT NULL,
                    rule_format TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )

            # 6. Alerts
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    source_alert_id TEXT,
                    source_type TEXT NOT NULL,
                    alert_timestamp TEXT,
                    ingested_at TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    rule_reference TEXT,
                    alert_title TEXT,
                    execution_token TEXT,
                    payload_json TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_reference);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_rule_ts ON alerts(rule_reference, alert_timestamp);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_host_ts ON alerts(host_id, alert_timestamp);"
            )

            # 7. Diagnostic Results
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS diagnostic_results (
                    diagnostic_id TEXT PRIMARY KEY,
                    test_run_id TEXT NOT NULL,
                    scenario_id TEXT NOT NULL,
                    predicted_category TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_diagnostic_results_run_id ON diagnostic_results(test_run_id);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_diagnostic_results_run ON diagnostic_results(test_run_id, evaluated_at);"
            )

            # 8. Ground Truth
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ground_truths (
                    ground_truth_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    expected_diagnostic_category TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_ground_truths_run ON ground_truths(run_id);"
            )

            # 9. Campaigns
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )

            # 10. Campaign Runs
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS campaign_runs (
                    run_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id) ON DELETE RESTRICT,
                    status TEXT NOT NULL,
                    is_replay INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    payload_json TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_campaign_runs_campaign ON campaign_runs(campaign_id);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_campaign_runs_started ON campaign_runs(started_at);"
            )

            # 11. Campaign Assurance Reports
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS campaign_assurance_reports (
                    report_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES campaign_runs(run_id) ON DELETE RESTRICT,
                    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id) ON DELETE RESTRICT,
                    report_digest TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    is_complete INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_campaign_assurance_reports_campaign ON campaign_assurance_reports(campaign_id);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_campaign_assurance_reports_run ON campaign_assurance_reports(run_id);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_campaign_assurance_reports_generated ON campaign_assurance_reports(generated_at);"
            )

            # 12. Verify physical schema integrity across all core tables
            required_columns = {
                "scenarios": {"scenario_id", "name", "mitre_technique_id", "payload_json"},
                "test_runs": {"run_id", "scenario_id", "execution_mode", "payload_json"},
                "raw_telemetry": {"raw_event_id", "payload_json"},
                "normalized_telemetry": {"normalized_event_id", "payload_json"},
                "detection_rules": {"rule_id", "payload_json"},
                "alerts": {"alert_id", "payload_json"},
                "diagnostic_results": {"diagnostic_id", "payload_json"},
                "ground_truths": {"ground_truth_id", "payload_json"},
                "campaigns": {"campaign_id", "name", "created_at", "payload_json"},
                "campaign_runs": {"run_id", "campaign_id", "status", "is_replay", "started_at", "payload_json"},
                "campaign_assurance_reports": {"report_id", "run_id", "campaign_id", "report_digest", "generated_at", "is_complete", "payload_json"},
            }
            for tbl, expected_cols in required_columns.items():
                cursor.execute(f"PRAGMA table_info({tbl});")
                actual_cols = {col_row[1] for col_row in cursor.fetchall()}
                missing = expected_cols - actual_cols
                if missing:
                    raise ValueError(
                        f"Incompatible physical database schema: table '{tbl}' is missing required columns: {sorted(missing)}."
                    )

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager for atomic transaction management.

        Uses SQLite SAVEPOINTs for full multi-level nesting and ACID atomicity.
        Inner transaction failures roll back only the inner savepoint.
        Outer transaction failures roll back all modifications in the transaction block.
        """
        with self._lock:
            self._check_open()
            self._savepoint_counter += 1
            savepoint_name = f"ps_sp_{self._savepoint_counter}"
            cursor = self.connection.cursor()
            cursor.execute(f"SAVEPOINT {savepoint_name};")

            try:
                yield cursor
                cursor.execute(f"RELEASE SAVEPOINT {savepoint_name};")
            except Exception:
                cursor.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name};")
                cursor.execute(f"RELEASE SAVEPOINT {savepoint_name};")
                raise
            finally:
                cursor.close()

    def close(self) -> None:
        """Close connection and clean up resources safely and idempotently."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def reset(self) -> None:
        """Clear all stored data across all tables within an atomic transaction."""
        self._check_open()
        with self.transaction() as cursor:
            # Delete child tables before parent tables to respect foreign keys
            cursor.execute("DELETE FROM campaign_assurance_reports;")
            cursor.execute("DELETE FROM campaign_runs;")
            cursor.execute("DELETE FROM campaigns;")
            cursor.execute("DELETE FROM ground_truths;")
            cursor.execute("DELETE FROM diagnostic_results;")
            cursor.execute("DELETE FROM alerts;")
            cursor.execute("DELETE FROM detection_rules;")
            cursor.execute("DELETE FROM normalized_telemetry;")
            cursor.execute("DELETE FROM raw_telemetry;")
            cursor.execute("DELETE FROM test_runs;")
            cursor.execute("DELETE FROM scenarios;")

    def get_schema_version(self) -> str:
        """Return the schema version recorded in the database."""
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT value FROM schema_metadata WHERE key = 'schema_version';")
                row = cur.fetchone()
                return str(row[0]) if row else self.SCHEMA_VERSION
            finally:
                cur.close()

    def backup(self, destination: Union[str, Path, "SQLiteStore"]) -> None:
        """Perform a consistent, online atomic backup of the database.

        Supports file paths (creating parent directories as needed) or destination SQLiteStore.
        Uses SQLite's online backup API, safe even with active WAL journals and readers.
        Prevents self-backup, AB-BA deadlocks between stores, and cleans up partial files on failure.
        """
        if destination is self:
            raise ValueError("Backup destination cannot be the same SQLiteStore instance.")

        if isinstance(destination, SQLiteStore):
            # Deadlock prevention via deterministic lock ordering based on object id
            first, second = (self, destination) if id(self) < id(destination) else (destination, self)
            with first._lock:
                with second._lock:
                    self._check_open()
                    destination._check_open()
                    self.connection.backup(destination.connection)
        else:
            dest_str = str(destination).strip()
            dest_path = Path(validate_sqlite_path(dest_str)).resolve()

            if self.is_file_backed and dest_path == Path(self.db_path).resolve():
                raise ValueError("Backup destination path cannot be the same as the active database path.")

            with self._lock:
                self._check_open()
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                dest_conn = sqlite3.connect(str(dest_path), timeout=self.timeout)
                try:
                    self.connection.backup(dest_conn)
                except Exception:
                    try:
                        dest_conn.close()
                    except Exception:
                        pass
                    if dest_path.exists():
                        try:
                            dest_path.unlink()
                        except Exception:
                            pass
                    raise
                else:
                    dest_conn.close()

    # ── Scenarios ─────────────────────────────────────────────────────────

    def add_scenario(self, scenario: ScenarioV1) -> ScenarioV1:
        """Register a scenario. Raises ValueError on duplicate ID."""
        self._check_open()
        try:
            with self.transaction() as cur:
                cur.execute("SELECT 1 FROM scenarios WHERE scenario_id = ?;", (scenario.scenario_id,))
                if cur.fetchone() is not None:
                    raise ValueError(f"Scenario already exists: {scenario.scenario_id}")

                payload_json = scenario.model_dump_json(by_alias=True)
                cur.execute(
                    """
                    INSERT INTO scenarios (
                        scenario_id, name, mitre_technique_id, mitre_tactic,
                        expected_event_category, validation_target, expected_process_name,
                        expected_command_pattern, expected_detection_rule_id,
                        max_acceptable_latency_seconds, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        scenario.scenario_id,
                        scenario.name,
                        scenario.mitre_technique_id,
                        scenario.mitre_tactic,
                        scenario.expected_event_category.value,
                        scenario.validation_target.value,
                        scenario.expected_process_name,
                        scenario.expected_command_pattern,
                        scenario.expected_detection_rule_id,
                        scenario.max_acceptable_latency_seconds,
                        payload_json,
                    ),
                )
        except sqlite3.IntegrityError as e:
            if "unique" in str(e).lower() or "primary key" in str(e).lower():
                raise ValueError(f"Scenario already exists: {scenario.scenario_id}") from e
            raise
        return scenario

    def get_scenario(self, scenario_id: str) -> Optional[ScenarioV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM scenarios WHERE scenario_id = ?;", (scenario_id,))
                row = cur.fetchone()
                return ScenarioV1.model_validate_json(row[0]) if row else None
            finally:
                cur.close()

    def list_scenarios(self) -> List[ScenarioV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM scenarios ORDER BY rowid;")
                return [ScenarioV1.model_validate_json(row[0]) for row in cur.fetchall()]
            finally:
                cur.close()

    # ── Test Runs ─────────────────────────────────────────────────────────

    def add_run(self, run: TestRunV1) -> TestRunV1:
        """Record a test run. Raises ValueError on duplicate ID or missing scenario."""
        self._check_open()
        try:
            with self.transaction() as cur:
                cur.execute("SELECT 1 FROM test_runs WHERE run_id = ?;", (run.run_id,))
                if cur.fetchone() is not None:
                    raise ValueError(f"Run already exists: {run.run_id}")

                cur.execute("SELECT 1 FROM scenarios WHERE scenario_id = ?;", (run.scenario_id,))
                if cur.fetchone() is None:
                    raise ValueError(f"Scenario not found: {run.scenario_id}")

                payload_json = run.model_dump_json(by_alias=True)
                cur.execute(
                    """
                    INSERT INTO test_runs (
                        run_id, scenario_id, execution_mode, is_synthetic,
                        target_host, target_user, window_start, window_end,
                        executed_at, execution_status, execution_token, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        run.run_id,
                        run.scenario_id,
                        run.execution_mode.value,
                        1 if run.is_synthetic else 0,
                        run.target_host,
                        run.target_user,
                        serialize_timestamp(run.window_start),
                        serialize_timestamp(run.window_end),
                        serialize_timestamp(run.executed_at),
                        run.execution_status.value,
                        run.execution_token,
                        payload_json,
                    ),
                )
        except sqlite3.IntegrityError as e:
            err = str(e).lower()
            if "foreign key" in err:
                raise ValueError(f"Scenario not found: {run.scenario_id}") from e
            if "unique" in err or "primary key" in err:
                raise ValueError(f"Run already exists: {run.run_id}") from e
            raise
        return run

    def get_run(self, run_id: str) -> Optional[TestRunV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM test_runs WHERE run_id = ?;", (run_id,))
                row = cur.fetchone()
                return TestRunV1.model_validate_json(row[0]) if row else None
            finally:
                cur.close()

    def list_runs(self, scenario_id: Optional[str] = None) -> List[TestRunV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                if scenario_id:
                    cur.execute(
                        "SELECT payload_json FROM test_runs WHERE scenario_id = ? ORDER BY rowid;",
                        (scenario_id,),
                    )
                else:
                    cur.execute("SELECT payload_json FROM test_runs ORDER BY rowid;")
                return [TestRunV1.model_validate_json(row[0]) for row in cur.fetchall()]
            finally:
                cur.close()

    # ── Raw Events ────────────────────────────────────────────────────────

    def add_raw_event(self, event: RawTelemetryEventV1) -> RawTelemetryEventV1:
        """Store a raw event. Raises ValueError on duplicate ID."""
        self._check_open()
        try:
            with self.transaction() as cur:
                cur.execute("SELECT 1 FROM raw_telemetry WHERE raw_event_id = ?;", (event.raw_event_id,))
                if cur.fetchone() is not None:
                    raise ValueError(f"Raw event already exists: {event.raw_event_id}")

                payload_json = event.model_dump_json(by_alias=True)
                cur.execute(
                    """
                    INSERT INTO raw_telemetry (
                        raw_event_id, source_event_id, source_format, source_timestamp,
                        ingested_at, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        event.raw_event_id,
                        event.source_event_id,
                        event.source_format,
                        serialize_timestamp(event.source_timestamp),
                        serialize_timestamp(event.ingested_at),
                        payload_json,
                    ),
                )
        except sqlite3.IntegrityError as e:
            if "unique" in str(e).lower() or "primary key" in str(e).lower():
                raise ValueError(f"Raw event already exists: {event.raw_event_id}") from e
            raise
        return event

    def get_raw_event(self, raw_event_id: str) -> Optional[RawTelemetryEventV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM raw_telemetry WHERE raw_event_id = ?;", (raw_event_id,))
                row = cur.fetchone()
                return RawTelemetryEventV1.model_validate_json(row[0]) if row else None
            finally:
                cur.close()

    def list_raw_events(self) -> List[RawTelemetryEventV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM raw_telemetry ORDER BY rowid;")
                return [RawTelemetryEventV1.model_validate_json(row[0]) for row in cur.fetchall()]
            finally:
                cur.close()

    # ── Normalized Events ─────────────────────────────────────────────────

    def add_normalized_event(
        self, event: NormalizedTelemetryEventV1
    ) -> NormalizedTelemetryEventV1:
        """Store a normalized event. Raises ValueError on duplicate ID."""
        self._check_open()
        try:
            with self.transaction() as cur:
                cur.execute(
                    "SELECT 1 FROM normalized_telemetry WHERE normalized_event_id = ?;",
                    (event.normalized_event_id,),
                )
                if cur.fetchone() is not None:
                    raise ValueError(
                        f"Normalized event already exists: {event.normalized_event_id}"
                    )

                payload_json = event.model_dump_json(by_alias=True)
                cur.execute(
                    """
                    INSERT INTO normalized_telemetry (
                        normalized_event_id, raw_event_id, source_event_id,
                        source_timestamp, normalized_timestamp, event_category,
                        host, process_name, command_line, execution_token, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        event.normalized_event_id,
                        event.raw_event_id,
                        event.source_event_id,
                        serialize_timestamp(event.source_timestamp),
                        serialize_timestamp(event.normalized_timestamp),
                        event.event_category.value,
                        event.host,
                        event.process_name,
                        event.command_line,
                        event.execution_token,
                        payload_json,
                    ),
                )
        except sqlite3.IntegrityError as e:
            if "unique" in str(e).lower() or "primary key" in str(e).lower():
                raise ValueError(
                    f"Normalized event already exists: {event.normalized_event_id}"
                ) from e
            raise
        return event

    def get_normalized_event(
        self, event_id: str
    ) -> Optional[NormalizedTelemetryEventV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute(
                    "SELECT payload_json FROM normalized_telemetry WHERE normalized_event_id = ?;",
                    (event_id,),
                )
                row = cur.fetchone()
                return NormalizedTelemetryEventV1.model_validate_json(row[0]) if row else None
            finally:
                cur.close()

    def list_normalized_events(self) -> List[NormalizedTelemetryEventV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM normalized_telemetry ORDER BY rowid;")
                return [
                    NormalizedTelemetryEventV1.model_validate_json(row[0])
                    for row in cur.fetchall()
                ]
            finally:
                cur.close()

    def get_events_for_run(
        self, run: TestRunV1
    ) -> List[NormalizedTelemetryEventV1]:
        """Correlate normalized events to a test run by host and time window.

        Retrieves candidate events and evaluates hosts_match() and time window
        in Python to ensure 100% deterministic parity with InMemoryStore.
        Results are sorted chronologically and deterministically.
        """
        all_events = self.list_normalized_events()
        matched = []
        for event in all_events:
            if not hosts_match(run.target_host, event.host):
                continue
            if _is_in_window(event.normalized_timestamp, run.window_start, run.window_end):
                matched.append(event)

        return sorted(
            matched,
            key=lambda e: (
                e.normalized_timestamp or datetime.min.replace(tzinfo=timezone.utc),
                e.normalized_event_id,
            ),
        )

    # ── Detection Rules ───────────────────────────────────────────────────

    def add_rule(self, rule: DetectionRuleV1) -> DetectionRuleV1:
        """Register a detection rule. Raises ValueError on duplicate ID."""
        self._check_open()
        try:
            with self.transaction() as cur:
                cur.execute("SELECT 1 FROM detection_rules WHERE rule_id = ?;", (rule.rule_id,))
                if cur.fetchone() is not None:
                    raise ValueError(f"Rule already exists: {rule.rule_id}")

                payload_json = rule.model_dump_json(by_alias=True)
                cur.execute(
                    """
                    INSERT INTO detection_rules (
                        rule_id, rule_name, rule_format, rule_version, payload_json
                    ) VALUES (?, ?, ?, ?, ?);
                    """,
                    (
                        rule.rule_id,
                        rule.rule_name,
                        rule.rule_format,
                        rule.rule_version,
                        payload_json,
                    ),
                )
        except sqlite3.IntegrityError as e:
            if "unique" in str(e).lower() or "primary key" in str(e).lower():
                raise ValueError(f"Rule already exists: {rule.rule_id}") from e
            raise
        return rule

    def get_rule(self, rule_id: str) -> Optional[DetectionRuleV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM detection_rules WHERE rule_id = ?;", (rule_id,))
                row = cur.fetchone()
                return DetectionRuleV1.model_validate_json(row[0]) if row else None
            finally:
                cur.close()

    def list_rules(self) -> List[DetectionRuleV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM detection_rules ORDER BY rowid;")
                return [DetectionRuleV1.model_validate_json(row[0]) for row in cur.fetchall()]
            finally:
                cur.close()

    # ── Alerts ────────────────────────────────────────────────────────────

    def add_alert(self, alert: AlertV1) -> AlertV1:
        """Store an alert with token extraction. Raises ValueError on duplicate ID."""
        self._check_open()
        try:
            with self.transaction() as cur:
                cur.execute("SELECT 1 FROM alerts WHERE alert_id = ?;", (alert.alert_id,))
                if cur.fetchone() is not None:
                    raise ValueError(f"Alert already exists: {alert.alert_id}")

                if alert.ingested_at is None:
                    alert.ingested_at = datetime.now(timezone.utc)
                if alert.alert_timestamp is None:
                    alert.metadata["ingestion_time_only"] = True

                # Structured-first token extraction / conflict verification on alert
                token = extract_execution_token(
                    payload=alert.metadata,
                    explicit_token=alert.execution_token,
                    text_fields=[alert.alert_title],
                )
                alert.execution_token = token

                payload_json = alert.model_dump_json(by_alias=True)
                cur.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, source_alert_id, source_type, alert_timestamp,
                        ingested_at, host_id, rule_reference, alert_title,
                        execution_token, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        alert.alert_id,
                        alert.source_alert_id,
                        alert.source_type,
                        serialize_timestamp(alert.alert_timestamp),
                        serialize_timestamp(alert.ingested_at),
                        alert.host_id,
                        alert.rule_reference,
                        alert.alert_title,
                        alert.execution_token,
                        payload_json,
                    ),
                )
        except sqlite3.IntegrityError as e:
            if "unique" in str(e).lower() or "primary key" in str(e).lower():
                raise ValueError(f"Alert already exists: {alert.alert_id}") from e
            raise
        return alert

    def get_alert(self, alert_id: str) -> Optional[AlertV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM alerts WHERE alert_id = ?;", (alert_id,))
                row = cur.fetchone()
                return AlertV1.model_validate_json(row[0]) if row else None
            finally:
                cur.close()

    def list_alerts(self) -> List[AlertV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM alerts ORDER BY rowid;")
                return [AlertV1.model_validate_json(row[0]) for row in cur.fetchall()]
            finally:
                cur.close()

    def list_alerts_for_rule(
        self,
        rule_id: str,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
    ) -> List[AlertV1]:
        """Return alerts referencing a given rule ID, optionally bounded by time."""
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                # Query candidate alerts matching the rule reference via indexed column
                cur.execute(
                    "SELECT payload_json FROM alerts WHERE rule_reference = ? ORDER BY rowid;",
                    (rule_id,),
                )
                rule_alerts = [AlertV1.model_validate_json(row[0]) for row in cur.fetchall()]
            finally:
                cur.close()

        matched = []
        for a in rule_alerts:
            if not (a.rule_reference and a.rule_reference == rule_id):
                continue
            if _matches_rule_window(a.alert_timestamp, window_start, window_end):
                matched.append(a)

        return sorted(
            matched,
            key=lambda a: (
                a.alert_timestamp or datetime.min.replace(tzinfo=timezone.utc),
                a.alert_id,
            ),
        )

    def get_alerts_for_run(self, run: TestRunV1) -> List[AlertV1]:
        """Correlate alerts to a test run by host and time window.

        Retrieves candidate alerts and evaluates hosts_match() and time window
        in Python to ensure 100% deterministic parity with InMemoryStore.
        Results are sorted chronologically and deterministically.
        """
        all_alerts = self.list_alerts()
        matched = []
        for alert in all_alerts:
            if not hosts_match(run.target_host, alert.host_id):
                continue
            if _is_in_window(alert.alert_timestamp, run.window_start, run.window_end):
                matched.append(alert)

        return sorted(
            matched,
            key=lambda a: (
                a.alert_timestamp or datetime.min.replace(tzinfo=timezone.utc),
                a.alert_id,
            ),
        )

    # ── Diagnostic Results ────────────────────────────────────────────────

    def add_result(self, result: DiagnosticResultV1) -> DiagnosticResultV1:
        """Store a diagnostic result. Overwrites previous result for same diagnostic_id."""
        self._check_open()
        payload_json = result.model_dump_json(by_alias=True)
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT INTO diagnostic_results (
                    diagnostic_id, test_run_id, scenario_id, predicted_category,
                    confidence, evaluated_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(diagnostic_id) DO UPDATE SET
                    test_run_id = excluded.test_run_id,
                    scenario_id = excluded.scenario_id,
                    predicted_category = excluded.predicted_category,
                    confidence = excluded.confidence,
                    evaluated_at = excluded.evaluated_at,
                    payload_json = excluded.payload_json;
                """,
                (
                    result.diagnostic_id,
                    result.test_run_id,
                    result.scenario_id,
                    result.predicted_category.value,
                    result.confidence,
                    serialize_timestamp(result.evaluated_at),
                    payload_json,
                ),
            )
        return result

    def get_result(self, result_id: str) -> Optional[DiagnosticResultV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute(
                    "SELECT payload_json FROM diagnostic_results WHERE diagnostic_id = ?;",
                    (result_id,),
                )
                row = cur.fetchone()
                return DiagnosticResultV1.model_validate_json(row[0]) if row else None
            finally:
                cur.close()

    def get_result_for_run(self, run_id: str) -> Optional[DiagnosticResultV1]:
        """Return the most recent diagnostic result for a test run."""
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute(
                    "SELECT payload_json FROM diagnostic_results WHERE test_run_id = ? ORDER BY rowid DESC LIMIT 1;",
                    (run_id,),
                )
                row = cur.fetchone()
                return DiagnosticResultV1.model_validate_json(row[0]) if row else None
            finally:
                cur.close()

    def list_results(self) -> List[DiagnosticResultV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM diagnostic_results ORDER BY rowid;")
                return [DiagnosticResultV1.model_validate_json(row[0]) for row in cur.fetchall()]
            finally:
                cur.close()

    # ── Ground Truth ──────────────────────────────────────────────────────

    def add_ground_truth(self, gt: GroundTruthV1) -> GroundTruthV1:
        """Store a ground truth record. Raises ValueError on duplicate ID."""
        self._check_open()
        try:
            with self.transaction() as cur:
                cur.execute(
                    "SELECT 1 FROM ground_truths WHERE ground_truth_id = ?;",
                    (gt.ground_truth_id,),
                )
                if cur.fetchone() is not None:
                    raise ValueError(f"Ground truth already exists: {gt.ground_truth_id}")

                payload_json = gt.model_dump_json(by_alias=True)
                cur.execute(
                    """
                    INSERT INTO ground_truths (
                        ground_truth_id, run_id, expected_diagnostic_category, payload_json
                    ) VALUES (?, ?, ?, ?);
                    """,
                    (
                        gt.ground_truth_id,
                        gt.run_id,
                        gt.expected_diagnostic_category.value,
                        payload_json,
                    ),
                )
        except sqlite3.IntegrityError as e:
            if "unique" in str(e).lower() or "primary key" in str(e).lower():
                raise ValueError(f"Ground truth already exists: {gt.ground_truth_id}") from e
            raise
        return gt

    def get_ground_truth_for_run(self, run_id: str) -> Optional[GroundTruthV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute(
                    "SELECT payload_json FROM ground_truths WHERE run_id = ? ORDER BY rowid ASC LIMIT 1;",
                    (run_id,),
                )
                row = cur.fetchone()
                return GroundTruthV1.model_validate_json(row[0]) if row else None
            finally:
                cur.close()

    def list_ground_truths(self) -> List[GroundTruthV1]:
        with self._lock:
            self._check_open()
            cur = self.connection.cursor()
            try:
                cur.execute("SELECT payload_json FROM ground_truths ORDER BY rowid;")
                return [GroundTruthV1.model_validate_json(row[0]) for row in cur.fetchall()]
            finally:
                cur.close()

    # ── Campaigns ─────────────────────────────────────────────────────────

    def add_campaign(self, campaign: CampaignDefinitionV1) -> CampaignDefinitionV1:
        """Register a campaign definition. Raises ValueError on duplicate ID."""
        with self._lock:
            self._check_open()
            with self.transaction() as cursor:
                try:
                    cursor.execute(
                        """
                        INSERT INTO campaigns (campaign_id, name, created_at, payload_json)
                        VALUES (?, ?, ?, ?);
                        """,
                        (
                            campaign.campaign_id,
                            campaign.name,
                            to_canonical_utc_iso(campaign.created_at),
                            campaign.model_dump_json(),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ValueError(f"Campaign already exists: {campaign.campaign_id}") from exc
            return campaign

    def get_campaign(self, campaign_id: str) -> Optional[CampaignDefinitionV1]:
        """Retrieve a campaign definition by its identifier."""
        with self._lock:
            self._check_open()
            cursor = self.connection.cursor()
            try:
                cursor.execute(
                    "SELECT payload_json FROM campaigns WHERE campaign_id = ?;",
                    (campaign_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                return CampaignDefinitionV1.model_validate_json(row[0])
            finally:
                cursor.close()

    def list_campaigns(self) -> List[CampaignDefinitionV1]:
        """List all registered campaign definitions, ordered deterministically by creation timestamp."""
        with self._lock:
            self._check_open()
            cursor = self.connection.cursor()
            try:
                cursor.execute(
                    "SELECT payload_json FROM campaigns ORDER BY created_at ASC;"
                )
                return [CampaignDefinitionV1.model_validate_json(r[0]) for r in cursor.fetchall()]
            finally:
                cursor.close()

    # ── Campaign Runs ─────────────────────────────────────────────────────

    def add_campaign_run(self, run: CampaignRunV1) -> CampaignRunV1:
        """Record an executed campaign run. Raises ValueError on duplicate ID or missing campaign."""
        with self._lock:
            self._check_open()
            with self.transaction() as cursor:
                cursor.execute(
                    "SELECT 1 FROM campaigns WHERE campaign_id = ?;",
                    (run.campaign_id,),
                )
                if cursor.fetchone() is None:
                    raise ValueError(f"Campaign not found: {run.campaign_id}")
                try:
                    cursor.execute(
                        """
                        INSERT INTO campaign_runs (
                            run_id, campaign_id, status, is_replay, started_at, completed_at, payload_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            run.run_id,
                            run.campaign_id,
                            run.status.value,
                            1 if run.is_replay else 0,
                            to_canonical_utc_iso(run.started_at),
                            to_canonical_utc_iso(run.completed_at) if run.completed_at else None,
                            run.model_dump_json(),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ValueError(f"Campaign run already exists: {run.run_id}") from exc
            return run

    def get_campaign_run(self, run_id: str) -> Optional[CampaignRunV1]:
        """Retrieve an executed campaign run by its identifier."""
        with self._lock:
            self._check_open()
            cursor = self.connection.cursor()
            try:
                cursor.execute(
                    "SELECT payload_json FROM campaign_runs WHERE run_id = ?;",
                    (run_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                return CampaignRunV1.model_validate_json(row[0])
            finally:
                cursor.close()

    def list_campaign_runs(
        self, campaign_id: Optional[str] = None
    ) -> List[CampaignRunV1]:
        """List campaign runs, optionally filtered by campaign ID, ordered by start time."""
        with self._lock:
            self._check_open()
            cursor = self.connection.cursor()
            try:
                if campaign_id is not None:
                    cursor.execute(
                        "SELECT payload_json FROM campaign_runs WHERE campaign_id = ? ORDER BY started_at ASC;",
                        (campaign_id,),
                    )
                else:
                    cursor.execute(
                        "SELECT payload_json FROM campaign_runs ORDER BY started_at ASC;"
                    )
                return [CampaignRunV1.model_validate_json(r[0]) for r in cursor.fetchall()]
            finally:
                cursor.close()

    # ── Campaign Assurance Reports ────────────────────────────────────────

    def add_assurance_report(
        self, report: CampaignAssuranceReportV1
    ) -> CampaignAssuranceReportV1:
        """Record an assurance report. Raises ValueError on duplicate ID or missing campaign run."""
        with self._lock:
            self._check_open()
            with self.transaction() as cursor:
                # 1. Validate foreign keys: campaign run and campaign must exist
                cursor.execute(
                    "SELECT 1 FROM campaign_runs WHERE run_id = ?;",
                    (report.campaign_run_id,),
                )
                if cursor.fetchone() is None:
                    raise ValueError(f"Campaign run not found: {report.campaign_run_id}")

                cursor.execute(
                    "SELECT 1 FROM campaigns WHERE campaign_id = ?;",
                    (report.campaign_id,),
                )
                if cursor.fetchone() is None:
                    raise ValueError(f"Campaign not found: {report.campaign_id}")

                # 2. Check duplicate report ID
                cursor.execute(
                    "SELECT 1 FROM campaign_assurance_reports WHERE report_id = ?;",
                    (report.report_id,),
                )
                if cursor.fetchone() is not None:
                    raise ValueError(f"Assurance report already exists: {report.report_id}")

                # 3. Insert report
                try:
                    cursor.execute(
                        """
                        INSERT INTO campaign_assurance_reports (
                            report_id, run_id, campaign_id, report_digest, generated_at, is_complete, payload_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            report.report_id,
                            report.campaign_run_id,
                            report.campaign_id,
                            report.report_digest,
                            to_canonical_utc_iso(report.generated_at),
                            1 if report.is_complete else 0,
                            report.model_dump_json(),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ValueError(f"Assurance report integrity error: {exc}") from exc
            return report

    def get_assurance_report(
        self, report_id: str
    ) -> Optional[CampaignAssuranceReportV1]:
        """Retrieve an assurance report by its identifier."""
        with self._lock:
            self._check_open()
            cursor = self.connection.cursor()
            try:
                cursor.execute(
                    "SELECT payload_json FROM campaign_assurance_reports WHERE report_id = ?;",
                    (report_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                return CampaignAssuranceReportV1.model_validate_json(row[0])
            finally:
                cursor.close()

    def list_assurance_reports(
        self, campaign_id: Optional[str] = None, run_id: Optional[str] = None
    ) -> List[CampaignAssuranceReportV1]:
        """List assurance reports, optionally filtered by campaign ID or run ID, ordered by generation time."""
        with self._lock:
            self._check_open()
            cursor = self.connection.cursor()
            try:
                query = "SELECT payload_json FROM campaign_assurance_reports"
                params: List[Any] = []
                conditions: List[str] = []

                if campaign_id is not None:
                    conditions.append("campaign_id = ?")
                    params.append(campaign_id)
                if run_id is not None:
                    conditions.append("run_id = ?")
                    params.append(run_id)

                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

                query += " ORDER BY generated_at ASC;"

                cursor.execute(query, tuple(params))
                return [CampaignAssuranceReportV1.model_validate_json(r[0]) for r in cursor.fetchall()]
            finally:
                cursor.close()
