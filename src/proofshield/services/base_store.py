"""Storage protocol defining the interface for PROOFSHIELD entity stores.

Defines the contract that both InMemoryStore and persistent adapters (e.g. SQLiteStore)
must satisfy for deterministic evaluation and entity management.
"""

from datetime import datetime, timezone
from typing import Any, List, Optional, Protocol, runtime_checkable

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1, RawTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1


def to_comparable_utc(ts: Optional[datetime]) -> datetime:
    """Normalize a timestamp to UTC for consistent, deterministic comparison and ordering.

    - Returns datetime.min (UTC) if ts is None.
    - If ts is naive, treats it as UTC.
    - If ts is timezone-aware, converts it to UTC.
    Preserves microsecond precision and ensures safe ordering across mixed naive/aware values.
    """
    if ts is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


@runtime_checkable
class StoreProtocol(Protocol):
    """Protocol defining the core storage interface for PROOFSHIELD entities."""

    def reset(self) -> None:
        """Clear all stored data. Used for test isolation."""
        ...

    def transaction(self) -> Any:
        """Context manager for atomic transaction management."""
        ...

    # ── Scenarios ─────────────────────────────────────────────────────────

    def add_scenario(self, scenario: ScenarioV1) -> ScenarioV1:
        """Register a scenario. Raises ValueError on duplicate ID."""
        ...

    def get_scenario(self, scenario_id: str) -> Optional[ScenarioV1]:
        """Retrieve a scenario by its identifier."""
        ...

    def list_scenarios(self) -> List[ScenarioV1]:
        """List all registered scenarios."""
        ...

    # ── Test Runs ─────────────────────────────────────────────────────────

    def add_run(self, run: TestRunV1) -> TestRunV1:
        """Record a test run. Raises ValueError on duplicate ID or missing scenario."""
        ...

    def get_run(self, run_id: str) -> Optional[TestRunV1]:
        """Retrieve a test run by its identifier."""
        ...

    def list_runs(self, scenario_id: Optional[str] = None) -> List[TestRunV1]:
        """List test runs, optionally filtered by scenario ID."""
        ...

    # ── Raw Events ────────────────────────────────────────────────────────

    def add_raw_event(self, event: RawTelemetryEventV1) -> RawTelemetryEventV1:
        """Store a raw telemetry event. Raises ValueError on duplicate ID."""
        ...

    def get_raw_event(self, raw_event_id: str) -> Optional[RawTelemetryEventV1]:
        """Retrieve a raw telemetry event by its identifier."""
        ...

    def list_raw_events(self) -> List[RawTelemetryEventV1]:
        """List all stored raw telemetry events."""
        ...

    # ── Normalized Events ─────────────────────────────────────────────────

    def add_normalized_event(
        self, event: NormalizedTelemetryEventV1
    ) -> NormalizedTelemetryEventV1:
        """Store a normalized event. Raises ValueError on duplicate ID."""
        ...

    def get_normalized_event(
        self, event_id: str
    ) -> Optional[NormalizedTelemetryEventV1]:
        """Retrieve a normalized event by its identifier."""
        ...

    def list_normalized_events(self) -> List[NormalizedTelemetryEventV1]:
        """List all stored normalized telemetry events."""
        ...

    def get_events_for_run(
        self, run: TestRunV1
    ) -> List[NormalizedTelemetryEventV1]:
        """Correlate normalized events to a test run by host and time window."""
        ...

    # ── Detection Rules ───────────────────────────────────────────────────

    def add_rule(self, rule: DetectionRuleV1) -> DetectionRuleV1:
        """Register a detection rule. Raises ValueError on duplicate ID."""
        ...

    def get_rule(self, rule_id: str) -> Optional[DetectionRuleV1]:
        """Retrieve a detection rule by its identifier."""
        ...

    def list_rules(self) -> List[DetectionRuleV1]:
        """List all registered detection rules."""
        ...

    # ── Alerts ────────────────────────────────────────────────────────────

    def add_alert(self, alert: AlertV1) -> AlertV1:
        """Store an alert with token extraction. Raises ValueError on duplicate ID."""
        ...

    def get_alert(self, alert_id: str) -> Optional[AlertV1]:
        """Retrieve an alert by its identifier."""
        ...

    def list_alerts(self) -> List[AlertV1]:
        """List all stored alerts."""
        ...

    def list_alerts_for_rule(
        self,
        rule_id: str,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
    ) -> List[AlertV1]:
        """Return alerts referencing a given rule ID, optionally bounded by time."""
        ...

    def get_alerts_for_run(self, run: TestRunV1) -> List[AlertV1]:
        """Correlate alerts to a test run by host and time window."""
        ...

    # ── Diagnostic Results ────────────────────────────────────────────────

    def add_result(self, result: DiagnosticResultV1) -> DiagnosticResultV1:
        """Store a diagnostic result. Overwrites previous result for same run."""
        ...

    def get_result(self, result_id: str) -> Optional[DiagnosticResultV1]:
        """Retrieve a diagnostic result by its identifier."""
        ...

    def get_result_for_run(self, run_id: str) -> Optional[DiagnosticResultV1]:
        """Return the most recent diagnostic result for a test run."""
        ...

    def list_results(self) -> List[DiagnosticResultV1]:
        """List all diagnostic evaluation results."""
        ...

    # ── Ground Truth ──────────────────────────────────────────────────────

    def add_ground_truth(self, gt: GroundTruthV1) -> GroundTruthV1:
        """Store a ground truth record. Raises ValueError on duplicate ID."""
        ...

    def get_ground_truth_for_run(self, run_id: str) -> Optional[GroundTruthV1]:
        """Retrieve ground truth for a test run."""
        ...

    def list_ground_truths(self) -> List[GroundTruthV1]:
        """List all ground truth records."""
        ...
