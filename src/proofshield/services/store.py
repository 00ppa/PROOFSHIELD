"""In-memory data store for PROOFSHIELD entities.

Thread-unsafe singleton store for development and testing. Provides CRUD
operations and time-window-based event correlation. Will be replaced by
PostgreSQL-backed storage when the core data model stabilises.
"""

from datetime import datetime, timezone
import ipaddress
from typing import Dict, List, Optional, Union

from proofshield.normalisation.engine import extract_execution_token
from proofshield.schemas.alert import AlertV1
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1, RawTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1


def hosts_match(host1: str, host2: str) -> bool:
    """Compare two host identifiers with canonicalized IP comparison and FQDN/NetBIOS matching.

    Rules:
    1. Exact string match (case-insensitive, whitespace-trimmed) returns True.
    2. If both identifiers parse as IP addresses (IPv4 or IPv6), compare their canonicalized
       ipaddress objects (handles compressed/uncompressed IPv6, leading zeros, etc.).
    3. If only one identifier is an IP address and the other is a hostname, return False.
    4. If both identifiers contain domain dots (both are full FQDNs), exact match is required
       (prevents cross-domain collisions like host.prod.corp vs host.dev.corp).
    5. If one is a short NetBIOS/hostname and the other is an FQDN, compare short names.
    """
    h1 = host1.strip().lower()
    h2 = host2.strip().lower()
    if h1 == h2:
        return True

    def _parse_ip(val: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        try:
            return ipaddress.ip_address(val)
        except ValueError:
            return None

    ip1 = _parse_ip(h1)
    ip2 = _parse_ip(h2)

    if ip1 is not None and ip2 is not None:
        return ip1 == ip2

    if ip1 is not None or ip2 is not None:
        return False

    if "." in h1 and "." in h2:
        return False

    return h1.split(".")[0] == h2.split(".")[0]


class InMemoryStore:
    """In-memory entity store for development and testing.

    Stores all PROOFSHIELD entities in dictionaries keyed by their primary
    identifiers. Provides basic query methods including time-window-based
    event correlation for linking telemetry and alerts to test runs.

    Not suitable for production use — no persistence, concurrency, or transactions.
    """

    def __init__(self) -> None:
        self._scenarios: Dict[str, ScenarioV1] = {}
        self._runs: Dict[str, TestRunV1] = {}
        self._raw_events: Dict[str, RawTelemetryEventV1] = {}
        self._normalized_events: Dict[str, NormalizedTelemetryEventV1] = {}
        self._rules: Dict[str, DetectionRuleV1] = {}
        self._alerts: Dict[str, AlertV1] = {}
        self._results: Dict[str, DiagnosticResultV1] = {}
        self._ground_truths: Dict[str, GroundTruthV1] = {}

    def reset(self) -> None:
        """Clear all stored data. Used for test isolation."""
        self._scenarios.clear()
        self._runs.clear()
        self._raw_events.clear()
        self._normalized_events.clear()
        self._rules.clear()
        self._alerts.clear()
        self._results.clear()
        self._ground_truths.clear()

    # ── Scenarios ─────────────────────────────────────────────────────────

    def add_scenario(self, scenario: ScenarioV1) -> ScenarioV1:
        """Register a scenario. Raises ValueError on duplicate ID."""
        if scenario.scenario_id in self._scenarios:
            raise ValueError(f"Scenario already exists: {scenario.scenario_id}")
        self._scenarios[scenario.scenario_id] = scenario
        return scenario

    def get_scenario(self, scenario_id: str) -> Optional[ScenarioV1]:
        return self._scenarios.get(scenario_id)

    def list_scenarios(self) -> List[ScenarioV1]:
        return list(self._scenarios.values())

    # ── Test Runs ─────────────────────────────────────────────────────────

    def add_run(self, run: TestRunV1) -> TestRunV1:
        """Record a test run. Raises ValueError on duplicate or missing scenario."""
        if run.run_id in self._runs:
            raise ValueError(f"Run already exists: {run.run_id}")
        if run.scenario_id not in self._scenarios:
            raise ValueError(f"Scenario not found: {run.scenario_id}")
        self._runs[run.run_id] = run
        return run

    def get_run(self, run_id: str) -> Optional[TestRunV1]:
        return self._runs.get(run_id)

    def list_runs(self, scenario_id: Optional[str] = None) -> List[TestRunV1]:
        runs = list(self._runs.values())
        if scenario_id:
            runs = [r for r in runs if r.scenario_id == scenario_id]
        return runs

    # ── Raw Events ────────────────────────────────────────────────────────

    def add_raw_event(self, event: RawTelemetryEventV1) -> RawTelemetryEventV1:
        """Store a raw event. Raises ValueError on duplicate ID."""
        if event.raw_event_id in self._raw_events:
            raise ValueError(f"Raw event already exists: {event.raw_event_id}")
        self._raw_events[event.raw_event_id] = event
        return event

    def get_raw_event(self, raw_event_id: str) -> Optional[RawTelemetryEventV1]:
        return self._raw_events.get(raw_event_id)

    def list_raw_events(self) -> List[RawTelemetryEventV1]:
        return list(self._raw_events.values())

    # ── Normalized Events ─────────────────────────────────────────────────

    def add_normalized_event(
        self, event: NormalizedTelemetryEventV1
    ) -> NormalizedTelemetryEventV1:
        """Store a normalized event. Raises ValueError on duplicate ID."""
        if event.normalized_event_id in self._normalized_events:
            raise ValueError(
                f"Normalized event already exists: {event.normalized_event_id}"
            )
        self._normalized_events[event.normalized_event_id] = event
        return event

    def get_normalized_event(
        self, event_id: str
    ) -> Optional[NormalizedTelemetryEventV1]:
        return self._normalized_events.get(event_id)

    def list_normalized_events(self) -> List[NormalizedTelemetryEventV1]:
        return list(self._normalized_events.values())


    def get_events_for_run(
        self, run: TestRunV1
    ) -> List[NormalizedTelemetryEventV1]:
        """Correlate normalized events to a test run by host and time window.

        Returns events where host matches via hosts_match() and the
        normalized_timestamp falls within [window_start, window_end].
        Results are sorted chronologically and deterministically.
        """
        matched = []
        for event in self._normalized_events.values():
            if not hosts_match(run.target_host, event.host):
                continue
            ts = event.normalized_timestamp
            if ts is None:
                continue
            w_start = run.window_start
            w_end = run.window_end
            if ts.tzinfo is not None and w_start.tzinfo is None:
                w_start = w_start.replace(tzinfo=ts.tzinfo)
                w_end = w_end.replace(tzinfo=ts.tzinfo)
            elif ts.tzinfo is None and w_start.tzinfo is not None:
                ts = ts.replace(tzinfo=w_start.tzinfo)
            if w_start <= ts <= w_end:
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
        if rule.rule_id in self._rules:
            raise ValueError(f"Rule already exists: {rule.rule_id}")
        self._rules[rule.rule_id] = rule
        return rule

    def get_rule(self, rule_id: str) -> Optional[DetectionRuleV1]:
        return self._rules.get(rule_id)

    def list_rules(self) -> List[DetectionRuleV1]:
        return list(self._rules.values())

    # ── Alerts ────────────────────────────────────────────────────────────

    def add_alert(self, alert: AlertV1) -> AlertV1:
        """Store an alert. Raises ValueError on duplicate ID."""
        if alert.alert_id in self._alerts:
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

        self._alerts[alert.alert_id] = alert
        return alert

    def get_alert(self, alert_id: str) -> Optional[AlertV1]:
        return self._alerts.get(alert_id)

    def list_alerts(self) -> List[AlertV1]:
        return list(self._alerts.values())

    def list_alerts_for_rule(
        self,
        rule_id: str,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
    ) -> List[AlertV1]:
        """Return alerts referencing a given detection rule ID, optionally bounded by time."""
        matched = []
        for a in self._alerts.values():
            if not (a.rule_reference and a.rule_reference == rule_id):
                continue
            ts = a.alert_timestamp
            if ts is None:
                # Alerts without timestamps cannot satisfy time-bounded queries
                if window_start is not None or window_end is not None:
                    continue
            else:
                if window_start is not None:
                    w_start = window_start
                    if ts.tzinfo is not None and w_start.tzinfo is None:
                        w_start = w_start.replace(tzinfo=ts.tzinfo)
                    elif ts.tzinfo is None and w_start.tzinfo is not None:
                        ts = ts.replace(tzinfo=w_start.tzinfo)
                    if ts < w_start:
                        continue
                if window_end is not None:
                    w_end = window_end
                    if ts.tzinfo is not None and w_end.tzinfo is None:
                        w_end = w_end.replace(tzinfo=ts.tzinfo)
                    elif ts.tzinfo is None and w_end.tzinfo is not None:
                        ts = ts.replace(tzinfo=w_end.tzinfo)
                    if ts > w_end:
                        continue
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

        Returns alerts where host_id matches via hosts_match() and the
        alert_timestamp falls within [window_start, window_end].
        Results are sorted chronologically and deterministically.
        """
        matched = []
        for alert in self._alerts.values():
            if not hosts_match(run.target_host, alert.host_id):
                continue
            ts = alert.alert_timestamp
            if ts is None:
                continue
            w_start = run.window_start
            w_end = run.window_end
            if ts.tzinfo is not None and w_start.tzinfo is None:
                w_start = w_start.replace(tzinfo=ts.tzinfo)
                w_end = w_end.replace(tzinfo=ts.tzinfo)
            elif ts.tzinfo is None and w_start.tzinfo is not None:
                ts = ts.replace(tzinfo=w_start.tzinfo)
            if w_start <= ts <= w_end:
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
        """Store a diagnostic result. Overwrites previous result for same run."""
        self._results[result.diagnostic_id] = result
        return result

    def get_result(self, result_id: str) -> Optional[DiagnosticResultV1]:
        return self._results.get(result_id)

    def get_result_for_run(self, run_id: str) -> Optional[DiagnosticResultV1]:
        """Return the most recent diagnostic result for a test run."""
        for result in reversed(list(self._results.values())):
            if result.test_run_id == run_id:
                return result
        return None

    def list_results(self) -> List[DiagnosticResultV1]:
        return list(self._results.values())

    # ── Ground Truth ──────────────────────────────────────────────────────

    def add_ground_truth(self, gt: GroundTruthV1) -> GroundTruthV1:
        """Store a ground truth record. Raises ValueError on duplicate ID."""
        if gt.ground_truth_id in self._ground_truths:
            raise ValueError(f"Ground truth already exists: {gt.ground_truth_id}")
        self._ground_truths[gt.ground_truth_id] = gt
        return gt

    def get_ground_truth_for_run(self, run_id: str) -> Optional[GroundTruthV1]:
        for gt in self._ground_truths.values():
            if gt.run_id == run_id:
                return gt
        return None

    def list_ground_truths(self) -> List[GroundTruthV1]:
        return list(self._ground_truths.values())


# Module-level singleton
_store_instance: Optional[InMemoryStore] = None


def get_store() -> InMemoryStore:
    """Get or create the global in-memory store instance."""
    global _store_instance
    if _store_instance is None:
        _store_instance = InMemoryStore()
    return _store_instance
