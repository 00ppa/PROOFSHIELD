"""In-memory data store for PROOFSHIELD entities.

Thread-unsafe singleton store for development and testing. Provides CRUD
operations and time-window-based event correlation. Will be replaced by
PostgreSQL-backed storage when the core data model stabilises.
"""

from contextlib import contextmanager
from copy import deepcopy
from collections.abc import Mapping, Sequence, Set
from datetime import datetime, timezone
import ipaddress
import threading
from typing import Any, Dict, Generator, List, Optional, Union
from pydantic import BaseModel

from proofshield.normalisation.engine import extract_execution_token
from proofshield.schemas.alert import AlertV1
from proofshield.schemas.assurance_report import CampaignAssuranceReportV1
from proofshield.schemas.campaign import CampaignDefinitionV1, CampaignRunV1
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.execution import ExecutionEvidenceV1
from proofshield.schemas.explanation import AnalystExplanationV1
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1, RawTelemetryEventV1
from proofshield.config import StorageBackend, get_settings
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.base_store import StoreProtocol, to_comparable_utc


class _ReadOnlyMapping(Mapping):
    """Lazy read-only view over a mapping held by a stored Pydantic model."""

    __slots__ = ("_value",)

    def __init__(self, value: Mapping) -> None:
        object.__setattr__(self, "_value", value)

    def __getitem__(self, key: Any) -> Any:
        return _readonly_value(self._value[key])

    def __iter__(self):
        return iter(self._value)

    def __len__(self) -> int:
        return len(self._value)


class _ReadOnlySequence(Sequence):
    """Lazy read-only view over a list or tuple in evidence payloads."""

    __slots__ = ("_value",)

    def __init__(self, value: Sequence) -> None:
        object.__setattr__(self, "_value", value)

    def __getitem__(self, index):
        value = self._value[index]
        if isinstance(index, slice):
            return tuple(_readonly_value(item) for item in value)
        return _readonly_value(value)

    def __iter__(self):
        return (_readonly_value(item) for item in self._value)

    def __len__(self) -> int:
        return len(self._value)


class _ReadOnlySet(Set):
    """Lazy read-only view over a set in an evidence payload."""

    __slots__ = ("_value",)

    def __init__(self, value: Set) -> None:
        object.__setattr__(self, "_value", value)

    def __contains__(self, value: Any) -> bool:
        return value in self._value

    def __iter__(self):
        return (_readonly_value(item) for item in self._value)

    def __len__(self) -> int:
        return len(self._value)


class _ReadOnlyModelView:
    """Attribute-read-only view over a stored Pydantic model."""

    __slots__ = ("__dict__",)

    def __init__(self, model: Any, fields: Sequence[str]) -> None:
        values = dict(model.__dict__)
        for field in fields:
            values[field] = _readonly_value(getattr(model, field))
        object.__setattr__(self, "__dict__", values)

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError("read-only evidence view cannot be modified")

    def __delattr__(self, name: str) -> None:
        raise TypeError("read-only evidence view cannot be modified")


def _readonly_value(value: Any) -> Any:
    """Return a lazy immutable view for nested evidence values."""
    if isinstance(value, BaseModel):
        return _ReadOnlyModelView(value, tuple(type(value).model_fields))
    if isinstance(value, Mapping):
        return _ReadOnlyMapping(value)
    if isinstance(value, (list, tuple)):
        return _ReadOnlySequence(value)
    if isinstance(value, (set, frozenset)):
        return _ReadOnlySet(value)
    return value


def _readonly_model(model: Any, fields: Sequence[str]) -> Any:
    """Make an attribute-read-only snapshot with immutable payload fields."""
    return _ReadOnlyModelView(model, fields)


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
        self._lock = threading.RLock()
        self._scenarios: Dict[str, ScenarioV1] = {}
        self._runs: Dict[str, TestRunV1] = {}
        self._raw_events: Dict[str, RawTelemetryEventV1] = {}
        self._normalized_events: Dict[str, NormalizedTelemetryEventV1] = {}
        self._rules: Dict[str, DetectionRuleV1] = {}
        self._alerts: Dict[str, AlertV1] = {}
        self._results: Dict[str, DiagnosticResultV1] = {}
        self._explanations: Dict[str, AnalystExplanationV1] = {}
        self._ground_truths: Dict[str, GroundTruthV1] = {}
        self._campaigns: Dict[str, CampaignDefinitionV1] = {}
        self._campaign_runs: Dict[str, CampaignRunV1] = {}
        self._assurance_reports: Dict[str, CampaignAssuranceReportV1] = {}
        self._executions: Dict[str, ExecutionEvidenceV1] = {}

    def reset(self) -> None:
        """Clear all stored data. Used for test isolation."""
        with self._lock:
            self._scenarios.clear()
            self._runs.clear()
            self._raw_events.clear()
            self._normalized_events.clear()
            self._rules.clear()
            self._alerts.clear()
            self._results.clear()
            self._explanations.clear()
            self._ground_truths.clear()
            self._campaigns.clear()
            self._campaign_runs.clear()
            self._assurance_reports.clear()
            self._executions.clear()

    def close(self) -> None:
        """No-op close method to satisfy store lifecycle uniformity."""
        pass

    @contextmanager
    def transaction(self) -> Generator[None, None, None]:
        """Context manager for atomic transaction management.

        Snapshots store state and rolls back all mutations if an exception occurs.
        Thread-safe: serializes concurrent transactions to prevent rollback clobbering.
        """
        with self._lock:
            snapshot = {
                "scenarios": deepcopy(self._scenarios),
                "runs": deepcopy(self._runs),
                "raw_events": deepcopy(self._raw_events),
                "normalized_events": deepcopy(self._normalized_events),
                "rules": deepcopy(self._rules),
                "alerts": deepcopy(self._alerts),
                "results": deepcopy(self._results),
                "explanations": deepcopy(self._explanations),
                "ground_truths": deepcopy(self._ground_truths),
                "campaigns": deepcopy(self._campaigns),
                "campaign_runs": deepcopy(self._campaign_runs),
                "assurance_reports": deepcopy(self._assurance_reports),
                "executions": deepcopy(self._executions),
            }
            try:
                yield
            except Exception:
                self._scenarios = snapshot["scenarios"]
                self._runs = snapshot["runs"]
                self._raw_events = snapshot["raw_events"]
                self._normalized_events = snapshot["normalized_events"]
                self._rules = snapshot["rules"]
                self._alerts = snapshot["alerts"]
                self._results = snapshot["results"]
                self._explanations = snapshot["explanations"]
                self._ground_truths = snapshot["ground_truths"]
                self._campaigns = snapshot["campaigns"]
                self._campaign_runs = snapshot["campaign_runs"]
                self._assurance_reports = snapshot["assurance_reports"]
                self._executions = snapshot["executions"]
                raise

    # ── Scenarios ─────────────────────────────────────────────────────────

    def add_scenario(self, scenario: ScenarioV1) -> ScenarioV1:
        """Register a scenario. Raises ValueError on duplicate ID."""
        with self._lock:
            if scenario.scenario_id in self._scenarios:
                raise ValueError(f"Scenario already exists: {scenario.scenario_id}")
            stored = scenario.model_copy(deep=True)
            self._scenarios[scenario.scenario_id] = stored
            return stored.model_copy(deep=True)

    def get_scenario(self, scenario_id: str) -> Optional[ScenarioV1]:
        with self._lock:
            item = self._scenarios.get(scenario_id)
            return item.model_copy(deep=True) if item else None

    def list_scenarios(self) -> List[ScenarioV1]:
        with self._lock:
            return [item.model_copy(deep=True) for item in self._scenarios.values()]

    # ── Test Runs ─────────────────────────────────────────────────────────

    def add_run(self, run: TestRunV1) -> TestRunV1:
        """Record a test run. Raises ValueError on duplicate or missing scenario."""
        with self._lock:
            if run.run_id in self._runs:
                raise ValueError(f"Run already exists: {run.run_id}")
            if run.scenario_id not in self._scenarios:
                raise ValueError(f"Scenario not found: {run.scenario_id}")
            stored = run.model_copy(deep=True)
            self._runs[run.run_id] = stored
            return stored.model_copy(deep=True)

    def get_run(self, run_id: str) -> Optional[TestRunV1]:
        with self._lock:
            item = self._runs.get(run_id)
            return item.model_copy(deep=True) if item else None

    def list_runs(self, scenario_id: Optional[str] = None) -> List[TestRunV1]:
        with self._lock:
            runs = list(self._runs.values())
            if scenario_id:
                runs = [r for r in runs if r.scenario_id == scenario_id]
            return [item.model_copy(deep=True) for item in runs]

    # ── Raw Events ────────────────────────────────────────────────────────

    def add_raw_event(self, event: RawTelemetryEventV1) -> RawTelemetryEventV1:
        """Store a raw event. Raises ValueError on duplicate ID."""
        with self._lock:
            if event.raw_event_id in self._raw_events:
                raise ValueError(f"Raw event already exists: {event.raw_event_id}")
            stored = event.model_copy(deep=True)
            self._raw_events[event.raw_event_id] = stored
            return stored.model_copy(deep=True)

    def get_raw_event(self, raw_event_id: str) -> Optional[RawTelemetryEventV1]:
        with self._lock:
            item = self._raw_events.get(raw_event_id)
            return item.model_copy(deep=True) if item else None

    def list_raw_events(self) -> List[RawTelemetryEventV1]:
        with self._lock:
            return [item.model_copy(deep=True) for item in self._raw_events.values()]

    # ── Normalized Events ─────────────────────────────────────────────────

    def add_normalized_event(
        self, event: NormalizedTelemetryEventV1
    ) -> NormalizedTelemetryEventV1:
        """Store a normalized event. Raises ValueError on duplicate ID."""
        with self._lock:
            if event.normalized_event_id in self._normalized_events:
                raise ValueError(
                    f"Normalized event already exists: {event.normalized_event_id}"
                )
            stored = event.model_copy(deep=True)
            self._normalized_events[event.normalized_event_id] = stored
            return stored.model_copy(deep=True)

    def get_normalized_event(
        self, event_id: str
    ) -> Optional[NormalizedTelemetryEventV1]:
        with self._lock:
            item = self._normalized_events.get(event_id)
            return item.model_copy(deep=True) if item else None

    def list_normalized_events(self) -> List[NormalizedTelemetryEventV1]:
        with self._lock:
            return [item.model_copy(deep=True) for item in self._normalized_events.values()]

    def get_events_for_run(
        self, run: TestRunV1, copy: bool = True
    ) -> List[NormalizedTelemetryEventV1]:
        """Correlate normalized events to a test run by host and time window.

        Returns events where host matches via hosts_match() and the
        normalized_timestamp falls within [window_start, window_end].
        Results are sorted chronologically and deterministically. ``copy=False``
        returns isolated snapshots for internal evaluation without exposing
        stored model instances or mutable nested payloads.
        """
        with self._lock:
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
            ordered = sorted(
                matched,
                key=lambda e: (
                    e.normalized_timestamp or datetime.min.replace(tzinfo=timezone.utc),
                    e.normalized_event_id,
                ),
            )
            if copy:
                return [item.model_copy(deep=True) for item in ordered]
            return [
                _readonly_model(item, ("hashes", "extra_attributes"))
                for item in ordered
            ]

    # ── Detection Rules ───────────────────────────────────────────────────

    def add_rule(self, rule: DetectionRuleV1) -> DetectionRuleV1:
        """Register a detection rule. Raises ValueError on duplicate ID."""
        with self._lock:
            if rule.rule_id in self._rules:
                raise ValueError(f"Rule already exists: {rule.rule_id}")
            stored = rule.model_copy(deep=True)
            self._rules[rule.rule_id] = stored
            return stored.model_copy(deep=True)

    def get_rule(self, rule_id: str) -> Optional[DetectionRuleV1]:
        with self._lock:
            item = self._rules.get(rule_id)
            return item.model_copy(deep=True) if item else None

    def list_rules(self) -> List[DetectionRuleV1]:
        with self._lock:
            return [item.model_copy(deep=True) for item in self._rules.values()]

    # ── Alerts ────────────────────────────────────────────────────────────

    def add_alert(self, alert: AlertV1) -> AlertV1:
        """Store an alert. Raises ValueError on duplicate ID."""
        with self._lock:
            if alert.alert_id in self._alerts:
                raise ValueError(f"Alert already exists: {alert.alert_id}")
            stored = alert.model_copy(deep=True)
            if stored.ingested_at is None:
                stored.ingested_at = datetime.now(timezone.utc)
            if stored.alert_timestamp is None:
                stored.metadata["ingestion_time_only"] = True
            token = extract_execution_token(
                payload=stored.metadata,
                explicit_token=stored.execution_token,
                text_fields=[stored.alert_title],
            )
            stored.execution_token = token
            self._alerts[stored.alert_id] = stored
            return stored.model_copy(deep=True)

    def get_alert(self, alert_id: str) -> Optional[AlertV1]:
        with self._lock:
            item = self._alerts.get(alert_id)
            return item.model_copy(deep=True) if item else None

    def list_alerts(self) -> List[AlertV1]:
        with self._lock:
            return [item.model_copy(deep=True) for item in self._alerts.values()]

    def list_alerts_for_rule(
        self,
        rule_id: str,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        copy: bool = True,
    ) -> List[AlertV1]:
        """Return alerts, optionally bounded by time.

        ``copy=False`` returns isolated snapshots for internal evaluation.
        """
        with self._lock:
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
            ordered = sorted(
                matched,
                key=lambda a: (
                    a.alert_timestamp or datetime.min.replace(tzinfo=timezone.utc),
                    a.alert_id,
                ),
            )
            if copy:
                return [item.model_copy(deep=True) for item in ordered]
            return [_readonly_model(item, ("metadata",)) for item in ordered]

    def get_alerts_for_run(self, run: TestRunV1, copy: bool = True) -> List[AlertV1]:
        """Correlate alerts to a test run by host and time window.

        Returns alerts where host_id matches via hosts_match() and the
        alert_timestamp falls within [window_start, window_end].
        Results are sorted chronologically and deterministically. ``copy=False``
        returns isolated snapshots for internal evaluation.
        """
        with self._lock:
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
            ordered = sorted(
                matched,
                key=lambda a: (
                    a.alert_timestamp or datetime.min.replace(tzinfo=timezone.utc),
                    a.alert_id,
                ),
            )
            if copy:
                return [item.model_copy(deep=True) for item in ordered]
            return [_readonly_model(item, ("metadata",)) for item in ordered]

    # ── Diagnostic Results ────────────────────────────────────────────────

    def add_result(self, result: DiagnosticResultV1) -> DiagnosticResultV1:
        """Store a diagnostic result. Overwrites previous result for same run."""
        with self._lock:
            self._results[result.diagnostic_id] = result.model_copy(deep=True)
            return result.model_copy(deep=True)

    def get_result(self, result_id: str) -> Optional[DiagnosticResultV1]:
        with self._lock:
            result = self._results.get(result_id)
            return result.model_copy(deep=True) if result else None

    def get_result_for_run(self, run_id: str) -> Optional[DiagnosticResultV1]:
        """Return the most recent diagnostic result for a test run."""
        with self._lock:
            for result in reversed(list(self._results.values())):
                if result.test_run_id == run_id:
                    return result.model_copy(deep=True)
            return None

    def list_results(self) -> List[DiagnosticResultV1]:
        with self._lock:
            return [item.model_copy(deep=True) for item in self._results.values()]

    # ── Analyst Explanations ───────────────────────────────────────────────

    def add_explanation(self, explanation: AnalystExplanationV1) -> AnalystExplanationV1:
        with self._lock:
            if explanation.explanation_id in self._explanations:
                raise ValueError(f"Explanation already exists: {explanation.explanation_id}")
            self._explanations[explanation.explanation_id] = explanation.model_copy(deep=True)
            return explanation.model_copy(deep=True)

    def get_explanation(self, explanation_id: str) -> Optional[AnalystExplanationV1]:
        with self._lock:
            item = self._explanations.get(explanation_id)
            return item.model_copy(deep=True) if item else None

    def list_explanations(self, run_id: Optional[str] = None) -> List[AnalystExplanationV1]:
        with self._lock:
            values = list(self._explanations.values())
            if run_id is not None:
                values = [item for item in values if item.test_run_id == run_id]
            return [item.model_copy(deep=True) for item in values]

    # ── Ground Truth ──────────────────────────────────────────────────────

    def add_ground_truth(self, gt: GroundTruthV1) -> GroundTruthV1:
        """Store a ground truth record. Raises ValueError on duplicate ID."""
        with self._lock:
            if gt.ground_truth_id in self._ground_truths:
                raise ValueError(f"Ground truth already exists: {gt.ground_truth_id}")
            stored = gt.model_copy(deep=True)
            self._ground_truths[gt.ground_truth_id] = stored
            return stored.model_copy(deep=True)

    def get_ground_truth_for_run(self, run_id: str) -> Optional[GroundTruthV1]:
        with self._lock:
            for gt in self._ground_truths.values():
                if gt.run_id == run_id:
                    return gt.model_copy(deep=True)
            return None

    def list_ground_truths(self) -> List[GroundTruthV1]:
        with self._lock:
            return [item.model_copy(deep=True) for item in self._ground_truths.values()]

    # ── Campaigns ─────────────────────────────────────────────────────────

    def add_campaign(self, campaign: CampaignDefinitionV1) -> CampaignDefinitionV1:
        """Register a campaign definition. Raises ValueError on duplicate ID."""
        with self._lock:
            if campaign.campaign_id in self._campaigns:
                raise ValueError(f"Campaign already exists: {campaign.campaign_id}")
            self._campaigns[campaign.campaign_id] = campaign.model_copy(deep=True)
            return campaign.model_copy(deep=True)

    def get_campaign(self, campaign_id: str) -> Optional[CampaignDefinitionV1]:
        """Retrieve a campaign definition by its identifier (returns immutable deep copy)."""
        with self._lock:
            item = self._campaigns.get(campaign_id)
            return item.model_copy(deep=True) if item else None

    def list_campaigns(self) -> List[CampaignDefinitionV1]:
        """List all registered campaign definitions, ordered deterministically by creation timestamp."""
        with self._lock:
            sorted_items = sorted(
                list(self._campaigns.values()),
                key=lambda c: to_comparable_utc(c.created_at),
            )
            return [c.model_copy(deep=True) for c in sorted_items]

    # ── Campaign Runs ─────────────────────────────────────────────────────

    def add_campaign_run(self, run: CampaignRunV1) -> CampaignRunV1:
        """Record an executed campaign run. Raises ValueError on duplicate ID or missing campaign."""
        with self._lock:
            if run.run_id in self._campaign_runs:
                raise ValueError(f"Campaign run already exists: {run.run_id}")
            if run.campaign_id not in self._campaigns:
                raise ValueError(f"Campaign not found: {run.campaign_id}")
            self._campaign_runs[run.run_id] = run.model_copy(deep=True)
            return run.model_copy(deep=True)

    def get_campaign_run(self, run_id: str) -> Optional[CampaignRunV1]:
        """Retrieve an executed campaign run by its identifier (returns immutable deep copy)."""
        with self._lock:
            item = self._campaign_runs.get(run_id)
            return item.model_copy(deep=True) if item else None

    def list_campaign_runs(
        self, campaign_id: Optional[str] = None
    ) -> List[CampaignRunV1]:
        """List campaign runs, optionally filtered by campaign ID, ordered by start time."""
        with self._lock:
            runs = list(self._campaign_runs.values())
            if campaign_id is not None:
                runs = [r for r in runs if r.campaign_id == campaign_id]
            sorted_runs = sorted(runs, key=lambda r: to_comparable_utc(r.started_at))
            return [r.model_copy(deep=True) for r in sorted_runs]

    # ── Campaign Assurance Reports ────────────────────────────────────────

    def add_assurance_report(
        self, report: CampaignAssuranceReportV1
    ) -> CampaignAssuranceReportV1:
        """Record an assurance report. Raises ValueError on duplicate ID or missing campaign run."""
        with self._lock:
            if report.report_id in self._assurance_reports:
                raise ValueError(f"Assurance report already exists: {report.report_id}")
            if report.campaign_id not in self._campaigns:
                raise ValueError(f"Campaign not found: {report.campaign_id}")
            if report.campaign_run_id not in self._campaign_runs:
                raise ValueError(f"Campaign run not found: {report.campaign_run_id}")
            self._assurance_reports[report.report_id] = report.model_copy(deep=True)
            return report.model_copy(deep=True)

    def get_assurance_report(
        self, report_id: str
    ) -> Optional[CampaignAssuranceReportV1]:
        """Retrieve an assurance report by its identifier (returns immutable deep copy)."""
        with self._lock:
            item = self._assurance_reports.get(report_id)
            return item.model_copy(deep=True) if item else None

    def list_assurance_reports(
        self, campaign_id: Optional[str] = None, run_id: Optional[str] = None
    ) -> List[CampaignAssuranceReportV1]:
        """List assurance reports, optionally filtered by campaign ID or run ID, ordered by generation time."""
        with self._lock:
            reports = list(self._assurance_reports.values())
            if campaign_id is not None:
                reports = [r for r in reports if r.campaign_id == campaign_id]
            if run_id is not None:
                reports = [r for r in reports if r.campaign_run_id == run_id]
            sorted_reports = sorted(reports, key=lambda r: to_comparable_utc(r.generated_at))
            return [r.model_copy(deep=True) for r in sorted_reports]

    # ── Execution Records ──────────────────────────────────────────────────

    def add_execution(self, execution: ExecutionEvidenceV1) -> ExecutionEvidenceV1:
        """Store an execution evidence record. Raises ValueError on duplicate ID."""
        with self._lock:
            if execution.execution_id in self._executions:
                raise ValueError(f"Execution record already exists: {execution.execution_id}")
            self._executions[execution.execution_id] = execution.model_copy(deep=True)
            return execution.model_copy(deep=True)

    def get_execution(self, execution_id: str) -> Optional[ExecutionEvidenceV1]:
        """Retrieve an execution evidence record by its identifier."""
        with self._lock:
            rec = self._executions.get(execution_id)
            return rec.model_copy(deep=True) if rec else None

    def list_executions(
        self,
        scenario_id: Optional[str] = None,
        run_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[ExecutionEvidenceV1]:
        """List execution evidence records, optionally filtered."""
        with self._lock:
            results = list(self._executions.values())
            if scenario_id is not None:
                results = [r for r in results if r.scenario_id == scenario_id]
            if run_id is not None:
                results = [r for r in results if r.test_run_id == run_id]
            if status is not None:
                status_str = status.value if hasattr(status, "value") else str(status)
                results = [
                    r for r in results
                    if (r.status.value if hasattr(r.status, "value") else str(r.status)) == status_str
                ]
            results.sort(key=lambda r: to_comparable_utc(r.started_at))
            return [r.model_copy(deep=True) for r in results]


# Module-level singleton and initialization lock
_store_lock = threading.Lock()
_store_instance: Optional[StoreProtocol] = None


def get_store() -> StoreProtocol:
    """Get or create the global store instance based on active configuration.

    Default backend: InMemoryStore.
    If configured for SQLite: SQLiteStore with configured path.
    Startup/configuration failures raise immediately and NEVER silently fall back.
    Thread-safe double-checked locking prevents concurrent initialization races.
    """
    global _store_instance
    if _store_instance is None:
        with _store_lock:
            if _store_instance is None:
                settings = get_settings()
                if settings.storage_backend == StorageBackend.MEMORY:
                    _store_instance = InMemoryStore()
                elif settings.storage_backend == StorageBackend.SQLITE:
                    from proofshield.services.sqlite_store import SQLiteStore
                    _store_instance = SQLiteStore(settings.sqlite_path)
    return _store_instance


def set_store(store: Optional[StoreProtocol]) -> None:
    """Set or override the global store instance. Used for testing or custom lifecycles."""
    global _store_instance
    with _store_lock:
        if _store_instance is not None and _store_instance is not store:
            if hasattr(_store_instance, "close"):
                try:
                    _store_instance.close()
                except Exception:
                    pass
        _store_instance = store


def close_store() -> None:
    """Close and clean up the active store instance if it supports close()."""
    global _store_instance
    with _store_lock:
        if _store_instance is not None:
            if hasattr(_store_instance, "close"):
                try:
                    _store_instance.close()
                except Exception:
                    pass
            _store_instance = None


def reset_store() -> None:
    """Close and reset the active store singleton, forcing re-creation on next get_store()."""
    close_store()
    from proofshield.config import reset_settings
    reset_settings()
