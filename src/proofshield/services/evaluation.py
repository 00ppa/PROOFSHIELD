"""Deterministic assurance engine for diagnostic evaluation.

Architecture Layer 5 — the central component of the research prototype.
Evaluates test runs against scenario expectations using collected evidence
and classifies outcomes into one of seven diagnostic categories.
"""

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.common import (
    DiagnosticCategory,
    ExecutionStatus,
    FailureCategory,
    GroundTruthLabel,
    ValidationTarget,
)
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.store import InMemoryStore, hosts_match


class AssuranceEngine:
    """Deterministic diagnostic engine (Architecture Layer 5).

    Evaluates test runs against scenario expectations using collected evidence.
    Implements the seven diagnostic categories from Section 6:

        PASS, TEST_NOT_EXECUTED, EXPECTED_TELEMETRY_MISSING,
        DETECTION_NOT_TRIGGERED, ALERT_NOT_CORRELATED,
        INCONCLUSIVE, ERROR

    The engine must distinguish confirmed diagnoses from likely explanations.
    It must never classify missing evidence as proof of a particular failure.
    """

    VERSION = "v0.1.0"

    def __init__(
        self,
        store: InMemoryStore,
        default_alert_grace_period_seconds: int = 3600,
    ) -> None:
        self.store = store
        self.default_alert_grace_period_seconds = default_alert_grace_period_seconds

    def evaluate_run(self, run_id: str) -> DiagnosticResultV1:
        """Evaluate a test run and produce a diagnostic result.

        Follows the deterministic evaluation workflow:
        1. Verify run and scenario exist
        2. Check execution status
        3. Correlate telemetry events to the run
        4. Verify expected telemetry presence
        5. Evaluate detection outcomes (if applicable)
        6. Classify the result
        """
        run = self.store.get_run(run_id)
        if run is None:
            return self._error_result(
                run_id=run_id,
                scenario_id="UNKNOWN",
                reason=f"Test run not found: {run_id}",
            )

        scenario = self.store.get_scenario(run.scenario_id)
        if scenario is None:
            return self._error_result(
                run_id=run_id,
                scenario_id=run.scenario_id,
                reason=f"Scenario not found: {run.scenario_id}",
            )

        try:
            return self._evaluate(run, scenario)
        except Exception as exc:
            return self._error_result(
                run_id=run_id,
                scenario_id=run.scenario_id,
                reason=f"Internal evaluation error: {str(exc)}",
            )

    def _evaluate(
        self, run: TestRunV1, scenario: ScenarioV1
    ) -> DiagnosticResultV1:
        """Core deterministic evaluation logic."""

        # ── Step 1: Check execution status ────────────────────────────────
        if run.execution_status == ExecutionStatus.RUNNING:
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.INCONCLUSIVE,
                reason=(
                    "Test execution is still RUNNING; diagnostic evaluation cannot "
                    "conclude until test run status is COMPLETED"
                ),
                confidence="uncertain",
            )

        if run.execution_status in (
            ExecutionStatus.FAILED,
            ExecutionStatus.ERROR,
            ExecutionStatus.PENDING,
        ):
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.TEST_NOT_EXECUTED,
                reason=(
                    f"Test execution reported as {run.execution_status.value} "
                    f"before producing intended behaviour"
                ),
                confidence="definitive",
            )

        # ── Step 2: Correlate events to the run ──────────────────────────
        events = self.store.get_events_for_run(run)

        if not events:
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
                reason=(
                    "No telemetry events observed within the test run "
                    "observation window"
                ),
                confidence="likely",
                diagnostic_reasons=[
                    f"Host: {run.target_host}",
                    f"Window: {run.window_start.isoformat()} to "
                    f"{run.window_end.isoformat()}",
                    "Note: absence of telemetry does not confirm the event "
                    "was never generated",
                ],
            )

        # ── Step 3: Find events matching expected telemetry ──────────────
        matching_events = self._find_matching_events(scenario, events)
        all_evidence_ids = [e.normalized_event_id for e in events]

        if not matching_events:
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
                reason=(
                    "Telemetry events observed but none match the expected "
                    "signature"
                ),
                confidence="likely",
                supporting_evidence=all_evidence_ids,
                diagnostic_reasons=[
                    f"Expected category: {scenario.expected_event_category.value}",
                    f"Expected process: {scenario.expected_process_name or 'any'}",
                    f"Expected pattern: "
                    f"{scenario.expected_command_pattern or 'any'}",
                    f"Events in window: {len(events)} (none matched)",
                    "Note: absence does not confirm the event was never "
                    "generated",
                ],
            )

        matched_evidence_ids = [e.normalized_event_id for e in matching_events]

        # ── Step 4: Check detection outcome ──────────────────────────────
        if scenario.expected_detection_rule_id:
            return self._evaluate_detection(
                run, scenario, matching_events, matched_evidence_ids
            )

        # No detection rule expected — telemetry-only scenario
        if scenario.validation_target == ValidationTarget.EXPECTED_TELEMETRY_ONLY:
            failure_cat, latency_meta, latency_notes = self._compute_latency(
                scenario, matching_events
            )
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.PASS,
                reason=(
                    "Expected telemetry observed (telemetry-only scenario — "
                    "no detection rule expected)"
                ),
                confidence="definitive",
                supporting_evidence=matched_evidence_ids,
                failure_category=failure_cat,
                metadata={"latency": latency_meta} if latency_meta else {},
                diagnostic_reasons=[
                    f"Matched {len(matching_events)} event(s) against "
                    f"expected signature",
                ]
                + latency_notes,
            )

        # Telemetry found but no rule and not telemetry-only
        return self._make_result(
            run=run,
            scenario=scenario,
            category=DiagnosticCategory.INCONCLUSIVE,
            reason=(
                "Expected telemetry observed but no detection rule specified "
                "for evaluation"
            ),
            confidence="uncertain",
            supporting_evidence=matched_evidence_ids,
        )

    def _evaluate_detection(
        self,
        run: TestRunV1,
        scenario: ScenarioV1,
        matching_events: List[NormalizedTelemetryEventV1],
        matched_evidence_ids: List[str],
    ) -> DiagnosticResultV1:
        """Evaluate detection rule outcome after confirming telemetry presence."""

        rule_id = scenario.expected_detection_rule_id

        # Determine configurable alert search window with grace period
        grace_seconds = self.default_alert_grace_period_seconds
        if run.metadata and "alert_grace_period_seconds" in run.metadata:
            try:
                grace_seconds = int(run.metadata["alert_grace_period_seconds"])
            except (ValueError, TypeError):
                grace_seconds = self.default_alert_grace_period_seconds

        grace = timedelta(seconds=grace_seconds)
        search_start = run.window_start - grace
        search_end = run.window_end + grace

        # Query alerts across the monitoring system for this rule within run's time window + grace period
        all_rule_alerts = self.store.list_alerts_for_rule(
            rule_id, window_start=search_start, window_end=search_end
        )

        # Check if there are candidate alerts for this rule on the target host that lack event timestamps
        missing_ts_candidate_alerts = [
            a
            for a in self.store.list_alerts_for_rule(rule_id)
            if a.alert_timestamp is None and hosts_match(run.target_host, a.host_id)
        ]

        # The rule DID fire in the monitoring system — now evaluate correlation to this test run
        correlated_alerts = self._correlate_alerts(run, all_rule_alerts)

        if not correlated_alerts:
            # If an alert for this rule on the target host exists but lacks an event timestamp,
            # detection timing cannot be reliably verified (ingestion time cannot prove detection occurrence).
            # Reliable diagnosis is prevented -> INCONCLUSIVE.
            if missing_ts_candidate_alerts:
                missing_alert_ids = [a.alert_id for a in missing_ts_candidate_alerts]
                return self._make_result(
                    run=run,
                    scenario=scenario,
                    category=DiagnosticCategory.INCONCLUSIVE,
                    reason=(
                        f"Alert from expected rule {rule_id} observed on host {run.target_host} "
                        f"but lacks event timestamp; detection timing cannot be reliably verified"
                    ),
                    confidence="uncertain",
                    supporting_evidence=matched_evidence_ids,
                    contradictory_evidence=missing_alert_ids,
                    diagnostic_reasons=[
                        f"Alert '{a.alert_id}' has no event timestamp; ingestion time "
                        f"({a.ingested_at.isoformat() if a.ingested_at else 'unrecorded'}) is ingestion metadata "
                        f"only and cannot prove detection timing"
                        for a in missing_ts_candidate_alerts
                    ],
                )

            # Compute telemetry pipeline latency for failure diagnostics
            failure_cat, latency_meta, latency_notes = self._compute_latency(
                scenario, matching_events
            )

            if not all_rule_alerts:
                # Rule never triggered anywhere in the monitored environment
                all_alerts_in_window = self.store.get_alerts_for_run(run)
                diagnostic_reasons = [
                    f"Expected rule: {rule_id}",
                    f"Telemetry was present ({len(matching_events)} matched event(s))",
                    f"Rule '{rule_id}' did not trigger any alerts in the monitoring system",
                ]
                if all_alerts_in_window:
                    diagnostic_reasons.append(
                        f"Other rules generated {len(all_alerts_in_window)} alert(s) on this host, "
                        f"but expected rule {rule_id} was silent"
                    )
                else:
                    diagnostic_reasons.append(
                        "Rule may be misconfigured, disabled, or observed telemetry "
                        "did not satisfy rule filter logic"
                    )

                return self._make_result(
                    run=run,
                    scenario=scenario,
                    category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
                    reason=f"Expected detection rule {rule_id} did not trigger",
                    confidence="likely",
                    supporting_evidence=matched_evidence_ids,
                    failure_category=failure_cat,
                    metadata={"latency": latency_meta} if latency_meta else {},
                    diagnostic_reasons=diagnostic_reasons + latency_notes,
                )

            rule_alert_ids = [a.alert_id for a in all_rule_alerts]
            diagnostic_reasons = [
                f"Expected rule {rule_id} triggered {len(all_rule_alerts)} alert(s) in SIEM/monitoring",
                "Host or timestamp correlation failed for this test run",
                f"Test run target: host={run.target_host}, window={run.window_start.isoformat()} to {run.window_end.isoformat()}",
                "Alerts observed with mismatched host or outside execution time window",
            ]
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.ALERT_NOT_CORRELATED,
                reason=(
                    f"Alert from expected rule {rule_id} exists in monitoring system, "
                    f"but could not be correlated to this test run's host or time window"
                ),
                confidence="likely",
                supporting_evidence=matched_evidence_ids,
                contradictory_evidence=rule_alert_ids,
                failure_category=failure_cat,
                metadata={"latency": latency_meta} if latency_meta else {},
                diagnostic_reasons=diagnostic_reasons + latency_notes,
            )

        # Full PASS: telemetry + detection + correlation confirmed
        failure_cat, latency_meta, latency_notes = self._compute_latency(
            scenario, matching_events, correlated_alerts
        )
        alert_ids = [a.alert_id for a in correlated_alerts]
        return self._make_result(
            run=run,
            scenario=scenario,
            category=DiagnosticCategory.PASS,
            reason=(
                "Expected telemetry observed and detection alert verified "
                "and correlated"
            ),
            confidence="definitive",
            supporting_evidence=matched_evidence_ids + alert_ids,
            failure_category=failure_cat,
            metadata={"latency": latency_meta} if latency_meta else {},
            diagnostic_reasons=[
                f"Matched {len(matching_events)} telemetry event(s)",
                f"Correlated {len(correlated_alerts)} alert(s) from rule "
                f"{rule_id}",
            ]
            + latency_notes,
        )

    def _find_matching_events(
        self,
        scenario: ScenarioV1,
        events: List[NormalizedTelemetryEventV1],
    ) -> List[NormalizedTelemetryEventV1]:
        """Find events matching the scenario's expected telemetry signature."""
        matched = []
        for event in events:
            # Category must match
            if event.event_category != scenario.expected_event_category:
                continue

            # Process name check (case-insensitive) if specified
            if scenario.expected_process_name:
                if not event.process_name:
                    continue
                if (
                    event.process_name.lower()
                    != scenario.expected_process_name.lower()
                ):
                    continue

            # Command pattern check if specified
            if scenario.expected_command_pattern:
                if not event.command_line:
                    continue
                try:
                    if not re.search(
                        scenario.expected_command_pattern, event.command_line
                    ):
                        continue
                except re.error:
                    # If the pattern is not valid regex, try substring match
                    if scenario.expected_command_pattern not in event.command_line:
                        continue

            matched.append(event)

        return matched

    def _correlate_alerts(
        self, run: TestRunV1, alerts: List[AlertV1]
    ) -> List[AlertV1]:
        """Check if alerts correlate to the test run by host and time window."""
        correlated = []
        for alert in alerts:
            if hosts_match(run.target_host, alert.host_id):
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
                    correlated.append(alert)
        return sorted(
            correlated,
            key=lambda a: (
                a.alert_timestamp or datetime.min.replace(tzinfo=timezone.utc),
                a.alert_id,
            ),
        )

    def _make_result(
        self,
        run: TestRunV1,
        scenario: ScenarioV1,
        category: DiagnosticCategory,
        reason: str,
        confidence: str = "definitive",
        supporting_evidence: Optional[List[str]] = None,
        contradictory_evidence: Optional[List[str]] = None,
        diagnostic_reasons: Optional[List[str]] = None,
        failure_category: Optional[FailureCategory] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DiagnosticResultV1:
        """Construct a DiagnosticResultV1 with consistent formatting."""
        return DiagnosticResultV1(
            diagnostic_id=f"DIAG-{uuid.uuid4().hex[:12].upper()}",
            test_run_id=run.run_id,
            scenario_id=scenario.scenario_id,
            predicted_category=category,
            failure_category=failure_category,
            confidence=confidence,
            reason=reason,
            diagnostic_reasons=diagnostic_reasons or [],
            supporting_evidence_ids=supporting_evidence or [],
            contradictory_evidence_ids=contradictory_evidence or [],
            evaluated_at=datetime.now(timezone.utc),
            engine_version=self.VERSION,
            metadata=metadata or {},
        )

    def _compute_latency(
        self,
        scenario: ScenarioV1,
        matching_events: List[NormalizedTelemetryEventV1],
        correlated_alerts: Optional[List[AlertV1]] = None,
    ) -> Tuple[Optional[FailureCategory], Dict[str, Any], List[str]]:
        """Compute pipeline and detection latency only when required timestamps are available with clear meanings.

        Never infers latency from unrelated timestamps (e.g. test run scheduling windows).
        """
        latency_metadata: Dict[str, Any] = {}
        diagnostic_notes: List[str] = []
        failure_cat: Optional[FailureCategory] = None

        if not matching_events:
            return None, latency_metadata, diagnostic_notes

        primary_event = matching_events[0]
        raw_event = self.store.get_raw_event(primary_event.raw_event_id)

        # 1. Telemetry pipeline latency: action (source_timestamp) -> ingestion (raw_event.ingested_at)
        if (
            raw_event is not None
            and raw_event.ingested_at is not None
            and primary_event.source_timestamp is not None
        ):
            t_src = primary_event.source_timestamp
            t_ing = raw_event.ingested_at
            if t_src.tzinfo is not None and t_ing.tzinfo is None:
                t_ing = t_ing.replace(tzinfo=t_src.tzinfo)
            elif t_src.tzinfo is None and t_ing.tzinfo is not None:
                t_src = t_src.replace(tzinfo=t_ing.tzinfo)

            pipeline_latency = (t_ing - t_src).total_seconds()
            latency_exceeded = pipeline_latency > scenario.max_acceptable_latency_seconds

            latency_metadata["telemetry_pipeline_latency_seconds"] = round(pipeline_latency, 3)
            latency_metadata["max_acceptable_latency_seconds"] = scenario.max_acceptable_latency_seconds
            latency_metadata["latency_exceeded"] = latency_exceeded

            if latency_exceeded:
                failure_cat = FailureCategory.PIPELINE_LATENCY
                diagnostic_notes.append(
                    f"Telemetry pipeline latency ({pipeline_latency:.1f}s) exceeded max acceptable threshold ({scenario.max_acceptable_latency_seconds}s)"
                )
        else:
            latency_metadata["telemetry_pipeline_latency"] = {
                "status": "unavailable",
                "reason": "Required raw event ingestion timestamp or event source timestamp not available; latency was not inferred.",
            }

        # 2. Detection latency: action (source_timestamp) -> alert generation (alert.alert_timestamp)
        if correlated_alerts and primary_event.source_timestamp is not None:
            first_alert = correlated_alerts[0]
            if first_alert.alert_timestamp is not None:
                t_src = primary_event.source_timestamp
                t_alt = first_alert.alert_timestamp
                if t_src.tzinfo is not None and t_alt.tzinfo is None:
                    t_alt = t_alt.replace(tzinfo=t_src.tzinfo)
                elif t_src.tzinfo is None and t_alt.tzinfo is not None:
                    t_src = t_src.replace(tzinfo=t_alt.tzinfo)

                detection_latency = (t_alt - t_src).total_seconds()
                latency_metadata["detection_latency_seconds"] = round(detection_latency, 3)
            else:
                latency_metadata["detection_latency"] = {
                    "status": "unavailable",
                    "reason": "Alert lacks alert_timestamp; detection latency cannot be reliably calculated.",
                }

        return failure_cat, latency_metadata, diagnostic_notes

    def _error_result(
        self,
        run_id: str,
        scenario_id: str,
        reason: str,
    ) -> DiagnosticResultV1:
        """Construct an ERROR diagnostic result."""
        return DiagnosticResultV1(
            diagnostic_id=f"DIAG-{uuid.uuid4().hex[:12].upper()}",
            test_run_id=run_id,
            scenario_id=scenario_id,
            predicted_category=DiagnosticCategory.ERROR,
            confidence="definitive",
            reason=reason,
            evaluated_at=datetime.now(timezone.utc),
            engine_version=self.VERSION,
        )
