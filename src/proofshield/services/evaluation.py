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
    AttributionStatus,
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


def _is_in_window(ts: Optional[datetime], w_start: datetime, w_end: datetime) -> bool:
    """Check if timestamp falls within [w_start, w_end] accounting for timezone differences."""
    if ts is None:
        return False
    if ts.tzinfo is not None and w_start.tzinfo is None:
        w_start = w_start.replace(tzinfo=ts.tzinfo)
        w_end = w_end.replace(tzinfo=ts.tzinfo)
    elif ts.tzinfo is None and w_start.tzinfo is not None:
        ts = ts.replace(tzinfo=w_start.tzinfo)
    return w_start <= ts <= w_end


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
        strict_attribution: bool = False,
    ) -> None:
        self.store = store
        self.default_alert_grace_period_seconds = default_alert_grace_period_seconds
        self.strict_attribution = strict_attribution

    def evaluate_run(
        self, run_id: str, strict_attribution: Optional[bool] = None
    ) -> DiagnosticResultV1:
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

        # Resolve strict attribution setting: parameter overrides run.metadata overrides engine default
        if strict_attribution is not None:
            is_strict = strict_attribution
        elif run.metadata and "strict_attribution" in run.metadata:
            val = run.metadata["strict_attribution"]
            is_strict = bool(val) and str(val).lower() not in ("false", "0")
        else:
            is_strict = self.strict_attribution

        try:
            return self._evaluate(run, scenario, is_strict=is_strict)
        except Exception as exc:
            return self._error_result(
                run_id=run_id,
                scenario_id=run.scenario_id,
                reason=f"Internal evaluation error: {str(exc)}",
            )

    def _build_attribution_metadata(
        self,
        run_token: Optional[str],
        status: str,
        is_strict: bool,
        events: Optional[List[NormalizedTelemetryEventV1]] = None,
        alerts: Optional[List[AlertV1]] = None,
        mismatched_alerts: Optional[List[AlertV1]] = None,
        notes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Construct structured attribution metadata without claiming cryptographic proof."""
        telemetry_tokens = {}
        if events:
            for e in events:
                telemetry_tokens[e.normalized_event_id] = e.execution_token

        alert_tokens = {}
        if alerts:
            for a in alerts:
                alert_tokens[a.alert_id] = a.execution_token

        mismatched_ids = [a.alert_id for a in (mismatched_alerts or [])]

        return {
            "status": status,
            "strict_attribution": is_strict,
            "run_execution_token": run_token,
            "telemetry_tokens": telemetry_tokens,
            "alert_tokens": alert_tokens,
            "mismatched_alert_ids": mismatched_ids,
            "cryptographic_proof": False,
            "provenance_assurance": "token_attribution",
            "disclaimer": (
                "Token attribution provides execution provenance linking via correlated execution tokens; "
                "it does not constitute or claim cryptographic proof."
            ),
            "attribution_notes": notes or [],
        }

    def _has_valid_timestamped_alert(
        self,
        run: TestRunV1,
        alerts: List[AlertV1],
        is_strict: bool,
        run_token: Optional[str],
    ) -> bool:
        """Check if at least one candidate alert has a valid timestamp and correlates."""
        for a in alerts:
            if a.alert_timestamp is not None and hosts_match(run.target_host, a.host_id):
                if not is_strict:
                    if _is_in_window(a.alert_timestamp, run.window_start, run.window_end):
                        return True
                else:
                    if run_token and a.execution_token == run_token and _is_in_window(a.alert_timestamp, run.window_start, run.window_end):
                        return True
        return False

    def _evaluate(
        self, run: TestRunV1, scenario: ScenarioV1, is_strict: bool = False
    ) -> DiagnosticResultV1:
        """Core deterministic evaluation logic."""

        # Resolve execution token for run
        run_token = run.execution_token
        if not run_token and run.metadata and "execution_token" in run.metadata:
            val = str(run.metadata["execution_token"]).strip()
            if val:
                run_token = val

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
                metadata={
                    "attribution": self._build_attribution_metadata(
                        run_token=run_token,
                        status=AttributionStatus.INCONCLUSIVE.value if is_strict else AttributionStatus.NOT_REQUESTED.value,
                        is_strict=is_strict,
                        notes=["Evaluation deferred while run status is RUNNING"],
                    )
                },
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
                metadata={
                    "attribution": self._build_attribution_metadata(
                        run_token=run_token,
                        status=AttributionStatus.UNATTRIBUTED.value if is_strict else AttributionStatus.NOT_REQUESTED.value,
                        is_strict=is_strict,
                    )
                },
            )

        # Strict attribution check on test run
        if is_strict:
            if not run_token:
                return self._make_result(
                    run=run,
                    scenario=scenario,
                    category=DiagnosticCategory.INCONCLUSIVE,
                    reason=(
                        "Strict attribution requested but test run lacks an execution token; "
                        "causal provenance cannot be verified"
                    ),
                    confidence="uncertain",
                    metadata={
                        "attribution": self._build_attribution_metadata(
                            run_token=None,
                            status=AttributionStatus.INCONCLUSIVE.value,
                            is_strict=True,
                            notes=["Missing execution token on test run"],
                        )
                    },
                )
            if run_token == "CONFLICT":
                return self._make_result(
                    run=run,
                    scenario=scenario,
                    category=DiagnosticCategory.INCONCLUSIVE,
                    reason="Conflicting execution token on test run; causal provenance cannot be verified",
                    confidence="uncertain",
                    metadata={
                        "attribution": self._build_attribution_metadata(
                            run_token="CONFLICT",
                            status=AttributionStatus.CONFLICT.value,
                            is_strict=True,
                            notes=["Conflicting execution token on test run"],
                        )
                    },
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
                    f"Window: {run.window_start.isoformat()} to {run.window_end.isoformat()}",
                    "Note: absence of telemetry does not confirm the event was never generated",
                ],
                metadata={
                    "attribution": self._build_attribution_metadata(
                        run_token=run_token,
                        status=AttributionStatus.UNATTRIBUTED.value if is_strict else AttributionStatus.NOT_REQUESTED.value,
                        is_strict=is_strict,
                    )
                },
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
                    "Telemetry events observed but none match the expected signature"
                ),
                confidence="likely",
                supporting_evidence=all_evidence_ids,
                diagnostic_reasons=[
                    f"Expected category: {scenario.expected_event_category.value}",
                    f"Expected process: {scenario.expected_process_name or 'any'}",
                    f"Expected pattern: {scenario.expected_command_pattern or 'any'}",
                    f"Events in window: {len(events)} (none matched)",
                    "Note: absence does not confirm the event was never generated",
                ],
                metadata={
                    "attribution": self._build_attribution_metadata(
                        run_token=run_token,
                        status=AttributionStatus.UNATTRIBUTED.value if is_strict else AttributionStatus.NOT_REQUESTED.value,
                        is_strict=is_strict,
                        events=events,
                    )
                },
            )

        # Strict attribution check on candidate matching events
        if is_strict:
            conflict_events = [e for e in matching_events if e.execution_token == "CONFLICT"]
            if conflict_events:
                return self._make_result(
                    run=run,
                    scenario=scenario,
                    category=DiagnosticCategory.INCONCLUSIVE,
                    reason=(
                        "Candidate telemetry event carries conflicting execution tokens; "
                        "attribution cannot be verified"
                    ),
                    confidence="uncertain",
                    supporting_evidence=[e.normalized_event_id for e in matching_events],
                    metadata={
                        "attribution": self._build_attribution_metadata(
                            run_token=run_token,
                            status=AttributionStatus.CONFLICT.value,
                            is_strict=True,
                            events=matching_events,
                            notes=["Conflicting execution token in candidate telemetry"],
                        )
                    },
                )

            if all(e.execution_token is None for e in matching_events):
                return self._make_result(
                    run=run,
                    scenario=scenario,
                    category=DiagnosticCategory.INCONCLUSIVE,
                    reason=(
                        "Matching telemetry events lack execution tokens required for strict attribution; "
                        "missing evidence prevents causal linking"
                    ),
                    confidence="uncertain",
                    supporting_evidence=[e.normalized_event_id for e in matching_events],
                    metadata={
                        "attribution": self._build_attribution_metadata(
                            run_token=run_token,
                            status=AttributionStatus.INCONCLUSIVE.value,
                            is_strict=True,
                            events=matching_events,
                            notes=["Missing execution token on candidate telemetry"],
                        )
                    },
                )

            attributed_events = [e for e in matching_events if e.execution_token == run_token]
            if not attributed_events:
                # All candidate matching events have different tokens (mismatched)
                return self._make_result(
                    run=run,
                    scenario=scenario,
                    category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
                    reason=f"Telemetry observed on host but none match test run execution token '{run_token}'",
                    confidence="likely",
                    supporting_evidence=all_evidence_ids,
                    diagnostic_reasons=[
                        f"Mismatched tokens on {len(matching_events)} candidate event(s) rejected under strict attribution"
                    ],
                    metadata={
                        "attribution": self._build_attribution_metadata(
                            run_token=run_token,
                            status=AttributionStatus.MISMATCHED.value,
                            is_strict=True,
                            events=matching_events,
                            notes=["Mismatched tokens on candidate telemetry"],
                        )
                    },
                )
            matching_events = attributed_events

        matched_evidence_ids = [e.normalized_event_id for e in matching_events]

        # ── Step 4: Check detection outcome ──────────────────────────────
        if scenario.expected_detection_rule_id:
            return self._evaluate_detection(
                run, scenario, matching_events, matched_evidence_ids, run_token, is_strict
            )

        # No detection rule expected — telemetry-only scenario
        if scenario.validation_target == ValidationTarget.EXPECTED_TELEMETRY_ONLY:
            failure_cat, latency_meta, latency_notes = self._compute_latency(
                scenario, matching_events
            )
            attr_status = AttributionStatus.NOT_REQUESTED.value
            if run_token:
                if all(e.execution_token == run_token for e in matching_events):
                    attr_status = AttributionStatus.VERIFIED.value
                elif any(e.execution_token and e.execution_token != run_token for e in matching_events):
                    attr_status = AttributionStatus.MISMATCHED.value
                else:
                    attr_status = AttributionStatus.UNATTRIBUTED.value
            res_meta = {
                "attribution": self._build_attribution_metadata(
                    run_token=run_token,
                    status=attr_status,
                    is_strict=is_strict,
                    events=matching_events,
                )
            }
            if latency_meta:
                res_meta["latency"] = latency_meta
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.PASS,
                reason="Expected telemetry observed (telemetry-only scenario — no detection rule expected)",
                confidence="definitive",
                supporting_evidence=matched_evidence_ids,
                failure_category=failure_cat,
                metadata=res_meta,
                diagnostic_reasons=[
                    f"Matched {len(matching_events)} event(s) against expected signature",
                ] + latency_notes,
            )

        # Telemetry found but no rule and not telemetry-only
        return self._make_result(
            run=run,
            scenario=scenario,
            category=DiagnosticCategory.INCONCLUSIVE,
            reason="Expected telemetry observed but no detection rule specified for evaluation",
            confidence="uncertain",
            supporting_evidence=matched_evidence_ids,
            metadata={
                "attribution": self._build_attribution_metadata(
                    run_token=run_token,
                    status=AttributionStatus.INCONCLUSIVE.value if is_strict else AttributionStatus.NOT_REQUESTED.value,
                    is_strict=is_strict,
                    events=matching_events,
                )
            },
        )

    def _evaluate_detection(
        self,
        run: TestRunV1,
        scenario: ScenarioV1,
        matching_events: List[NormalizedTelemetryEventV1],
        matched_evidence_ids: List[str],
        run_token: Optional[str],
        is_strict: bool,
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

        # Query alerts across the monitoring system for this rule within search window (including grace period)
        all_rule_alerts = self.store.list_alerts_for_rule(
            rule_id, window_start=search_start, window_end=search_end
        )

        # Check candidate alerts on target host lacking timestamps
        missing_ts_candidate_alerts = [
            a
            for a in self.store.list_alerts_for_rule(rule_id)
            if a.alert_timestamp is None and hosts_match(run.target_host, a.host_id)
        ]
        if missing_ts_candidate_alerts and not self._has_valid_timestamped_alert(run, all_rule_alerts, is_strict, run_token):
            missing_alert_ids = [a.alert_id for a in missing_ts_candidate_alerts]
            attr_meta = self._build_attribution_metadata(
                run_token=run_token,
                status=AttributionStatus.INCONCLUSIVE.value,
                is_strict=is_strict,
                events=matching_events,
                alerts=missing_ts_candidate_alerts,
                notes=["Candidate alert lacks event timestamp"],
            )
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
                metadata={"attribution": attr_meta},
                diagnostic_reasons=[
                    f"Alert '{a.alert_id}' has no event timestamp; ingestion time "
                    f"({a.ingested_at.isoformat() if a.ingested_at else 'unrecorded'}) is ingestion metadata "
                    f"only and cannot prove detection timing"
                    for a in missing_ts_candidate_alerts
                ],
            )

        # ── DEFAULT ATTRIBUTION MODE (Preserves backwards compatibility & BM-25 default expectations) ──
        if not is_strict:
            correlated_alerts = self._correlate_alerts(run, all_rule_alerts)

            if not correlated_alerts:
                failure_cat, latency_meta, latency_notes = self._compute_latency(
                    scenario, matching_events
                )
                attr_meta = self._build_attribution_metadata(
                    run_token=run_token,
                    status=AttributionStatus.NOT_REQUESTED.value if not run_token else AttributionStatus.UNATTRIBUTED.value,
                    is_strict=False,
                    events=matching_events,
                    alerts=all_rule_alerts,
                )
                res_meta = {"attribution": attr_meta}
                if latency_meta:
                    res_meta["latency"] = latency_meta

                if not all_rule_alerts:
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
                        metadata=res_meta,
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
                    metadata=res_meta,
                    diagnostic_reasons=diagnostic_reasons + latency_notes,
                )

            # Full PASS in default mode
            failure_cat, latency_meta, latency_notes = self._compute_latency(
                scenario, matching_events, correlated_alerts
            )
            alert_ids = [a.alert_id for a in correlated_alerts]
            attr_status = AttributionStatus.NOT_REQUESTED.value
            if run_token:
                if any(a.execution_token == run_token for a in correlated_alerts):
                    attr_status = AttributionStatus.VERIFIED.value
                elif any(a.execution_token and a.execution_token != run_token for a in correlated_alerts):
                    attr_status = AttributionStatus.MISMATCHED.value
                else:
                    attr_status = AttributionStatus.UNATTRIBUTED.value
            attr_meta = self._build_attribution_metadata(
                run_token=run_token,
                status=attr_status,
                is_strict=False,
                events=matching_events,
                alerts=correlated_alerts,
            )
            res_meta = {"attribution": attr_meta}
            if latency_meta:
                res_meta["latency"] = latency_meta
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.PASS,
                reason="Expected telemetry observed and detection alert verified and correlated",
                confidence="definitive",
                supporting_evidence=matched_evidence_ids + alert_ids,
                failure_category=failure_cat,
                metadata=res_meta,
                diagnostic_reasons=[
                    f"Matched {len(matching_events)} telemetry event(s)",
                    f"Correlated {len(correlated_alerts)} alert(s) from rule {rule_id}",
                ] + latency_notes,
            )

        # ── STRICT ATTRIBUTION MODE ──────────────────────────────────────────
        # Candidate alerts for rule on target host within search window (window + grace period)
        host_candidate_alerts = [
            a for a in all_rule_alerts if hosts_match(run.target_host, a.host_id)
        ]

        # 1. Check for conflict tokens on candidate alerts on host
        conflict_alerts = [a for a in host_candidate_alerts if a.execution_token == "CONFLICT"]
        if conflict_alerts:
            attr_meta = self._build_attribution_metadata(
                run_token=run_token,
                status=AttributionStatus.CONFLICT.value,
                is_strict=True,
                events=matching_events,
                alerts=conflict_alerts,
                notes=["Conflicting execution token on candidate alert; never verified"],
            )
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.INCONCLUSIVE,
                reason=(
                    f"Candidate alert for rule {rule_id} on host {run.target_host} carries conflicting "
                    f"execution tokens; causal attribution cannot be verified"
                ),
                confidence="uncertain",
                supporting_evidence=matched_evidence_ids,
                contradictory_evidence=[a.alert_id for a in conflict_alerts],
                metadata={"attribution": attr_meta},
                diagnostic_reasons=[
                    f"Alert '{a.alert_id}' marked CONFLICT; conflicting explicit/extracted tokens must never be verified"
                    for a in conflict_alerts
                ],
            )

        # 2. Check for missing tokens on candidate alerts on host within execution window
        # Missing evidence prevents causal linking -> INCONCLUSIVE
        missing_token_window_alerts = [
            a for a in host_candidate_alerts
            if a.execution_token is None and _is_in_window(a.alert_timestamp, run.window_start, run.window_end)
        ]
        if missing_token_window_alerts:
            attr_meta = self._build_attribution_metadata(
                run_token=run_token,
                status=AttributionStatus.INCONCLUSIVE.value,
                is_strict=True,
                events=matching_events,
                alerts=missing_token_window_alerts,
                notes=["Candidate alert in execution window lacks execution token"],
            )
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.INCONCLUSIVE,
                reason=(
                    f"Alert from expected rule {rule_id} observed on host {run.target_host} within window "
                    f"but lacks execution token; missing evidence prevents strict attribution"
                ),
                confidence="uncertain",
                supporting_evidence=matched_evidence_ids,
                contradictory_evidence=[a.alert_id for a in missing_token_window_alerts],
                metadata={"attribution": attr_meta},
                diagnostic_reasons=[
                    f"Alert '{a.alert_id}' has no execution token; cannot prove causal attribution in strict mode"
                    for a in missing_token_window_alerts
                ],
            )

        # 3. Separate matching vs mismatched alerts
        matching_token_alerts = [
            a for a in all_rule_alerts if a.execution_token == run_token
        ]
        mismatched_alerts = [
            a for a in host_candidate_alerts
            if a.execution_token is not None and a.execution_token != run_token
        ]

        # Correlate matching alerts strictly within the execution window on target host
        correlated_alerts = [
            a for a in matching_token_alerts
            if hosts_match(run.target_host, a.host_id) and _is_in_window(a.alert_timestamp, run.window_start, run.window_end)
        ]

        if correlated_alerts:
            # Full PASS: matching token + target host + strictly within execution window
            failure_cat, latency_meta, latency_notes = self._compute_latency(
                scenario, matching_events, correlated_alerts
            )
            alert_ids = [a.alert_id for a in correlated_alerts]
            attr_meta = self._build_attribution_metadata(
                run_token=run_token,
                status=AttributionStatus.VERIFIED.value,
                is_strict=True,
                events=matching_events,
                alerts=correlated_alerts,
                mismatched_alerts=mismatched_alerts,
                notes=["Execution token verified across run, telemetry, and correlated alert(s)"],
            )
            res_meta = {"attribution": attr_meta}
            if latency_meta:
                res_meta["latency"] = latency_meta
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.PASS,
                reason=(
                    f"Expected telemetry observed and detection alert verified with matching "
                    f"execution token '{run_token}' strictly within execution window"
                ),
                confidence="definitive",
                supporting_evidence=matched_evidence_ids + alert_ids,
                failure_category=failure_cat,
                metadata=res_meta,
                diagnostic_reasons=[
                    f"Matched {len(matching_events)} telemetry event(s) with token '{run_token}'",
                    f"Attributed {len(correlated_alerts)} alert(s) from rule {rule_id} with token '{run_token}'",
                ] + (
                    [f"Rejected {len(mismatched_alerts)} mismatched alert(s) without assuming detection failure"]
                    if mismatched_alerts else []
                ) + latency_notes,
            )

        # 4. Check if matching token alert exists in the grace window (outside execution window)
        grace_matching_alerts = [
            a for a in matching_token_alerts
            if hosts_match(run.target_host, a.host_id) and not _is_in_window(a.alert_timestamp, run.window_start, run.window_end)
        ]
        if grace_matching_alerts:
            # "Keep correlation strictly within the execution window; grace-window alerts must not produce PASS."
            failure_cat, latency_meta, latency_notes = self._compute_latency(
                scenario, matching_events, grace_matching_alerts
            )
            attr_meta = self._build_attribution_metadata(
                run_token=run_token,
                status=AttributionStatus.VERIFIED.value,
                is_strict=True,
                events=matching_events,
                alerts=grace_matching_alerts,
                notes=["Matching token alert arrived outside execution window (grace period)"],
            )
            res_meta = {"attribution": attr_meta}
            if latency_meta:
                res_meta["latency"] = latency_meta
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.ALERT_NOT_CORRELATED,
                reason=(
                    f"Alert with matching execution token '{run_token}' exists in monitoring system, "
                    f"but arrived outside the execution window (within grace period); timing correlation failed"
                ),
                confidence="likely",
                supporting_evidence=matched_evidence_ids,
                contradictory_evidence=[a.alert_id for a in grace_matching_alerts],
                failure_category=failure_cat or FailureCategory.PIPELINE_LATENCY,
                metadata=res_meta,
                diagnostic_reasons=[
                    f"Alert '{grace_matching_alerts[0].alert_id}' with token '{run_token}' timestamped outside execution window",
                    "Grace-window alerts must not produce PASS",
                ] + latency_notes,
            )

        # 5. Check if matching token alert exists on a different host
        diff_host_matching_alerts = [
            a for a in matching_token_alerts if not hosts_match(run.target_host, a.host_id)
        ]
        if diff_host_matching_alerts:
            attr_meta = self._build_attribution_metadata(
                run_token=run_token,
                status=AttributionStatus.VERIFIED.value,
                is_strict=True,
                events=matching_events,
                alerts=diff_host_matching_alerts,
                notes=["Matching token alert routed to mismatched host"],
            )
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.ALERT_NOT_CORRELATED,
                reason=(
                    f"Alert with matching execution token '{run_token}' exists in monitoring system, "
                    f"but was routed to host '{diff_host_matching_alerts[0].host_id}' instead of '{run.target_host}'"
                ),
                confidence="likely",
                supporting_evidence=matched_evidence_ids,
                contradictory_evidence=[a.alert_id for a in diff_host_matching_alerts],
                metadata={"attribution": attr_meta},
                diagnostic_reasons=[
                    f"Alert '{a.alert_id}' with token '{run_token}' observed on mismatched host '{a.host_id}'"
                    for a in diff_host_matching_alerts
                ],
            )

        # 6. No matching token alerts exist anywhere in the monitoring system.
        # "reject mismatched alerts without assuming they prove detection failure."
        failure_cat, latency_meta, latency_notes = self._compute_latency(
            scenario, matching_events
        )
        attr_meta = self._build_attribution_metadata(
            run_token=run_token,
            status=AttributionStatus.MISMATCHED.value if mismatched_alerts else AttributionStatus.UNATTRIBUTED.value,
            is_strict=True,
            events=matching_events,
            alerts=host_candidate_alerts,
            mismatched_alerts=mismatched_alerts,
            notes=[
                "No alert matching test run execution token was generated",
                *(["Mismatched alerts rejected without assuming they prove detection failure"] if mismatched_alerts else []),
            ],
        )
        res_meta = {"attribution": attr_meta}
        if latency_meta:
            res_meta["latency"] = latency_meta

        diagnostic_reasons = [
            f"Expected rule: {rule_id}",
            f"Telemetry present ({len(matching_events)} matched event(s)) with execution token '{run_token}'",
            f"Rule '{rule_id}' did not trigger any alert matching execution token '{run_token}'",
        ]
        if mismatched_alerts:
            diagnostic_reasons.append(
                f"Rejected {len(mismatched_alerts)} mismatched alert(s) on host (concurrent tasks/admin activity); "
                f"mismatched alerts do not prove detection failure, but expected rule was silent for tested attack"
            )

        return self._make_result(
            run=run,
            scenario=scenario,
            category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
            reason=f"Expected detection rule {rule_id} did not trigger for execution token '{run_token}'",
            confidence="likely",
            supporting_evidence=matched_evidence_ids,
            contradictory_evidence=[],
            failure_category=failure_cat,
            metadata=res_meta,
            diagnostic_reasons=diagnostic_reasons + latency_notes,
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
        meta = dict(metadata or {})
        if "attribution" not in meta:
            run_tok = run.execution_token
            meta["attribution"] = {
                "status": AttributionStatus.NOT_REQUESTED.value if not run_tok else AttributionStatus.UNATTRIBUTED.value,
                "strict_attribution": False,
                "run_execution_token": run_tok,
                "cryptographic_proof": False,
                "disclaimer": (
                    "Token attribution provides execution provenance linking via correlated execution tokens; "
                    "it does not constitute or claim cryptographic proof."
                ),
            }

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
            metadata=meta,
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
            metadata={
                "attribution": {
                    "status": AttributionStatus.NOT_REQUESTED.value,
                    "strict_attribution": False,
                    "cryptographic_proof": False,
                    "disclaimer": (
                        "Token attribution provides execution provenance linking via correlated execution tokens; "
                        "it does not constitute or claim cryptographic proof."
                    ),
                }
            },
        )
