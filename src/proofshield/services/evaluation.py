"""Deterministic assurance engine for diagnostic evaluation.

Architecture Layer 5 — the central component of the research prototype.
Evaluates test runs against scenario expectations using collected evidence
and classifies outcomes into one of seven diagnostic categories.
"""

import ipaddress
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


def _ip_matches(expected: str, candidate: Optional[str]) -> bool:
    """Compare expected and candidate IP addresses supporting IPv4 and IPv6 canonicalization."""
    if not expected or not candidate:
        return False
    exp_clean = expected.strip()
    cand_clean = candidate.strip()
    if exp_clean.lower() == cand_clean.lower():
        return True
    try:
        exp_obj = ipaddress.ip_address(exp_clean)
        cand_obj = ipaddress.ip_address(cand_clean)
        return exp_obj == cand_obj
    except ValueError:
        return exp_clean.lower() == cand_clean.lower()


def _path_matches(expected: str, candidate: str) -> bool:
    """Compare expected and candidate file paths safely across Windows and POSIX boundaries.

    Prevents false substring collisions such as '/etc/hosts.bak' matching '/etc/hosts'
    while supporting basename matching, relative path matching, and explicit regex.
    """
    if not expected or not candidate:
        return False

    exp_clean = expected.strip()
    cand_clean = candidate.strip()

    # Normalize directory separators and lower-case
    exp_norm = exp_clean.replace("\\", "/").rstrip("/").lower()
    cand_norm = cand_clean.replace("\\", "/").rstrip("/").lower()

    if not exp_norm or not cand_norm:
        return False

    # 1. Exact normalized match
    if exp_norm == cand_norm:
        return True

    # 2. Check component suffix match at a path separator boundary
    # e.g. candidate="c:/windows/system32/drivers/etc/hosts", expected="etc/hosts"
    # or candidate="/etc/hosts", expected="hosts"
    if cand_norm.endswith(exp_norm):
        prefix_len = len(cand_norm) - len(exp_norm)
        if prefix_len > 0 and cand_norm[prefix_len - 1] in ("/", ":"):
            if exp_norm.startswith("/"):
                prefix = cand_norm[:prefix_len]
                # If expected was an absolute path starting with '/', only allow drive prefix or root
                if prefix in ("/", "") or (len(prefix) == 2 and prefix[1] == ":") or (len(prefix) == 3 and prefix[1] == ":" and prefix[2] == "/"):
                    return True
                return False
            return True

    # 3. Handle Windows drive letter variance: expected="c:/etc/hosts", candidate="/etc/hosts"
    if len(exp_norm) >= 3 and exp_norm[1] == ":" and exp_norm[2] == "/":
        exp_no_drive = exp_norm[2:]
        if cand_norm == exp_no_drive:
            return True

    # 4. If expected explicitly uses regex metacharacters, attempt regex matching
    regex_metachars = set(r"*+?[](){}^$")
    if any(c in regex_metachars for c in exp_clean):
        try:
            if re.search(exp_clean, cand_clean, re.IGNORECASE):
                return True
        except re.error:
            pass

    return False


def _hash_matches(expected: str, event_hashes: Optional[Dict[str, str]]) -> bool:
    """Match expected file hash against event hashes, supporting algorithm prefixes and raw digests."""
    if not expected or not event_hashes:
        return False

    exp_clean = expected.strip().lower()

    algo_specified = None
    expected_digest = exp_clean
    for sep in (":", "="):
        if sep in exp_clean:
            parts = exp_clean.split(sep, 1)
            algo_cand = parts[0].strip()
            if algo_cand in {"sha256", "md5", "sha1", "imphash"}:
                algo_specified = algo_cand
                expected_digest = parts[1].strip()
                break

    # If algorithm was explicitly specified, check only that specific algorithm key
    if algo_specified:
        actual_val = event_hashes.get(algo_specified)
        if actual_val and str(actual_val).strip().lower() == expected_digest:
            return True
        return False

    # Otherwise, check all hash entries in event_hashes
    for k, v in event_hashes.items():
        v_clean = str(v).strip().lower()
        if v_clean == expected_digest:
            return True
        for sep in (":", "="):
            if sep in v_clean:
                v_parts = v_clean.split(sep, 1)
                if v_parts[1].strip() == expected_digest:
                    return True

    return False


def _parse_user_domain(user_str: str) -> Tuple[Optional[str], str]:
    """Split user string into (domain, username). Supports DOMAIN\\user and user@domain."""
    clean = user_str.strip().lower()
    if "\\" in clean:
        parts = clean.split("\\", 1)
        return parts[0], parts[1]
    if "@" in clean:
        parts = clean.split("@", 1)
        return parts[1], parts[0]
    return None, clean


def _user_matches(expected: str, candidate: Optional[str]) -> bool:
    """Match expected user against candidate identity.

    Prevents cross-domain collisions (e.g. CORPA\\alice != CORPB\\alice) while
    allowing bare username matching if domain is not specified by either party.
    """
    if not expected or not candidate:
        return False

    exp_domain, exp_user = _parse_user_domain(expected)
    cand_domain, cand_user = _parse_user_domain(candidate)

    if exp_user != cand_user:
        return False

    # If both specified domains, both domains must match
    if exp_domain and cand_domain:
        return exp_domain == cand_domain

    return True


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


def _is_before_window(ts: Optional[datetime], w_start: datetime) -> bool:
    """Check if timestamp occurs strictly before w_start accounting for timezone differences."""
    if ts is None:
        return False
    if ts.tzinfo is not None and w_start.tzinfo is None:
        w_start = w_start.replace(tzinfo=ts.tzinfo)
    elif ts.tzinfo is None and w_start.tzinfo is not None:
        ts = ts.replace(tzinfo=w_start.tzinfo)
    return ts < w_start


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
                if not _is_before_window(a.alert_timestamp, run.executed_at):
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
        run_token = run.execution_token.strip() if run.execution_token else None
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

            # Guard against execution-token reuse across distinct runs with overlapping windows
            other_runs = [
                r for r in self.store.list_runs()
                if r.run_id != run.run_id
                and (
                    (r.execution_token.strip() if r.execution_token else None) == run_token
                    or (
                        r.metadata
                        and "execution_token" in r.metadata
                        and str(r.metadata["execution_token"]).strip() == run_token
                    )
                )
            ]
            if other_runs:
                grace_seconds = self.default_alert_grace_period_seconds
                if run.metadata and "alert_grace_period_seconds" in run.metadata:
                    try:
                        grace_seconds = int(run.metadata["alert_grace_period_seconds"])
                    except (ValueError, TypeError):
                        grace_seconds = self.default_alert_grace_period_seconds
                grace = timedelta(seconds=grace_seconds)
                run_w_start = run.window_start - grace
                run_w_end = run.window_end + grace

                overlapping_reused_runs = []
                for other in other_runs:
                    other_w_start = other.window_start - grace
                    other_w_end = other.window_end + grace
                    o_start = other_w_start
                    o_end = other_w_end
                    r_start = run_w_start
                    r_end = run_w_end
                    if o_start.tzinfo is not None and r_start.tzinfo is None:
                        r_start = r_start.replace(tzinfo=o_start.tzinfo)
                        r_end = r_end.replace(tzinfo=o_start.tzinfo)
                    elif o_start.tzinfo is None and r_start.tzinfo is not None:
                        o_start = o_start.replace(tzinfo=r_start.tzinfo)
                        o_end = o_end.replace(tzinfo=r_start.tzinfo)
                    if max(r_start, o_start) <= min(r_end, o_end):
                        overlapping_reused_runs.append(other)

                if overlapping_reused_runs:
                    other_ids = [r.run_id for r in overlapping_reused_runs]
                    return self._make_result(
                        run=run,
                        scenario=scenario,
                        category=DiagnosticCategory.INCONCLUSIVE,
                        reason=(
                            f"Strict attribution requested but execution token '{run_token}' is reused "
                            f"across multiple runs ({', '.join(other_ids)}) "
                            f"with overlapping observation windows; causal provenance cannot be verified"
                        ),
                        confidence="uncertain",
                        metadata={
                            "attribution": self._build_attribution_metadata(
                                run_token=run_token,
                                status=AttributionStatus.CONFLICT.value,
                                is_strict=True,
                                notes=[
                                    f"Execution token '{run_token}' reused by overlapping run(s): {', '.join(other_ids)}"
                                ],
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
        all_evidence_ids = [e.normalized_event_id for e in events]

        # Guard: Check whether scenario defines a discriminating signature
        # An attack-detection scenario (EXPECTED_ALERT) without a discriminating signature
        # cannot be causally linked to alerts and would produce false passes on ambient noise.
        if scenario.validation_target == ValidationTarget.EXPECTED_ALERT and not scenario.has_discriminating_signature():
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.INCONCLUSIVE,
                reason=(
                    f"Scenario '{scenario.scenario_id}' lacks a discriminating signature for "
                    f"{scenario.expected_event_category.value}; cannot distinguish tested activity "
                    f"from ambient background telemetry"
                ),
                confidence="uncertain",
                supporting_evidence=all_evidence_ids,
                diagnostic_reasons=[
                    f"Expected category: {scenario.expected_event_category.value}",
                    "Scenario provides no discriminating fields (process, command, IP, port, path, hash, or user)",
                    f"Events in window: {len(events)} (cannot be causally attributed without discriminating signature)",
                ],
                metadata={
                    "missing_evidence": True,
                    "underspecified_scenario": True,
                    "attribution": self._build_attribution_metadata(
                        run_token=run_token,
                        status=AttributionStatus.INCONCLUSIVE.value if is_strict else AttributionStatus.NOT_REQUESTED.value,
                        is_strict=is_strict,
                        events=events,
                        notes=["Underspecified scenario lacks discriminating signature"],
                    ),
                },
            )

        matching_events = self._find_matching_events(scenario, events)

        if not matching_events:
            diag_reasons = [
                f"Expected category: {scenario.expected_event_category.value}",
                f"Expected process: {scenario.expected_process_name or 'any'}",
                f"Expected pattern: {scenario.expected_command_pattern or 'any'}",
            ]
            if scenario.expected_destination_ip:
                diag_reasons.append(f"Expected destination IP: {scenario.expected_destination_ip}")
            if scenario.expected_destination_port is not None:
                diag_reasons.append(f"Expected destination port: {scenario.expected_destination_port}")
            if scenario.expected_file_path:
                diag_reasons.append(f"Expected file path: {scenario.expected_file_path}")
            if scenario.expected_file_hash:
                diag_reasons.append(f"Expected file hash: {scenario.expected_file_hash}")
            if scenario.expected_user:
                diag_reasons.append(f"Expected user: {scenario.expected_user}")
            diag_reasons.extend([
                f"Events in window: {len(events)} (none matched)",
                "Note: absence does not confirm the event was never generated",
            ])
            return self._make_result(
                run=run,
                scenario=scenario,
                category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
                reason=(
                    "Telemetry events observed but none match the expected signature"
                ),
                confidence="likely",
                supporting_evidence=all_evidence_ids,
                diagnostic_reasons=diag_reasons,
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

            attributed_events = [
                e for e in matching_events
                if (e.execution_token.strip() if e.execution_token else None) == run_token
            ]
            if attributed_events:
                # Matching token found: attribute strictly to the run.
                # Do not reject matching telemetry solely because unrelated untokenized events coexist.
                matching_events = attributed_events
            else:
                # No matching token found among candidate matching events.
                # If untokenized candidate events exist, missing evidence prevents definitive classification.
                untokenized_events = [
                    e for e in matching_events
                    if not (e.execution_token and e.execution_token.strip())
                ]
                if untokenized_events:
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
                else:
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

        # Check candidate alerts on target host lacking timestamps within defensible scope:
        # 1. Alert must reference this detection rule and match target host.
        # 2. In strict mode, an alert with an explicit mismatched token belongs to another execution
        #    and must be rejected rather than forcing INCONCLUSIVE.
        # 3. For temporal relevance: an alert lacking an event timestamp cannot be presumed
        #    to belong to all future runs. It is considered an in-scope candidate for this run
        #    only if its ingestion timestamp (ingested_at) was NOT prior to the run's evaluation
        #    window (i.e. not historical: a.ingested_at is not before search_start).
        #    Historical alerts ingested prior to search_start cannot have been produced by this run.
        #    Completely undated alerts (lacking both event timestamp and ingestion time) are not
        #    silently treated as current unless explicitly bearing the run's execution token.
        missing_ts_candidate_alerts = []
        for a in self.store.list_alerts_for_rule(rule_id):
            if a.alert_timestamp is not None:
                continue
            if not hosts_match(run.target_host, a.host_id):
                continue
            if is_strict and a.execution_token is not None and a.execution_token != run_token and a.execution_token != "CONFLICT":
                continue
            # Check temporal anchoring:
            if a.ingested_at is not None:
                if _is_before_window(a.ingested_at, search_start):
                    # Historical alert ingested before search window started — out of scope
                    continue
            else:
                # Alert has no alert_timestamp and no ingested_at.
                # Do not silently treat undated alerts as current unless explicitly tagged with run_token.
                if not (is_strict and a.execution_token == run_token):
                    continue
            missing_ts_candidate_alerts.append(a)

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

        # 2. Separate matching vs mismatched alerts
        matching_token_alerts = [
            a for a in all_rule_alerts
            if (a.execution_token.strip() if a.execution_token else None) == run_token
        ]
        mismatched_alerts = [
            a for a in host_candidate_alerts
            if (a.execution_token and a.execution_token.strip())
            and (a.execution_token.strip() if a.execution_token else None) != run_token
        ]

        # Correlate matching alerts strictly within the execution window on target host, occurring on or after run execution
        correlated_alerts = [
            a for a in matching_token_alerts
            if hosts_match(run.target_host, a.host_id)
            and _is_in_window(a.alert_timestamp, run.window_start, run.window_end)
            and not _is_before_window(a.alert_timestamp, run.executed_at)
        ]

        # 3. Check for valid matching-token alert inside execution window FIRST.
        # An untokenized alert on the host must not block a verified matching-token alert.
        if correlated_alerts:
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

        # 6. Only if NO matching token alert exists anywhere:
        # Check for missing tokens on candidate alerts on host within execution window
        # Missing evidence prevents causal linking -> INCONCLUSIVE
        missing_token_window_alerts = [
            a for a in host_candidate_alerts
            if not (a.execution_token and a.execution_token.strip())
            and _is_in_window(a.alert_timestamp, run.window_start, run.window_end)
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
        pre_exec_alerts = [
            a for a in matching_token_alerts
            if hosts_match(run.target_host, a.host_id) and _is_before_window(a.alert_timestamp, run.executed_at)
        ]
        if pre_exec_alerts:
            diagnostic_reasons.append(
                f"Rejected {len(pre_exec_alerts)} alert(s) carrying token '{run_token}' occurring before test execution ({run.executed_at.isoformat()})"
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
            # 1. Category must match
            if event.event_category != scenario.expected_event_category:
                continue

            # 2. Process name check (case-insensitive) if specified
            # 2. Process name check if specified
            if scenario.expected_process_name and scenario.expected_process_name.strip():
                if not event.process_name:
                    continue
                if (
                    event.process_name.strip().lower()
                    != scenario.expected_process_name.strip().lower()
                ):
                    continue

            # 3. Command pattern check if specified
            if scenario.expected_command_pattern and scenario.expected_command_pattern.strip():
                if not event.command_line:
                    continue
                exp_pat = scenario.expected_command_pattern.strip()
                try:
                    if not re.search(exp_pat, event.command_line):
                        continue
                except re.error:
                    # If the pattern is not valid regex, try substring match
                    if exp_pat not in event.command_line:
                        continue

            # 4. Network destination IP check if specified
            if scenario.expected_destination_ip and scenario.expected_destination_ip.strip():
                if not _ip_matches(scenario.expected_destination_ip, event.network_destination_ip):
                    continue

            # 5. Network destination port check if specified
            if scenario.expected_destination_port is not None:
                if event.network_destination_port is None:
                    continue
                if event.network_destination_port != scenario.expected_destination_port:
                    continue

            # 6. File path check if specified
            if scenario.expected_file_path and scenario.expected_file_path.strip():
                # Prioritize target file attributes if present (e.g. on file events or logging that separates process from target file)
                target_paths = [
                    str(event.extra_attributes[k])
                    for k in ("TargetFilename", "file_path", "path", "target_filename", "filename", "name", "FilePath", "TargetFilePath")
                    if k in event.extra_attributes and event.extra_attributes[k]
                ]

                if target_paths:
                    candidate_paths = target_paths
                else:
                    candidate_paths = [p for p in (event.process_path, event.process_name) if p]

                if not candidate_paths:
                    continue

                if not any(_path_matches(scenario.expected_file_path, cpath) for cpath in candidate_paths):
                    continue

            # 7. File hash check if specified
            if scenario.expected_file_hash and scenario.expected_file_hash.strip():
                if not _hash_matches(scenario.expected_file_hash, event.hashes):
                    continue

            # 8. User check if specified
            if scenario.expected_user and scenario.expected_user.strip():
                if not _user_matches(scenario.expected_user, event.user):
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
                if _is_before_window(ts, run.executed_at):
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

    def _derive_missing_evidence(self, category: DiagnosticCategory, reason: str) -> bool:
        """Determine if diagnosis was driven by missing or incomplete evidence."""
        if category in (
            DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
            DiagnosticCategory.INCONCLUSIVE,
            DiagnosticCategory.ERROR,
        ):
            return True
        return False

    def _derive_checks_performed(
        self,
        run: TestRunV1,
        scenario: ScenarioV1,
        category: DiagnosticCategory,
        supporting_evidence: Optional[List[str]] = None,
        contradictory_evidence: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        checks: List[Dict[str, Any]] = [
            {
                "check": "run_and_scenario_existence",
                "status": "PASSED",
                "detail": f"Run {run.run_id} and scenario {scenario.scenario_id} verified",
            }
        ]

        # Execution status check
        if run.execution_status == ExecutionStatus.RUNNING:
            checks.append({
                "check": "execution_status",
                "status": "INCONCLUSIVE",
                "detail": "Test execution is still RUNNING",
            })
            return checks
        elif run.execution_status in (
            ExecutionStatus.FAILED,
            ExecutionStatus.ERROR,
            ExecutionStatus.PENDING,
        ):
            checks.append({
                "check": "execution_status",
                "status": "FAILED",
                "detail": f"Test execution reported as {run.execution_status.value}",
            })
            return checks
        else:
            checks.append({
                "check": "execution_status",
                "status": "PASSED",
                "detail": "ExecutionStatus.COMPLETED",
            })

        # Token check if token present or requested
        if run.execution_token:
            if run.execution_token == "CONFLICT":
                checks.append({
                    "check": "run_token_provenance",
                    "status": "FAILED",
                    "detail": "Run execution token marked CONFLICT",
                })
            else:
                checks.append({
                    "check": "run_token_provenance",
                    "status": "PASSED",
                    "detail": f"Run execution token '{run.execution_token}' recorded",
                })

        # Telemetry checks
        if category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING:
            if supporting_evidence:
                checks.append({
                    "check": "telemetry_presence",
                    "status": "PASSED",
                    "detail": f"{len(supporting_evidence)} telemetry event(s) observed on host",
                    "evidence_ids": supporting_evidence,
                })
                checks.append({
                    "check": "telemetry_signature_match",
                    "status": "FAILED",
                    "detail": f"Observed telemetry did not match expected signature for {scenario.expected_event_category.value}",
                })
            else:
                checks.append({
                    "check": "telemetry_presence",
                    "status": "FAILED",
                    "detail": "No telemetry events observed within observation window on target host",
                })
            return checks

        # Telemetry passed for subsequent categories
        sup = supporting_evidence or []
        checks.append({
            "check": "telemetry_presence",
            "status": "PASSED",
            "detail": "Telemetry events observed within execution window",
        })
        checks.append({
            "check": "telemetry_signature_match",
            "status": "PASSED",
            "detail": "Observed telemetry matched expected scenario signature",
            "evidence_ids": [eid for eid in sup if eid.startswith("NORM-") or eid.startswith("RAW-")],
        })

        if scenario.validation_target == ValidationTarget.EXPECTED_TELEMETRY_ONLY:
            checks.append({
                "check": "validation_target",
                "status": "PASSED",
                "detail": "Telemetry-only validation target satisfied",
            })
            return checks

        # Alert and detection checks
        if category == DiagnosticCategory.DETECTION_NOT_TRIGGERED:
            checks.append({
                "check": "detection_rule_fired",
                "status": "FAILED",
                "detail": f"Expected detection rule '{scenario.expected_detection_rule_id}' did not trigger an alert",
            })
        elif category == DiagnosticCategory.ALERT_NOT_CORRELATED:
            checks.append({
                "check": "detection_rule_fired",
                "status": "PASSED",
                "detail": f"Expected detection rule '{scenario.expected_detection_rule_id}' triggered alert(s)",
                "evidence_ids": contradictory_evidence or [],
            })
            checks.append({
                "check": "alert_correlation",
                "status": "FAILED",
                "detail": "Alerts failed correlation to target host or execution time window",
            })
        elif category == DiagnosticCategory.PASS:
            checks.append({
                "check": "detection_rule_fired",
                "status": "PASSED",
                "detail": f"Expected detection rule '{scenario.expected_detection_rule_id}' triggered alert(s)",
            })
            checks.append({
                "check": "alert_correlation",
                "status": "PASSED",
                "detail": "Alert correlated successfully to target host and execution time window",
                "evidence_ids": [eid for eid in sup if eid.startswith("ALT-")],
            })
        elif category == DiagnosticCategory.INCONCLUSIVE:
            checks.append({
                "check": "evidence_conclusiveness",
                "status": "INCONCLUSIVE",
                "detail": "Ambiguous, missing, or contradictory evidence prevents conclusive diagnosis",
                "evidence_ids": contradictory_evidence or [],
            })

        return checks

    def _derive_alternative_eliminations(
        self,
        run: TestRunV1,
        scenario: ScenarioV1,
        category: DiagnosticCategory,
        reason: str,
    ) -> Dict[str, str]:
        eliminations: Dict[str, str] = {}

        if category == DiagnosticCategory.TEST_NOT_EXECUTED:
            eliminations[DiagnosticCategory.PASS.value] = "Test execution failed or aborted before producing intended attack behaviour."
            eliminations[DiagnosticCategory.EXPECTED_TELEMETRY_MISSING.value] = "Downstream telemetry checks were not reached because test execution failed."
            eliminations[DiagnosticCategory.DETECTION_NOT_TRIGGERED.value] = "Downstream detection checks were not reached because test execution failed."
            eliminations[DiagnosticCategory.ALERT_NOT_CORRELATED.value] = "Downstream alert correlation checks were not reached because test execution failed."
            eliminations[DiagnosticCategory.INCONCLUSIVE.value] = "Execution status definitively indicated execution failure."
            eliminations[DiagnosticCategory.ERROR.value] = "Test run and scenario entities are valid and loaded."

        elif category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING:
            eliminations[DiagnosticCategory.PASS.value] = "Required telemetry signature was not observed on target host within execution window."
            eliminations[DiagnosticCategory.TEST_NOT_EXECUTED.value] = "Test execution completed successfully."
            eliminations[DiagnosticCategory.DETECTION_NOT_TRIGGERED.value] = "Detection rules cannot be evaluated when prerequisite telemetry is missing."
            eliminations[DiagnosticCategory.ALERT_NOT_CORRELATED.value] = "Alert correlation cannot be evaluated when prerequisite telemetry is missing."
            eliminations[DiagnosticCategory.INCONCLUSIVE.value] = "Telemetry observation window on target host definitively contained no matching events."
            eliminations[DiagnosticCategory.ERROR.value] = "Test run and scenario entities are valid and loaded."

        elif category == DiagnosticCategory.DETECTION_NOT_TRIGGERED:
            eliminations[DiagnosticCategory.PASS.value] = "Expected detection rule did not trigger an alert matching the test execution."
            eliminations[DiagnosticCategory.TEST_NOT_EXECUTED.value] = "Test execution completed successfully."
            eliminations[DiagnosticCategory.EXPECTED_TELEMETRY_MISSING.value] = "Prerequisite telemetry was observed matching the expected signature."
            eliminations[DiagnosticCategory.ALERT_NOT_CORRELATED.value] = "No candidate alerts were produced by the expected rule in the monitoring system."
            eliminations[DiagnosticCategory.INCONCLUSIVE.value] = "Telemetry presence and rule silence were confirmed with sufficient evidence."
            eliminations[DiagnosticCategory.ERROR.value] = "Test run and scenario entities are valid and loaded."

        elif category == DiagnosticCategory.ALERT_NOT_CORRELATED:
            eliminations[DiagnosticCategory.PASS.value] = "Alert from expected rule was generated but failed host routing or time window correlation."
            eliminations[DiagnosticCategory.TEST_NOT_EXECUTED.value] = "Test execution completed successfully."
            eliminations[DiagnosticCategory.EXPECTED_TELEMETRY_MISSING.value] = "Prerequisite telemetry was observed matching the expected signature."
            eliminations[DiagnosticCategory.DETECTION_NOT_TRIGGERED.value] = "Expected rule did fire in the monitoring system (silence disproven)."
            eliminations[DiagnosticCategory.INCONCLUSIVE.value] = "Alert host mismatch or timing discrepancy was definitively verified."
            eliminations[DiagnosticCategory.ERROR.value] = "Test run and scenario entities are valid and loaded."

        elif category == DiagnosticCategory.PASS:
            eliminations[DiagnosticCategory.TEST_NOT_EXECUTED.value] = "Test execution completed successfully."
            eliminations[DiagnosticCategory.EXPECTED_TELEMETRY_MISSING.value] = "Matching telemetry was observed on target host within window."
            eliminations[DiagnosticCategory.DETECTION_NOT_TRIGGERED.value] = "Expected detection rule fired and was verified."
            eliminations[DiagnosticCategory.ALERT_NOT_CORRELATED.value] = "Detection alert correlated to target host and execution time window."
            eliminations[DiagnosticCategory.INCONCLUSIVE.value] = "All required evidence was complete, unambiguous, and verified."
            eliminations[DiagnosticCategory.ERROR.value] = "Test run and scenario entities are valid and loaded."

        elif category == DiagnosticCategory.INCONCLUSIVE:
            eliminations[DiagnosticCategory.PASS.value] = f"Cannot declare PASS due to ambiguous or missing evidence: {reason}"
            eliminations[DiagnosticCategory.TEST_NOT_EXECUTED.value] = "Execution did not report definitive failure."
            eliminations[DiagnosticCategory.EXPECTED_TELEMETRY_MISSING.value] = "Missing evidence prevents concluding that telemetry was genuinely absent."
            eliminations[DiagnosticCategory.DETECTION_NOT_TRIGGERED.value] = "Missing evidence prevents concluding that detection rule was silent."
            eliminations[DiagnosticCategory.ALERT_NOT_CORRELATED.value] = "Missing evidence prevents concluding correlation failed."
            eliminations[DiagnosticCategory.ERROR.value] = "Test run and scenario entities are valid and loaded."

        elif category == DiagnosticCategory.ERROR:
            for cat in DiagnosticCategory:
                if cat != DiagnosticCategory.ERROR:
                    eliminations[cat.value] = f"Evaluation aborted due to entity or internal error: {reason}"

        return eliminations

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
        checks_performed: Optional[List[Dict[str, Any]]] = None,
        alternative_eliminations: Optional[Dict[str, str]] = None,
        missing_evidence: Optional[bool] = None,
    ) -> DiagnosticResultV1:
        """Construct a DiagnosticResultV1 with consistent formatting and evidence traceability."""
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

        if checks_performed is not None:
            meta["checks_performed"] = checks_performed
        elif "checks_performed" not in meta:
            meta["checks_performed"] = self._derive_checks_performed(
                run, scenario, category, supporting_evidence, contradictory_evidence
            )

        if alternative_eliminations is not None:
            meta["alternative_eliminations"] = alternative_eliminations
        elif "alternative_eliminations" not in meta:
            meta["alternative_eliminations"] = self._derive_alternative_eliminations(
                run, scenario, category, reason
            )

        if missing_evidence is not None:
            meta["missing_evidence"] = missing_evidence
        elif "missing_evidence" not in meta:
            meta["missing_evidence"] = self._derive_missing_evidence(category, reason)

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
        eliminations = {
            c.value: f"Evaluation aborted at entity resolution stage: {reason}"
            for c in DiagnosticCategory
            if c != DiagnosticCategory.ERROR
        }
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
                },
                "checks_performed": [
                    {
                        "check": "entity_resolution",
                        "status": "FAILED",
                        "detail": reason,
                    }
                ],
                "alternative_eliminations": eliminations,
                "missing_evidence": True,
            },
        )
