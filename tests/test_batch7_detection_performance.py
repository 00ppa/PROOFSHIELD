"""Semantic regressions for the optimized deterministic correlation path."""

from datetime import datetime, timedelta, timezone

import pytest

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.common import (
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    ValidationTarget,
)
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.store import InMemoryStore


def _context(strict: bool = False):
    store = InMemoryStore()
    start = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
    scenario = ScenarioV1(
        scenario_id="SCN-BATCH7",
        name="Batch 7 performance scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="whoami",
        expected_detection_rule_id="RULE-BATCH7",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    run = TestRunV1(
        run_id="RUN-BATCH7",
        scenario_id=scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="HOST-BATCH7",
        target_user="secops",
        window_start=start,
        window_end=start + timedelta(minutes=5),
        executed_at=start,
        execution_status=ExecutionStatus.COMPLETED,
        execution_token="TOK-BATCH7" if strict else None,
    )
    store.add_scenario(scenario)
    store.add_rule(DetectionRuleV1(rule_id="RULE-BATCH7", rule_name="Batch 7 rule", rule_format="sigma"))
    store.add_run(run)
    return store, run, start


def _event(event_id, timestamp, token=None):
    return NormalizedTelemetryEventV1(
        normalized_event_id=event_id,
        raw_event_id=f"RAW-{event_id}",
        source_event_id=f"SRC-{event_id}",
        source_timestamp=timestamp,
        normalized_timestamp=timestamp,
        event_category=EventCategory.PROCESS_CREATION,
        host="HOST-BATCH7",
        process_name="whoami",
        command_line="whoami",
        execution_token=token,
    )


def _alert(alert_id, timestamp, token=None):
    return AlertV1(
        alert_id=alert_id,
        source_alert_id=f"SRC-{alert_id}",
        source_type="synthetic",
        alert_timestamp=timestamp,
        host_id="HOST-BATCH7",
        rule_reference="RULE-BATCH7",
        alert_title="Batch 7 alert",
        execution_token=token,
    )


def test_fast_correlation_preserves_inclusive_boundaries_and_duplicates():
    store, run, start = _context()
    end = run.window_end
    store.add_normalized_event(_event("N-START", start))
    store.add_normalized_event(_event("N-END", end))
    store.add_normalized_event(_event("N-DUPLICATE-DATA", start))
    store.add_alert(_alert("A-END", end))

    result = AssuranceEngine(store).evaluate_run(run.run_id)

    assert result.predicted_category == DiagnosticCategory.PASS
    assert result.supporting_evidence_ids[:3] == ["N-DUPLICATE-DATA", "N-START", "N-END"]


def test_fast_correlation_preserves_strict_token_attribution():
    store, run, start = _context(strict=True)
    store.add_normalized_event(_event("N-MATCH", start, "TOK-BATCH7"))
    store.add_normalized_event(_event("N-MISMATCH", start + timedelta(seconds=1), "TOK-OTHER"))
    store.add_alert(_alert("A-MATCH", start + timedelta(seconds=2), "TOK-BATCH7"))

    result = AssuranceEngine(store).evaluate_run(run.run_id, strict_attribution=True)

    assert result.predicted_category == DiagnosticCategory.PASS
    assert "N-MATCH" in result.supporting_evidence_ids
    assert "N-MISMATCH" not in result.supporting_evidence_ids
    assert "A-MATCH" in result.supporting_evidence_ids
    assert result.metadata["attribution"]["status"] == "VERIFIED"


def test_fast_correlation_preserves_missing_and_insufficient_evidence_outcomes():
    empty_store, empty_run, _ = _context()
    empty_result = AssuranceEngine(empty_store).evaluate_run(empty_run.run_id)
    assert empty_result.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    strict_store, strict_run, start = _context(strict=True)
    strict_store.add_normalized_event(_event("N-UNTOKENED", start))
    strict_store.add_alert(_alert("A-TOKENED", start + timedelta(seconds=1), "TOK-BATCH7"))
    strict_result = AssuranceEngine(strict_store).evaluate_run(strict_run.run_id, strict_attribution=True)
    assert strict_result.predicted_category == DiagnosticCategory.INCONCLUSIVE


def test_default_correlation_results_remain_isolated_from_callers():
    store, run, start = _context()
    store.add_normalized_event(_event("N-ISOLATED", start))
    store.add_alert(_alert("A-ISOLATED", start))

    events = store.get_events_for_run(run)
    alerts = store.list_alerts_for_rule("RULE-BATCH7")
    events[0].host = "MUTATED"
    alerts[0].host_id = "MUTATED"

    assert store.get_events_for_run(run)[0].host == "HOST-BATCH7"
    assert store.list_alerts_for_rule("RULE-BATCH7")[0].host_id == "HOST-BATCH7"
