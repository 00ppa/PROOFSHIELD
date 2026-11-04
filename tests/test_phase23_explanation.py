"""Phase 23 evidence-grounded explanation and persistence tests."""

from datetime import datetime, timezone

from proofshield.schemas.common import DiagnosticCategory, EventCategory, ExecutionMode, ExecutionStatus, ValidationTarget
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.explanation import EvidenceGroundedExplanationService
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore


def _store(store):
    now = datetime(2026, 11, 3, 13, 0, tzinfo=timezone.utc)
    store.add_scenario(
        ScenarioV1(
            scenario_id="SCN-EXPLAIN-01",
            name="Explanation scenario",
            mitre_technique_id="T1082",
            mitre_tactic="Discovery",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="whoami",
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
    )
    store.add_run(
        TestRunV1(
            run_id="RUN-EXPLAIN-01",
            scenario_id="SCN-EXPLAIN-01",
            target_host="EXPLAIN-HOST",
            target_user="tester",
            execution_mode=ExecutionMode.EMULATED_AGENT,
            window_start=now,
            window_end=now,
            executed_at=now,
            execution_status=ExecutionStatus.COMPLETED,
        )
    )
    return store


def _result():
    return DiagnosticResultV1(
        diagnostic_id="DIAG-EXPLAIN-01",
        test_run_id="RUN-EXPLAIN-01",
        scenario_id="SCN-EXPLAIN-01",
        predicted_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        confidence="likely",
        reason="No matching telemetry was observed in the configured window.",
        diagnostic_reasons=["No normalized event matched the expected signature"],
        evaluated_at=datetime(2026, 11, 3, 13, 1, tzinfo=timezone.utc),
    )


def test_explanation_is_fact_hypothesis_separated_and_integrity_verifiable():
    explanation = EvidenceGroundedExplanationService(_store(InMemoryStore())).explain(_result())
    assert explanation.deterministic_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert explanation.confirmed_facts
    assert explanation.missing_evidence
    assert explanation.hypotheses
    assert all(item.confirmed is False for item in explanation.hypotheses)
    assert EvidenceGroundedExplanationService.verify(explanation) is True
    explanation.summary = "tampered"
    assert EvidenceGroundedExplanationService.verify(explanation) is False


def test_explanation_persists_in_memory_and_sqlite(tmp_path):
    for store in (InMemoryStore(), SQLiteStore(tmp_path / "explanations.db")):
        try:
            _store(store)
            explanation = EvidenceGroundedExplanationService(store).explain(_result())
            store.add_explanation(explanation)
            assert store.get_explanation(explanation.explanation_id).explanation_hash == explanation.explanation_hash
            assert len(store.list_explanations(run_id="RUN-EXPLAIN-01")) == 1
        finally:
            store.close()
