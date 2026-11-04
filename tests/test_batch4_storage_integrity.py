"""Focused cross-backend integrity and transaction regressions."""

from datetime import datetime, timezone

import pytest

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.common import DiagnosticCategory, EventCategory, ExecutionMode, ExecutionStatus, ValidationTarget
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.execution import ExecutionEvidenceV1, RunnerExecutionState
from proofshield.schemas.explanation import AnalystExplanationV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore


def _scenario_and_run(store, suffix="01"):
    now = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
    scenario = ScenarioV1(
        scenario_id=f"SCN-STORAGE-{suffix}",
        name="Storage integrity scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
    )
    run = TestRunV1(
        run_id=f"RUN-STORAGE-{suffix}",
        scenario_id=scenario.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-STORAGE-01",
        target_user="secops",
        window_start=now,
        window_end=now,
        executed_at=now,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_scenario(scenario)
    store.add_run(run)
    return scenario, run, now


def _records(scenario, run, now, suffix="01"):
    alert = AlertV1(
        alert_id=f"ALT-STORAGE-{suffix}",
        source_alert_id=f"SRC-STORAGE-{suffix}",
        source_type="elastic",
        host_id="WS-STORAGE-01",
        alert_title="Observed token=TOK-STORAGE-01",
        metadata={"nested": {"value": "original-alert"}},
    )
    result = DiagnosticResultV1(
        diagnostic_id=f"DIAG-STORAGE-{suffix}",
        test_run_id=run.run_id,
        scenario_id=scenario.scenario_id,
        predicted_category=DiagnosticCategory.INCONCLUSIVE,
        reason="Insufficient evidence",
        evaluated_at=now,
        metadata={"nested": {"value": "original-result"}},
    )
    explanation = AnalystExplanationV1(
        explanation_id=f"EXPL-STORAGE-{suffix}",
        diagnostic_id=result.diagnostic_id,
        test_run_id=run.run_id,
        scenario_id=scenario.scenario_id,
        deterministic_category=DiagnosticCategory.INCONCLUSIVE,
        summary="Evidence is incomplete.",
        source_digest="a" * 64,
    )
    execution = ExecutionEvidenceV1(
        execution_id=f"EXEC-STORAGE-{suffix}",
        execution_token=f"tok-storage-{suffix}",
        target_host="WS-STORAGE-01",
        action_id="process.spawn_benign",
        action_version="1.0.0",
        parameters={"nested": {"value": "original-execution"}},
        requested_at=now,
        started_at=now,
        completed_at=now,
        duration_seconds=0.0,
        status=RunnerExecutionState.COMPLETED,
        integrity_hash="b" * 64,
    )
    return alert, result, explanation, execution


def _stores(tmp_path):
    return [InMemoryStore(), SQLiteStore(tmp_path / "batch4.db")]


def test_reset_clears_all_evidence_entities_and_preserves_reusability(tmp_path):
    for store in _stores(tmp_path):
        try:
            scenario, run, now = _scenario_and_run(store)
            alert, result, explanation, execution = _records(scenario, run, now)
            store.add_alert(alert)
            store.add_result(result)
            store.add_explanation(explanation)
            store.add_execution(execution)

            assert store.list_alerts()
            assert store.list_results()
            assert store.list_explanations()
            assert store.list_executions()

            store.reset()

            assert store.list_scenarios() == []
            assert store.list_runs() == []
            assert store.list_alerts() == []
            assert store.list_results() == []
            assert store.list_explanations() == []
            assert store.list_executions() == []

            scenario2, _, _ = _scenario_and_run(store, suffix="02")
            assert store.get_scenario(scenario2.scenario_id) == scenario2
        finally:
            store.close()


def test_alert_ingestion_does_not_mutate_caller_and_retrieval_is_isolated(tmp_path):
    for store in _stores(tmp_path):
        try:
            scenario, run, now = _scenario_and_run(store)
            alert, _, _, _ = _records(scenario, run, now)
            original = alert.model_copy(deep=True)

            saved = store.add_alert(alert)
            assert alert == original
            assert saved.ingested_at is not None
            assert saved.execution_token == "TOK-STORAGE-01"

            saved.metadata["nested"]["value"] = "mutated-return"
            retrieved = store.get_alert(saved.alert_id)
            assert retrieved.metadata["nested"]["value"] == "original-alert"

            alert.metadata["nested"]["value"] = "mutated-input"
            assert store.get_alert(saved.alert_id).metadata["nested"]["value"] == "original-alert"
        finally:
            store.close()


def test_transaction_rollback_isolates_results_and_all_evidence_records(tmp_path):
    for store in _stores(tmp_path):
        try:
            scenario, run, now = _scenario_and_run(store)
            stable_alert, stable_result, stable_explanation, stable_execution = _records(
                scenario, run, now, suffix="STABLE"
            )
            store.add_alert(stable_alert)
            store.add_result(stable_result)
            store.add_explanation(stable_explanation)
            store.add_execution(stable_execution)

            replacement = stable_result.model_copy(deep=True)
            replacement.reason = "replacement that must roll back"
            transient_alert, _, transient_explanation, transient_execution = _records(
                scenario, run, now, suffix="TRANSIENT"
            )
            with pytest.raises(RuntimeError, match="rollback"):
                with store.transaction():
                    store.add_result(replacement)
                    store.add_alert(transient_alert)
                    store.add_explanation(transient_explanation)
                    store.add_execution(transient_execution)
                    raise RuntimeError("rollback")

            assert store.get_result(stable_result.diagnostic_id).reason == stable_result.reason
            assert store.get_alert(transient_alert.alert_id) is None
            assert store.get_explanation(transient_explanation.explanation_id) is None
            assert store.get_execution(transient_execution.execution_id) is None
            assert store.get_alert(stable_alert.alert_id) is not None
            assert store.get_explanation(stable_explanation.explanation_id) is not None
            assert store.get_execution(stable_execution.execution_id) is not None
        finally:
            store.close()


def test_sqlite_reopen_preserves_alert_result_explanation_and_execution(tmp_path):
    db_path = tmp_path / "reopen.db"
    store = SQLiteStore(db_path)
    scenario, run, now = _scenario_and_run(store)
    alert, result, explanation, execution = _records(scenario, run, now)
    store.add_alert(alert)
    store.add_result(result)
    store.add_explanation(explanation)
    store.add_execution(execution)
    store.close()

    reopened = SQLiteStore(db_path)
    try:
        assert reopened.get_alert(alert.alert_id) is not None
        assert reopened.get_result(result.diagnostic_id) == result
        assert reopened.get_explanation(explanation.explanation_id) == explanation
        assert reopened.get_execution(execution.execution_id) == execution
        reopened.reset()
    finally:
        reopened.close()

    reopened_again = SQLiteStore(db_path)
    try:
        assert reopened_again.list_alerts() == []
        assert reopened_again.list_results() == []
        assert reopened_again.list_explanations() == []
        assert reopened_again.list_executions() == []
    finally:
        reopened_again.close()
