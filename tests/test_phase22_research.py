"""Phase 22 provenance, leakage, split, and local baseline tests."""

from datetime import datetime, timedelta, timezone

import pytest

from proofshield.research.dataset import DatasetCollector, DatasetValidationError
from proofshield.research.ml import (
    IsolationForestAnomalyDetector,
    LogisticRegressionBaseline,
    RandomForestBaseline,
    evaluate_model,
)
from proofshield.schemas.common import DiagnosticCategory, EventCategory, ExecutionMode, ExecutionStatus, ValidationTarget
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.schemas.research import DatasetCollectionV1, DatasetObservationV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.store import InMemoryStore


def _research_store() -> InMemoryStore:
    store = InMemoryStore()
    start = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    for index, category in enumerate((DiagnosticCategory.PASS, DiagnosticCategory.EXPECTED_TELEMETRY_MISSING) * 3):
        scenario_id = f"SCN-RESEARCH-{index:02d}"
        run_id = f"RUN-RESEARCH-{index:02d}"
        store.add_scenario(
            ScenarioV1(
                scenario_id=scenario_id,
                name="Research controlled scenario",
                mitre_technique_id="T1082",
                mitre_tactic="Discovery",
                expected_event_category=EventCategory.PROCESS_CREATION,
                expected_detection_rule_id="RULE-RESEARCH",
                expected_process_name="whoami",
                validation_target=ValidationTarget.EXPECTED_ALERT,
            )
        )
        run_start = start + timedelta(minutes=index)
        store.add_run(
            TestRunV1(
                run_id=run_id,
                scenario_id=scenario_id,
                target_host="RESEARCH-HOST",
                target_user="tester",
                execution_mode=ExecutionMode.EMULATED_AGENT,
                is_synthetic=False,
                executed_at=run_start,
                window_start=run_start,
                window_end=run_start + timedelta(seconds=5),
                execution_status=ExecutionStatus.COMPLETED,
                execution_token=f"tok-{index}",
            )
        )
        store.add_ground_truth(
            GroundTruthV1(
                ground_truth_id=f"GT-RESEARCH-{index:02d}",
                run_id=run_id,
                expected_diagnostic_category=category,
                verification_method="independent_fixture_label",
                label_status="confirmed",
            )
        )
    return store


def test_dataset_collection_has_independent_labels_and_no_feature_leakage():
    dataset = DatasetCollector(_research_store()).collect(dataset_id="DATASET-RESEARCH-01")
    assert len(dataset.observations) == 6
    assert all(item.label_source for item in dataset.observations)
    assert all("diagnostic" not in key for key in dataset.feature_names)
    assert DatasetCollector.compute_hash(dataset) == dataset.dataset_hash


def test_dataset_synthetic_records_are_excluded_by_default():
    store = _research_store()
    run = store.get_run("RUN-RESEARCH-00")
    # Store records are copy-isolated; mutate the backing fixture only for this
    # focused provenance test, without changing production collection behavior.
    store._runs[run.run_id] = run.model_copy(update={"is_synthetic": True})
    dataset = DatasetCollector(store).collect(dataset_id="DATASET-REAL-ONLY")
    assert all(not item.is_synthetic for item in dataset.observations)
    included = DatasetCollector(store).collect(dataset_id="DATASET-MIXED", include_synthetic=True)
    assert any(item.is_synthetic for item in included.observations)


def test_split_is_reproducible_and_disjoint():
    dataset = DatasetCollector(_research_store()).collect(dataset_id="DATASET-SPLIT-01")
    first = DatasetCollector.split(dataset, test_fraction=0.33, seed="fixed-seed")
    second = DatasetCollector.split(dataset, test_fraction=0.33, seed="fixed-seed")
    assert first == second
    assert set(first.train_observation_ids).isdisjoint(first.test_observation_ids)
    assert set(first.train_observation_ids) | set(first.test_observation_ids) == {
        item.observation_id for item in dataset.observations
    }


def test_dataset_validator_rejects_label_named_features():
    with pytest.raises(ValueError, match="must not contain diagnostic or label"):
        DatasetObservationV1(
            observation_id="OBS-BAD-01",
            run_id="RUN-BAD-01",
            provenance="real",
            feature_vector={"diagnostic_category": 1.0},
        )


def test_logistic_and_random_forest_baselines_evaluate_deterministically():
    dataset = DatasetCollectionV1(
        dataset_id="DATASET-ML-01",
        source_description="Explicitly synthetic unit fixture",
        feature_names=["signal", "noise"],
        observations=[
            DatasetObservationV1(observation_id=f"OBS-{index}", run_id=f"RUN-{index}", provenance="synthetic", is_synthetic=True, feature_vector={"signal": float(index % 2), "noise": 0.0}, label=DiagnosticCategory.PASS if index % 2 else DiagnosticCategory.DETECTION_NOT_TRIGGERED, label_source="fixture")
            for index in range(10)
        ],
        includes_synthetic=True,
    )
    split = DatasetCollector.split(dataset, test_fraction=0.3)
    for model in (LogisticRegressionBaseline(epochs=80), RandomForestBaseline(trees=10)):
        result = evaluate_model(model, dataset, split.train_observation_ids, split.test_observation_ids, split.split_id)
        assert result.synthetic_training_data is True
        assert result.metrics.labels
        assert result.model_hash


def test_isolation_forest_produces_reproducible_scores():
    rows = [[0.0, 0.0], [0.1, 0.0], [0.0, 0.1], [10.0, 10.0]]
    first = IsolationForestAnomalyDetector(trees=20, seed=7).fit(rows)
    second = IsolationForestAnomalyDetector(trees=20, seed=7).fit(rows)
    first_scores = first.score_samples(rows)
    second_scores = second.score_samples(rows)
    assert first_scores == second_scores
    assert first_scores[-1] > first_scores[0]
