#!/usr/bin/env python3
"""Run a reproducible local research evaluation over bundled synthetic fixtures.

This script reports metrics for development verification only. It does not claim
that bundled fixtures represent real operational data.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from proofshield.normalisation.engine import NormalisationEngine
from proofshield.schemas import AlertV1, DetectionRuleV1, GroundTruthV1, RawTelemetryEventV1, ScenarioV1, TestRunV1
from proofshield.research.dataset import DatasetCollector
from proofshield.research.dataset import DatasetValidationError
from proofshield.research.ml import LogisticRegressionBaseline, RandomForestBaseline, evaluate_model
from proofshield.services.store import InMemoryStore
from proofshield.storage.jsonl_loader import validate_jsonl_file


def load_fixture_store() -> InMemoryStore:
    store = InMemoryStore()
    fixtures = REPO_ROOT / "fixtures"
    for name, schema, add in (
        ("scenarios_v1.jsonl", ScenarioV1, store.add_scenario),
        ("test_runs_v1.jsonl", TestRunV1, store.add_run),
        ("detection_rules_v1.jsonl", DetectionRuleV1, store.add_rule),
        ("alerts_v1.jsonl", AlertV1, store.add_alert),
        ("ground_truth_v1.jsonl", GroundTruthV1, store.add_ground_truth),
    ):
        for record in validate_jsonl_file(fixtures / name, schema).records:
            add(record)
    normaliser = NormalisationEngine()
    for raw in validate_jsonl_file(fixtures / "raw_telemetry_valid_v1.jsonl", RawTelemetryEventV1).records:
        store.add_raw_event(raw)
        normalized = normaliser.normalize(raw)
        # Fixture imports must identify the same source event across repeated
        # experiments even when a legacy normalizer allocates a UUID.
        normalized.normalized_event_id = f"NORM-FIXTURE-{raw.raw_event_id}"
        store.add_normalized_event(normalized)
    return store


def main() -> None:
    store = load_fixture_store()
    dataset = DatasetCollector(store).collect(
        dataset_id="DATASET-BUNDLED-SYNTHETIC-V1",
        include_synthetic=True,
    )
    split = DatasetCollector.split(dataset, seed="bundled-fixture-v1")
    results = []
    for model in (LogisticRegressionBaseline(), RandomForestBaseline()):
        try:
            results.append(evaluate_model(model, dataset, split.train_observation_ids, split.test_observation_ids, split.split_id).model_dump(mode="json"))
        except DatasetValidationError as exc:
            results.append({"model_type": model.model_type, "status": "INSUFFICIENT_DATA", "reason": str(exc)})
    print(json.dumps({"dataset": dataset.model_dump(mode="json"), "split": split.model_dump(mode="json"), "models": results}, indent=2))


if __name__ == "__main__":
    main()
