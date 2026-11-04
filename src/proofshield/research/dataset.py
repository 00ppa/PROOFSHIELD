"""Deterministic collection and validation of evidence-derived observations."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
import uuid

from proofshield.schemas.common import DiagnosticCategory
from proofshield.schemas.research import DatasetCollectionV1, DatasetObservationV1, DatasetSplitV1
from proofshield.services.base_store import StoreProtocol, to_comparable_utc
from proofshield.services.canonical import compute_canonical_hash
from proofshield.services.evaluation import AssuranceEngine


class DatasetValidationError(ValueError):
    """Raised when a research dataset violates provenance or leakage rules."""


class DatasetCollector:
    """Builds feature rows from stored evidence without changing assurance records."""

    FEATURE_NAMES = (
        "execution_completed",
        "execution_duration_seconds",
        "telemetry_event_count",
        "token_matched_telemetry_count",
        "telemetry_categories_count",
        "alert_count",
        "token_matched_alert_count",
        "alert_rule_present",
        "normalization_complete",
        "collection_error",
        "collection_status_known",
    )

    def __init__(self, store: StoreProtocol, assurance_engine: Optional[AssuranceEngine] = None) -> None:
        self.store = store
        self.assurance_engine = assurance_engine or AssuranceEngine(store=store)

    def collect(
        self,
        dataset_id: Optional[str] = None,
        include_synthetic: bool = False,
        include_unlabeled: bool = False,
        strict_attribution: bool = True,
    ) -> DatasetCollectionV1:
        observations: List[DatasetObservationV1] = []
        for run in sorted(self.store.list_runs(), key=lambda item: item.run_id):
            if run.is_synthetic and not include_synthetic:
                continue
            ground_truth = self.store.get_ground_truth_for_run(run.run_id)
            label = ground_truth.expected_diagnostic_category if ground_truth and ground_truth.label_status == "confirmed" else None
            if label is None and not include_unlabeled:
                continue
            events = self.store.get_events_for_run(run)
            alerts = self.store.get_alerts_for_run(run)
            execution = next((item for item in self.store.list_executions(run_id=run.run_id)), None)
            token = run.execution_token
            matched_events = (
                [event for event in events if token and event.execution_token == token]
                if strict_attribution
                else events
            )
            matched_alerts = (
                [alert for alert in alerts if token and alert.execution_token == token]
                if strict_attribution
                else alerts
            )
            rule_present = bool(self.store.get_scenario(run.scenario_id).expected_detection_rule_id) if self.store.get_scenario(run.scenario_id) else False
            diagnostic = self.store.get_result_for_run(run.run_id)
            collection = diagnostic.metadata.get("collection", {}) if diagnostic else {}
            collection_error = float(bool(collection) and not collection.get("is_complete", False))
            feature_vector = {
                "execution_completed": 1.0 if str(run.execution_status.value) == "COMPLETED" else 0.0,
                "execution_duration_seconds": float(execution.duration_seconds if execution else 0.0),
                "telemetry_event_count": float(len(events)),
                "token_matched_telemetry_count": float(len(matched_events)),
                "telemetry_categories_count": float(len({event.event_category.value for event in events})),
                "alert_count": float(len(alerts)),
                "token_matched_alert_count": float(len(matched_alerts)),
                "alert_rule_present": 1.0 if rule_present else 0.0,
                "normalization_complete": float(collection.get("normalization_status") == "COMPLETE"),
                "collection_error": collection_error,
                "collection_status_known": float(bool(collection)),
            }
            refs = sorted([event.raw_event_id for event in events] + [alert.alert_id for alert in alerts])
            evidence_hashes = {event.raw_event_id: compute_canonical_hash(self.store.get_raw_event(event.raw_event_id).raw_payload)
                               for event in events if self.store.get_raw_event(event.raw_event_id) is not None}
            evidence_hashes.update({alert.alert_id: compute_canonical_hash(alert.model_dump(exclude={"ingested_at"})) for alert in alerts})
            if execution:
                refs.append(execution.execution_id)
                evidence_hashes[execution.execution_id] = execution.integrity_hash
            observations.append(
                DatasetObservationV1(
                    observation_id=f"OBS-{run.run_id}",
                    run_id=run.run_id,
                    scenario_id=run.scenario_id,
                    is_synthetic=run.is_synthetic,
                    provenance="synthetic" if run.is_synthetic else "real",
                    feature_vector=feature_vector,
                    label=label,
                    label_source=ground_truth.ground_truth_id if ground_truth else None,
                    evidence_references=refs,
                    evidence_hashes=evidence_hashes,
                    observed_outcome=diagnostic.predicted_category if diagnostic else None,
                )
            )
        collection = DatasetCollectionV1(
            dataset_id=dataset_id or f"DATASET-{uuid.uuid4().hex[:12].upper()}",
            source_description="Collected from ProofShield execution, telemetry, alert, and independent ground-truth records",
            observations=observations,
            feature_names=list(self.FEATURE_NAMES),
            includes_synthetic=any(item.is_synthetic for item in observations),
            includes_real=any(not item.is_synthetic for item in observations),
        )
        collection.dataset_hash = self.compute_hash(collection)
        self.validate(collection)
        return collection

    @staticmethod
    def compute_hash(collection: DatasetCollectionV1) -> str:
        # Creation time is provenance metadata, not dataset content. Excluding
        # it keeps the same source evidence reproducible across collection runs.
        return compute_canonical_hash(collection.model_dump(exclude={"dataset_hash", "created_at"}))

    @staticmethod
    def validate(collection: DatasetCollectionV1, require_single_provenance: bool = False) -> None:
        if collection.dataset_hash and collection.dataset_hash != DatasetCollector.compute_hash(collection):
            raise DatasetValidationError("Dataset hash does not match its immutable content")
        if collection.includes_synthetic != any(row.is_synthetic for row in collection.observations) or collection.includes_real != any(not row.is_synthetic for row in collection.observations):
            raise DatasetValidationError("Dataset provenance flags do not match observations")
        if require_single_provenance and collection.includes_synthetic and collection.includes_real:
            raise DatasetValidationError("Synthetic and real observations must be explicitly separated")
        feature_names = set(collection.feature_names)
        if not feature_names or len(feature_names) != len(collection.feature_names):
            raise DatasetValidationError("Features must be nonempty and unique")
        for observation in collection.observations:
            if observation.provenance != ("synthetic" if observation.is_synthetic else "real"):
                raise DatasetValidationError("Ambiguous or inconsistent observation provenance")
            if set(observation.feature_vector) != feature_names:
                raise DatasetValidationError(f"Feature schema mismatch for {observation.observation_id}")
            if observation.label is not None and not observation.label_source:
                raise DatasetValidationError(f"Label provenance missing for {observation.observation_id}")

    @staticmethod
    def split(collection: DatasetCollectionV1, test_fraction: float = 0.2, seed: str = "proofshield-v1") -> DatasetSplitV1:
        if not 0.0 < test_fraction < 1.0:
            raise DatasetValidationError("test_fraction must be between 0 and 1")
        DatasetCollector.validate(collection)
        groups = DatasetCollector.groups(collection)
        ordered = sorted(groups, key=lambda group: hashlib.sha256(f"{seed}:{','.join(sorted(group))}".encode()).hexdigest())
        if len(ordered) < 2:
            raise DatasetValidationError("At least two independent evidence/scenario groups are required")
        test_count = min(len(ordered) - 1, max(1, round(len(ordered) * test_fraction)))
        test_ids = sorted(identifier for group in ordered[:test_count] for identifier in group)
        train_ids = sorted(identifier for group in ordered[test_count:] for identifier in group)
        return DatasetSplitV1(
            split_id="SPLIT-" + compute_canonical_hash({"dataset": DatasetCollector.compute_hash(collection), "seed": seed, "fraction": test_fraction, "test": test_ids})[:16],
            seed=seed,
            test_fraction=test_fraction,
            train_observation_ids=train_ids,
            test_observation_ids=test_ids,
            leakage_checks=[
                "Connected scenario, run and shared-evidence groups never cross splits",
                "Group assignment is deterministic for the declared seed and dataset",
                "Labels are excluded from feature vectors",
            ],
        )

    @staticmethod
    def groups(collection):
        groups = []
        keys = []
        for row in collection.observations:
            row_keys = {f"run:{row.run_id}"} | {f"evidence:{ref}" for ref in row.evidence_references}
            if row.scenario_id:
                row_keys.add(f"scenario:{row.scenario_id}")
            merged_ids = {row.observation_id}
            for index in reversed(range(len(groups))):
                if keys[index] & row_keys:
                    merged_ids |= groups.pop(index)
                    row_keys |= keys.pop(index)
            groups.append(merged_ids)
            keys.append(row_keys)
        return groups
