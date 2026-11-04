"""Local research exports with explicit insufficient-data results."""

from fastapi import APIRouter, HTTPException
from proofshield.research.dataset import DatasetCollector, DatasetValidationError
from proofshield.research.ml import LogisticRegressionBaseline, RandomForestBaseline, IsolationForestAnomalyDetector, evaluate_model
from proofshield.services.store import get_store

router = APIRouter(prefix="/api/v1/research", tags=["Research"])


@router.get("/dataset")
def dataset(include_synthetic: bool = False):
    return DatasetCollector(get_store()).collect(include_synthetic=include_synthetic)


@router.post("/evaluate")
def evaluate(include_synthetic: bool = False):
    data = dataset(include_synthetic)
    try:
        split = DatasetCollector.split(data)
        models = [evaluate_model(model, data, split.train_observation_ids, split.test_observation_ids, split.split_id)
                  for model in (LogisticRegressionBaseline(), RandomForestBaseline())]
        rows = {row.observation_id: row for row in data.observations}
        train = [[rows[key].feature_vector[name] for name in data.feature_names] for key in split.train_observation_ids]
        held_out = [[rows[key].feature_vector[name] for name in data.feature_names] for key in split.test_observation_ids]
        anomalies = IsolationForestAnomalyDetector().fit(train).predict(held_out, split.test_observation_ids)
        return {"dataset": data, "split": split, "models": models, "anomalies": anomalies,
                "authority": "Deterministic assurance only; model outputs are hypotheses"}
    except DatasetValidationError as exc:
        return {"status": "INSUFFICIENT_DATA", "reason": str(exc), "dataset": data}
    except ImportError as exc:
        raise HTTPException(503, "Install ProofShield's research extra to run local models") from exc
