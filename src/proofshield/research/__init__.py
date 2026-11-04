"""Evidence-grounded dataset and local ML research services."""

from proofshield.research.dataset import DatasetCollector, DatasetValidationError
from proofshield.research.ml import (
    IsolationForestAnomalyDetector,
    LogisticRegressionBaseline,
    RandomForestBaseline,
    evaluate_model,
    evaluate_classifier,
)

__all__ = [
    "DatasetCollector",
    "DatasetValidationError",
    "IsolationForestAnomalyDetector",
    "LogisticRegressionBaseline",
    "RandomForestBaseline",
    "evaluate_model",
    "evaluate_classifier",
]
