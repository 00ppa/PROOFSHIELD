"""Versioned schemas for evidence-derived research datasets and model results."""

from datetime import datetime, timezone
import math
from typing import Dict, List, Literal, Optional

from pydantic import Field, field_validator

from proofshield.schemas.common import DiagnosticCategory, ProofshieldBaseModel, validate_nesting_depth


class DatasetObservationV1(ProofshieldBaseModel):
    schema_version: Literal["v1"] = "v1"
    observation_id: str = Field(..., min_length=3)
    run_id: str = Field(..., min_length=3)
    scenario_id: Optional[str] = None
    is_synthetic: bool = False
    provenance: Literal["synthetic", "real", "mixed"]
    feature_vector: Dict[str, float] = Field(default_factory=dict)
    label: Optional[DiagnosticCategory] = None
    label_source: Optional[str] = None
    evidence_references: List[str] = Field(default_factory=list)
    evidence_hashes: Dict[str, str] = Field(default_factory=dict)
    observed_outcome: Optional[DiagnosticCategory] = None

    @field_validator("feature_vector")
    @classmethod
    def validate_features(cls, value: Dict[str, float]) -> Dict[str, float]:
        if any("label" in key.lower() or "diagnostic" in key.lower() for key in value):
            raise ValueError("Feature vectors must not contain diagnostic or label fields")
        if any(not isinstance(item, (int, float)) for item in value.values()):
            raise ValueError("Feature values must be numeric")
        if any(not math.isfinite(item) for item in value.values()):
            raise ValueError("Feature values must be finite")
        return {key: float(item) for key, item in value.items()}


class DatasetCollectionV1(ProofshieldBaseModel):
    schema_version: Literal["v1"] = "v1"
    dataset_id: str = Field(..., min_length=3)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_description: str = Field(..., min_length=1)
    observations: List[DatasetObservationV1] = Field(default_factory=list)
    feature_names: List[str] = Field(default_factory=list)
    includes_synthetic: bool = False
    includes_real: bool = False
    dataset_hash: Optional[str] = None

    @field_validator("observations")
    @classmethod
    def validate_observations(cls, value: List[DatasetObservationV1]) -> List[DatasetObservationV1]:
        ids = [item.observation_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("Dataset observation IDs must be unique")
        return value


class DatasetSplitV1(ProofshieldBaseModel):
    schema_version: Literal["v1"] = "v1"
    split_id: str = Field(..., min_length=3)
    seed: str = Field(..., min_length=1)
    test_fraction: float = Field(..., gt=0.0, lt=1.0)
    train_observation_ids: List[str] = Field(default_factory=list)
    test_observation_ids: List[str] = Field(default_factory=list)
    leakage_checks: List[str] = Field(default_factory=list)


class ClassificationMetricsV1(ProofshieldBaseModel):
    accuracy: float = Field(..., ge=0.0, le=1.0)
    macro_precision: float = Field(..., ge=0.0, le=1.0)
    macro_recall: float = Field(..., ge=0.0, le=1.0)
    macro_f1: float = Field(..., ge=0.0, le=1.0)
    labels: List[str] = Field(default_factory=list)
    confusion_matrix: Dict[str, Dict[str, int]] = Field(default_factory=dict)


class ModelEvaluationResultV1(ProofshieldBaseModel):
    schema_version: Literal["v1"] = "v1"
    model_id: str = Field(..., min_length=3)
    model_type: str = Field(..., min_length=1)
    model_version: str = Field(..., min_length=1)
    dataset_id: str = Field(..., min_length=3)
    split_id: str = Field(..., min_length=3)
    metrics: ClassificationMetricsV1
    training_observations: int = Field(..., ge=0)
    test_observations: int = Field(..., ge=0)
    synthetic_training_data: bool = False
    notes: List[str] = Field(default_factory=list)
    model_hash: Optional[str] = None
    dataset_hash: Optional[str] = None
    parameters: Dict = Field(default_factory=dict)
    learned_state: Dict = Field(default_factory=dict)
    feature_importance: Dict[str, float] = Field(default_factory=dict)
    log_loss: Optional[float] = None
    brier_score: Optional[float] = None


class AnomalyScoreV1(ProofshieldBaseModel):
    observation_id: str = Field(..., min_length=3)
    score: float
    is_anomaly: bool
    model_id: str = Field(..., min_length=3)
