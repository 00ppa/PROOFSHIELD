# Evidence Dataset and ML Research Layer

The Phase 22 research layer is deliberately separate from assurance. It collects feature rows from stored execution, telemetry, alert, and independently authored ground-truth records. It never changes those records and never changes a deterministic diagnosis.

## Provenance rules

- `DatasetObservationV1` records whether an observation is synthetic or real.
- Confirmed labels must reference a `GroundTruthV1` identifier.
- Synthetic observations are excluded by default and must be explicitly enabled.
- Feature vectors reject keys containing `label` or `diagnostic` to reduce leakage.
- Splits group connected scenarios, runs and shared evidence before deterministic
  assignment by seed. Related observations cannot cross training/test boundaries.
- Evaluators validate content hashes, provenance flags, split overlap, unknown
  identifiers and class coverage. Mixed real/synthetic evaluation is rejected.
- Model results identify the dataset, split, model version, and model hash.

The current repository contains controlled and synthetic fixtures. It does not claim that these represent real operational prevalence or model performance.

## Baselines

Install `python -m pip install -e ".[research]"` for the optional local
scikit-learn 1.5.x implementations. Core assurance has no ML dependency:

- Logistic Regression with training-only standardization.
- Random Forest classifier with learned recursive tree splits and fixed seeds.
- Isolation Forest anomaly scoring.

Metrics include accuracy, macro precision/recall/F1, confusion matrix, log loss
and multiclass Brier score. Feature importances, learned parameters, library
version, dataset/split identity and model digest are exported in JSON; unsafe
pickle loading is not used. Isolation Forest scores held-out observations after
training on training rows only.

These are **post-observation classification experiments**, not prospective
failure forecasts. Collection error and normalization completeness derive from
recorded collection reports; an absent report has an explicit unknown flag.
An empty event set is not labeled a retrieval error.

`py -3.12 scripts/run_research.py` uses three explicitly synthetic bundled
observations. Its current split has one unseen held-out class, so both models
report `INSUFFICIENT_DATA` instead of publishing misleading metrics. A real,
independently labeled dataset remains an external research prerequisite.

The UI exposes `/api/v1/research/dataset` and `/api/v1/research/evaluate`. Exported
model predictions are hypotheses only; `AssuranceEngine` remains authoritative.

## Python usage

```python
from proofshield.research.dataset import DatasetCollector
from proofshield.research.ml import LogisticRegressionBaseline, evaluate_model

dataset = DatasetCollector(store).collect(dataset_id="DATASET-LOCAL-01")
split = DatasetCollector.split(dataset, seed="experiment-1")
result = evaluate_model(
    LogisticRegressionBaseline(), dataset,
    split.train_observation_ids, split.test_observation_ids, split.split_id,
)
```
