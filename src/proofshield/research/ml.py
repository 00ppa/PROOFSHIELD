"""Auditable local scikit-learn baselines; optional research dependency only.

No model is invoked by the deterministic assurance engine. All scaling is fitted
on training observations only. Learned state is exported as JSON, never pickle.
"""

import math
from proofshield.schemas.research import ClassificationMetricsV1, ModelEvaluationResultV1, AnomalyScoreV1
from proofshield.services.canonical import compute_canonical_hash
from proofshield.research.dataset import DatasetCollector, DatasetValidationError


def evaluate_classifier(actual, predicted, known_labels=None):
    if len(actual) != len(predicted) or not actual:
        raise ValueError("Metrics require equally sized nonempty truth and prediction arrays")
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
    labels = sorted(set(actual) | set(predicted) | set(known_labels or []))
    precision, recall, f1, _ = precision_recall_fscore_support(actual, predicted, labels=labels, average="macro", zero_division=0)
    matrix = confusion_matrix(actual, predicted, labels=labels).tolist()
    return ClassificationMetricsV1(accuracy=accuracy_score(actual, predicted), macro_precision=precision,
                                   macro_recall=recall, macro_f1=f1, labels=labels,
                                   confusion_matrix={label: dict(zip(labels, row)) for label, row in zip(labels, matrix)})


class LogisticRegressionBaseline:
    model_type = "logistic_regression"
    model_version = "2.0.0"

    def __init__(self, learning_rate=0.08, epochs=300, l2=0.001, seed=7):
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        from sklearn.linear_model import LogisticRegression
        self.estimator = make_pipeline(StandardScaler(), LogisticRegression(max_iter=epochs, C=1.0 / max(l2, 1e-9), random_state=seed))
        self.parameters = {"max_iter": epochs, "l2": l2, "seed": seed}

    def fit(self, rows, labels):
        if len(set(labels)) < 2:
            raise DatasetValidationError("At least two training classes are required")
        self.estimator.fit(rows, labels)
        self.labels = self.estimator.classes_.tolist()
        return self

    def predict(self, rows):
        return self.estimator.predict(rows).tolist()

    def state(self):
        scaler, model = self.estimator.steps[0][1], self.estimator.steps[1][1]
        return {"classes": self.labels, "coef": model.coef_.tolist(), "intercept": model.intercept_.tolist(),
                "mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist()}


class RandomForestBaseline(LogisticRegressionBaseline):
    model_type = "random_forest"

    def __init__(self, trees=100, seed=7):
        from sklearn.ensemble import RandomForestClassifier
        self.estimator = RandomForestClassifier(n_estimators=trees, max_depth=8, random_state=seed, n_jobs=1)
        self.parameters = {"n_estimators": trees, "max_depth": 8, "seed": seed}

    def state(self):
        return {"classes": self.labels, "trees": [{"left": tree.tree_.children_left.tolist(),
                "right": tree.tree_.children_right.tolist(), "feature": tree.tree_.feature.tolist(),
                "threshold": tree.tree_.threshold.tolist(), "values": tree.tree_.value.tolist()}
                for tree in self.estimator.estimators_]}


class IsolationForestAnomalyDetector:
    model_type = "isolation_forest"
    model_version = "2.0.0"

    def __init__(self, trees=100, seed=7, contamination=0.1):
        from sklearn.ensemble import IsolationForest
        self.estimator = IsolationForest(n_estimators=trees, random_state=seed, contamination=contamination, n_jobs=1)

    def fit(self, rows):
        self.estimator.fit(rows)
        return self

    def score_samples(self, rows):
        return (-self.estimator.score_samples(rows)).tolist()

    def predict(self, rows, observation_ids, model_id="MODEL-IF-01"):
        if len(rows) != len(observation_ids):
            raise ValueError("Observation IDs must match score rows")
        return [AnomalyScoreV1(observation_id=identifier, score=score, is_anomaly=int(flag) == -1, model_id=model_id)
                for identifier, score, flag in zip(observation_ids, self.score_samples(rows), self.estimator.predict(rows))]


def evaluate_model(model, collection, train_ids, test_ids, split_id):
    import sklearn
    from sklearn.metrics import log_loss
    DatasetCollector.validate(collection, require_single_provenance=True)
    rows = {row.observation_id: row for row in collection.observations}
    train, test = set(train_ids), set(test_ids)
    if not train or not test or train & test or (train | test) - rows.keys():
        raise DatasetValidationError("Training/test IDs must be nonempty, known and disjoint")
    if len(train) != len(train_ids) or len(test) != len(test_ids):
        raise DatasetValidationError("Duplicate observation IDs in split")
    for group in DatasetCollector.groups(collection):
        if group & train and group & test:
            raise DatasetValidationError("Scenario/run/shared-evidence leakage across splits")
    selected = [rows[identifier] for identifier in sorted(train | test)]
    if any(row.label is None for row in selected):
        raise DatasetValidationError("Evaluation requires confirmed independent labels")
    features = collection.feature_names
    x_train = [[rows[key].feature_vector[name] for name in features] for key in sorted(train)]
    y_train = [rows[key].label.value for key in sorted(train)]
    x_test = [[rows[key].feature_vector[name] for name in features] for key in sorted(test)]
    y_test = [rows[key].label.value for key in sorted(test)]
    if set(y_test) - set(y_train):
        raise DatasetValidationError("Held-out labels absent from training; collect more independently labeled groups")
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    probabilities = model.estimator.predict_proba(x_test)
    state = model.state()
    parameters = {**model.parameters, "scikit_learn_version": sklearn.__version__}
    digest = compute_canonical_hash({"state": state, "parameters": parameters, "features": features})
    importance = {}
    if hasattr(model.estimator, "feature_importances_"):
        importance = dict(zip(features, model.estimator.feature_importances_.tolist()))
    else:
        coefficients = state["coef"]
        importance = {name: sum(abs(row[index]) for row in coefficients) / len(coefficients) for index, name in enumerate(features)}
    brier = sum(sum((float(p) - float(label == truth))**2 for p, label in zip(row, model.labels))
                for row, truth in zip(probabilities, y_test)) / len(y_test)
    return ModelEvaluationResultV1(model_id="MODEL-" + digest[:16], model_type=model.model_type,
        model_version=model.model_version, dataset_id=collection.dataset_id, split_id=split_id,
        metrics=evaluate_classifier(y_test, predictions, model.labels), training_observations=len(train), test_observations=len(test),
        synthetic_training_data=collection.includes_synthetic, dataset_hash=DatasetCollector.compute_hash(collection),
        model_hash=digest, parameters=parameters, learned_state=state, feature_importance=importance,
        log_loss=float(log_loss(y_test, probabilities, labels=model.labels)), brier_score=brier,
        notes=["Post-observation classification experiment, not prospective failure prediction.",
               "Deterministic assurance is authoritative; predictions are research hypotheses only."])
