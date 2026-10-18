#!/usr/bin/env python3
"""PROOFSHIELD Benchmark Runner — Reproducible Evaluation Report Generator.

Executes the versioned benchmark corpus, computes diagnostic quality metrics,
and produces a deterministic, machine-readable JSON report suitable for
regression tracking and CI integration.

Usage:
    python scripts/run_benchmark.py [--output FILEPATH] [--backend BACKEND]

Backends:
    memory      - InMemoryStore (default)
    sqlite      - SQLiteStore with :memory: database
    sqlite_file - SQLiteStore with temporary file-backed database

The report includes:
    - Benchmark corpus version and case count
    - Python version and run timestamp
    - Per-case outcomes (predicted vs expected, evidence validity, reason)
    - Aggregate metrics: accuracy, precision/recall/F1 per category,
      false-diagnosis rate, inconclusive rate, coverage, evidence completeness
    - Confusion matrix
    - Metric definitions with explicit numerators, denominators, and edge cases

Exit code:
    0 if all cases executed successfully (regardless of accuracy)
    1 if benchmark execution failed
"""

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is on sys.path for direct execution
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticCategory,
    DiagnosticResultV1,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    FailureCategory,
    GroundTruthV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.store import InMemoryStore

# Conditionally import SQLiteStore
try:
    from proofshield.services.sqlite_store import SQLiteStore
    HAS_SQLITE = True
except ImportError:
    HAS_SQLITE = False

# Reuse existing benchmark infrastructure
sys.path.insert(0, str(REPO_ROOT / "tests"))
from test_benchmark import (
    ALL_CATEGORIES,
    BenchmarkScenarioCase,
    BenchmarkMetrics,
    ConfusionMatrix,
    build_benchmark_suite,
    compute_metrics,
    validate_evidence_support,
    verify_ground_truth_label,
)

# ── Constants ────────────────────────────────────────────────────────────────

BENCHMARK_VERSION = "7.0.0"
CORPUS_VERSION = "2.2"  # Phase 2.2 benchmark corpus


# ── Benchmark Execution ─────────────────────────────────────────────────────

def _create_store(backend: str, tmp_dir: Optional[str] = None, case_id: Optional[str] = None):
    """Create a store instance for the specified backend."""
    if backend == "memory":
        return InMemoryStore(), None
    elif backend == "sqlite":
        if not HAS_SQLITE:
            raise RuntimeError("SQLiteStore not available")
        store = SQLiteStore(":memory:")
        return store, None
    elif backend == "sqlite_file":
        if not HAS_SQLITE:
            raise RuntimeError("SQLiteStore not available")
        target_dir = tmp_dir or tempfile.mkdtemp()
        db_name = f"benchmark_{case_id or 'default'}_{os.getpid()}.db"
        db_path = os.path.join(target_dir, db_name)
        store = SQLiteStore(db_path)
        return store, db_path
    else:
        raise ValueError(f"Unknown backend: {backend}")


def run_benchmark_corpus(
    backend: str = "memory",
) -> Dict[str, Any]:
    """Execute the full benchmark corpus and return structured results.

    Returns a dictionary containing per-case outcomes and aggregate metrics,
    suitable for JSON serialization.
    """
    suite = build_benchmark_suite()
    assert len(suite) >= 25, f"Expected >= 25 benchmark cases, got {len(suite)}"

    run_timestamp = datetime.now(timezone.utc).isoformat()
    tmp_dir = tempfile.mkdtemp() if backend == "sqlite_file" else None

    case_results: List[Dict[str, Any]] = []
    true_labels: List[DiagnosticCategory] = []
    pred_labels: List[DiagnosticCategory] = []
    evidence_checks: List[bool] = []

    try:
        for case in suite:
            # Verify ground-truth label independently
            verified_gt = verify_ground_truth_label(case)
            gt_verified = (case.ground_truth.expected_diagnostic_category == verified_gt)

            # Create isolated store per case
            store, db_path = _create_store(backend, tmp_dir, case.case_id)

            try:
                # Ingest ground truth (before evaluation, but engine never reads it)
                store.add_ground_truth(case.ground_truth)

                # Ingest scenario evidence
                if case.scenario is not None:
                    store.add_scenario(case.scenario)
                    store.add_run(case.run)
                else:
                    # Orphaned run (BM-13 style)
                    if hasattr(store, '_runs'):
                        store._runs[case.run.run_id] = case.run
                    else:
                        # For SQLiteStore, add run without scenario validation
                        try:
                            store.add_run(case.run)
                        except ValueError:
                            # Expected for orphaned runs in SQLite
                            pass

                for r in case.rules:
                    try:
                        store.add_rule(r)
                    except ValueError:
                        pass  # Duplicate rules across cases
                for raw in case.raw_events:
                    store.add_raw_event(raw)
                for norm in case.normalized_events:
                    store.add_normalized_event(norm)
                for alert in case.alerts:
                    store.add_alert(alert)
                for dist in case.distractor_alerts:
                    store.add_alert(dist)

                # Run engine evaluation
                engine = AssuranceEngine(store)
                diag = engine.evaluate_run(case.run.run_id)

                # Validate evidence support
                is_evidence_valid, evidence_errors = validate_evidence_support(
                    store, case.run, case.scenario, diag
                )

                true_labels.append(case.ground_truth.expected_diagnostic_category)
                pred_labels.append(diag.predicted_category)
                evidence_checks.append(is_evidence_valid)

                case_results.append({
                    "case_id": case.case_id,
                    "name": case.name,
                    "description": case.description,
                    "expected_category": case.ground_truth.expected_diagnostic_category.value,
                    "predicted_category": diag.predicted_category.value,
                    "correct": (
                        case.ground_truth.expected_diagnostic_category == diag.predicted_category
                    ),
                    "confidence": diag.confidence,
                    "reason": diag.reason,
                    "failure_category": diag.failure_category.value if diag.failure_category else None,
                    "evidence_valid": is_evidence_valid,
                    "evidence_errors": evidence_errors if not is_evidence_valid else [],
                    "ground_truth_verified": gt_verified,
                    "injected_fault": case.ground_truth.injected_fault_type,
                    "supporting_evidence_count": len(diag.supporting_evidence_ids),
                    "contradictory_evidence_count": len(diag.contradictory_evidence_ids),
                    "checks_performed_count": len(diag.checks_performed),
                    "missing_evidence": diag.missing_evidence,
                })

            finally:
                # Clean up store resources
                if hasattr(store, 'close'):
                    store.close()
                if db_path and os.path.exists(db_path):
                    try:
                        os.unlink(db_path)
                    except OSError:
                        pass

        # Compute aggregate metrics
        metrics = compute_metrics(true_labels, pred_labels, evidence_checks)

        # Compute coverage: proportion of cases with a confident (non-INCONCLUSIVE) prediction
        confident_count = sum(
            1 for yp in pred_labels if yp != DiagnosticCategory.INCONCLUSIVE
        )
        coverage = confident_count / len(pred_labels) if pred_labels else 0.0

        # Compute unexecuted rate
        unexecuted_count = sum(
            1 for yp in pred_labels if yp == DiagnosticCategory.TEST_NOT_EXECUTED
        )
        unexecuted_rate = unexecuted_count / len(pred_labels) if pred_labels else 0.0

        # Format confusion matrix
        cm_data: Dict[str, Dict[str, int]] = {}
        for true_cat in ALL_CATEGORIES:
            cm_data[true_cat.value] = {
                pred_cat.value: metrics.confusion_matrix.matrix[true_cat][pred_cat]
                for pred_cat in ALL_CATEGORIES
            }

        # Build report
        report: Dict[str, Any] = {
            "benchmark_version": BENCHMARK_VERSION,
            "corpus_version": CORPUS_VERSION,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "run_timestamp": run_timestamp,
            "backend": backend,
            "total_cases": len(suite),
            "cases": case_results,
            "aggregate_metrics": {
                "accuracy": round(metrics.accuracy, 6),
                "false_diagnosis_rate": round(metrics.false_diagnosis_rate, 6),
                "inconclusive_rate": round(metrics.inconclusive_rate, 6),
                "unexecuted_rate": round(unexecuted_rate, 6),
                "coverage": round(coverage, 6),
                "evidence_support_completeness": round(
                    metrics.evidence_support_completeness, 6
                ),
                "per_category_precision": {
                    cat.value: round(v, 6)
                    for cat, v in metrics.per_class_precision.items()
                },
                "per_category_recall": {
                    cat.value: round(v, 6)
                    for cat, v in metrics.per_class_recall.items()
                },
                "per_category_f1": {
                    cat.value: round(v, 6)
                    for cat, v in metrics.per_class_f1.items()
                },
            },
            "confusion_matrix": cm_data,
            "metric_definitions": {
                "accuracy": {
                    "description": "Proportion of cases where predicted category matches ground truth",
                    "formula": "correct / total",
                    "zero_denominator": "Returns 0.0 if total == 0",
                },
                "false_diagnosis_rate": {
                    "description": "Proportion of confident (non-INCONCLUSIVE) predictions that are incorrect",
                    "formula": "false_confident / total_confident",
                    "zero_denominator": "Returns 0.0 if no confident predictions exist",
                    "note": "INCONCLUSIVE predictions are excluded from both numerator and denominator",
                },
                "inconclusive_rate": {
                    "description": "Proportion of all cases classified as INCONCLUSIVE",
                    "formula": "inconclusive_count / total",
                    "zero_denominator": "Returns 0.0 if total == 0",
                    "note": "Reported separately from accuracy; INCONCLUSIVE is never counted as correct unless ground truth is also INCONCLUSIVE",
                },
                "unexecuted_rate": {
                    "description": "Proportion of all cases classified as TEST_NOT_EXECUTED",
                    "formula": "unexecuted_count / total",
                    "zero_denominator": "Returns 0.0 if total == 0",
                },
                "coverage": {
                    "description": "Proportion of cases receiving a confident (non-INCONCLUSIVE) diagnosis",
                    "formula": "confident_count / total",
                    "zero_denominator": "Returns 0.0 if total == 0",
                },
                "evidence_support_completeness": {
                    "description": "Proportion of cases with validated evidence supporting the diagnosis",
                    "formula": "valid_evidence_count / total",
                    "zero_denominator": "Returns 0.0 if total == 0",
                },
                "per_category_precision": {
                    "description": "TP / (TP + FP) per diagnostic category",
                    "zero_denominator": "Returns 1.0 if TP + FP == 0 and FN == 0 (absent category); 0.0 otherwise",
                },
                "per_category_recall": {
                    "description": "TP / (TP + FN) per diagnostic category",
                    "zero_denominator": "Returns 1.0 if TP + FN == 0 and FP == 0 (absent category); 0.0 otherwise",
                },
                "per_category_f1": {
                    "description": "Harmonic mean of precision and recall per category",
                    "formula": "2 * precision * recall / (precision + recall)",
                    "zero_denominator": "Returns 0.0 if precision + recall == 0",
                },
            },
            "known_limitations": [
                "BM-25 demonstrates that spatio-temporal correlation cannot prove causation without execution provenance (strict attribution mode)",
                "The benchmark corpus is synthetic; production environments may exhibit faults not covered here",
                "INCONCLUSIVE outcomes are genuine diagnostic conclusions, not missing data -- they reflect ambiguous evidence",
            ],
        }

        return report

    finally:
        # Clean up temporary directory and any remaining files
        if tmp_dir and os.path.exists(tmp_dir):
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)


def print_summary(report: Dict[str, Any]) -> None:
    """Print a human-readable summary to stdout."""
    metrics = report["aggregate_metrics"]
    total = report["total_cases"]
    correct = sum(1 for c in report["cases"] if c["correct"])

    print()
    print("=" * 80)
    print(f"PROOFSHIELD BENCHMARK REPORT v{report['benchmark_version']}")
    print(f"Corpus v{report['corpus_version']} | {total} cases | Backend: {report['backend']}")
    print(f"Python {report['python_version']} | {report['run_timestamp']}")
    print("=" * 80)

    # Per-case results
    print(f"\n{'Case':<8} {'Expected':<28} {'Predicted':<28} {'Match':>5} {'Evidence':>8}")
    print("-" * 80)
    for c in report["cases"]:
        match_str = "OK" if c["correct"] else "FAIL"
        ev_str = "OK" if c["evidence_valid"] else "FAIL"
        print(
            f"{c['case_id']:<8} {c['expected_category']:<28} "
            f"{c['predicted_category']:<28} {match_str:>5} {ev_str:>8}"
        )

    # Aggregate metrics
    print()
    print("-" * 80)
    print(f"Accuracy:                     {metrics['accuracy']:.4f} ({correct}/{total})")
    print(f"False Diagnosis Rate:         {metrics['false_diagnosis_rate']:.4f}")
    print(f"Inconclusive Rate:            {metrics['inconclusive_rate']:.4f}")
    print(f"Unexecuted Rate:              {metrics['unexecuted_rate']:.4f}")
    print(f"Coverage (confident):         {metrics['coverage']:.4f}")
    print(f"Evidence Completeness:        {metrics['evidence_support_completeness']:.4f}")

    # Per-category F1
    print()
    print(f"{'Category':<32} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    print("-" * 64)
    for cat in ALL_CATEGORIES:
        cat_name = cat.value
        p = metrics["per_category_precision"].get(cat_name, 0)
        r = metrics["per_category_recall"].get(cat_name, 0)
        f1 = metrics["per_category_f1"].get(cat_name, 0)
        print(f"{cat_name:<32} {p:>10.4f} {r:>10.4f} {f1:>10.4f}")

    # Confusion matrix
    print()
    print("Confusion Matrix (True \\ Predicted):")
    short = {
        "PASS": "PASS", "TEST_NOT_EXECUTED": "T_NOT_EX",
        "EXPECTED_TELEMETRY_MISSING": "TEL_MISS",
        "DETECTION_NOT_TRIGGERED": "DET_N_TR",
        "ALERT_NOT_CORRELATED": "ALT_N_CR",
        "INCONCLUSIVE": "INCONCL", "ERROR": "ERROR",
    }
    cm = report["confusion_matrix"]
    cats = [c.value for c in ALL_CATEGORIES]
    header = f"{'':>12}" + "".join(f"{short.get(c, c):>10}" for c in cats)
    print(header)
    for tc in cats:
        row = f"{short.get(tc, tc):>12}"
        for pc in cats:
            row += f"{cm[tc][pc]:>10}"
        print(row)

    print()
    print(f"Known Limitations: {len(report['known_limitations'])}")
    for i, lim in enumerate(report["known_limitations"], 1):
        print(f"  {i}. {lim}")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="PROOFSHIELD Benchmark Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output JSON file path (default: stdout summary only)",
    )
    parser.add_argument(
        "--backend", "-b",
        type=str,
        default="memory",
        choices=["memory", "sqlite", "sqlite_file"],
        help="Storage backend to use (default: memory)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress human-readable summary output",
    )
    args = parser.parse_args()

    try:
        report = run_benchmark_corpus(backend=args.backend)
    except Exception as e:
        print(f"BENCHMARK FAILED: {e}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print_summary(report)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\nJSON report written to: {output_path}")

    # Also write to stdout as JSON if output is specified (for piping)
    if not args.output and args.quiet:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        print()  # trailing newline


if __name__ == "__main__":
    main()
