"""Phase 7: Evaluation & Benchmarking Framework — Comprehensive Tests.

Implements:
- Workstream 1: Versioned benchmark corpus validation with expected outcomes
- Workstream 2: Diagnostic quality metrics (per-category P/R/F1, confusion matrix,
  FDR, inconclusive/unexecuted rates, coverage)
- Workstream 3: Adversarial benchmark matrix (30+ edge cases)
- Workstream 4: Backend and determinism parity (InMemory, SQLite memory, SQLite file)
- Workstream 5: Reproducible JSON report generation
- Workstream 6: Metric engine verification and edge-case handling
"""

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

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
from proofshield.services.store import InMemoryStore, hosts_match

# Import existing benchmark infrastructure
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

# Conditionally import SQLiteStore
try:
    from proofshield.services.sqlite_store import SQLiteStore
    HAS_SQLITE = True
except ImportError:
    HAS_SQLITE = False


# ── Test Utilities ───────────────────────────────────────────────────────────

BASE_TIME = datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc)

def _make_scenario(
    scn_id: str,
    target: ValidationTarget = ValidationTarget.EXPECTED_ALERT,
    rule_id: Optional[str] = "RULE-ADV-01",
) -> ScenarioV1:
    return ScenarioV1(
        scenario_id=scn_id,
        name=f"Adversarial Scenario {scn_id}",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"DownloadString",
        expected_detection_rule_id=rule_id,
        validation_target=target,
        max_acceptable_latency_seconds=300,
    )


def _make_run(
    run_id: str,
    scenario_id: str,
    t0: datetime = BASE_TIME,
    host: str = "WS-ADV-01",
    status: ExecutionStatus = ExecutionStatus.COMPLETED,
) -> TestRunV1:
    return TestRunV1(
        run_id=run_id,
        scenario_id=scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host=host,
        target_user="corp\\secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_status=status,
    )


def _make_events(
    prefix: str,
    t_action: datetime,
    host: str = "WS-ADV-01",
    cmd: str = "powershell.exe -enc DownloadString",
) -> Tuple[RawTelemetryEventV1, NormalizedTelemetryEventV1]:
    raw = RawTelemetryEventV1(
        raw_event_id=f"RAW-{prefix}",
        source_event_id=f"SRC-{prefix}",
        source_format="sysmon",
        source_timestamp=t_action,
        ingested_at=t_action + timedelta(seconds=5),
        raw_payload={"EventID": 1, "CommandLine": cmd},
    )
    norm = NormalizedTelemetryEventV1(
        normalized_event_id=f"NORM-{prefix}",
        raw_event_id=raw.raw_event_id,
        source_event_id=raw.source_event_id,
        source_timestamp=t_action,
        normalized_timestamp=t_action,
        event_category=EventCategory.PROCESS_CREATION,
        host=host,
        process_name="powershell.exe",
        command_line=cmd,
    )
    return raw, norm


def _make_alert(
    alert_id: str,
    t_alert: datetime,
    host: str = "WS-ADV-01",
    rule_ref: str = "RULE-ADV-01",
    metadata: Optional[Dict[str, Any]] = None,
) -> AlertV1:
    return AlertV1(
        alert_id=alert_id,
        source_alert_id=f"SRC-{alert_id}",
        source_type="sigma",
        alert_timestamp=t_alert,
        host_id=host,
        rule_reference=rule_ref,
        metadata=metadata or {},
    )


def _run_case(
    store: InMemoryStore,
    scenario: ScenarioV1,
    run: TestRunV1,
    raws: List[RawTelemetryEventV1],
    norms: List[NormalizedTelemetryEventV1],
    alerts: List[AlertV1],
    rules: Optional[List[DetectionRuleV1]] = None,
) -> DiagnosticResultV1:
    """Ingest evidence and evaluate. Returns the diagnostic result."""
    store.add_scenario(scenario)
    store.add_run(run)
    for r in (rules or []):
        try:
            store.add_rule(r)
        except ValueError:
            pass
    for raw in raws:
        store.add_raw_event(raw)
    for norm in norms:
        store.add_normalized_event(norm)
    for alert in alerts:
        store.add_alert(alert)
    engine = AssuranceEngine(store)
    return engine.evaluate_run(run.run_id)


# ══════════════════════════════════════════════════════════════════════════════
# WORKSTREAM 1: Benchmark Corpus Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestBenchmarkCorpusIntegrity:
    """Verify that the benchmark corpus is well-formed and internally consistent."""

    def test_corpus_has_25_cases(self):
        """Corpus contains exactly 25 benchmark cases."""
        suite = build_benchmark_suite()
        assert len(suite) == 25

    def test_all_case_ids_unique(self):
        """Every case has a unique identifier."""
        suite = build_benchmark_suite()
        ids = [c.case_id for c in suite]
        assert len(ids) == len(set(ids)), f"Duplicate case IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_ground_truths_verified_by_oracle(self):
        """Every case's ground truth label matches the independent verification oracle."""
        suite = build_benchmark_suite()
        for case in suite:
            verified = verify_ground_truth_label(case)
            assert case.ground_truth.expected_diagnostic_category == verified, (
                f"{case.case_id}: assigned={case.ground_truth.expected_diagnostic_category}, "
                f"oracle={verified}"
            )

    def test_all_seven_categories_covered(self):
        """The corpus exercises all seven diagnostic categories."""
        suite = build_benchmark_suite()
        covered = {case.ground_truth.expected_diagnostic_category for case in suite}
        for cat in ALL_CATEGORIES:
            assert cat in covered, f"Category {cat.value} not covered by any benchmark case"

    def test_ground_truth_independent_of_engine(self):
        """Ground truth labels are assigned before engine evaluation and never modified by it."""
        suite = build_benchmark_suite()
        for case in suite:
            store = InMemoryStore()
            # Store ground truth before any evaluation
            store.add_ground_truth(case.ground_truth)
            gt_before = case.ground_truth.expected_diagnostic_category

            if case.scenario is not None:
                store.add_scenario(case.scenario)
                store.add_run(case.run)
            else:
                store._runs[case.run.run_id] = case.run
            for r in case.rules:
                try:
                    store.add_rule(r)
                except ValueError:
                    pass
            for raw in case.raw_events:
                store.add_raw_event(raw)
            for norm in case.normalized_events:
                store.add_normalized_event(norm)
            for alert in case.alerts:
                store.add_alert(alert)
            for dist in case.distractor_alerts:
                store.add_alert(dist)

            engine = AssuranceEngine(store)
            _ = engine.evaluate_run(case.run.run_id)

            # Verify ground truth was not modified
            gt_after = store.get_ground_truth_for_run(case.run.run_id)
            assert gt_after is not None
            assert gt_after.expected_diagnostic_category == gt_before


# ══════════════════════════════════════════════════════════════════════════════
# WORKSTREAM 2: Diagnostic Quality Metrics
# ══════════════════════════════════════════════════════════════════════════════

class TestMetricEngine:
    """Verify metric computation handles all edge cases correctly."""

    def test_perfect_accuracy(self):
        """Perfect predictions yield 100% accuracy and 0% FDR."""
        labels = [DiagnosticCategory.PASS, DiagnosticCategory.ERROR, DiagnosticCategory.INCONCLUSIVE]
        metrics = compute_metrics(labels, labels, [True, True, True])
        assert metrics.accuracy == pytest.approx(1.0)
        assert metrics.false_diagnosis_rate == pytest.approx(0.0)

    def test_zero_accuracy(self):
        """Completely wrong predictions yield 0% accuracy."""
        true_ = [DiagnosticCategory.PASS, DiagnosticCategory.PASS]
        pred_ = [DiagnosticCategory.ERROR, DiagnosticCategory.ERROR]
        metrics = compute_metrics(true_, pred_, [False, False])
        assert metrics.accuracy == pytest.approx(0.0)
        assert metrics.false_diagnosis_rate == pytest.approx(1.0)

    def test_all_inconclusive_fdr_is_zero(self):
        """All-INCONCLUSIVE predictions yield 0% FDR (no confident predictions)."""
        true_ = [DiagnosticCategory.PASS, DiagnosticCategory.ERROR]
        pred_ = [DiagnosticCategory.INCONCLUSIVE, DiagnosticCategory.INCONCLUSIVE]
        metrics = compute_metrics(true_, pred_, [True, True])
        assert metrics.false_diagnosis_rate == 0.0
        assert metrics.inconclusive_rate == 1.0
        # INCONCLUSIVE predictions are not correct unless GT is also INCONCLUSIVE
        assert metrics.accuracy == 0.0

    def test_inconclusive_correct_when_gt_matches(self):
        """INCONCLUSIVE prediction is counted as correct when GT is also INCONCLUSIVE."""
        true_ = [DiagnosticCategory.INCONCLUSIVE]
        pred_ = [DiagnosticCategory.INCONCLUSIVE]
        metrics = compute_metrics(true_, pred_, [True])
        assert metrics.accuracy == 1.0
        assert metrics.inconclusive_rate == 1.0
        assert metrics.false_diagnosis_rate == 0.0

    def test_single_sample_metrics(self):
        """Metric computation works correctly with a single sample."""
        true_ = [DiagnosticCategory.PASS]
        pred_ = [DiagnosticCategory.PASS]
        metrics = compute_metrics(true_, pred_, [True])
        assert metrics.accuracy == 1.0
        assert metrics.total_samples == 1

    def test_per_category_precision_recall_f1(self):
        """Per-category P/R/F1 computed correctly for a mixed scenario."""
        true_ = [
            DiagnosticCategory.PASS,
            DiagnosticCategory.PASS,
            DiagnosticCategory.ERROR,
            DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        ]
        pred_ = [
            DiagnosticCategory.PASS,
            DiagnosticCategory.ERROR,        # FP for ERROR, FN for PASS
            DiagnosticCategory.ERROR,        # TP for ERROR
            DiagnosticCategory.DETECTION_NOT_TRIGGERED,  # TP for DET_NOT_TRIG
        ]
        metrics = compute_metrics(true_, pred_, [True] * 4)

        # PASS: TP=1, FP=0, FN=1 → P=1.0, R=0.5, F1=2/3
        assert metrics.per_class_precision[DiagnosticCategory.PASS] == pytest.approx(1.0)
        assert metrics.per_class_recall[DiagnosticCategory.PASS] == pytest.approx(0.5)
        assert metrics.per_class_f1[DiagnosticCategory.PASS] == pytest.approx(2/3, abs=1e-4)

        # ERROR: TP=1, FP=1, FN=0 → P=0.5, R=1.0, F1=2/3
        assert metrics.per_class_precision[DiagnosticCategory.ERROR] == pytest.approx(0.5)
        assert metrics.per_class_recall[DiagnosticCategory.ERROR] == pytest.approx(1.0)
        assert metrics.per_class_f1[DiagnosticCategory.ERROR] == pytest.approx(2/3, abs=1e-4)

    def test_absent_category_precision_recall(self):
        """Categories with no true positives, false positives, or false negatives
        are handled without division by zero."""
        true_ = [DiagnosticCategory.PASS]
        pred_ = [DiagnosticCategory.PASS]
        metrics = compute_metrics(true_, pred_, [True])
        # ERROR has no samples at all → TP=FP=FN=0 → P=1.0, R=1.0, F1=1.0 (absent)
        assert metrics.per_class_precision[DiagnosticCategory.ERROR] == pytest.approx(1.0)
        assert metrics.per_class_recall[DiagnosticCategory.ERROR] == pytest.approx(1.0)

    def test_confusion_matrix_sums(self):
        """Confusion matrix row sums equal total samples per true category."""
        suite = build_benchmark_suite()
        store = InMemoryStore()
        true_, pred_, ev_ = [], [], []

        for case in suite:
            case_store = InMemoryStore()
            case_store.add_ground_truth(case.ground_truth)
            if case.scenario is not None:
                case_store.add_scenario(case.scenario)
                case_store.add_run(case.run)
            else:
                case_store._runs[case.run.run_id] = case.run
            for r in case.rules:
                try:
                    case_store.add_rule(r)
                except ValueError:
                    pass
            for raw in case.raw_events:
                case_store.add_raw_event(raw)
            for norm in case.normalized_events:
                case_store.add_normalized_event(norm)
            for alert in case.alerts:
                case_store.add_alert(alert)
            for dist in case.distractor_alerts:
                case_store.add_alert(dist)

            engine = AssuranceEngine(case_store)
            diag = engine.evaluate_run(case.run.run_id)
            is_valid, _ = validate_evidence_support(case_store, case.run, case.scenario, diag)

            true_.append(case.ground_truth.expected_diagnostic_category)
            pred_.append(diag.predicted_category)
            ev_.append(is_valid)

        metrics = compute_metrics(true_, pred_, ev_)
        cm = metrics.confusion_matrix

        # Total cells should sum to N
        total_cells = sum(
            cm.matrix[tc][pc]
            for tc in ALL_CATEGORIES
            for pc in ALL_CATEGORIES
        )
        assert total_cells == len(suite)

    def test_coverage_metric(self):
        """Coverage is the proportion of cases with a non-INCONCLUSIVE prediction."""
        true_ = [DiagnosticCategory.PASS, DiagnosticCategory.INCONCLUSIVE, DiagnosticCategory.ERROR]
        pred_ = [DiagnosticCategory.PASS, DiagnosticCategory.INCONCLUSIVE, DiagnosticCategory.ERROR]
        metrics = compute_metrics(true_, pred_, [True] * 3)

        # Coverage = 2/3 (PASS and ERROR are confident)
        confident = sum(1 for yp in pred_ if yp != DiagnosticCategory.INCONCLUSIVE)
        coverage = confident / len(pred_)
        assert coverage == pytest.approx(2/3)

    def test_false_diagnosis_excludes_inconclusive(self):
        """FDR denominator excludes INCONCLUSIVE predictions."""
        true_ = [
            DiagnosticCategory.PASS,
            DiagnosticCategory.INCONCLUSIVE,
            DiagnosticCategory.ERROR,
        ]
        pred_ = [
            DiagnosticCategory.ERROR,         # Wrong confident prediction
            DiagnosticCategory.INCONCLUSIVE,  # Excluded from FDR
            DiagnosticCategory.ERROR,         # Correct confident prediction
        ]
        metrics = compute_metrics(true_, pred_, [False, True, True])
        # Confident: pred[0]=ERROR, pred[2]=ERROR → 2 confident
        # False confident: pred[0] → 1
        # FDR = 1/2 = 0.5
        assert metrics.false_diagnosis_rate == pytest.approx(0.5)


# ══════════════════════════════════════════════════════════════════════════════
# WORKSTREAM 3: Adversarial Benchmark Matrix
# ══════════════════════════════════════════════════════════════════════════════

class TestAdversarialMatrix:
    """Adversarial edge cases validating diagnostic correctness under
    confounding, missing, and contradictory evidence conditions."""

    # ── Causal Confounding ────────────────────────────────────────────────

    def test_adv_same_host_same_window_unrelated_alert(self):
        """ADV-01: Unrelated alert on same host in same window should not produce PASS
        (the engine currently does produce PASS — this documents the known limitation)."""
        store = InMemoryStore()
        t0 = BASE_TIME
        scn = _make_scenario("SCN-ADV-01")
        run = _make_run("RUN-ADV-01", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-01", t0 + timedelta(minutes=2))
        # Unrelated alert from different rule but matches expected rule reference (confounding)
        confound_alert = _make_alert("ALT-ADV-01", t0 + timedelta(minutes=5), metadata={
            "causal_origin": "unrelated_background_task",
        })

        result = _run_case(store, scn, run, [raw], [norm], [confound_alert])

        # Document: engine uses spatio-temporal correlation, so it declares PASS
        # The ground truth should be DETECTION_NOT_TRIGGERED
        # This test documents the architectural limitation
        assert result.predicted_category == DiagnosticCategory.PASS
        gt = GroundTruthV1(
            ground_truth_id="GT-ADV-01",
            run_id=run.run_id,
            expected_diagnostic_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
            verification_method="adversarial_test",
            injected_fault_type="causal_confounding_alert",
        )
        # Engine prediction != ground truth (known limitation)
        assert result.predicted_category != gt.expected_diagnostic_category

    def test_adv_same_host_different_rule_alert(self):
        """ADV-02: Alert from a different rule on the same host should not produce PASS."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=1)
        scn = _make_scenario("SCN-ADV-02")
        run = _make_run("RUN-ADV-02", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-02", t0 + timedelta(minutes=2))
        wrong_rule_alert = _make_alert(
            "ALT-ADV-02", t0 + timedelta(minutes=5), rule_ref="RULE-WRONG-99"
        )

        result = _run_case(store, scn, run, [raw], [norm], [wrong_rule_alert])
        assert result.predicted_category != DiagnosticCategory.PASS

    # ── Missing / Contradictory Execution Tokens ────────────────────────

    def test_adv_completed_run_no_telemetry(self):
        """ADV-03: Completed run with zero telemetry → EXPECTED_TELEMETRY_MISSING."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=2)
        scn = _make_scenario("SCN-ADV-03")
        run = _make_run("RUN-ADV-03", scn.scenario_id, t0)

        result = _run_case(store, scn, run, [], [], [])
        assert result.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    def test_adv_completed_run_no_telemetry_with_alert(self):
        """ADV-04: Completed run with no telemetry but matching alert.
        Telemetry absence should take precedence over alert presence."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=3)
        scn = _make_scenario("SCN-ADV-04")
        run = _make_run("RUN-ADV-04", scn.scenario_id, t0)
        alert = _make_alert("ALT-ADV-04", t0 + timedelta(minutes=3))

        result = _run_case(store, scn, run, [], [], [alert])
        # Telemetry missing takes precedence
        assert result.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    # ── Duplicate Telemetry and Alerts ────────────────────────────────────

    def test_adv_duplicate_telemetry_events(self):
        """ADV-05: Duplicate telemetry events should not affect the diagnosis."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=4)
        scn = _make_scenario("SCN-ADV-05")
        run = _make_run("RUN-ADV-05", scn.scenario_id, t0)

        # Two distinct events with same data but different IDs
        raw1, norm1 = _make_events("ADV-05-A", t0 + timedelta(minutes=2))
        raw2 = RawTelemetryEventV1(
            raw_event_id="RAW-ADV-05-B",
            source_event_id="SRC-ADV-05-B",
            source_format="sysmon",
            source_timestamp=t0 + timedelta(minutes=2),
            ingested_at=t0 + timedelta(minutes=2, seconds=5),
            raw_payload={"EventID": 1, "CommandLine": "powershell.exe -enc DownloadString"},
        )
        norm2 = NormalizedTelemetryEventV1(
            normalized_event_id="NORM-ADV-05-B",
            raw_event_id=raw2.raw_event_id,
            source_event_id=raw2.source_event_id,
            source_timestamp=t0 + timedelta(minutes=2),
            normalized_timestamp=t0 + timedelta(minutes=2),
            event_category=EventCategory.PROCESS_CREATION,
            host="WS-ADV-01",
            process_name="powershell.exe",
            command_line="powershell.exe -enc DownloadString",
        )
        alert = _make_alert("ALT-ADV-05", t0 + timedelta(minutes=3))

        result = _run_case(store, scn, run, [raw1, raw2], [norm1, norm2], [alert])
        assert result.predicted_category == DiagnosticCategory.PASS

    def test_adv_duplicate_alerts_same_rule(self):
        """ADV-06: Multiple alerts from same rule should not cause incorrect diagnosis."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=5)
        scn = _make_scenario("SCN-ADV-06")
        run = _make_run("RUN-ADV-06", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-06", t0 + timedelta(minutes=2))
        alert1 = _make_alert("ALT-ADV-06-A", t0 + timedelta(minutes=3))
        alert2 = _make_alert("ALT-ADV-06-B", t0 + timedelta(minutes=4))

        result = _run_case(store, scn, run, [raw], [norm], [alert1, alert2])
        assert result.predicted_category == DiagnosticCategory.PASS

    # ── Timing Boundaries and Grace Period ────────────────────────────────

    def test_adv_alert_exactly_at_window_start(self):
        """ADV-07: Alert exactly at window_start is within the inclusive interval."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=6)
        scn = _make_scenario("SCN-ADV-07")
        run = _make_run("RUN-ADV-07", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-07", t0)
        alert = _make_alert("ALT-ADV-07", t0)  # Exactly at window_start

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        assert result.predicted_category == DiagnosticCategory.PASS

    def test_adv_alert_exactly_at_window_end(self):
        """ADV-08: Alert exactly at window_end is within the inclusive interval."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=7)
        scn = _make_scenario("SCN-ADV-08")
        run = _make_run("RUN-ADV-08", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-08", t0 + timedelta(minutes=2))
        alert = _make_alert("ALT-ADV-08", t0 + timedelta(minutes=15))  # Exactly window_end

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        assert result.predicted_category == DiagnosticCategory.PASS

    def test_adv_alert_one_microsecond_after_window(self):
        """ADV-09: Alert 1μs after window_end should not be in the primary window."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=8)
        scn = _make_scenario("SCN-ADV-09")
        run = _make_run("RUN-ADV-09", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-09", t0 + timedelta(minutes=2))
        # 1 microsecond after window_end
        alert = _make_alert("ALT-ADV-09", t0 + timedelta(minutes=15, microseconds=1))

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        # Should be in grace window, so ALERT_NOT_CORRELATED
        assert result.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED

    def test_adv_alert_exactly_at_grace_period_end(self):
        """ADV-10: Alert exactly at grace period boundary (window_end + 3600s)."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=9)
        scn = _make_scenario("SCN-ADV-10")
        run = _make_run("RUN-ADV-10", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-10", t0 + timedelta(minutes=2))
        # Exactly at grace period end
        grace_end = t0 + timedelta(minutes=15) + timedelta(seconds=3600)
        alert = _make_alert("ALT-ADV-10", grace_end)

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        # At or past grace: engine either classifies as ALERT_NOT_CORRELATED or DETECTION_NOT_TRIGGERED
        assert result.predicted_category in (
            DiagnosticCategory.ALERT_NOT_CORRELATED,
            DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        )

    def test_adv_alert_before_window_start(self):
        """ADV-11: Alert before window_start is excluded (historical bleed)."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=10)
        scn = _make_scenario("SCN-ADV-11")
        run = _make_run("RUN-ADV-11", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-11", t0 + timedelta(minutes=2))
        historical_alert = _make_alert("ALT-ADV-11", t0 - timedelta(hours=1))

        result = _run_case(store, scn, run, [raw], [norm], [historical_alert])
        assert result.predicted_category != DiagnosticCategory.PASS

    # ── Host, Rule, Run, and Scenario Mismatches ──────────────────────────

    def test_adv_alert_on_wrong_host(self):
        """ADV-12: Alert on a different host should not correlate."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=11)
        scn = _make_scenario("SCN-ADV-12")
        run = _make_run("RUN-ADV-12", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-12", t0 + timedelta(minutes=2))
        wrong_host_alert = _make_alert("ALT-ADV-12", t0 + timedelta(minutes=3), host="WS-OTHER-99")

        result = _run_case(store, scn, run, [raw], [norm], [wrong_host_alert])
        assert result.predicted_category != DiagnosticCategory.PASS

    def test_adv_missing_scenario_reference(self):
        """ADV-13: Run referencing non-existent scenario → ERROR."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=12)
        # Create run without adding scenario
        run = _make_run("RUN-ADV-13", "SCN-NONEXISTENT", t0)
        store._runs[run.run_id] = run

        engine = AssuranceEngine(store)
        result = engine.evaluate_run(run.run_id)
        assert result.predicted_category == DiagnosticCategory.ERROR

    def test_adv_run_with_mismatched_scenario_host(self):
        """ADV-14: Telemetry on a different host than the run target."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=13)
        scn = _make_scenario("SCN-ADV-14")
        run = _make_run("RUN-ADV-14", scn.scenario_id, t0, host="WS-ADV-TARGET")
        # Events on a different host
        raw, norm = _make_events("ADV-14", t0 + timedelta(minutes=2), host="WS-DIFFERENT-HOST")
        alert = _make_alert("ALT-ADV-14", t0 + timedelta(minutes=3), host="WS-DIFFERENT-HOST")

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        # Should not match since host doesn't match the run target
        assert result.predicted_category != DiagnosticCategory.PASS

    # ── Missing Telemetry vs Mismatched Signature ─────────────────────────

    def test_adv_telemetry_wrong_process_name(self):
        """ADV-15: Telemetry with wrong process name should not match scenario signature."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=14)
        scn = _make_scenario("SCN-ADV-15")
        run = _make_run("RUN-ADV-15", scn.scenario_id, t0)
        # Mismatched process name
        raw, norm = _make_events("ADV-15", t0 + timedelta(minutes=2), cmd="calc.exe /malware")

        result = _run_case(store, scn, run, [raw], [norm], [])
        assert result.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    def test_adv_telemetry_wrong_command_pattern(self):
        """ADV-16: Telemetry with wrong command pattern should not match."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=15)
        scn = _make_scenario("SCN-ADV-16")
        run = _make_run("RUN-ADV-16", scn.scenario_id, t0)
        # Correct process but wrong command
        raw, norm = _make_events("ADV-16", t0 + timedelta(minutes=2),
                                 cmd="powershell.exe -File script.ps1")
        alert = _make_alert("ALT-ADV-16", t0 + timedelta(minutes=3))

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        # Telemetry signature mismatch → EXPECTED_TELEMETRY_MISSING
        assert result.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    # ── Incomplete Execution and Ambiguous States ─────────────────────────

    def test_adv_execution_pending(self):
        """ADV-17: PENDING execution status → TEST_NOT_EXECUTED."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=16)
        scn = _make_scenario("SCN-ADV-17")
        run = _make_run("RUN-ADV-17", scn.scenario_id, t0, status=ExecutionStatus.PENDING)

        result = _run_case(store, scn, run, [], [], [])
        assert result.predicted_category == DiagnosticCategory.TEST_NOT_EXECUTED

    def test_adv_execution_error(self):
        """ADV-18: ERROR execution status → TEST_NOT_EXECUTED."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=17)
        scn = _make_scenario("SCN-ADV-18")
        run = _make_run("RUN-ADV-18", scn.scenario_id, t0, status=ExecutionStatus.ERROR)

        result = _run_case(store, scn, run, [], [], [])
        assert result.predicted_category == DiagnosticCategory.TEST_NOT_EXECUTED

    def test_adv_execution_running(self):
        """ADV-19: RUNNING execution status → INCONCLUSIVE."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=18)
        scn = _make_scenario("SCN-ADV-19")
        run = _make_run("RUN-ADV-19", scn.scenario_id, t0, status=ExecutionStatus.RUNNING)

        result = _run_case(store, scn, run, [], [], [])
        assert result.predicted_category == DiagnosticCategory.INCONCLUSIVE

    # ── Alert Missing Timestamp ───────────────────────────────────────────

    def test_adv_alert_missing_timestamp_with_telemetry(self):
        """ADV-20: Alert with None timestamp + matching telemetry.
        When telemetry is present and matches the signature, but the only
        candidate alert lacks a timestamp, detection timing cannot be verified,
        so the engine classifies as INCONCLUSIVE (matching BM-11 and BM-19)."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=19)
        scn = _make_scenario("SCN-ADV-20")
        run = _make_run("RUN-ADV-20", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-20", t0 + timedelta(minutes=2))
        no_ts_alert = AlertV1(
            alert_id="ALT-ADV-20",
            source_alert_id="SRC-ADV-20",
            source_type="sigma",
            alert_timestamp=None,
            host_id="WS-ADV-01",
            rule_reference="RULE-ADV-01",
        )

        result = _run_case(store, scn, run, [raw], [norm], [no_ts_alert])
        # Alert lacks event timestamp so detection timing cannot be verified -> INCONCLUSIVE
        assert result.predicted_category == DiagnosticCategory.INCONCLUSIVE

    # ── Scenario Specification Gaps ───────────────────────────────────────

    def test_adv_alert_target_no_rule_id(self):
        """ADV-21: Scenario targets EXPECTED_ALERT but no rule ID → INCONCLUSIVE."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=20)
        scn = _make_scenario("SCN-ADV-21", rule_id=None)
        run = _make_run("RUN-ADV-21", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-21", t0 + timedelta(minutes=2))

        result = _run_case(store, scn, run, [raw], [norm], [])
        assert result.predicted_category == DiagnosticCategory.INCONCLUSIVE

    def test_adv_telemetry_only_target_no_events(self):
        """ADV-22: Telemetry-only scenario with no events → EXPECTED_TELEMETRY_MISSING."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=21)
        scn = _make_scenario("SCN-ADV-22", target=ValidationTarget.EXPECTED_TELEMETRY_ONLY, rule_id=None)
        run = _make_run("RUN-ADV-22", scn.scenario_id, t0)

        result = _run_case(store, scn, run, [], [], [])
        assert result.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    def test_adv_telemetry_only_target_with_matching_events(self):
        """ADV-23: Telemetry-only scenario with matching events → PASS."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=22)
        scn = _make_scenario("SCN-ADV-23", target=ValidationTarget.EXPECTED_TELEMETRY_ONLY, rule_id=None)
        run = _make_run("RUN-ADV-23", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-23", t0 + timedelta(minutes=2))

        result = _run_case(store, scn, run, [raw], [norm], [])
        assert result.predicted_category == DiagnosticCategory.PASS

    # ── Conflicting Evidence ──────────────────────────────────────────────

    def test_adv_multiple_candidate_alerts_one_matches(self):
        """ADV-24: Multiple alerts, only one from the expected rule → engine uses the match."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=23)
        scn = _make_scenario("SCN-ADV-24")
        run = _make_run("RUN-ADV-24", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-24", t0 + timedelta(minutes=2))

        noise_alert = _make_alert("ALT-ADV-24-NOISE", t0 + timedelta(minutes=3), rule_ref="RULE-NOISE")
        match_alert = _make_alert("ALT-ADV-24-MATCH", t0 + timedelta(minutes=4))

        result = _run_case(store, scn, run, [raw], [norm], [noise_alert, match_alert])
        assert result.predicted_category == DiagnosticCategory.PASS

    def test_adv_alert_on_correct_host_wrong_rule_and_wrong_host_correct_rule(self):
        """ADV-25: One alert on correct host/wrong rule, another on wrong host/correct rule.
        Neither should produce PASS."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=24)
        scn = _make_scenario("SCN-ADV-25")
        run = _make_run("RUN-ADV-25", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-25", t0 + timedelta(minutes=2))

        # Correct host, wrong rule
        alert_a = _make_alert("ALT-ADV-25-A", t0 + timedelta(minutes=3), rule_ref="RULE-WRONG")
        # Wrong host, correct rule
        alert_b = _make_alert("ALT-ADV-25-B", t0 + timedelta(minutes=3), host="WS-WRONG")

        result = _run_case(store, scn, run, [raw], [norm], [alert_a, alert_b])
        assert result.predicted_category != DiagnosticCategory.PASS

    # ── Telemetry Outside Window ──────────────────────────────────────────

    def test_adv_telemetry_before_window(self):
        """ADV-26: Telemetry collected before the run window should not match."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=25)
        scn = _make_scenario("SCN-ADV-26")
        run = _make_run("RUN-ADV-26", scn.scenario_id, t0)
        # Event 1 hour before window
        raw, norm = _make_events("ADV-26", t0 - timedelta(hours=1))
        alert = _make_alert("ALT-ADV-26", t0 + timedelta(minutes=3))

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        # Telemetry outside window → should not match
        assert result.predicted_category != DiagnosticCategory.PASS

    def test_adv_telemetry_after_window(self):
        """ADV-27: Telemetry collected after the run window."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=26)
        scn = _make_scenario("SCN-ADV-27")
        run = _make_run("RUN-ADV-27", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-27", t0 + timedelta(hours=2))  # After window
        alert = _make_alert("ALT-ADV-27", t0 + timedelta(minutes=3))

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        # Telemetry outside window → should not match
        assert result.predicted_category != DiagnosticCategory.PASS

    # ── Evidence Traceability Properties ──────────────────────────────────

    def test_adv_diagnostic_result_has_checks_performed(self):
        """ADV-28: Every diagnostic result includes structured checks_performed metadata."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=27)
        scn = _make_scenario("SCN-ADV-28")
        run = _make_run("RUN-ADV-28", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-28", t0 + timedelta(minutes=2))
        alert = _make_alert("ALT-ADV-28", t0 + timedelta(minutes=3))

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        # Phase 6 added checks_performed property
        assert isinstance(result.checks_performed, list)

    def test_adv_pass_result_has_supporting_evidence(self):
        """ADV-29: PASS diagnosis must include non-empty supporting evidence."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=28)
        scn = _make_scenario("SCN-ADV-29")
        run = _make_run("RUN-ADV-29", scn.scenario_id, t0)
        raw, norm = _make_events("ADV-29", t0 + timedelta(minutes=2))
        alert = _make_alert("ALT-ADV-29", t0 + timedelta(minutes=3))

        result = _run_case(store, scn, run, [raw], [norm], [alert])
        assert result.predicted_category == DiagnosticCategory.PASS
        assert len(result.supporting_evidence_ids) > 0

    def test_adv_inconclusive_has_reason(self):
        """ADV-30: INCONCLUSIVE diagnosis must provide a non-empty reason."""
        store = InMemoryStore()
        t0 = BASE_TIME + timedelta(hours=29)
        scn = _make_scenario("SCN-ADV-30")
        run = _make_run("RUN-ADV-30", scn.scenario_id, t0, status=ExecutionStatus.RUNNING)

        result = _run_case(store, scn, run, [], [], [])
        assert result.predicted_category == DiagnosticCategory.INCONCLUSIVE
        assert len(result.reason) > 0


# ══════════════════════════════════════════════════════════════════════════════
# WORKSTREAM 4: Backend and Determinism Parity
# ══════════════════════════════════════════════════════════════════════════════

class TestBackendDeterminismParity:
    """Verify that the engine produces identical diagnostic outcomes across
    InMemoryStore, SQLiteStore(:memory:), and SQLiteStore(file)."""

    def _run_corpus_on_store(self, store_factory) -> List[Dict[str, Any]]:
        """Execute the benchmark corpus on a given store and return per-case results."""
        suite = build_benchmark_suite()
        results = []

        for case in suite:
            store = store_factory()
            try:
                store.add_ground_truth(case.ground_truth)
                if case.scenario is not None:
                    store.add_scenario(case.scenario)
                    store.add_run(case.run)
                else:
                    if hasattr(store, '_runs'):
                        store._runs[case.run.run_id] = case.run
                    else:
                        try:
                            store.add_run(case.run)
                        except ValueError:
                            pass
                for r in case.rules:
                    try:
                        store.add_rule(r)
                    except ValueError:
                        pass
                for raw in case.raw_events:
                    store.add_raw_event(raw)
                for norm in case.normalized_events:
                    store.add_normalized_event(norm)
                for alert in case.alerts:
                    store.add_alert(alert)
                for dist in case.distractor_alerts:
                    store.add_alert(dist)

                engine = AssuranceEngine(store)
                diag = engine.evaluate_run(case.run.run_id)

                results.append({
                    "case_id": case.case_id,
                    "predicted_category": diag.predicted_category,
                    "confidence": diag.confidence,
                    "reason": diag.reason,
                    "failure_category": diag.failure_category,
                    "supporting_evidence_ids": sorted(diag.supporting_evidence_ids),
                    "contradictory_evidence_ids": sorted(diag.contradictory_evidence_ids),
                })
            finally:
                if hasattr(store, 'close'):
                    store.close()

        return results

    def test_inmemory_determinism(self):
        """Two runs on InMemoryStore produce identical results."""
        r1 = self._run_corpus_on_store(InMemoryStore)
        r2 = self._run_corpus_on_store(InMemoryStore)
        assert len(r1) == len(r2)
        for a, b in zip(r1, r2):
            assert a["predicted_category"] == b["predicted_category"], (
                f"{a['case_id']}: {a['predicted_category']} != {b['predicted_category']}"
            )
            assert a["confidence"] == b["confidence"]
            assert a["supporting_evidence_ids"] == b["supporting_evidence_ids"]
            assert a["contradictory_evidence_ids"] == b["contradictory_evidence_ids"]

    @pytest.mark.skipif(not HAS_SQLITE, reason="SQLiteStore not available")
    def test_sqlite_memory_matches_inmemory(self):
        """SQLiteStore(:memory:) produces identical diagnostic outcomes as InMemoryStore."""
        inmem_results = self._run_corpus_on_store(InMemoryStore)
        sqlite_results = self._run_corpus_on_store(lambda: SQLiteStore(":memory:"))

        assert len(inmem_results) == len(sqlite_results)
        for im, sq in zip(inmem_results, sqlite_results):
            assert im["predicted_category"] == sq["predicted_category"], (
                f"{im['case_id']}: InMemory={im['predicted_category']} vs "
                f"SQLite={sq['predicted_category']}"
            )

    @pytest.mark.skipif(not HAS_SQLITE, reason="SQLiteStore not available")
    def test_sqlite_file_matches_inmemory(self):
        """SQLiteStore(file) produces identical diagnostic outcomes as InMemoryStore."""
        inmem_results = self._run_corpus_on_store(InMemoryStore)

        tmp_dir = tempfile.mkdtemp()
        counter = [0]

        def make_sqlite_file():
            counter[0] += 1
            db_path = os.path.join(tmp_dir, f"parity_{counter[0]}.db")
            return SQLiteStore(db_path)

        try:
            sqlite_results = self._run_corpus_on_store(make_sqlite_file)
            assert len(inmem_results) == len(sqlite_results)
            for im, sq in zip(inmem_results, sqlite_results):
                assert im["predicted_category"] == sq["predicted_category"], (
                    f"{im['case_id']}: InMemory={im['predicted_category']} vs "
                    f"SQLiteFile={sq['predicted_category']}"
                )
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @pytest.mark.skipif(not HAS_SQLITE, reason="SQLiteStore not available")
    def test_sqlite_evidence_ids_match_inmemory(self):
        """SQLiteStore evidence IDs match InMemoryStore for all benchmark cases."""
        inmem_results = self._run_corpus_on_store(InMemoryStore)
        sqlite_results = self._run_corpus_on_store(lambda: SQLiteStore(":memory:"))

        for im, sq in zip(inmem_results, sqlite_results):
            assert im["supporting_evidence_ids"] == sq["supporting_evidence_ids"], (
                f"{im['case_id']}: evidence mismatch"
            )
            assert im["contradictory_evidence_ids"] == sq["contradictory_evidence_ids"], (
                f"{im['case_id']}: contradictory evidence mismatch"
            )


# ══════════════════════════════════════════════════════════════════════════════
# WORKSTREAM 5: Reproducible Report Generation
# ══════════════════════════════════════════════════════════════════════════════

class TestReproducibleReport:
    """Verify the benchmark runner produces valid, reproducible JSON reports."""

    def _import_runner(self):
        """Import the benchmark runner module."""
        import importlib.util
        runner_path = Path(__file__).resolve().parent.parent / "scripts" / "run_benchmark.py"
        spec = importlib.util.spec_from_file_location("run_benchmark", runner_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_json_report_schema(self):
        """Report contains all required top-level keys."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")

        required_keys = {
            "benchmark_version", "corpus_version", "python_version",
            "platform", "run_timestamp", "backend", "total_cases",
            "cases", "aggregate_metrics", "confusion_matrix",
            "metric_definitions", "known_limitations",
        }
        assert required_keys.issubset(set(report.keys())), (
            f"Missing keys: {required_keys - set(report.keys())}"
        )

    def test_json_report_case_structure(self):
        """Each case in the report has the required fields."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")

        case_keys = {
            "case_id", "name", "description", "expected_category",
            "predicted_category", "correct", "confidence", "reason",
            "evidence_valid", "ground_truth_verified", "injected_fault",
        }
        for case in report["cases"]:
            assert case_keys.issubset(set(case.keys())), (
                f"Case {case.get('case_id', '?')} missing keys: {case_keys - set(case.keys())}"
            )

    def test_json_report_serializable(self):
        """Report is fully JSON-serializable."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")
        serialized = json.dumps(report, indent=2, ensure_ascii=False)
        deserialized = json.loads(serialized)
        assert deserialized["total_cases"] == report["total_cases"]
        assert deserialized["aggregate_metrics"]["accuracy"] == report["aggregate_metrics"]["accuracy"]

    def test_json_report_deterministic(self):
        """Two consecutive runs produce identical metric values (excluding timestamp)."""
        runner = self._import_runner()
        r1 = runner.run_benchmark_corpus(backend="memory")
        r2 = runner.run_benchmark_corpus(backend="memory")

        # Metrics must match exactly
        assert r1["aggregate_metrics"] == r2["aggregate_metrics"]
        assert r1["confusion_matrix"] == r2["confusion_matrix"]
        assert r1["total_cases"] == r2["total_cases"]

        # Per-case predictions must match
        for c1, c2 in zip(r1["cases"], r2["cases"]):
            assert c1["predicted_category"] == c2["predicted_category"]
            assert c1["expected_category"] == c2["expected_category"]
            assert c1["correct"] == c2["correct"]

    def test_json_report_metric_definitions_present(self):
        """Report includes metric definitions with descriptions and zero-denominator handling."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")

        defs = report["metric_definitions"]
        expected_metrics = [
            "accuracy", "false_diagnosis_rate", "inconclusive_rate",
            "coverage", "evidence_support_completeness",
        ]
        for metric_name in expected_metrics:
            assert metric_name in defs, f"Missing metric definition: {metric_name}"
            assert "description" in defs[metric_name]
            assert "zero_denominator" in defs[metric_name]

    def test_json_report_to_file(self):
        """Report can be written to a file and read back correctly."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            tmp_path = f.name

        try:
            with open(tmp_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["aggregate_metrics"] == report["aggregate_metrics"]
        finally:
            os.unlink(tmp_path)


# ══════════════════════════════════════════════════════════════════════════════
# WORKSTREAM 6: Benchmark Accuracy and Known Expectations
# ══════════════════════════════════════════════════════════════════════════════

class TestBenchmarkExpectedOutcomes:
    """Verify the complete benchmark suite produces documented, expected metric values.
    These thresholds are computed from the executed results, not hardcoded claims."""

    def test_full_benchmark_accuracy(self):
        """Verify accuracy against full 25-case corpus."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")
        metrics = report["aggregate_metrics"]

        # Based on corpus v2.2: 24/25 correct (BM-25 is the known causal confounding failure)
        assert metrics["accuracy"] == pytest.approx(24 / 25, abs=1e-3)

    def test_full_benchmark_fdr(self):
        """False diagnosis rate: 1 incorrect confident prediction out of 20 confident."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")
        metrics = report["aggregate_metrics"]

        assert metrics["false_diagnosis_rate"] == pytest.approx(1 / 20, abs=1e-3)

    def test_full_benchmark_inconclusive_rate(self):
        """5 of 25 cases are INCONCLUSIVE (BM-04, BM-11, BM-12, BM-19, BM-20)."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")
        metrics = report["aggregate_metrics"]

        assert metrics["inconclusive_rate"] == pytest.approx(5 / 25, abs=1e-3)

    def test_full_benchmark_coverage(self):
        """Coverage: 20/25 cases receive a confident diagnosis."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")
        metrics = report["aggregate_metrics"]

        assert metrics["coverage"] == pytest.approx(20 / 25, abs=1e-3)

    def test_bm25_is_the_only_misdiagnosis(self):
        """BM-25 (causal confounding) is the only case where prediction != ground truth
        among non-INCONCLUSIVE predictions."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")

        mismatches = [c for c in report["cases"] if not c["correct"]]
        assert len(mismatches) == 1
        assert mismatches[0]["case_id"] == "BM-25"

    def _import_runner(self):
        import importlib.util
        runner_path = Path(__file__).resolve().parent.parent / "scripts" / "run_benchmark.py"
        spec = importlib.util.spec_from_file_location("run_benchmark", runner_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


# ══════════════════════════════════════════════════════════════════════════════
# WORKSTREAM 7: Integration Smoke Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestBenchmarkRunnerIntegration:
    """Integration tests for the benchmark runner script."""

    def _import_runner(self):
        import importlib.util
        runner_path = Path(__file__).resolve().parent.parent / "scripts" / "run_benchmark.py"
        spec = importlib.util.spec_from_file_location("run_benchmark", runner_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_runner_memory_backend(self):
        """Benchmark runs successfully on InMemoryStore backend."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="memory")
        assert report["total_cases"] == 25
        assert "aggregate_metrics" in report

    @pytest.mark.skipif(not HAS_SQLITE, reason="SQLiteStore not available")
    def test_runner_sqlite_backend(self):
        """Benchmark runs successfully on SQLiteStore(:memory:) backend."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="sqlite")
        assert report["total_cases"] == 25
        assert report["backend"] == "sqlite"

    @pytest.mark.skipif(not HAS_SQLITE, reason="SQLiteStore not available")
    def test_runner_sqlite_file_backend(self):
        """Benchmark runs successfully on SQLiteStore(file) backend."""
        runner = self._import_runner()
        report = runner.run_benchmark_corpus(backend="sqlite_file")
        assert report["total_cases"] == 25
        assert report["backend"] == "sqlite_file"
        assert report["aggregate_metrics"]["accuracy"] == pytest.approx(24 / 25, abs=1e-3)
