"""Phase 2.2 Synthetic Benchmark Validity Audit: Diagnostic Accuracy, Fault Isolation & Causal Verification.

Reproducible evaluation comparing PROOFSHIELD's deterministic AssuranceEngine
against a simple alert-only baseline across 25 controlled benchmark scenarios (BM-01 to BM-25)
with independently assigned GroundTruthV1 labels.

Phase 2.2 Benchmark Validity Audit:
1. Re-labeled comparison: Simple alert-only baseline strictly defined by rule/window correlation;
   all unsupported commercial/industry-comparison claims removed.
2. Formal metric definitions and denominators: Documented exact mathematical formulas for
   accuracy, false-diagnosis rate, inconclusive rate, and evidence-support completeness.
   All metrics recalculated dynamically from actual predictions; no hardcoded baseline metrics.
3. Causal linkage audit (BM-25): Controlled test case where an unrelated alert matches target host,
   expected rule, and time window. Evaluates whether spatio-temporal correlation establishes causal
   linkage (finding: it does not; host/time co-occurrence cannot prove causation).
4. Independent ground-truth oracle: Ground truth is verified from synthetic fault injection
   specifications rather than reproducing the evaluator's spatio-temporal decision heuristic.
   Remaining shared assumptions are explicitly documented.
5. Regression tests: Specific tests for causal confounding, evidence validation rejection,
   and metric edge-case denominator handling.

───────────────────────────────────────────────────────────────────────────────
EXACT METRIC DEFINITIONS AND DENOMINATORS:

1. Diagnostic Accuracy:
   - Definition: The proportion of all evaluated test runs where the predicted diagnostic
     category exactly matches the independently verified ground-truth category.
   - Formula: Accuracy = Correct / Total
   - Numerator: Number of test runs with exact category agreement:
       sum(1 for yt, yp in zip(true_labels, pred_labels) if yt == yp)
   - Denominator: Total number of evaluated test runs:
       N = len(true_labels)
   - Edge case: Returns 0.0 if Total == 0.

2. False-Diagnosis Rate (FDR):
   - Definition: The proportion of confident diagnostic predictions (predictions other than
     INCONCLUSIVE) that are incorrect (i.e. disagree with ground truth). An evaluator that
     reports INCONCLUSIVE when evidence is ambiguous does not commit a false diagnosis; only
     confident incorrect assertions incur a false diagnosis.
   - Formula: FDR = False_Confident_Predictions / Total_Confident_Predictions
   - Numerator: Number of confident predictions that disagree with ground truth:
       sum(1 for yt, yp in zip(true_labels, pred_labels)
           if yp != DiagnosticCategory.INCONCLUSIVE and yt != yp)
   - Denominator: Total number of confident predictions (excluding INCONCLUSIVE):
       sum(1 for yp in pred_labels if yp != DiagnosticCategory.INCONCLUSIVE)
   - Edge case: If Denominator == 0 (all predictions are INCONCLUSIVE), FDR = 0.0.

3. Inconclusive Rate (IR):
   - Definition: The proportion of all evaluated test runs classified as INCONCLUSIVE due to
     ambiguous, missing, or contradictory evidence (e.g. missing alert timestamps, running status,
     or unspecified rules).
   - Formula: IR = Inconclusive_Count / Total
   - Numerator: Number of test runs predicted as INCONCLUSIVE:
       sum(1 for yp in pred_labels if yp == DiagnosticCategory.INCONCLUSIVE)
   - Denominator: Total number of evaluated test runs:
       N = len(true_labels)
   - Edge case: Returns 0.0 if Total == 0.

4. Evidence-Support Completeness (ESC):
   - Definition: The proportion of all evaluated test runs whose diagnostic result is backed by
     strictly validated evidence records in the store (every referenced evidence ID exists in the
     store and genuinely satisfies the category-specific substantiation rules).
   - Formula: ESC = Valid_Evidence_Count / Total
   - Numerator: Number of test runs with valid evidence support:
       sum(1 for valid in evidence_support_valid if valid)
   - Denominator: Total number of evaluated test runs:
       N = len(true_labels)
   - Edge case: Returns 0.0 if Total == 0.
───────────────────────────────────────────────────────────────────────────────
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import re
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


# ── Benchmark Data Structures ────────────────────────────────────────────────

ALL_CATEGORIES: List[DiagnosticCategory] = [
    DiagnosticCategory.PASS,
    DiagnosticCategory.TEST_NOT_EXECUTED,
    DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
    DiagnosticCategory.DETECTION_NOT_TRIGGERED,
    DiagnosticCategory.ALERT_NOT_CORRELATED,
    DiagnosticCategory.INCONCLUSIVE,
    DiagnosticCategory.ERROR,
]


@dataclass
class BenchmarkScenarioCase:
    case_id: str
    name: str
    description: str
    run: TestRunV1
    scenario: Optional[ScenarioV1]
    raw_events: List[RawTelemetryEventV1] = field(default_factory=list)
    normalized_events: List[NormalizedTelemetryEventV1] = field(default_factory=list)
    rules: List[DetectionRuleV1] = field(default_factory=list)
    alerts: List[AlertV1] = field(default_factory=list)
    distractor_alerts: List[AlertV1] = field(default_factory=list)
    ground_truth: GroundTruthV1 = None  # type: ignore
    expected_failure_category: Optional[FailureCategory] = None
    expect_latency_flag: bool = False


@dataclass
class ConfusionMatrix:
    matrix: Dict[DiagnosticCategory, Dict[DiagnosticCategory, int]]

    @classmethod
    def create(cls) -> "ConfusionMatrix":
        return cls({gt: {pred: 0 for pred in ALL_CATEGORIES} for gt in ALL_CATEGORIES})

    def record(self, true_cat: DiagnosticCategory, pred_cat: DiagnosticCategory) -> None:
        self.matrix[true_cat][pred_cat] += 1

    def format_table(self) -> str:
        short_names = {
            DiagnosticCategory.PASS: "PASS",
            DiagnosticCategory.TEST_NOT_EXECUTED: "T_NOT_EX",
            DiagnosticCategory.EXPECTED_TELEMETRY_MISSING: "TEL_MISS",
            DiagnosticCategory.DETECTION_NOT_TRIGGERED: "DET_NOT_TRIG",
            DiagnosticCategory.ALERT_NOT_CORRELATED: "ALT_NOT_CORR",
            DiagnosticCategory.INCONCLUSIVE: "INCONCL",
            DiagnosticCategory.ERROR: "ERROR",
        }
        headers = ["True \\ Pred"] + [short_names[c] for c in ALL_CATEGORIES]
        col_width = 13
        header_line = "".join(h.ljust(col_width) for h in headers)
        separator = "-" * len(header_line)
        lines = [header_line, separator]

        for true_cat in ALL_CATEGORIES:
            row = [short_names[true_cat].ljust(col_width)]
            for pred_cat in ALL_CATEGORIES:
                row.append(str(self.matrix[true_cat][pred_cat]).ljust(col_width))
            lines.append("".join(row))
        return "\n".join(lines)


@dataclass
class BenchmarkMetrics:
    total_samples: int
    accuracy: float
    per_class_precision: Dict[DiagnosticCategory, float]
    per_class_recall: Dict[DiagnosticCategory, float]
    per_class_f1: Dict[DiagnosticCategory, float]
    false_diagnosis_rate: float
    inconclusive_rate: float
    evidence_support_completeness: float
    confusion_matrix: ConfusionMatrix


# ── Simple Alert-Only Baseline ───────────────────────────────────────────────

def run_alert_only_baseline(store: InMemoryStore, run: TestRunV1) -> DiagnosticCategory:
    """Simple alert-only baseline evaluating rule and temporal window correlation.

    This baseline implements the most direct alert-correlation rule:
    1. If the run references an un-registered scenario -> ERROR.
    2. If the scenario does not specify an expected detection rule -> INCONCLUSIVE.
    3. If execution status is RUNNING -> INCONCLUSIVE.
    4. If execution is not completed (FAILED / ERROR / PENDING) -> maps to
       DETECTION_NOT_TRIGGERED (alert-only tools cannot inspect process execution).
    5. Evaluates strictly whether an alert for the scenario's expected rule is observed
       on the target host within the run time window:
       - Alert observed within window -> PASS (Detected).
       - Alert missing or outside window -> DETECTION_NOT_TRIGGERED (Undetected).

    Note: This is a minimal heuristic baseline provided as an experimental contrast.
    It does not inspect endpoint telemetry, cannot isolate pipeline faults, and
    assumes spatio-temporal correlation equals detection.
    """
    scenario = store.get_scenario(run.scenario_id)
    if scenario is None:
        return DiagnosticCategory.ERROR

    if run.execution_status == ExecutionStatus.RUNNING:
        return DiagnosticCategory.INCONCLUSIVE

    if not scenario.expected_detection_rule_id:
        return DiagnosticCategory.INCONCLUSIVE

    # Query alerts correlated to the run by host and exact temporal window
    alerts_in_window = store.get_alerts_for_run(run)
    matching = [
        a for a in alerts_in_window
        if a.rule_reference == scenario.expected_detection_rule_id
    ]
    if matching:
        return DiagnosticCategory.PASS

    # Alert-only tools map all absences and execution failures to rule silence
    return DiagnosticCategory.DETECTION_NOT_TRIGGERED


# ── Independent Ground-Truth Verification Oracle ─────────────────────────────

def verify_ground_truth_label(case: BenchmarkScenarioCase) -> DiagnosticCategory:
    """Independent ground-truth oracle verifying labels from synthetic fault injection specifications.

    Ground-truth labels are established *by construction* via the benchmark synthesis
    specification, completely independent of the AssuranceEngine's heuristic evaluation:
    - If the scenario reference is invalid -> ERROR.
    - If the run failed execution -> TEST_NOT_EXECUTED.
    - If execution is incomplete/running -> INCONCLUSIVE.
    - If telemetry drop/signature mismatch fault was injected -> EXPECTED_TELEMETRY_MISSING.
    - If rule silence, historical alert bleed, or causal confounding was injected -> DETECTION_NOT_TRIGGERED.
    - If host routing or delay fault was injected -> ALERT_NOT_CORRELATED.
    - If timestamp missing or rule unspecified -> INCONCLUSIVE.
    - If nominal attack without fault -> PASS.

    ───────────────────────────────────────────────────────────────────────────
    DOCUMENTATION OF SHARED ASSUMPTIONS:
    1. Telemetry Ingestion Fidelity: Both oracle and engine assume the normalized
       events in the store accurately reflect what was executed on the host.
    2. Host Identity Consistency: Both assume hostname and IP matching via hosts_match
       consistently identifies the target endpoint without DNS/DHCP aliasing.
    3. Clock Synchronization: Both assume synchronized UTC clocks across log sources.
    4. Causal Attribution Limitation: The evaluator (AssuranceEngine) assumes that
       alert co-occurrence on the target host within the time window implies detection.
       The independent oracle DOES NOT share this assumption: in BM-25, the oracle
       knows the test attack was silent and the concurrent alert was from an unrelated
       task, correctly assigning DETECTION_NOT_TRIGGERED.
    ───────────────────────────────────────────────────────────────────────────
    """
    # 1. Foreign-key validity / scenario existence
    if case.scenario is None or case.run.scenario_id != case.scenario.scenario_id:
        return DiagnosticCategory.ERROR

    scenario = case.scenario
    run = case.run

    # 2. Execution status check
    if run.execution_status == ExecutionStatus.RUNNING:
        return DiagnosticCategory.INCONCLUSIVE
    if run.execution_status in (
        ExecutionStatus.FAILED,
        ExecutionStatus.ERROR,
        ExecutionStatus.PENDING,
    ):
        return DiagnosticCategory.TEST_NOT_EXECUTED

    # 3. Fault-injection specification check (oracle by construction)
    fault = case.ground_truth.injected_fault_type if case.ground_truth else None

    if fault in ("telemetry_drop", "signature_mismatch", "signature_mismatch_with_concurrent_alert", "overlapping_telemetry_drop_and_noise_alert"):
        return DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    if fault in ("rule_silent", "historical_alert_bleed", "unrelated_same_host_alert", "causal_confounding_alert", "post_grace_period_alert"):
        return DiagnosticCategory.DETECTION_NOT_TRIGGERED

    if fault in ("host_misattribution", "delayed_alert", "one_second_post_window_delay"):
        return DiagnosticCategory.ALERT_NOT_CORRELATED

    if fault in ("missing_alert_timestamp", "ambiguous_missing_timestamp", "unspecified_rule", "ambiguous_scenario_specification", "stalled_execution"):
        return DiagnosticCategory.INCONCLUSIVE

    if fault == "missing_scenario_foreign_key":
        return DiagnosticCategory.ERROR

    if fault == "overlapping_crash_and_pipeline_absence":
        return DiagnosticCategory.TEST_NOT_EXECUTED

    # 4. Telemetry-only validation check
    if scenario.validation_target == ValidationTarget.EXPECTED_TELEMETRY_ONLY:
        return DiagnosticCategory.PASS

    # 5. Alert validation target check
    if not scenario.expected_detection_rule_id:
        return DiagnosticCategory.INCONCLUSIVE

    # 6. Nominal validation path (no fault injected)
    return DiagnosticCategory.PASS


# ── Evidence Support Completeness Validator ──────────────────────────────────

def validate_evidence_support(
    store: InMemoryStore,
    run: TestRunV1,
    scenario: Optional[ScenarioV1],
    diag: DiagnosticResultV1,
) -> Tuple[bool, List[str]]:
    """Validate that referenced evidence IDs exist in store and genuinely support the diagnosis.

    Validates:
    1. Existence: All IDs in supporting_evidence_ids and contradictory_evidence_ids must exist.
    2. Telemetry support: Referenced events must match expected category, process, command, host, and window.
    3. Alert support: Referenced alerts must match expected rule, host, and window.
    4. Causal validity: Alerts carrying metadata indicating an unrelated origin (e.g. background task)
       are rejected as valid supporting evidence for PASS, preventing causal attribution errors.
    """
    errors: List[str] = []

    # 1. Existence check for all supporting evidence IDs
    for eid in diag.supporting_evidence_ids:
        norm = store.get_normalized_event(eid)
        raw = store.get_raw_event(eid)
        alt = store.get_alert(eid)
        if norm is None and raw is None and alt is None:
            errors.append(f"Supporting evidence ID '{eid}' does not exist in store")

    # Existence check for all contradictory evidence IDs
    for cid in diag.contradictory_evidence_ids:
        norm = store.get_normalized_event(cid)
        raw = store.get_raw_event(cid)
        alt = store.get_alert(cid)
        if norm is None and raw is None and alt is None:
            errors.append(f"Contradictory evidence ID '{cid}' does not exist in store")

    if errors:
        return False, errors

    cat = diag.predicted_category

    # 2. Genuine support verification by diagnosis category
    if cat == DiagnosticCategory.PASS:
        if not diag.supporting_evidence_ids:
            errors.append("PASS diagnosis requires supporting evidence IDs")
        else:
            # Telemetry verification: at least one valid normalized event matching signature in window on host
            matched_events = [
                store.get_normalized_event(eid)
                for eid in diag.supporting_evidence_ids
                if store.get_normalized_event(eid) is not None
            ]
            if not matched_events:
                errors.append("PASS diagnosis missing valid normalized telemetry event in supporting evidence")
            else:
                for ev in matched_events:
                    if scenario and ev.event_category != scenario.expected_event_category:
                        errors.append(
                            f"Supporting event '{ev.normalized_event_id}' category {ev.event_category} does not match expected {scenario.expected_event_category}"
                        )
                    if scenario and scenario.expected_process_name and ev.process_name:
                        if ev.process_name.lower() != scenario.expected_process_name.lower():
                            errors.append(
                                f"Supporting event '{ev.normalized_event_id}' process {ev.process_name} does not match expected {scenario.expected_process_name}"
                            )
                    if not hosts_match(run.target_host, ev.host):
                        errors.append(
                            f"Supporting event '{ev.normalized_event_id}' host {ev.host} does not match run host {run.target_host}"
                        )

            # Alert verification: if alert was expected, at least one valid alert matching rule and host in window
            if scenario and scenario.expected_detection_rule_id:
                matched_alerts = [
                    store.get_alert(eid)
                    for eid in diag.supporting_evidence_ids
                    if store.get_alert(eid) is not None
                ]
                if not matched_alerts:
                    errors.append(
                        "PASS diagnosis for alert-expected scenario missing supporting alert ID"
                    )
                else:
                    for alt in matched_alerts:
                        if alt.rule_reference != scenario.expected_detection_rule_id:
                            errors.append(
                                f"Supporting alert '{alt.alert_id}' rule {alt.rule_reference} does not match expected {scenario.expected_detection_rule_id}"
                            )
                        if not hosts_match(run.target_host, alt.host_id):
                            errors.append(
                                f"Supporting alert '{alt.alert_id}' host {alt.host_id} does not match run host {run.target_host}"
                            )
                        # Causal validity check: unrelated alerts carrying explicit non-attack origin cannot support PASS
                        if alt.metadata and alt.metadata.get("causal_origin") == "unrelated_background_admin_task":
                            errors.append(
                                f"Supporting alert '{alt.alert_id}' originates from an unrelated task "
                                f"('{alt.metadata.get('causal_origin')}'); spatio-temporal co-occurrence does not establish causation"
                            )

    elif cat == DiagnosticCategory.ALERT_NOT_CORRELATED:
        if not diag.supporting_evidence_ids:
            errors.append("ALERT_NOT_CORRELATED diagnosis requires supporting telemetry evidence")
        if not diag.contradictory_evidence_ids:
            errors.append("ALERT_NOT_CORRELATED diagnosis requires contradictory alert evidence")
        else:
            for cid in diag.contradictory_evidence_ids:
                alt = store.get_alert(cid)
                if alt:
                    if scenario and alt.rule_reference != scenario.expected_detection_rule_id:
                        errors.append(
                            f"Contradictory alert '{cid}' references rule {alt.rule_reference}, expected {scenario.expected_detection_rule_id}"
                        )
                    # Contradictory alert must genuinely fail either host or window correlation
                    host_ok = hosts_match(run.target_host, alt.host_id)
                    time_ok = (
                        alt.alert_timestamp is not None
                        and run.window_start <= alt.alert_timestamp <= run.window_end
                    )
                    if host_ok and time_ok:
                        errors.append(
                            f"Contradictory alert '{cid}' actually correlates to run; cannot serve as contradictory evidence"
                        )

    elif cat == DiagnosticCategory.DETECTION_NOT_TRIGGERED:
        if not diag.supporting_evidence_ids:
            errors.append(
                "DETECTION_NOT_TRIGGERED diagnosis requires supporting telemetry evidence proving execution"
            )

    elif cat == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING:
        # If supporting evidence was provided (e.g. signature mismatch / evasion), none should match
        if diag.supporting_evidence_ids:
            for eid in diag.supporting_evidence_ids:
                ev = store.get_normalized_event(eid)
                if ev and scenario:
                    sig_match = (
                        ev.event_category == scenario.expected_event_category
                        and (
                            not scenario.expected_process_name
                            or (ev.process_name and ev.process_name.lower() == scenario.expected_process_name.lower())
                        )
                        and (
                            not scenario.expected_command_pattern
                            or (ev.command_line and re.search(scenario.expected_command_pattern, ev.command_line))
                        )
                    )
                    if sig_match:
                        errors.append(
                            f"Event '{eid}' actually matches scenario signature; contradicts EXPECTED_TELEMETRY_MISSING"
                        )

    elif cat == DiagnosticCategory.INCONCLUSIVE:
        if diag.contradictory_evidence_ids:
            for cid in diag.contradictory_evidence_ids:
                alt = store.get_alert(cid)
                if alt and alt.alert_timestamp is not None:
                    errors.append(
                        f"Alert '{cid}' has valid timestamp; contradicts missing timestamp reasoning"
                    )

    elif cat == DiagnosticCategory.TEST_NOT_EXECUTED:
        if run.execution_status not in (
            ExecutionStatus.FAILED,
            ExecutionStatus.ERROR,
            ExecutionStatus.PENDING,
        ):
            errors.append(
                f"TEST_NOT_EXECUTED requires non-completed status, found: {run.execution_status}"
            )

    elif cat == DiagnosticCategory.ERROR:
        if scenario is not None and run is not None and scenario.scenario_id == run.scenario_id:
            errors.append("ERROR diagnosis declared despite valid run and scenario")

    return len(errors) == 0, errors


# ── Synthetic Benchmark Suite Factory ────────────────────────────────────────

def build_benchmark_suite() -> List[BenchmarkScenarioCase]:
    """Generate the 25 controlled benchmark cases with independent ground truth.

    Covers nominal paths, realistic pipeline failures, and controlled adversarial edge cases:
    - BM-01 to BM-14: Primary baseline and fault-isolation benchmark cases.
    - BM-15: Unrelated same-host alert noise (distractor alert on target host).
    - BM-16: Overlapping faults — telemetry drop + unrelated same-host alert.
    - BM-17: Overlapping faults — execution crash + missing pipeline telemetry/alerts.
    - BM-18: Overlapping faults — telemetry evasion tampering + concurrent expected alert.
    - BM-19: Ambiguous evidence — candidate alert missing event timestamp with host match.
    - BM-20: Ambiguous evidence — missing rule ID on alert validation target.
    - BM-21: Timing boundary — exact window upper boundary (t_end).
    - BM-22: Timing boundary — 1 second beyond run window (within grace period).
    - BM-23: Timing boundary — 1 second beyond grace period.
    - BM-24: Timing boundary — exact window lower boundary (t_start).
    - BM-25: Unrelated concurrent alert on target host matching rule and window (causal confounding).
    """
    cases: List[BenchmarkScenarioCase] = []
    base_time = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)

    # Common rule definitions
    rule_sigma = DetectionRuleV1(
        rule_id="RULE-SIGMA-CRADLE-01",
        rule_name="PowerShell Web Cradle Detection",
        rule_format="sigma",
        mitre_technique_ids=["T1059.001"],
    )
    rule_distractor = DetectionRuleV1(
        rule_id="RULE-WAZUH-NOISE-99",
        rule_name="Noise Telemetry Rule",
        rule_format="wazuh",
        mitre_technique_ids=["T1082"],
    )

    def _make_base_scenario(
        scn_id: str,
        target: ValidationTarget = ValidationTarget.EXPECTED_ALERT,
        rule_id: Optional[str] = "RULE-SIGMA-CRADLE-01",
    ) -> ScenarioV1:
        return ScenarioV1(
            scenario_id=scn_id,
            name=f"Benchmark Scenario {scn_id}",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="powershell.exe",
            expected_command_pattern=r"DownloadString",
            expected_detection_rule_id=rule_id,
            validation_target=target,
            max_acceptable_latency_seconds=300,
        )

    def _make_events(
        case_id: str,
        t_action: datetime,
        t_ingest: datetime,
        host: str = "WS-TARGET-01",
        cmd: str = "powershell.exe -enc DownloadString",
    ) -> Tuple[RawTelemetryEventV1, NormalizedTelemetryEventV1]:
        raw = RawTelemetryEventV1(
            raw_event_id=f"RAW-{case_id}",
            source_event_id=f"SRC-EVT-{case_id}",
            source_format="sysmon",
            source_timestamp=t_action,
            ingested_at=t_ingest,
            raw_payload={"EventID": 1, "CommandLine": cmd},
        )
        norm = NormalizedTelemetryEventV1(
            normalized_event_id=f"NORM-{case_id}",
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

    def _make_run(
        run_id: str,
        scenario_id: str,
        t0: datetime,
        host: str = "WS-TARGET-01",
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

    # ── BM-01: Nominal Attack Execution -> PASS ──────────────────────────────
    t0 = base_time + timedelta(hours=1)
    scn_01 = _make_base_scenario("SCN-BM-01")
    run_01 = _make_run("RUN-BM-01", scn_01.scenario_id, t0)
    raw_01, norm_01 = _make_events("BM-01", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=10))
    alert_01 = AlertV1(
        alert_id="ALT-BM-01",
        source_alert_id="SRC-ALT-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id="WS-TARGET-01",
        rule_reference=scn_01.expected_detection_rule_id,
    )
    gt_01 = GroundTruthV1(
        ground_truth_id="GT-BM-01",
        run_id=run_01.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="independent_synthesis",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-01",
        name="Nominal Attack Execution",
        description="Telemetry and alert observed on target host within execution window.",
        run=run_01,
        scenario=scn_01,
        raw_events=[raw_01],
        normalized_events=[norm_01],
        rules=[rule_sigma],
        alerts=[alert_01],
        ground_truth=gt_01,
        expected_failure_category=FailureCategory.NONE,
    ))

    # ── BM-02: Nominal Telemetry-Only Validation -> PASS ─────────────────────
    t0 = base_time + timedelta(hours=2)
    scn_02 = _make_base_scenario("SCN-BM-02", target=ValidationTarget.EXPECTED_TELEMETRY_ONLY, rule_id=None)
    run_02 = _make_run("RUN-BM-02", scn_02.scenario_id, t0)
    raw_02, norm_02 = _make_events("BM-02", t0 + timedelta(minutes=1), t0 + timedelta(minutes=1, seconds=5))
    gt_02 = GroundTruthV1(
        ground_truth_id="GT-BM-02",
        run_id=run_02.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="independent_synthesis",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-02",
        name="Nominal Telemetry-Only Validation",
        description="Scenario targets telemetry collection only; matching telemetry observed.",
        run=run_02,
        scenario=scn_02,
        raw_events=[raw_02],
        normalized_events=[norm_02],
        rules=[],
        alerts=[],
        ground_truth=gt_02,
        expected_failure_category=FailureCategory.NONE,
    ))

    # ── BM-03: Execution Crash / Tool Failure -> TEST_NOT_EXECUTED ───────────
    t0 = base_time + timedelta(hours=3)
    scn_03 = _make_base_scenario("SCN-BM-03")
    run_03 = _make_run("RUN-BM-03", scn_03.scenario_id, t0, status=ExecutionStatus.FAILED)
    gt_03 = GroundTruthV1(
        ground_truth_id="GT-BM-03",
        run_id=run_03.run_id,
        expected_diagnostic_category=DiagnosticCategory.TEST_NOT_EXECUTED,
        verification_method="independent_synthesis",
        injected_fault_type="runner_crash",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-03",
        name="Execution Crash / Tool Failure",
        description="Execution status reported FAILED before producing intended behaviour.",
        run=run_03,
        scenario=scn_03,
        ground_truth=gt_03,
        expected_failure_category=FailureCategory.UNSPECIFIED,
    ))

    # ── BM-04: Execution Timeout / Stalled Run -> INCONCLUSIVE ───────────────
    t0 = base_time + timedelta(hours=4)
    scn_04 = _make_base_scenario("SCN-BM-04")
    run_04 = _make_run("RUN-BM-04", scn_04.scenario_id, t0, status=ExecutionStatus.RUNNING)
    gt_04 = GroundTruthV1(
        ground_truth_id="GT-BM-04",
        run_id=run_04.run_id,
        expected_diagnostic_category=DiagnosticCategory.INCONCLUSIVE,
        verification_method="independent_synthesis",
        injected_fault_type="stalled_execution",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-04",
        name="Execution Timeout / Stalled Run",
        description="Execution status remains RUNNING at evaluation time.",
        run=run_04,
        scenario=scn_04,
        ground_truth=gt_04,
        expected_failure_category=FailureCategory.AMBIGUOUS_EVIDENCE,
    ))

    # ── BM-05: Logging Sensor Disabled / Telemetry Drop -> EXPECTED_TELEMETRY_MISSING
    t0 = base_time + timedelta(hours=5)
    scn_05 = _make_base_scenario("SCN-BM-05")
    run_05 = _make_run("RUN-BM-05", scn_05.scenario_id, t0)
    gt_05 = GroundTruthV1(
        ground_truth_id="GT-BM-05",
        run_id=run_05.run_id,
        expected_diagnostic_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        verification_method="independent_synthesis",
        injected_fault_type="telemetry_drop",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-05",
        name="Logging Sensor Disabled / Telemetry Drop",
        description="Execution completed successfully, but zero telemetry events were collected.",
        run=run_05,
        scenario=scn_05,
        ground_truth=gt_05,
        expected_failure_category=FailureCategory.TELEMETRY_MISSING,
    ))

    # ── BM-06: Telemetry Field / Evasion Tampering -> EXPECTED_TELEMETRY_MISSING
    t0 = base_time + timedelta(hours=6)
    scn_06 = _make_base_scenario("SCN-BM-06")
    run_06 = _make_run("RUN-BM-06", scn_06.scenario_id, t0)
    raw_06, norm_06 = _make_events("BM-06", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5), cmd="calc.exe")
    gt_06 = GroundTruthV1(
        ground_truth_id="GT-BM-06",
        run_id=run_06.run_id,
        expected_diagnostic_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        verification_method="independent_synthesis",
        injected_fault_type="signature_mismatch",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-06",
        name="Telemetry Field / Evasion Tampering",
        description="Telemetry observed but command signature does not match expected pattern.",
        run=run_06,
        scenario=scn_06,
        raw_events=[raw_06],
        normalized_events=[norm_06],
        ground_truth=gt_06,
        expected_failure_category=FailureCategory.TELEMETRY_MISSING,
    ))

    # ── BM-07: Detection Rule Logic Ineffective -> DETECTION_NOT_TRIGGERED ───
    t0 = base_time + timedelta(hours=7)
    scn_07 = _make_base_scenario("SCN-BM-07")
    run_07 = _make_run("RUN-BM-07", scn_07.scenario_id, t0)
    raw_07, norm_07 = _make_events("BM-07", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    gt_07 = GroundTruthV1(
        ground_truth_id="GT-BM-07",
        run_id=run_07.run_id,
        expected_diagnostic_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        verification_method="independent_synthesis",
        injected_fault_type="rule_silent",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-07",
        name="Detection Rule Logic Ineffective",
        description="Telemetry matched expected signature, but rule never triggered in SIEM.",
        run=run_07,
        scenario=scn_07,
        raw_events=[raw_07],
        normalized_events=[norm_07],
        rules=[rule_sigma],
        alerts=[],
        ground_truth=gt_07,
        expected_failure_category=FailureCategory.DETECTION_RULE_MISMATCH,
    ))

    # ── BM-08: Cross-Run Historical Alert Bleed -> DETECTION_NOT_TRIGGERED ────
    t0 = base_time + timedelta(hours=8)
    scn_08 = _make_base_scenario("SCN-BM-08")
    run_08 = _make_run("RUN-BM-08", scn_08.scenario_id, t0)
    raw_08, norm_08 = _make_events("BM-08", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    historical_alert = AlertV1(
        alert_id="ALT-HIST-BM-08",
        source_alert_id="SRC-OLD-08",
        source_type="sigma",
        alert_timestamp=t0 - timedelta(hours=24),
        host_id="WS-TARGET-01",
        rule_reference=scn_08.expected_detection_rule_id,
    )
    gt_08 = GroundTruthV1(
        ground_truth_id="GT-BM-08",
        run_id=run_08.run_id,
        expected_diagnostic_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        verification_method="independent_synthesis",
        injected_fault_type="historical_alert_bleed",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-08",
        name="Cross-Run Historical Alert Bleed",
        description="Rule was silent for current run; historical alert from earlier run must be excluded.",
        run=run_08,
        scenario=scn_08,
        raw_events=[raw_08],
        normalized_events=[norm_08],
        rules=[rule_sigma],
        alerts=[historical_alert],
        ground_truth=gt_08,
        expected_failure_category=FailureCategory.DETECTION_RULE_MISMATCH,
    ))

    # ── BM-09: Alert Host-Routing Misattribution -> ALERT_NOT_CORRELATED ─────
    t0 = base_time + timedelta(hours=9)
    scn_09 = _make_base_scenario("SCN-BM-09")
    run_09 = _make_run("RUN-BM-09", scn_09.scenario_id, t0)
    raw_09, norm_09 = _make_events("BM-09", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    wrong_host_alert = AlertV1(
        alert_id="ALT-WRONG-HOST-09",
        source_alert_id="SRC-WH-09",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id="WS-OTHER-99",
        rule_reference=scn_09.expected_detection_rule_id,
    )
    gt_09 = GroundTruthV1(
        ground_truth_id="GT-BM-09",
        run_id=run_09.run_id,
        expected_diagnostic_category=DiagnosticCategory.ALERT_NOT_CORRELATED,
        verification_method="independent_synthesis",
        injected_fault_type="host_misattribution",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-09",
        name="Alert Host-Routing Misattribution",
        description="Rule fired in SIEM, but alert was attributed to an unrelated host.",
        run=run_09,
        scenario=scn_09,
        raw_events=[raw_09],
        normalized_events=[norm_09],
        rules=[rule_sigma],
        alerts=[wrong_host_alert],
        ground_truth=gt_09,
        expected_failure_category=FailureCategory.ALERT_SUPPRESSED,
    ))

    # ── BM-10: Delayed Alert / Late Processing -> ALERT_NOT_CORRELATED ───────
    t0 = base_time + timedelta(hours=10)
    scn_10 = _make_base_scenario("SCN-BM-10")
    run_10 = _make_run("RUN-BM-10", scn_10.scenario_id, t0)
    raw_10, norm_10 = _make_events("BM-10", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    late_alert = AlertV1(
        alert_id="ALT-LATE-BM-10",
        source_alert_id="SRC-LATE-10",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=35),
        host_id="WS-TARGET-01",
        rule_reference=scn_10.expected_detection_rule_id,
    )
    gt_10 = GroundTruthV1(
        ground_truth_id="GT-BM-10",
        run_id=run_10.run_id,
        expected_diagnostic_category=DiagnosticCategory.ALERT_NOT_CORRELATED,
        verification_method="independent_synthesis",
        injected_fault_type="delayed_alert",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-10",
        name="Delayed Alert / Late Processing",
        description="Rule alert was generated 20m late, falling outside exact observation window.",
        run=run_10,
        scenario=scn_10,
        raw_events=[raw_10],
        normalized_events=[norm_10],
        rules=[rule_sigma],
        alerts=[late_alert],
        ground_truth=gt_10,
        expected_failure_category=FailureCategory.PIPELINE_LATENCY,
    ))

    # ── BM-11: Missing Alert Timestamp -> INCONCLUSIVE ───────────────────────
    t0 = base_time + timedelta(hours=11)
    scn_11 = _make_base_scenario("SCN-BM-11")
    run_11 = _make_run("RUN-BM-11", scn_11.scenario_id, t0)
    raw_11, norm_11 = _make_events("BM-11", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    no_ts_alert = AlertV1(
        alert_id="ALT-NO-TS-BM-11",
        source_alert_id="SRC-NOTS-11",
        source_type="sigma",
        alert_timestamp=None,
        host_id="WS-TARGET-01",
        rule_reference=scn_11.expected_detection_rule_id,
    )
    gt_11 = GroundTruthV1(
        ground_truth_id="GT-BM-11",
        run_id=run_11.run_id,
        expected_diagnostic_category=DiagnosticCategory.INCONCLUSIVE,
        verification_method="independent_synthesis",
        injected_fault_type="missing_alert_timestamp",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-11",
        name="Missing Alert Timestamp",
        description="Alert exists on target host for rule, but lacks timestamp required for verification.",
        run=run_11,
        scenario=scn_11,
        raw_events=[raw_11],
        normalized_events=[norm_11],
        rules=[rule_sigma],
        alerts=[no_ts_alert],
        ground_truth=gt_11,
        expected_failure_category=FailureCategory.AMBIGUOUS_EVIDENCE,
    ))

    # ── BM-12: Ambiguous Validation Requirement -> INCONCLUSIVE ──────────────
    t0 = base_time + timedelta(hours=12)
    scn_12 = _make_base_scenario("SCN-BM-12", target=ValidationTarget.EXPECTED_ALERT, rule_id=None)
    run_12 = _make_run("RUN-BM-12", scn_12.scenario_id, t0)
    raw_12, norm_12 = _make_events("BM-12", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    gt_12 = GroundTruthV1(
        ground_truth_id="GT-BM-12",
        run_id=run_12.run_id,
        expected_diagnostic_category=DiagnosticCategory.INCONCLUSIVE,
        verification_method="independent_synthesis",
        injected_fault_type="unspecified_rule",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-12",
        name="Ambiguous Validation Requirement",
        description="Scenario targets EXPECTED_ALERT but provides no expected_detection_rule_id.",
        run=run_12,
        scenario=scn_12,
        raw_events=[raw_12],
        normalized_events=[norm_12],
        rules=[],
        alerts=[],
        ground_truth=gt_12,
        expected_failure_category=FailureCategory.AMBIGUOUS_EVIDENCE,
    ))

    # ── BM-13: Non-Existent Foreign Reference -> ERROR ───────────────────────
    t0 = base_time + timedelta(hours=13)
    run_13 = _make_run("RUN-BM-13", "SCN-NON-EXISTENT", t0)
    gt_13 = GroundTruthV1(
        ground_truth_id="GT-BM-13",
        run_id=run_13.run_id,
        expected_diagnostic_category=DiagnosticCategory.ERROR,
        verification_method="independent_synthesis",
        injected_fault_type="missing_scenario_foreign_key",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-13",
        name="Non-Existent Foreign Reference",
        description="Test run references an un-registered scenario identifier.",
        run=run_13,
        scenario=None,
        ground_truth=gt_13,
        expected_failure_category=FailureCategory.UNSPECIFIED,
    ))

    # ── BM-14: Telemetry Pipeline Latency Exceeded -> PASS (with Latency) ────
    t0 = base_time + timedelta(hours=14)
    scn_14 = _make_base_scenario("SCN-BM-14")
    run_14 = _make_run("RUN-BM-14", scn_14.scenario_id, t0)
    t_action_14 = t0 + timedelta(minutes=2)
    t_ingest_14 = t_action_14 + timedelta(seconds=360)
    raw_14, norm_14 = _make_events("BM-14", t_action_14, t_ingest_14)
    alert_14 = AlertV1(
        alert_id="ALT-BM-14",
        source_alert_id="SRC-ALT-14",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id="WS-TARGET-01",
        rule_reference=scn_14.expected_detection_rule_id,
    )
    gt_14 = GroundTruthV1(
        ground_truth_id="GT-BM-14",
        run_id=run_14.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="independent_synthesis",
        injected_fault_type="pipeline_ingestion_latency",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-14",
        name="Telemetry Pipeline Latency Exceeded",
        description="Telemetry and alert correlate (PASS), but pipeline ingestion latency exceeds threshold.",
        run=run_14,
        scenario=scn_14,
        raw_events=[raw_14],
        normalized_events=[norm_14],
        rules=[rule_sigma],
        alerts=[alert_14],
        ground_truth=gt_14,
        expected_failure_category=FailureCategory.PIPELINE_LATENCY,
        expect_latency_flag=True,
    ))

    # ── BM-15: Unrelated Same-Host Alert Noise -> DETECTION_NOT_TRIGGERED ────
    t0 = base_time + timedelta(hours=15)
    scn_15 = _make_base_scenario("SCN-BM-15")
    run_15 = _make_run("RUN-BM-15", scn_15.scenario_id, t0)
    raw_15, norm_15 = _make_events("BM-15", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    unrelated_alert_15 = AlertV1(
        alert_id="ALT-UNRELATED-BM-15",
        source_alert_id="SRC-UNREL-15",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=4),
        host_id="WS-TARGET-01",
        rule_reference="RULE-WAZUH-NOISE-99",
    )
    gt_15 = GroundTruthV1(
        ground_truth_id="GT-BM-15",
        run_id=run_15.run_id,
        expected_diagnostic_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        verification_method="independent_synthesis",
        injected_fault_type="unrelated_same_host_alert",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-15",
        name="Unrelated Same-Host Alert Noise",
        description="Expected rule was silent; distractor alert fired on the same host within the run window.",
        run=run_15,
        scenario=scn_15,
        raw_events=[raw_15],
        normalized_events=[norm_15],
        rules=[rule_sigma, rule_distractor],
        alerts=[unrelated_alert_15],
        ground_truth=gt_15,
        expected_failure_category=FailureCategory.DETECTION_RULE_MISMATCH,
    ))

    # ── BM-16: Overlapping Faults: Telemetry Drop + Unrelated Alert -> EXPECTED_TELEMETRY_MISSING
    t0 = base_time + timedelta(hours=16)
    scn_16 = _make_base_scenario("SCN-BM-16")
    run_16 = _make_run("RUN-BM-16", scn_16.scenario_id, t0)
    unrelated_alert_16 = AlertV1(
        alert_id="ALT-UNRELATED-BM-16",
        source_alert_id="SRC-UNREL-16",
        source_type="wazuh",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id="WS-TARGET-01",
        rule_reference="RULE-WAZUH-NOISE-99",
    )
    gt_16 = GroundTruthV1(
        ground_truth_id="GT-BM-16",
        run_id=run_16.run_id,
        expected_diagnostic_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        verification_method="independent_synthesis",
        injected_fault_type="overlapping_telemetry_drop_and_noise_alert",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-16",
        name="Overlapping Faults: Telemetry Drop + Unrelated Same-Host Alert",
        description="Telemetry dropped at sensor while unrelated alert fired on host; telemetry absence takes precedence.",
        run=run_16,
        scenario=scn_16,
        raw_events=[],
        normalized_events=[],
        rules=[rule_sigma, rule_distractor],
        alerts=[unrelated_alert_16],
        ground_truth=gt_16,
        expected_failure_category=FailureCategory.TELEMETRY_MISSING,
    ))

    # ── BM-17: Overlapping Faults: Execution Crash + Missing Pipeline -> TEST_NOT_EXECUTED
    t0 = base_time + timedelta(hours=17)
    scn_17 = _make_base_scenario("SCN-BM-17")
    run_17 = _make_run("RUN-BM-17", scn_17.scenario_id, t0, status=ExecutionStatus.FAILED)
    gt_17 = GroundTruthV1(
        ground_truth_id="GT-BM-17",
        run_id=run_17.run_id,
        expected_diagnostic_category=DiagnosticCategory.TEST_NOT_EXECUTED,
        verification_method="independent_synthesis",
        injected_fault_type="overlapping_crash_and_pipeline_absence",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-17",
        name="Overlapping Faults: Execution Crash + Missing Pipeline",
        description="Runner failed before completing attack; execution status takes precedence over pipeline absence.",
        run=run_17,
        scenario=scn_17,
        raw_events=[],
        normalized_events=[],
        rules=[rule_sigma],
        alerts=[],
        ground_truth=gt_17,
        expected_failure_category=FailureCategory.UNSPECIFIED,
    ))

    # ── BM-18: Overlapping Faults: Signature Mismatch + Concurrent Alert -> EXPECTED_TELEMETRY_MISSING
    t0 = base_time + timedelta(hours=18)
    scn_18 = _make_base_scenario("SCN-BM-18")
    run_18 = _make_run("RUN-BM-18", scn_18.scenario_id, t0)
    raw_18, norm_18 = _make_events("BM-18", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5), cmd="whoami.exe /priv")
    concurrent_alert_18 = AlertV1(
        alert_id="ALT-CONCURRENT-BM-18",
        source_alert_id="SRC-CONC-18",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id="WS-TARGET-01",
        rule_reference=scn_18.expected_detection_rule_id,
    )
    gt_18 = GroundTruthV1(
        ground_truth_id="GT-BM-18",
        run_id=run_18.run_id,
        expected_diagnostic_category=DiagnosticCategory.EXPECTED_TELEMETRY_MISSING,
        verification_method="independent_synthesis",
        injected_fault_type="signature_mismatch_with_concurrent_alert",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-18",
        name="Overlapping Faults: Signature Mismatch + Concurrent Alert",
        description="Telemetry was evaded/mismatched but rule alert arrived; signature failure prevents false pass.",
        run=run_18,
        scenario=scn_18,
        raw_events=[raw_18],
        normalized_events=[norm_18],
        rules=[rule_sigma],
        alerts=[concurrent_alert_18],
        ground_truth=gt_18,
        expected_failure_category=FailureCategory.TELEMETRY_MISSING,
    ))

    # ── BM-19: Ambiguous Evidence: Candidate Alert Missing Timestamp -> INCONCLUSIVE
    t0 = base_time + timedelta(hours=19)
    scn_19 = _make_base_scenario("SCN-BM-19")
    run_19 = _make_run("RUN-BM-19", scn_19.scenario_id, t0)
    raw_19, norm_19 = _make_events("BM-19", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    no_ts_alert_19 = AlertV1(
        alert_id="ALT-NO-TS-BM-19",
        source_alert_id="SRC-NOTS-19",
        source_type="sigma",
        alert_timestamp=None,
        host_id="WS-TARGET-01",
        rule_reference=scn_19.expected_detection_rule_id,
    )
    gt_19 = GroundTruthV1(
        ground_truth_id="GT-BM-19",
        run_id=run_19.run_id,
        expected_diagnostic_category=DiagnosticCategory.INCONCLUSIVE,
        verification_method="independent_synthesis",
        injected_fault_type="ambiguous_missing_timestamp",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-19",
        name="Ambiguous Evidence: Candidate Alert Missing Timestamp",
        description="Alert for expected rule observed on target host but lacks event timestamp required for timing proof.",
        run=run_19,
        scenario=scn_19,
        raw_events=[raw_19],
        normalized_events=[norm_19],
        rules=[rule_sigma],
        alerts=[no_ts_alert_19],
        ground_truth=gt_19,
        expected_failure_category=FailureCategory.AMBIGUOUS_EVIDENCE,
    ))

    # ── BM-20: Ambiguous Evidence: Missing Rule ID on Alert Target -> INCONCLUSIVE
    t0 = base_time + timedelta(hours=20)
    scn_20 = _make_base_scenario("SCN-BM-20", target=ValidationTarget.EXPECTED_ALERT, rule_id=None)
    run_20 = _make_run("RUN-BM-20", scn_20.scenario_id, t0)
    raw_20, norm_20 = _make_events("BM-20", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    gt_20 = GroundTruthV1(
        ground_truth_id="GT-BM-20",
        run_id=run_20.run_id,
        expected_diagnostic_category=DiagnosticCategory.INCONCLUSIVE,
        verification_method="independent_synthesis",
        injected_fault_type="ambiguous_scenario_specification",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-20",
        name="Ambiguous Evidence: Missing Rule ID on Alert Target",
        description="Scenario targets EXPECTED_ALERT but provides no expected_detection_rule_id; outcome is inconclusive.",
        run=run_20,
        scenario=scn_20,
        raw_events=[raw_20],
        normalized_events=[norm_20],
        rules=[],
        alerts=[],
        ground_truth=gt_20,
        expected_failure_category=FailureCategory.AMBIGUOUS_EVIDENCE,
    ))

    # ── BM-21: Timing Boundary: Exact Window Upper Boundary (t_end) -> PASS
    t0 = base_time + timedelta(hours=21)
    scn_21 = _make_base_scenario("SCN-BM-21")
    run_21 = _make_run("RUN-BM-21", scn_21.scenario_id, t0)
    raw_21, norm_21 = _make_events("BM-21", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    alert_21 = AlertV1(
        alert_id="ALT-BM-21",
        source_alert_id="SRC-ALT-21",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=15),
        host_id="WS-TARGET-01",
        rule_reference=scn_21.expected_detection_rule_id,
    )
    gt_21 = GroundTruthV1(
        ground_truth_id="GT-BM-21",
        run_id=run_21.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="independent_synthesis",
        injected_fault_type="exact_window_upper_boundary",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-21",
        name="Timing Boundary: Exact Window Upper Boundary",
        description="Alert timestamp coincides exactly with the upper boundary (window_end); inclusive interval correlates.",
        run=run_21,
        scenario=scn_21,
        raw_events=[raw_21],
        normalized_events=[norm_21],
        rules=[rule_sigma],
        alerts=[alert_21],
        ground_truth=gt_21,
        expected_failure_category=FailureCategory.NONE,
    ))

    # ── BM-22: Timing Boundary: 1 Second Beyond Run Window -> ALERT_NOT_CORRELATED
    t0 = base_time + timedelta(hours=22)
    scn_22 = _make_base_scenario("SCN-BM-22")
    run_22 = _make_run("RUN-BM-22", scn_22.scenario_id, t0)
    raw_22, norm_22 = _make_events("BM-22", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    alert_22 = AlertV1(
        alert_id="ALT-BM-22",
        source_alert_id="SRC-ALT-22",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=15, seconds=1),
        host_id="WS-TARGET-01",
        rule_reference=scn_22.expected_detection_rule_id,
    )
    gt_22 = GroundTruthV1(
        ground_truth_id="GT-BM-22",
        run_id=run_22.run_id,
        expected_diagnostic_category=DiagnosticCategory.ALERT_NOT_CORRELATED,
        verification_method="independent_synthesis",
        injected_fault_type="one_second_post_window_delay",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-22",
        name="Timing Boundary: 1 Second Beyond Run Window",
        description="Alert timestamp is 1s after window_end (within 3600s grace period); correlation fails due to delay.",
        run=run_22,
        scenario=scn_22,
        raw_events=[raw_22],
        normalized_events=[norm_22],
        rules=[rule_sigma],
        alerts=[alert_22],
        ground_truth=gt_22,
        expected_failure_category=FailureCategory.PIPELINE_LATENCY,
    ))

    # ── BM-23: Timing Boundary: 1 Second Beyond Grace Period -> DETECTION_NOT_TRIGGERED
    t0 = base_time + timedelta(hours=23)
    scn_23 = _make_base_scenario("SCN-BM-23")
    run_23 = _make_run("RUN-BM-23", scn_23.scenario_id, t0)
    raw_23, norm_23 = _make_events("BM-23", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    alert_23 = AlertV1(
        alert_id="ALT-BM-23",
        source_alert_id="SRC-ALT-23",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=15, seconds=3601),
        host_id="WS-TARGET-01",
        rule_reference=scn_23.expected_detection_rule_id,
    )
    gt_23 = GroundTruthV1(
        ground_truth_id="GT-BM-23",
        run_id=run_23.run_id,
        expected_diagnostic_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        verification_method="independent_synthesis",
        injected_fault_type="post_grace_period_alert",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-23",
        name="Timing Boundary: 1 Second Beyond Grace Period",
        description="Alert occurs 1s past the 3600s grace period; excluded from candidate window, rule diagnosed as silent.",
        run=run_23,
        scenario=scn_23,
        raw_events=[raw_23],
        normalized_events=[norm_23],
        rules=[rule_sigma],
        alerts=[alert_23],
        ground_truth=gt_23,
        expected_failure_category=FailureCategory.DETECTION_RULE_MISMATCH,
    ))

    # ── BM-24: Timing Boundary: Exact Window Lower Boundary (t_start) -> PASS
    t0 = base_time + timedelta(hours=24)
    scn_24 = _make_base_scenario("SCN-BM-24")
    run_24 = _make_run("RUN-BM-24", scn_24.scenario_id, t0)
    raw_24, norm_24 = _make_events("BM-24", t0, t0 + timedelta(seconds=5))
    alert_24 = AlertV1(
        alert_id="ALT-BM-24",
        source_alert_id="SRC-ALT-24",
        source_type="sigma",
        alert_timestamp=t0,
        host_id="WS-TARGET-01",
        rule_reference=scn_24.expected_detection_rule_id,
    )
    gt_24 = GroundTruthV1(
        ground_truth_id="GT-BM-24",
        run_id=run_24.run_id,
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="independent_synthesis",
        injected_fault_type="exact_window_lower_boundary",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-24",
        name="Timing Boundary: Exact Window Lower Boundary",
        description="Alert timestamp coincides exactly with window_start; inclusive interval correlates successfully.",
        run=run_24,
        scenario=scn_24,
        raw_events=[raw_24],
        normalized_events=[norm_24],
        rules=[rule_sigma],
        alerts=[alert_24],
        ground_truth=gt_24,
        expected_failure_category=FailureCategory.NONE,
    ))

    # ── BM-25: Unrelated Concurrent Alert on Target Host (Causal Confounding) -> DETECTION_NOT_TRIGGERED
    t0 = base_time + timedelta(hours=25)
    scn_25 = _make_base_scenario("SCN-BM-25")
    run_25 = _make_run("RUN-BM-25", scn_25.scenario_id, t0)
    # The attack was executed on the target host (PID 4001)
    raw_25, norm_25 = _make_events("BM-25", t0 + timedelta(minutes=2), t0 + timedelta(minutes=2, seconds=5))
    # Detection rule was silent for the attack, BUT an unrelated background admin task on the same host (PID 9999)
    # triggered the expected rule within the test window.
    spurious_alert_25 = AlertV1(
        alert_id="ALT-CONCURRENT-SPURIOUS-25",
        source_alert_id="SRC-SPURIOUS-25",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=4),  # Inside [t0, t0 + 15m] on WS-TARGET-01
        host_id="WS-TARGET-01",
        rule_reference=scn_25.expected_detection_rule_id,
        metadata={"causal_origin": "unrelated_background_admin_task", "process_id": 9999},
    )
    gt_25 = GroundTruthV1(
        ground_truth_id="GT-BM-25",
        run_id=run_25.run_id,
        expected_diagnostic_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        verification_method="independent_synthesis",
        injected_fault_type="causal_confounding_alert",
        verification_evidence="Synthesizer injected detection rule silence for test attack PID 4001; concurrent alert was generated by background admin task PID 9999.",
    )
    cases.append(BenchmarkScenarioCase(
        case_id="BM-25",
        name="Unrelated Concurrent Alert on Target Host (Causal Confounding)",
        description="Rule was silent for the tested attack, but an unrelated task triggered the expected rule on the same host in the window. Tests whether spatio-temporal correlation can prove causation.",
        run=run_25,
        scenario=scn_25,
        raw_events=[raw_25],
        normalized_events=[norm_25],
        rules=[rule_sigma],
        alerts=[spurious_alert_25],
        ground_truth=gt_25,
        expected_failure_category=FailureCategory.DETECTION_RULE_MISMATCH,
    ))

    # Add background distractor alerts to every case to ensure robustness against cross-rule noise
    for case in cases:
        t_case = case.run.window_start
        distractor = AlertV1(
            alert_id=f"ALT-DISTRACTOR-{case.case_id}",
            source_alert_id=f"SRC-DIST-{case.case_id}",
            source_type="wazuh",
            alert_timestamp=t_case + timedelta(minutes=5),
            host_id="WS-DISTRACTOR-NODE",
            rule_reference="RULE-WAZUH-NOISE-99",
        )
        case.distractor_alerts.append(distractor)
        if rule_distractor not in case.rules:
            case.rules.append(rule_distractor)

    return cases


# ── Metrics Calculator ───────────────────────────────────────────────────────

def compute_metrics(
    true_labels: List[DiagnosticCategory],
    pred_labels: List[DiagnosticCategory],
    evidence_support_valid: List[bool],
) -> BenchmarkMetrics:
    """Calculate evaluation metrics strictly according to documented formulas and denominators.

    Formulas & Denominators:
    1. Accuracy = sum(yt == yp) / len(true_labels)
    2. False-Diagnosis Rate = sum(yp != INCONCLUSIVE and yt != yp) / sum(yp != INCONCLUSIVE)
       (Returns 0.0 if sum(yp != INCONCLUSIVE) == 0)
    3. Inconclusive Rate = sum(yp == INCONCLUSIVE) / len(true_labels)
    4. Evidence Completeness = sum(evidence_support_valid) / len(true_labels)
    """
    total = len(true_labels)
    assert total == len(pred_labels), "Length mismatch between true and predicted labels"
    assert total == len(evidence_support_valid), "Length mismatch between labels and evidence validity"

    cm = ConfusionMatrix.create()
    for yt, yp in zip(true_labels, pred_labels):
        cm.record(yt, yp)

    correct = sum(1 for yt, yp in zip(true_labels, pred_labels) if yt == yp)
    accuracy = correct / total if total > 0 else 0.0

    precision: Dict[DiagnosticCategory, float] = {}
    recall: Dict[DiagnosticCategory, float] = {}
    f1: Dict[DiagnosticCategory, float] = {}

    for cat in ALL_CATEGORIES:
        tp = cm.matrix[cat][cat]
        fp = sum(cm.matrix[other][cat] for other in ALL_CATEGORIES if other != cat)
        fn = sum(cm.matrix[cat][other] for other in ALL_CATEGORIES if other != cat)

        prec = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 and tp == 0 else 0.0)
        rec = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if fp == 0 and tp == 0 else 0.0)
        f1_val = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        precision[cat] = prec
        recall[cat] = rec
        f1[cat] = f1_val

    # False Diagnosis Rate: denominator = confident predictions only (yp != INCONCLUSIVE)
    confident_preds = sum(1 for yp in pred_labels if yp != DiagnosticCategory.INCONCLUSIVE)
    false_confident_preds = sum(
        1 for yt, yp in zip(true_labels, pred_labels)
        if yp != DiagnosticCategory.INCONCLUSIVE and yt != yp
    )
    fdr = false_confident_preds / confident_preds if confident_preds > 0 else 0.0

    # Inconclusive Rate: denominator = total samples
    inconclusive_count = sum(1 for yp in pred_labels if yp == DiagnosticCategory.INCONCLUSIVE)
    ir = inconclusive_count / total if total > 0 else 0.0

    # Evidence Support Completeness: denominator = total samples
    esc = sum(1 for valid in evidence_support_valid if valid) / total if total > 0 else 0.0

    return BenchmarkMetrics(
        total_samples=total,
        accuracy=accuracy,
        per_class_precision=precision,
        per_class_recall=recall,
        per_class_f1=f1,
        false_diagnosis_rate=fdr,
        inconclusive_rate=ir,
        evidence_support_completeness=esc,
        confusion_matrix=cm,
    )


# ── Benchmark Verification Tests ─────────────────────────────────────────────

def test_benchmark_execution_and_accuracy():
    """Execute PROOFSHIELD and Simple alert-only baseline across all 25 benchmark scenarios."""
    suite = build_benchmark_suite()
    assert len(suite) == 25

    proofshield_preds: List[DiagnosticCategory] = []
    baseline_preds: List[DiagnosticCategory] = []
    ground_truth_labels: List[DiagnosticCategory] = []
    evidence_checks: List[bool] = []
    latency_evaluations: List[Tuple[bool, Optional[FailureCategory]]] = []

    for case in suite:
        # Step 0: Independently verify ground-truth label against specification oracle BEFORE test execution
        verified_gt = verify_ground_truth_label(case)
        assert (
            case.ground_truth.expected_diagnostic_category == verified_gt
        ), f"Ground-truth label mismatch for {case.case_id}: assigned {case.ground_truth.expected_diagnostic_category}, verified {verified_gt}"

        # Isolated store setup per scenario
        store = InMemoryStore()

        # Step 1: Assign and store independent ground truth BEFORE evaluation
        store.add_ground_truth(case.ground_truth)
        ground_truth_labels.append(case.ground_truth.expected_diagnostic_category)

        # Ingest scenario evidence & distractors
        if case.scenario is not None:
            store.add_scenario(case.scenario)
            store.add_run(case.run)
        else:
            # Orphaned run with missing scenario reference (BM-13)
            store._runs[case.run.run_id] = case.run
        for r in case.rules:
            store.add_rule(r)
        for raw in case.raw_events:
            store.add_raw_event(raw)
        for norm in case.normalized_events:
            store.add_normalized_event(norm)
        for alert in case.alerts:
            store.add_alert(alert)
        for dist in case.distractor_alerts:
            store.add_alert(dist)

        # Step 2: Run Simple alert-only baseline
        b_pred = run_alert_only_baseline(store, case.run)
        baseline_preds.append(b_pred)

        # Step 3: Run PROOFSHIELD Assurance Engine
        # Engine has NO access to ground truth; only evaluates run_id
        engine = AssuranceEngine(store)
        diag = engine.evaluate_run(case.run.run_id)
        proofshield_preds.append(diag.predicted_category)

        # Step 4: Strict evidence-support completeness validation
        is_evidence_valid, evidence_errors = validate_evidence_support(
            store, case.run, case.scenario, diag
        )
        # Note: BM-25 alert fails evidence support validation because it carries metadata from an unrelated task
        if case.case_id == "BM-25":
            assert not is_evidence_valid, "BM-25 spurious alert was unexpectedly validated as genuine evidence"
            assert any("does not establish causation" in e for e in evidence_errors)
        else:
            assert is_evidence_valid, f"Evidence validation failed for {case.case_id}: {evidence_errors}"
        evidence_checks.append(is_evidence_valid)

        # Latency flag inspection (evaluated separately from diagnostic category)
        has_latency_flag = diag.metadata.get("latency", {}).get("latency_exceeded", False)
        latency_evaluations.append((has_latency_flag, diag.failure_category))

    # Step 5: Recalculate metrics and confusion matrices dynamically from actual predictions
    ps_metrics = compute_metrics(ground_truth_labels, proofshield_preds, evidence_checks)
    base_metrics = compute_metrics(ground_truth_labels, baseline_preds, [True] * len(suite))

    # Print confusion matrices and metrics comparison for transparency
    print("\n" + "=" * 95)
    print("PROOFSHIELD ASSURANCE ENGINE CONFUSION MATRIX (Phase 2.2 Hardened Suite, N=25)")
    print("=" * 95)
    print(ps_metrics.confusion_matrix.format_table())
    print("-" * 95)
    print(f"Accuracy: {ps_metrics.accuracy:.4f} ({sum(1 for yt, yp in zip(ground_truth_labels, proofshield_preds) if yt == yp)}/{len(suite)}) | "
          f"False Diagnosis Rate: {ps_metrics.false_diagnosis_rate:.4f} | "
          f"Inconclusive Rate: {ps_metrics.inconclusive_rate:.4f} | "
          f"Evidence Completeness: {ps_metrics.evidence_support_completeness:.4f}")

    print("\n" + "=" * 95)
    print("ALERT-ONLY BASELINE CONFUSION MATRIX (Simple alert-only baseline, N=25)")
    print("=" * 95)
    print(base_metrics.confusion_matrix.format_table())
    print("-" * 95)
    print(f"Accuracy: {base_metrics.accuracy:.4f} ({sum(1 for yt, yp in zip(ground_truth_labels, baseline_preds) if yt == yp)}/{len(suite)}) | "
          f"False Diagnosis Rate: {base_metrics.false_diagnosis_rate:.4f} | "
          f"Inconclusive Rate: {base_metrics.inconclusive_rate:.4f}")
    print("=" * 95 + "\n")

    # Step 6: Assertions on PROOFSHIELD Performance
    # 1. Diagnostic Accuracy: 24 of 25 scenarios correctly diagnosed (96.0%).
    #    The single failure is BM-25 (spurious concurrent alert), demonstrating that
    #    spatio-temporal correlation cannot prove causation without execution provenance.
    assert ps_metrics.accuracy == pytest.approx(24 / 25, abs=1e-3)

    # 2. False Diagnosis Rate: 1 incorrect confident prediction out of 20 confident diagnoses (5.0%).
    assert ps_metrics.false_diagnosis_rate == pytest.approx(1 / 20, abs=1e-3)

    # 3. Inconclusive Rate matches ground-truth ambiguous scenarios (BM-04, BM-11, BM-12, BM-19, BM-20 -> 5/25 = 20.0%)
    assert ps_metrics.inconclusive_rate == pytest.approx(5 / 25, abs=1e-3)

    # 4. Evidence support completeness: 24 of 25 scenarios possess validated evidence (96.0%).
    #    BM-25 is flagged for non-causal evidence support.
    assert ps_metrics.evidence_support_completeness == pytest.approx(24 / 25, abs=1e-3)

    # 5. Latency flag verified separately: BM-14 has latency_exceeded=True, BM-01 does not
    assert latency_evaluations[13][0] is True  # BM-14
    assert latency_evaluations[13][1] == FailureCategory.PIPELINE_LATENCY
    assert latency_evaluations[0][0] is False  # BM-01

    # 6. Baseline Failure Attribution Contrast:
    # Baseline accuracy is substantially lower (12/25 = 48.0%) and false diagnosis rate is higher (12/21 = 57.1%)
    # because it maps pipeline/telemetry/execution faults to rule silence and falsely marks evasion with concurrent alerts as PASS.
    assert base_metrics.accuracy < ps_metrics.accuracy
    assert base_metrics.false_diagnosis_rate > ps_metrics.false_diagnosis_rate


def test_benchmark_causal_confounding_unrelated_alert_limitation():
    """Audit test demonstrating that spatio-temporal correlation cannot establish causal linkage.

    When an unrelated alert matches the target host, expected rule, and test window,
    AssuranceEngine correlates it and outputs PASS. This test proves that host/time
    co-occurrence does not prove causation and documents this concrete architectural boundary.
    """
    store = InMemoryStore()
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-AUDIT-CAUSAL",
        name="Causal Confounding Audit Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"DownloadString",
        expected_detection_rule_id="RULE-SIGMA-CRADLE-01",
    )
    run = TestRunV1(
        run_id="RUN-AUDIT-CAUSAL",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-TARGET-01",
        target_user="corp\\secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_scenario(scn)
    store.add_run(run)

    # Ingest attack telemetry for this run
    raw_ev = RawTelemetryEventV1(
        raw_event_id="RAW-AUDIT",
        source_event_id="SRC-AUDIT",
        source_format="sysmon",
        source_timestamp=t0 + timedelta(minutes=2),
        ingested_at=t0 + timedelta(minutes=2, seconds=5),
        raw_payload={"EventID": 1, "CommandLine": "powershell.exe -enc DownloadString"},
    )
    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-AUDIT",
        raw_event_id="RAW-AUDIT",
        source_event_id="SRC-AUDIT",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
    )
    store.add_raw_event(raw_ev)
    store.add_normalized_event(norm_ev)

    # Ingest an alert that was triggered by an unrelated background task, NOT the attack
    spurious_alert = AlertV1(
        alert_id="ALT-SPURIOUS-AUDIT",
        source_alert_id="SRC-SPURIOUS",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=5),  # Inside run window
        host_id=run.target_host,                     # Matches host
        rule_reference="RULE-SIGMA-CRADLE-01",       # Matches expected rule
        metadata={"causal_origin": "unrelated_background_admin_task", "process_id": 9999},
    )
    store.add_alert(spurious_alert)

    # Evaluator performs spatio-temporal correlation
    engine = AssuranceEngine(store)
    result = engine.evaluate_run(run.run_id)

    # AUDIT DETERMINATION:
    # 1. The engine declares PASS because host, rule, and window coincide
    assert result.predicted_category == DiagnosticCategory.PASS

    # 2. But the genuine ground truth for the test run attack is DETECTION_NOT_TRIGGERED
    #    (the attack execution was silent; the alert was spurious).
    ground_truth = GroundTruthV1(
        ground_truth_id="GT-AUDIT-CAUSAL",
        run_id=run.run_id,
        expected_diagnostic_category=DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        verification_method="independent_synthesis",
        injected_fault_type="causal_confounding_alert",
    )
    assert result.predicted_category != ground_truth.expected_diagnostic_category

    # 3. Evidence validator flags that the cited alert is causally unrelated
    is_valid, errors = validate_evidence_support(store, run, scn, result)
    assert not is_valid
    assert any("does not establish causation" in e for e in errors)


def test_benchmark_metrics_definitions_and_denominators():
    """Unit test verifying that compute_metrics accurately adheres to documented formulas and denominators."""
    # Test vector 1: Mixed outcomes
    # 2 PASS (1 correct, 1 incorrect), 1 INCONCLUSIVE, 1 ERROR
    true_labels = [
        DiagnosticCategory.PASS,
        DiagnosticCategory.DETECTION_NOT_TRIGGERED,
        DiagnosticCategory.INCONCLUSIVE,
        DiagnosticCategory.ERROR,
    ]
    pred_labels = [
        DiagnosticCategory.PASS,                     # TP for PASS (correct)
        DiagnosticCategory.PASS,                     # FP for PASS (false confident prediction)
        DiagnosticCategory.INCONCLUSIVE,             # Correct inconclusive
        DiagnosticCategory.ERROR,                    # Correct error
    ]
    evidence_valid = [True, False, True, True]

    metrics = compute_metrics(true_labels, pred_labels, evidence_valid)

    # Accuracy: 3 correct / 4 total = 0.75
    assert metrics.accuracy == pytest.approx(3 / 4)

    # Inconclusive Rate: 1 inconclusive / 4 total = 0.25
    assert metrics.inconclusive_rate == pytest.approx(1 / 4)

    # Evidence Completeness: 3 valid / 4 total = 0.75
    assert metrics.evidence_support_completeness == pytest.approx(3 / 4)

    # False Diagnosis Rate:
    # Confident predictions: [PASS, PASS, ERROR] = 3
    # Incorrect confident predictions: [pred_labels[1]] = 1
    # FDR = 1 / 3 = 0.3333...
    assert metrics.false_diagnosis_rate == pytest.approx(1 / 3)

    # Test vector 2: All predictions are INCONCLUSIVE
    # Edge case: Confident denominator is 0 -> FDR should be 0.0 (not ZeroDivisionError)
    all_inconcl_true = [DiagnosticCategory.PASS, DiagnosticCategory.ERROR]
    all_inconcl_pred = [DiagnosticCategory.INCONCLUSIVE, DiagnosticCategory.INCONCLUSIVE]
    m_inconcl = compute_metrics(all_inconcl_true, all_inconcl_pred, [True, True])
    assert m_inconcl.false_diagnosis_rate == 0.0
    assert m_inconcl.inconclusive_rate == 1.0
    assert m_inconcl.accuracy == 0.0


def test_benchmark_ground_truth_independent_verification():
    """Verify that every ground-truth label in the benchmark suite is independently verified from specifications."""
    suite = build_benchmark_suite()
    assert len(suite) == 25

    for case in suite:
        verified_category = verify_ground_truth_label(case)
        assert case.ground_truth.expected_diagnostic_category == verified_category, (
            f"Ground truth label for {case.case_id} failed independent verification: "
            f"expected {case.ground_truth.expected_diagnostic_category}, oracle determined {verified_category}"
        )


def test_benchmark_evidence_support_validation_rejection_of_invalid_evidence():
    """Verify that validate_evidence_support rejects non-existent IDs, contradictory evidence, and non-causal alerts."""
    store = InMemoryStore()
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-TEST-VAL",
        name="Validation Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"DownloadString",
        expected_detection_rule_id="RULE-SIGMA-CRADLE-01",
    )
    run = TestRunV1(
        run_id="RUN-TEST-VAL",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-TARGET-01",
        target_user="corp\\secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
    )
    store.add_scenario(scn)
    store.add_run(run)

    # 1. Reject hallucinated evidence ID (does not exist in store)
    diag_fake_id = DiagnosticResultV1(
        diagnostic_id="DIAG-FAKE-01",
        test_run_id=run.run_id,
        scenario_id=scn.scenario_id,
        predicted_category=DiagnosticCategory.PASS,
        confidence="definitive",
        reason="Fabricated pass",
        supporting_evidence_ids=["NORM-NON-EXISTENT-ID"],
        evaluated_at=t0,
    )
    is_valid, errors = validate_evidence_support(store, run, scn, diag_fake_id)
    assert not is_valid
    assert any("does not exist in store" in e for e in errors)

    # 2. Reject PASS with empty supporting evidence
    diag_empty_pass = DiagnosticResultV1(
        diagnostic_id="DIAG-FAKE-02",
        test_run_id=run.run_id,
        scenario_id=scn.scenario_id,
        predicted_category=DiagnosticCategory.PASS,
        confidence="definitive",
        reason="Unsupported pass",
        supporting_evidence_ids=[],
        evaluated_at=t0,
    )
    is_valid, errors = validate_evidence_support(store, run, scn, diag_empty_pass)
    assert not is_valid
    assert any("requires supporting evidence" in e for e in errors)

    # 3. Reject contradictory alert evidence that actually correlates
    real_alert = AlertV1(
        alert_id="ALT-REAL-01",
        source_alert_id="SRC-REAL-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=5),
        host_id="WS-TARGET-01",
        rule_reference="RULE-SIGMA-CRADLE-01",
    )
    store.add_alert(real_alert)

    diag_invalid_contradictory = DiagnosticResultV1(
        diagnostic_id="DIAG-FAKE-03",
        test_run_id=run.run_id,
        scenario_id=scn.scenario_id,
        predicted_category=DiagnosticCategory.ALERT_NOT_CORRELATED,
        confidence="likely",
        reason="False claim of un-correlated alert",
        supporting_evidence_ids=[],
        contradictory_evidence_ids=[real_alert.alert_id],
        evaluated_at=t0,
    )
    is_valid, errors = validate_evidence_support(store, run, scn, diag_invalid_contradictory)
    assert not is_valid
    assert any("actually correlates" in e for e in errors)


def test_benchmark_leakage_safeguard():
    """Verify that removing or corrupting ground truth records leaves benchmark predictions unaffected."""
    suite = build_benchmark_suite()
    store = InMemoryStore()

    case = suite[0]  # BM-01
    store.add_scenario(case.scenario)
    store.add_run(case.run)
    for raw in case.raw_events:
        store.add_raw_event(raw)
    for norm in case.normalized_events:
        store.add_normalized_event(norm)
    for alert in case.alerts:
        store.add_alert(alert)

    # Corrupt ground truth to completely opposite category
    corrupted_gt = GroundTruthV1(
        ground_truth_id="GT-LEAK-TEST",
        run_id=case.run.run_id,
        expected_diagnostic_category=DiagnosticCategory.ERROR,
        verification_method="adversarial_injection",
    )
    store.add_ground_truth(corrupted_gt)

    engine = AssuranceEngine(store)
    result = engine.evaluate_run(case.run.run_id)

    # Prediction must strictly remain PASS based on evidence, completely ignoring corrupted ground truth
    assert result.predicted_category == DiagnosticCategory.PASS
