"""Tests for Phase 2.7: Execution Token Attribution & Strict Causal Verification.

Validates:
1. Schema additions (optional execution_token across TestRunV1, AlertV1, NormalizedTelemetryEventV1).
2. Structured-first token extraction and conflict marking (explicit vs extracted, multiple extracted).
3. Normalisation engine automatic token extraction and preservation.
4. In-memory store alert token extraction and conflict detection.
5. Strict attribution mode:
   - Missing/conflicting run or telemetry evidence -> INCONCLUSIVE
   - Missing/conflicting alert evidence -> INCONCLUSIVE
   - Grace-window alerts strictly excluded from PASS -> ALERT_NOT_CORRELATED
   - Rejection of mismatched alerts without assuming they prove detection failure -> DETECTION_NOT_TRIGGERED
   - Matching tokens across run, telemetry, and alert strictly within window -> PASS
6. BM-25 causal confounding resolution under strict attribution vs default mode preservation.
7. Metadata guarantees: attribution status, evidence tokens, explicit disclaimer of cryptographic proof.
8. API endpoint strict_attribution query parameter support.
"""

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from proofshield.main import app
from proofshield.normalisation.engine import (
    FallbackNormaliser,
    GenericEDRNormaliser,
    NormalisationEngine,
    SysmonNormaliser,
    extract_execution_token,
)
from proofshield.schemas import (
    AlertV1,
    AttributionStatus,
    DetectionRuleV1,
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    FailureCategory,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.store import InMemoryStore, get_store


# ── 1. Schema Validation ─────────────────────────────────────────────────────

def test_schema_optional_execution_token():
    """Verify execution_token is optional and backwards-compatible across all schemas."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)

    # TestRunV1 without and with token
    run_default = TestRunV1(
        run_id="RUN-SCHEMA-01",
        scenario_id="SCN-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=10),
        executed_at=t0,
    )
    assert run_default.execution_token is None

    run_with_token = TestRunV1(
        run_id="RUN-SCHEMA-02",
        scenario_id="SCN-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=10),
        executed_at=t0,
        execution_token="TOK-RUN-999",
    )
    assert run_with_token.execution_token == "TOK-RUN-999"

    # AlertV1 without and with token
    alert_default = AlertV1(
        alert_id="ALT-SCHEMA-01",
        source_alert_id="SRC-01",
        source_type="sigma",
        host_id="WS-01",
    )
    assert alert_default.execution_token is None

    alert_with_token = AlertV1(
        alert_id="ALT-SCHEMA-02",
        source_alert_id="SRC-02",
        source_type="sigma",
        host_id="WS-01",
        execution_token="TOK-ALT-888",
    )
    assert alert_with_token.execution_token == "TOK-ALT-888"

    # NormalizedTelemetryEventV1 without and with token
    norm_default = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-SCHEMA-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t0,
        normalized_timestamp=t0,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
    )
    assert norm_default.execution_token is None

    norm_with_token = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-SCHEMA-02",
        raw_event_id="RAW-02",
        source_event_id="SRC-02",
        source_timestamp=t0,
        normalized_timestamp=t0,
        event_category=EventCategory.PROCESS_CREATION,
        host="WS-01",
        execution_token="TOK-NORM-777",
    )
    assert norm_with_token.execution_token == "TOK-NORM-777"


# ── 2. Structured-First Token Extraction & Conflict Detection ───────────────

def test_extract_token_structured_precedence():
    """Verify structured fields are extracted and take precedence."""
    # From structured key 'execution_token'
    tok = extract_execution_token(payload={"execution_token": "TOK-STRUCT-01"})
    assert tok == "TOK-STRUCT-01"

    # From alternate structured key 'test_token'
    tok = extract_execution_token(payload={"test_token": "TOK-TEST-02"})
    assert tok == "TOK-TEST-02"

    # From alternate structured key 'proofshield_token'
    tok = extract_execution_token(payload={"proofshield_token": "TOK-PS-03"})
    assert tok == "TOK-PS-03"

    # Matching structured and unstructured -> returns the token
    tok = extract_execution_token(
        payload={"execution_token": "TOK-AGREED"},
        text_fields=["powershell.exe -enc ... --token TOK-AGREED"],
    )
    assert tok == "TOK-AGREED"


def test_extract_token_unstructured_patterns():
    """Verify regex patterns for command-line and text token extraction."""
    # --execution-token flag
    tok = extract_execution_token(
        text_fields=["powershell.exe -NoProfile --execution-token TOK-CMD-01"]
    )
    assert tok == "TOK-CMD-01"

    # --token flag with equals
    tok = extract_execution_token(
        text_fields=["curl.exe https://example.com/cradle --token=TOK-CMD-02"]
    )
    assert tok == "TOK-CMD-02"

    # Bracket notation [TOKEN:xxx]
    tok = extract_execution_token(
        text_fields=["Scheduled Task Launch [TOKEN:TOK-BRACKET-03]"]
    )
    assert tok == "TOK-BRACKET-03"

    # Key-value TOKEN=xxx
    tok = extract_execution_token(
        text_fields=["cmd.exe /c set TOKEN=TOK-ENV-04 && calc.exe"]
    )
    assert tok == "TOK-ENV-04"


def test_extract_token_conflicts_marked_conflict_never_verified():
    """Verify that conflicting explicit/extracted tokens are marked CONFLICT."""
    # 1. Explicit structured token differs from unstructured extracted token
    tok = extract_execution_token(
        payload={"execution_token": "TOK-REAL-01"},
        text_fields=["powershell.exe --token TOK-IMPOSTER-02"],
    )
    assert tok == "CONFLICT"

    # 2. Explicit token parameter differs from payload token
    tok = extract_execution_token(
        explicit_token="TOK-EXPLICIT-01",
        payload={"execution_token": "TOK-PAYLOAD-02"},
    )
    assert tok == "CONFLICT"

    # 3. Multiple differing tokens in unstructured text
    tok = extract_execution_token(
        text_fields=["powershell.exe --token TOK-FIRST-01 and --token TOK-SECOND-02"]
    )
    assert tok == "CONFLICT"

    # 4. Explicit token already CONFLICT stays CONFLICT
    tok = extract_execution_token(explicit_token="CONFLICT")
    assert tok == "CONFLICT"


# ── 3. Normalisation Engine Extraction ──────────────────────────────────────

def test_normalisers_extract_execution_tokens():
    """Verify Sysmon, Generic EDR, and Fallback normalisers extract execution tokens."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)

    # Sysmon with structured token
    raw_sysmon = RawTelemetryEventV1(
        raw_event_id="RAW-SYS-TOK-01",
        source_event_id="SRC-01",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0 + timedelta(seconds=2),
        raw_payload={
            "EventID": 1,
            "CommandLine": "powershell.exe -enc abc",
            "Computer": "WS-01",
            "execution_token": "TOK-SYS-01",
        },
    )
    norm_sysmon = SysmonNormaliser().normalize(raw_sysmon)
    assert norm_sysmon.execution_token == "TOK-SYS-01"

    # Generic EDR with unstructured token in command line
    raw_edr = RawTelemetryEventV1(
        raw_event_id="RAW-EDR-TOK-01",
        source_event_id="SRC-02",
        source_format="edr",
        source_timestamp=t0,
        ingested_at=t0 + timedelta(seconds=2),
        raw_payload={
            "event_type": "process",
            "command_line": "whoami.exe /all --token TOK-EDR-02",
            "hostname": "WS-01",
        },
    )
    norm_edr = GenericEDRNormaliser().normalize(raw_edr)
    assert norm_edr.execution_token == "TOK-EDR-02"

    # Fallback with conflicting tokens
    raw_fallback = RawTelemetryEventV1(
        raw_event_id="RAW-FB-TOK-01",
        source_event_id="SRC-03",
        source_format="custom_audit",
        source_timestamp=t0,
        ingested_at=t0 + timedelta(seconds=2),
        raw_payload={
            "command": "test.exe --token TOK-UNSTRUCT",
            "execution_token": "TOK-STRUCT-DIFF",
            "host": "WS-01",
        },
    )
    norm_fallback = FallbackNormaliser().normalize(raw_fallback)
    assert norm_fallback.execution_token == "CONFLICT"


# ── 4. In-Memory Store Alert Extraction & Conflict Detection ────────────────

def test_store_alert_token_extraction_and_conflict():
    """Verify store.add_alert extracts tokens from metadata/title and catches conflicts."""
    store = InMemoryStore()

    # Alert with token in metadata
    alt1 = AlertV1(
        alert_id="ALT-STORE-01",
        source_alert_id="SRC-ALT-01",
        source_type="sigma",
        host_id="WS-01",
        metadata={"execution_token": "TOK-ALERT-META"},
    )
    store.add_alert(alt1)
    assert store.get_alert("ALT-STORE-01").execution_token == "TOK-ALERT-META"

    # Alert with conflicting explicit token vs metadata token
    alt2 = AlertV1(
        alert_id="ALT-STORE-02",
        source_alert_id="SRC-ALT-02",
        source_type="sigma",
        host_id="WS-01",
        execution_token="TOK-EXPLICIT",
        metadata={"token": "TOK-CONFLICTING"},
    )
    store.add_alert(alt2)
    assert store.get_alert("ALT-STORE-02").execution_token == "CONFLICT"


# ── 5. Strict Attribution Engine Evaluation ──────────────────────────────────

@pytest.fixture
def base_setup():
    store = InMemoryStore()
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-ATTRIBUTION-01",
        name="Attribution Test Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"DownloadString",
        expected_detection_rule_id="RULE-SIGMA-01",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    rule = DetectionRuleV1(
        rule_id="RULE-SIGMA-01",
        rule_name="Sigma PowerShell Rule",
        rule_format="sigma",
    )
    store.add_scenario(scn)
    store.add_rule(rule)
    return store, scn, rule, t0


def test_strict_attribution_nominal_pass(base_setup):
    """When execution tokens match across run, telemetry, and alert in window -> PASS."""
    store, scn, rule, t0 = base_setup

    token = "TOK-NOMINAL-PASS-01"
    run = TestRunV1(
        run_id="RUN-ATTR-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=token,
    )
    store.add_run(run)

    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-ATTR-01",
        raw_event_id="RAW-ATTR-01",
        source_event_id="SRC-ATTR-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
        execution_token=token,
    )
    store.add_normalized_event(norm_ev)

    alert = AlertV1(
        alert_id="ALT-ATTR-01",
        source_alert_id="SRC-ALT-ATTR-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=token,
    )
    store.add_alert(alert)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    assert res.predicted_category == DiagnosticCategory.PASS
    assert res.confidence == "definitive"
    assert norm_ev.normalized_event_id in res.supporting_evidence_ids
    assert alert.alert_id in res.supporting_evidence_ids

    # Metadata checks
    attr_meta = res.metadata.get("attribution", {})
    assert attr_meta["status"] == AttributionStatus.VERIFIED.value
    assert attr_meta["strict_attribution"] is True
    assert attr_meta["cryptographic_proof"] is False
    assert "disclaimer" in attr_meta


def test_strict_attribution_missing_run_token_inconclusive(base_setup):
    """When strict attribution is requested but run lacks execution_token -> INCONCLUSIVE."""
    store, scn, rule, t0 = base_setup

    run = TestRunV1(
        run_id="RUN-NO-TOKEN",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=None,
    )
    store.add_run(run)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert "lacks an execution token" in res.reason
    assert res.metadata["attribution"]["status"] == AttributionStatus.INCONCLUSIVE.value


def test_strict_attribution_conflict_run_token_inconclusive(base_setup):
    """When run has CONFLICT token -> INCONCLUSIVE, never verified."""
    store, scn, rule, t0 = base_setup

    run = TestRunV1(
        run_id="RUN-CONFLICT-TOKEN",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token="CONFLICT",
    )
    store.add_run(run)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert "Conflicting execution token" in res.reason
    assert res.metadata["attribution"]["status"] == AttributionStatus.CONFLICT.value


def test_strict_attribution_missing_telemetry_token_inconclusive(base_setup):
    """When strict attribution is enabled and matching telemetry lacks token -> INCONCLUSIVE."""
    store, scn, rule, t0 = base_setup
    token = "TOK-RUN-01"

    run = TestRunV1(
        run_id="RUN-TEL-NO-TOK",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=token,
    )
    store.add_run(run)

    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NO-TOK",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
        execution_token=None,  # missing token on telemetry
    )
    store.add_normalized_event(norm_ev)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert "lack execution tokens" in res.reason


def test_strict_attribution_conflict_telemetry_token_inconclusive(base_setup):
    """When candidate telemetry has CONFLICT token -> INCONCLUSIVE."""
    store, scn, rule, t0 = base_setup
    token = "TOK-RUN-01"

    run = TestRunV1(
        run_id="RUN-TEL-CONFLICT",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=token,
    )
    store.add_run(run)

    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-CONFLICT-TOK",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
        execution_token="CONFLICT",
    )
    store.add_normalized_event(norm_ev)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert "conflicting execution tokens" in res.reason


def test_strict_attribution_missing_alert_token_inconclusive(base_setup):
    """When candidate alert in window lacks execution_token under strict attribution -> INCONCLUSIVE."""
    store, scn, rule, t0 = base_setup
    token = "TOK-VALID-01"

    run = TestRunV1(
        run_id="RUN-ALT-MISSING-TOK",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=token,
    )
    store.add_run(run)

    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
        execution_token=token,
    )
    store.add_normalized_event(norm_ev)

    # Alert in window has no token
    alert_no_tok = AlertV1(
        alert_id="ALT-NO-TOK-01",
        source_alert_id="SRC-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=None,
    )
    store.add_alert(alert_no_tok)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert "lacks execution token" in res.reason


def test_strict_attribution_conflict_alert_token_inconclusive(base_setup):
    """When candidate alert in window has CONFLICT token -> INCONCLUSIVE."""
    store, scn, rule, t0 = base_setup
    token = "TOK-VALID-01"

    run = TestRunV1(
        run_id="RUN-ALT-CONFLICT-TOK",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=token,
    )
    store.add_run(run)

    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
        execution_token=token,
    )
    store.add_normalized_event(norm_ev)

    alert_conflict = AlertV1(
        alert_id="ALT-CONFLICT-01",
        source_alert_id="SRC-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token="CONFLICT",
    )
    store.add_alert(alert_conflict)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert "conflicting" in res.reason.lower()


def test_strict_attribution_grace_window_alert_never_produces_pass(base_setup):
    """Alert with matching token arriving in the grace window must NOT produce PASS."""
    store, scn, rule, t0 = base_setup
    token = "TOK-GRACE-TEST"

    run = TestRunV1(
        run_id="RUN-GRACE-WINDOW",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=token,
    )
    store.add_run(run)

    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-01",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
        execution_token=token,
    )
    store.add_normalized_event(norm_ev)

    # Alert timestamp is 2 minutes past window_end (within default 3600s grace period)
    late_alert = AlertV1(
        alert_id="ALT-LATE-TOK",
        source_alert_id="SRC-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=17),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=token,
    )
    store.add_alert(late_alert)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    # Must be ALERT_NOT_CORRELATED, NEVER PASS!
    assert res.predicted_category == DiagnosticCategory.ALERT_NOT_CORRELATED
    assert "Grace-window alerts must not produce PASS" in res.diagnostic_reasons
    assert res.failure_category == FailureCategory.PIPELINE_LATENCY


# ── 6. BM-25 Resolution & Mismatched Alert Rejection ─────────────────────────

def test_bm25_causal_confounding_resolution_under_strict_attribution(base_setup):
    """Verify BM-25 behavior: default mode correlates spurious alert (PASS);

    strict attribution rejects mismatched alert without assuming detection failure -> DETECTION_NOT_TRIGGERED.
    """
    store, scn, rule, t0 = base_setup

    attack_token = "TOK-ATTACK-PID4001"
    bg_admin_token = "TOK-BG-ADMIN-PID9999"

    run_25 = TestRunV1(
        run_id="RUN-BM-25-EXPERIMENT",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WS-TARGET-01",
        target_user="corp\\secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=attack_token,
    )
    store.add_run(run_25)

    # Telemetry produced by test attack
    attack_raw = RawTelemetryEventV1(
        raw_event_id="RAW-25",
        source_event_id="SRC-25",
        source_format="sysmon",
        source_timestamp=t0 + timedelta(minutes=2),
        ingested_at=t0 + timedelta(minutes=2, seconds=5),
        raw_payload={"EventID": 1, "CommandLine": "powershell.exe -enc DownloadString", "execution_token": attack_token},
    )
    attack_norm = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-25",
        raw_event_id="RAW-25",
        source_event_id="SRC-25",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run_25.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
        execution_token=attack_token,
    )
    store.add_raw_event(attack_raw)
    store.add_normalized_event(attack_norm)

    # Detection rule was silent for the attack, BUT an unrelated background admin task (PID 9999)
    # triggered the rule on the same host within the window.
    spurious_alert = AlertV1(
        alert_id="ALT-SPURIOUS-25",
        source_alert_id="SRC-SPURIOUS-25",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=4),
        host_id=run_25.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=bg_admin_token,  # Mismatched token!
        metadata={"causal_origin": "unrelated_background_admin_task", "process_id": 9999},
    )
    store.add_alert(spurious_alert)

    engine = AssuranceEngine(store)

    # 1. Default mode: spatio-temporal correlation correlates the spurious alert and predicts PASS
    # (Preserving existing benchmark behavior and causal audit finding)
    res_default = engine.evaluate_run(run_25.run_id, strict_attribution=False)
    assert res_default.predicted_category == DiagnosticCategory.PASS
    assert spurious_alert.alert_id in res_default.supporting_evidence_ids

    # 2. Strict attribution mode: spurious alert is rejected as mismatched without assuming detection failure;
    # since no alert with attack_token exists, the rule is accurately diagnosed as silent -> DETECTION_NOT_TRIGGERED
    res_strict = engine.evaluate_run(run_25.run_id, strict_attribution=True)
    assert res_strict.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED
    assert res_strict.confidence == "likely"
    assert attack_norm.normalized_event_id in res_strict.supporting_evidence_ids
    # Spurious alert is NOT in supporting evidence or contradictory evidence
    assert spurious_alert.alert_id not in res_strict.supporting_evidence_ids
    assert spurious_alert.alert_id not in res_strict.contradictory_evidence_ids

    # Attribution metadata
    attr_meta = res_strict.metadata["attribution"]
    assert attr_meta["status"] == AttributionStatus.MISMATCHED.value
    assert spurious_alert.alert_id in attr_meta["mismatched_alert_ids"]
    assert attr_meta["cryptographic_proof"] is False


def test_strict_attribution_multiple_alerts_with_one_matching(base_setup):
    """When a host has both a mismatched alert and a matching alert,

    the mismatched alert is rejected without assuming detection failure, and the matching alert correlates -> PASS.
    """
    store, scn, rule, t0 = base_setup
    attack_tok = "TOK-ATTACK"
    noise_tok = "TOK-NOISE"

    run = TestRunV1(
        run_id="RUN-MULTI-ALERT",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=attack_tok,
    )
    store.add_run(run)

    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-MULTI",
        raw_event_id="RAW-01",
        source_event_id="SRC-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
        execution_token=attack_tok,
    )
    store.add_normalized_event(norm_ev)

    # Mismatched alert on host
    alt_noise = AlertV1(
        alert_id="ALT-NOISE-01",
        source_alert_id="SRC-NOISE",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=noise_tok,
    )
    store.add_alert(alt_noise)

    # Matching alert for the test run
    alt_genuine = AlertV1(
        alert_id="ALT-GENUINE-02",
        source_alert_id="SRC-GENUINE",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=5),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=attack_tok,
    )
    store.add_alert(alt_genuine)

    engine = AssuranceEngine(store)
    res = engine.evaluate_run(run.run_id, strict_attribution=True)

    assert res.predicted_category == DiagnosticCategory.PASS
    assert alt_genuine.alert_id in res.supporting_evidence_ids
    assert alt_noise.alert_id not in res.supporting_evidence_ids
    assert any("Rejected 1 mismatched alert(s)" in r for r in res.diagnostic_reasons)


# ── 7. REST API Integration ──────────────────────────────────────────────────

def test_api_strict_attribution_query_param(base_setup):
    """Verify REST API /api/v1/evaluation/{run_id}?strict_attribution=true works end-to-end."""
    store, scn, rule, t0 = base_setup

    token = "TOK-API-TEST"
    run = TestRunV1(
        run_id="RUN-API-STRICT-01",
        scenario_id=scn.scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        target_host="WS-TARGET-01",
        target_user="secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=15),
        executed_at=t0,
        execution_token=token,
    )

    # Use global store that FastAPI app accesses
    global_store = get_store()
    global_store.reset()
    global_store.add_scenario(scn)
    global_store.add_rule(rule)
    global_store.add_run(run)

    norm_ev = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-API-01",
        raw_event_id="RAW-API-01",
        source_event_id="SRC-01",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        command_line="powershell.exe -enc DownloadString",
        execution_token=token,
    )
    global_store.add_normalized_event(norm_ev)

    alert = AlertV1(
        alert_id="ALT-API-01",
        source_alert_id="SRC-ALT-01",
        source_type="sigma",
        alert_timestamp=t0 + timedelta(minutes=3),
        host_id=run.target_host,
        rule_reference=scn.expected_detection_rule_id,
        execution_token=token,
    )
    global_store.add_alert(alert)

    client = TestClient(app)
    # Default evaluation call without param
    resp_default = client.post(f"/api/v1/evaluation/{run.run_id}")
    assert resp_default.status_code == 200
    data_default = resp_default.json()
    assert data_default["predicted_category"] == "PASS"
    assert data_default["metadata"]["attribution"]["strict_attribution"] is False

    # Strict evaluation call with query param
    resp_strict = client.post(f"/api/v1/evaluation/{run.run_id}?strict_attribution=true")
    assert resp_strict.status_code == 200
    data_strict = resp_strict.json()
    assert data_strict["predicted_category"] == "PASS"
    assert data_strict["metadata"]["attribution"]["strict_attribution"] is True
    assert data_strict["metadata"]["attribution"]["status"] == "VERIFIED"
    assert data_strict["metadata"]["attribution"]["cryptographic_proof"] is False
