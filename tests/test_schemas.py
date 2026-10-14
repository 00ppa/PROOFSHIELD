"""Unit tests for Pydantic v1 schemas."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticCategory,
    DiagnosticOutcome,
    DiagnosticResultV1,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    FailureCategory,
    GroundTruthLabel,
    GroundTruthV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)


def test_scenario_v1_valid():
    """Verify ScenarioV1 instantiates successfully with valid parameters."""
    scenario = ScenarioV1(
        scenario_id="SCN-T1059.001-01",
        name="PowerShell Execution Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    assert scenario.schema_version == "v1"
    assert scenario.scenario_id == "SCN-T1059.001-01"
    assert scenario.validation_target == ValidationTarget.EXPECTED_ALERT
    # Backwards compatibility alias
    assert scenario.ground_truth_label == ValidationTarget.EXPECTED_ALERT


def test_scenario_v1_backwards_compat_alias():
    """Verify ScenarioV1 accepts legacy ground_truth_label field."""
    scenario = ScenarioV1(
        scenario_id="SCN-T1059.001-02",
        name="Legacy Field Test",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        ground_truth_label=ValidationTarget.EXPECTED_TELEMETRY_ONLY,
    )
    assert scenario.validation_target == ValidationTarget.EXPECTED_TELEMETRY_ONLY
    data = scenario.model_dump()
    assert "validation_target" in data
    assert data["validation_target"] == "EXPECTED_TELEMETRY_ONLY"


def test_scenario_v1_invalid_mitre_id():
    """Verify ScenarioV1 rejects invalid MITRE technique IDs."""
    with pytest.raises(ValidationError) as exc:
        ScenarioV1(
            scenario_id="SCN-BAD-01",
            name="Bad MITRE ID Test",
            mitre_technique_id="INVALID_FORMAT",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
        )
    assert "mitre_technique_id" in str(exc.value)


def test_scenario_v1_forbids_extra_fields():
    """Verify ScenarioV1 strictly rejects unknown extra fields."""
    with pytest.raises(ValidationError):
        ScenarioV1(
            scenario_id="SCN-EXTRA-01",
            name="Extra field test",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
            unknown_injected_field="not_allowed",  # type: ignore
        )


def test_test_run_v1_valid():
    """Verify TestRunV1 instantiates successfully with valid time windows."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)

    run = TestRunV1(
        run_id="RUN-001",
        scenario_id="SCN-T1059.001-01",
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host="WORKSTATION-01",
        target_user="CORP\\alice",
        window_start=t0,
        window_end=t1,
        executed_at=t0,
    )
    assert run.run_id == "RUN-001"
    assert run.is_synthetic is True


def test_test_run_v1_invalid_window():
    """Verify TestRunV1 validator rejects window_end earlier than window_start."""
    t0 = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)

    with pytest.raises(ValidationError) as exc:
        TestRunV1(
            run_id="RUN-BAD-WINDOW",
            scenario_id="SCN-T1059.001-01",
            execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
            target_host="WORKSTATION-01",
            target_user="CORP\\alice",
            window_start=t0,
            window_end=t1,
            executed_at=t0,
        )
    assert "window_end must not be earlier than window_start" in str(exc.value)


def test_raw_telemetry_event_v1_structure():
    """Verify RawTelemetryEventV1 preserves source ID, timestamps, and payload dictionary."""
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
    raw = RawTelemetryEventV1(
        raw_event_id="RAW-001",
        source_event_id="SRC-SYS-999",
        source_format="sysmon",
        source_timestamp=t0,
        ingested_at=t0,
        raw_payload={"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe"},
    )
    assert raw.raw_event_id == "RAW-001"
    assert raw.source_event_id == "SRC-SYS-999"
    assert raw.raw_payload["EventID"] == 1


def test_diagnostic_result_v1_inconclusive_support():
    """Verify DiagnosticResultV1 supports INCONCLUSIVE category with evidence IDs."""
    t0 = datetime(2026, 10, 12, 10, 10, tzinfo=timezone.utc)
    diag = DiagnosticResultV1(
        diagnostic_id="DIAG-001",
        test_run_id="RUN-001",
        scenario_id="SCN-T1059.001-01",
        predicted_category=DiagnosticCategory.INCONCLUSIVE,
        confidence="uncertain",
        reason="Telemetry contains contradictory timestamps across cluster nodes.",
        supporting_evidence_ids=["RAW-001"],
        contradictory_evidence_ids=["RAW-002"],
        evaluated_at=t0,
    )
    assert diag.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert diag.confidence == "uncertain"
    assert diag.supporting_evidence_ids == ["RAW-001"]
    assert diag.contradictory_evidence_ids == ["RAW-002"]


def test_detection_rule_v1_valid():
    """Verify DetectionRuleV1 structure and field validation."""
    rule = DetectionRuleV1(
        rule_id="RULE-SIGMA-001",
        rule_name="PowerShell Download Cradles",
        rule_format="sigma",
        rule_content="title: PowerShell Download\ndetection:\n  selection:\n    CommandLine|contains: 'DownloadString'",
        mitre_technique_ids=["T1059.001"],
        description="Detects suspicious PowerShell cradle downloads",
    )
    assert rule.rule_id == "RULE-SIGMA-001"
    assert rule.rule_name == "PowerShell Download Cradles"
    assert rule.rule_format == "sigma"
    assert rule.mitre_technique_ids == ["T1059.001"]


def test_alert_v1_valid():
    """Verify AlertV1 structure and temporal fields."""
    t0 = datetime(2026, 10, 12, 10, 5, tzinfo=timezone.utc)
    alert = AlertV1(
        alert_id="ALT-WAZUH-001",
        source_alert_id="WAZ-9988",
        source_type="wazuh",
        alert_timestamp=t0,
        host_id="WS-WIN11-01",
        rule_reference="001",
        alert_title="Suspicious PowerShell Execution",
        severity="high",
    )
    assert alert.alert_id == "ALT-WAZUH-001"
    assert alert.source_alert_id == "WAZ-9988"
    assert alert.host_id == "WS-WIN11-01"
    assert alert.severity == "high"


def test_ground_truth_v1_valid():
    """Verify GroundTruthV1 remains independent from diagnostic predictions."""
    gt = GroundTruthV1(
        ground_truth_id="GT-001",
        run_id="RUN-001",
        expected_diagnostic_category=DiagnosticCategory.PASS,
        verification_method="manual_inspection",
        injected_fault_type=None,
    )
    assert gt.ground_truth_id == "GT-001"
    assert gt.expected_diagnostic_category == DiagnosticCategory.PASS
    assert gt.verification_method == "manual_inspection"


