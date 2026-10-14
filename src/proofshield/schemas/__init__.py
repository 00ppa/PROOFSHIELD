"""Versioned Pydantic schemas for PROOFSHIELD.

Explicitly versioned data structures ensuring strict separation between:
- Scenarios & independent ground-truth expectations
- Test runs & execution records
- Raw telemetry evidence
- Normalised telemetry events
- Detection rules & alert records
- Diagnostic evaluation results
- Ground truth labels
"""

from proofshield.schemas.alert import AlertV1
from proofshield.schemas.common import (
    DiagnosticCategory,
    DiagnosticOutcome,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    FailureCategory,
    GroundTruthLabel,
    SCHEMA_VERSION,
    ValidationTarget,
)
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.ground_truth import GroundTruthV1
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import (
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
)
from proofshield.schemas.test_run import TestRunV1

__all__ = [
    "SCHEMA_VERSION",
    "AlertV1",
    "DetectionRuleV1",
    "DiagnosticCategory",
    "DiagnosticOutcome",
    "DiagnosticResultV1",
    "EventCategory",
    "ExecutionMode",
    "ExecutionStatus",
    "FailureCategory",
    "GroundTruthLabel",
    "GroundTruthV1",
    "NormalizedTelemetryEventV1",
    "RawTelemetryEventV1",
    "ScenarioV1",
    "TestRunV1",
    "ValidationTarget",
]
