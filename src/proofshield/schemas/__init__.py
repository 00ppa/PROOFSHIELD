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
    AttributionStatus,
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
from proofshield.schemas.campaign import (
    CampaignComparisonV1,
    CampaignDefinitionV1,
    CampaignExecutionConfigV1,
    CampaignExecutionPolicy,
    CampaignReplayResultV1,
    CampaignRunStatus,
    CampaignRunV1,
    CampaignSummaryV1,
    EvidenceManifestV1,
    ReplayClassification,
    RootCauseGroupV1,
    ScenarioCampaignResultV1,
    ScenarioEvidenceRefV1,
    ScenarioRegressionV1,
    ScenarioRunStatus,
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
    "AttributionStatus",
    "CampaignComparisonV1",
    "CampaignDefinitionV1",
    "CampaignExecutionConfigV1",
    "CampaignExecutionPolicy",
    "CampaignReplayResultV1",
    "CampaignRunStatus",
    "CampaignRunV1",
    "CampaignSummaryV1",
    "DetectionRuleV1",
    "DiagnosticCategory",
    "DiagnosticOutcome",
    "DiagnosticResultV1",
    "EventCategory",
    "EvidenceManifestV1",
    "ExecutionMode",
    "ExecutionStatus",
    "FailureCategory",
    "GroundTruthLabel",
    "GroundTruthV1",
    "NormalizedTelemetryEventV1",
    "RawTelemetryEventV1",
    "ReplayClassification",
    "RootCauseGroupV1",
    "ScenarioCampaignResultV1",
    "ScenarioEvidenceRefV1",
    "ScenarioRegressionV1",
    "ScenarioRunStatus",
    "ScenarioV1",
    "TestRunV1",
    "ValidationTarget",
]
