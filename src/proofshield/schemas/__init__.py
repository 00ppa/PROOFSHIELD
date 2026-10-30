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
from proofshield.schemas.assurance_report import (
    AssuranceMetricV1,
    CampaignAssuranceReportV1,
    CampaignCompatibilityV1,
    CampaignRegressionAnalysisV1,
    DetectionAssuranceMetricsV1,
    DiagnosticDistributionV1,
    EvidenceQualityV1,
    EvidenceVerificationStatus,
    ExecutionSummaryV1,
    FindingCategory,
    FindingSeverity,
    MetricStatus,
    RegressionFindingV1,
    RegressionVerdict,
    RootCauseIntelligenceV1,
    RootCausePatternV1,
)
from proofshield.schemas.test_run import TestRunV1

__all__ = [
    "SCHEMA_VERSION",
    "AlertV1",
    "AssuranceMetricV1",
    "AttributionStatus",
    "CampaignAssuranceReportV1",
    "CampaignComparisonV1",
    "CampaignCompatibilityV1",
    "CampaignDefinitionV1",
    "CampaignExecutionConfigV1",
    "CampaignExecutionPolicy",
    "CampaignRegressionAnalysisV1",
    "CampaignReplayResultV1",
    "CampaignRunStatus",
    "CampaignRunV1",
    "CampaignSummaryV1",
    "DetectionAssuranceMetricsV1",
    "DetectionRuleV1",
    "DiagnosticCategory",
    "DiagnosticDistributionV1",
    "DiagnosticOutcome",
    "DiagnosticResultV1",
    "EventCategory",
    "EvidenceManifestV1",
    "EvidenceQualityV1",
    "EvidenceVerificationStatus",
    "ExecutionMode",
    "ExecutionStatus",
    "ExecutionSummaryV1",
    "FailureCategory",
    "FindingCategory",
    "FindingSeverity",
    "GroundTruthLabel",
    "GroundTruthV1",
    "MetricStatus",
    "NormalizedTelemetryEventV1",
    "RawTelemetryEventV1",
    "RegressionFindingV1",
    "RegressionVerdict",
    "ReplayClassification",
    "RootCauseGroupV1",
    "RootCauseIntelligenceV1",
    "RootCausePatternV1",
    "ScenarioCampaignResultV1",
    "ScenarioEvidenceRefV1",
    "ScenarioRegressionV1",
    "ScenarioRunStatus",
    "ScenarioV1",
    "TestRunV1",
    "ValidationTarget",
]
