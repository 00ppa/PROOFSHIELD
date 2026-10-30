"""Campaign assurance intelligence, metric models, and regression analysis schemas.

Phase 17 domain schemas defining:
- Versioned campaign assurance reports (CampaignAssuranceReportV1)
- Explicit detection assurance metrics with defined numerators, denominators, and statuses
- Diagnostic category distribution aggregations
- Cryptographic evidence quality and manifest verification results
- Regression intelligence findings, severities, and compatibility assessments
- Structured root-cause patterns distinguishing observed facts from inferred explanations
"""

from datetime import datetime, timezone
from enum import Enum
import math
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import Field, field_validator, model_validator

from proofshield.schemas.campaign import RootCauseGroupV1
from proofshield.schemas.common import (
    DiagnosticCategory,
    FailureCategory,
    ProofshieldBaseModel,
    validate_nesting_depth,
)


class MetricStatus(str, Enum):
    """Operational status of an assurance metric calculation."""
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class AssuranceMetricV1(ProofshieldBaseModel):
    """Deterministic, auditable metric value with explicit numerator and denominator."""

    name: str = Field(..., description="Canonical metric identifier")
    numerator: int = Field(..., ge=0, description="Numerator count")
    denominator: int = Field(..., ge=0, description="Denominator count")
    value: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Computed metric proportion between 0.0 and 1.0 (None if denominator is 0)",
    )
    status: MetricStatus = Field(
        default=MetricStatus.AVAILABLE,
        description="Calculation status: AVAILABLE, UNAVAILABLE, or INSUFFICIENT_DATA",
    )
    description: str = Field(..., description="Formal definition and meaning of the metric")
    formula: str = Field(..., description="Mathematical representation of numerator / denominator")
    notes: Optional[str] = Field(default=None, description="Contextual explanation if unavailable or edge case")

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            try:
                v_float = float(v)
            except (ValueError, TypeError) as err:
                raise ValueError(f"Invalid numeric value: {err}") from err
            if math.isnan(v_float) or math.isinf(v_float):
                raise ValueError("Metric value cannot be NaN or Infinite.")
            # Deterministically round to 6 decimal places to prevent floating-point platform divergence
            return round(v_float, 6)
        return None

    @model_validator(mode="after")
    def _validate_status_parity(self) -> "AssuranceMetricV1":
        if self.denominator == 0:
            if self.value is not None:
                raise ValueError(f"Metric '{self.name}' has zero denominator but non-null value {self.value}")
            if self.status == MetricStatus.AVAILABLE:
                self.status = MetricStatus.INSUFFICIENT_DATA
        elif self.value is None and self.status == MetricStatus.AVAILABLE:
            raise ValueError(f"Metric '{self.name}' marked AVAILABLE but value is None with non-zero denominator")
        return self


class DetectionAssuranceMetricsV1(ProofshieldBaseModel):
    """Suite of core detection assurance metrics with strict mathematical foundations."""

    detection_success_rate: AssuranceMetricV1 = Field(
        ...,
        description="Proportion of executed scenarios diagnosed as PASS (passed / executed)",
    )
    detection_failure_rate: AssuranceMetricV1 = Field(
        ...,
        description="Proportion of executed scenarios diagnosed with failure (failed / executed)",
    )
    telemetry_availability_rate: AssuranceMetricV1 = Field(
        ...,
        description="Proportion of executed scenarios where expected telemetry was present ((executed - missing_telemetry) / executed)",
    )
    evidence_completeness_rate: AssuranceMetricV1 = Field(
        ...,
        description="Proportion of executed scenarios with complete non-missing evidence (complete_evidence / executed)",
    )
    alert_correlation_rate: AssuranceMetricV1 = Field(
        ...,
        description="Proportion of scenarios with alert activity successfully correlated (correlated_alerts / applicable_scenarios)",
    )
    inconclusive_rate: AssuranceMetricV1 = Field(
        ...,
        description="Proportion of executed scenarios resulting in inconclusive outcomes (inconclusive / executed)",
    )
    execution_coverage: AssuranceMetricV1 = Field(
        ...,
        description="Proportion of declared campaign scenarios actually executed (executed / total_declared)",
    )


class DiagnosticDistributionV1(ProofshieldBaseModel):
    """Deterministic distribution across the seven formal diagnostic categories."""

    pass_count: int = Field(default=0, ge=0, description="Scenarios diagnosed as PASS")
    test_not_executed_count: int = Field(default=0, ge=0, description="Scenarios where test execution failed or was omitted")
    expected_telemetry_missing_count: int = Field(default=0, ge=0, description="Scenarios where required telemetry was absent")
    detection_not_triggered_count: int = Field(default=0, ge=0, description="Scenarios where rule failed to fire despite telemetry")
    alert_not_correlated_count: int = Field(default=0, ge=0, description="Scenarios where alert could not be correlated")
    inconclusive_count: int = Field(default=0, ge=0, description="Scenarios with ambiguous or contradictory evidence")
    error_count: int = Field(default=0, ge=0, description="Scenarios with evaluation or configuration errors")
    total_classified: int = Field(default=0, ge=0, description="Sum of all scenario classifications")
    distribution_percentages: Dict[str, float] = Field(
        default_factory=dict,
        description="Normalized percentage distribution (0.0 - 100.0) per category",
    )

    @field_validator("distribution_percentages")
    @classmethod
    def _validate_percentages(cls, v: Dict[str, float]) -> Dict[str, float]:
        for k, pct in v.items():
            if math.isnan(pct) or math.isinf(pct):
                raise ValueError(f"Distribution percentage for {k} cannot be NaN or Infinite.")
        return {k: round(pct, 2) for k, pct in v.items()}


class EvidenceVerificationStatus(str, Enum):
    """Formal verification state of evidence records and manifests."""
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    INTEGRITY_COMPROMISED = "INTEGRITY_COMPROMISED"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    MANIFEST_ABSENT = "MANIFEST_ABSENT"


class EvidenceQualityV1(ProofshieldBaseModel):
    """Audit assessment of evidence completeness and cryptographic integrity."""

    total_evidence_records: int = Field(..., ge=0, description="Total distinct evidence records indexed")
    manifest_verification_status: EvidenceVerificationStatus = Field(
        ...,
        description="Verification outcome of evidence manifest against stored entity hashes",
    )
    missing_evidence_references: List[str] = Field(
        default_factory=list,
        description="IDs of referenced events or alerts missing from underlying store",
    )
    invalid_evidence_references: List[str] = Field(
        default_factory=list,
        description="Malformed or invalid evidence references",
    )
    integrity_verification_failures: List[str] = Field(
        default_factory=list,
        description="IDs of records whose canonical hash mismatched stored manifest hash",
    )
    is_complete: bool = Field(..., description="True if all evidence references exist and hashes match")
    notes: List[str] = Field(default_factory=list, description="Observations regarding evidence quality")


class ExecutionSummaryV1(ProofshieldBaseModel):
    """High-level summary of campaign scenario execution outcomes."""

    campaign_id: str = Field(..., description="Referenced campaign identifier")
    campaign_name: str = Field(..., description="Campaign display name")
    campaign_run_id: str = Field(..., description="Referenced campaign run identifier")
    total_scenarios: int = Field(..., ge=0, description="Total declared scenarios in campaign")
    executed_test_cases: int = Field(..., ge=0, description="Number of scenarios executed against test runs")
    unexecuted_cases: int = Field(..., ge=0, description="Number of scenarios unexecuted or skipped")
    successful_executions: int = Field(..., ge=0, description="Scenarios evaluated with status PASS")
    failed_executions: int = Field(..., ge=0, description="Scenarios evaluated with status FAILURE")
    error_executions: int = Field(..., ge=0, description="Scenarios evaluated with status ERROR")
    inconclusive_executions: int = Field(..., ge=0, description="Scenarios evaluated with status INCONCLUSIVE")
    skipped_executions: int = Field(default=0, ge=0, description="Scenarios with status SKIPPED")


class CampaignAssuranceReportV1(ProofshieldBaseModel):
    """Versioned, auditable campaign assurance report.

    Aggregates verifiable evidence and diagnostics from an executed campaign run
    without re-executing payloads or modifying underlying records.
    """

    schema_version: Literal["v1"] = "v1"
    report_id: str = Field(
        ...,
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        description="Unique report identifier (e.g. RPT-CPG-20261031-ABCD)",
    )
    campaign_id: str = Field(..., description="Referenced campaign identifier")
    campaign_run_id: str = Field(..., description="Referenced campaign run identifier")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp (UTC) when report was compiled",
    )
    engine_version: str = Field(default="v1.0.0", description="Assurance engine version")
    execution_summary: ExecutionSummaryV1 = Field(..., description="Scenario execution count summary")
    assurance_metrics: DetectionAssuranceMetricsV1 = Field(..., description="Calculated assurance metrics")
    diagnostic_distribution: DiagnosticDistributionV1 = Field(..., description="Distribution of 7 diagnostic categories")
    evidence_quality: EvidenceQualityV1 = Field(..., description="Evidence completeness and cryptographic verification")
    root_cause_analysis: List[RootCauseGroupV1] = Field(
        default_factory=list,
        description="Structured root-cause diagnostic groupings",
    )
    is_complete: bool = Field(..., description="True if campaign has no unexecuted cases and evidence is intact")
    report_digest: str = Field(
        ...,
        description="Canonical SHA-256 digest computed over deterministic report contents",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional execution and environment metadata",
    )

    @field_validator("metadata")
    @classmethod
    def _validate_meta_depth(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        validate_nesting_depth(v, max_depth=16)
        return v


# ── Regression Intelligence Models ──────────────────────────────────────────

class FindingCategory(str, Enum):
    """Classification category for regression and comparative findings."""
    DETECTION_REGRESSION = "DETECTION_REGRESSION"
    DETECTION_IMPROVEMENT = "DETECTION_IMPROVEMENT"
    METRIC_DETERIORATION = "METRIC_DETERIORATION"
    METRIC_IMPROVEMENT = "METRIC_IMPROVEMENT"
    TELEMETRY_GAP_INCREASE = "TELEMETRY_GAP_INCREASE"
    ALERT_CORRELATION_DETERIORATION = "ALERT_CORRELATION_DETERIORATION"
    INCONCLUSIVE_RATE_INCREASE = "INCONCLUSIVE_RATE_INCREASE"
    EVIDENCE_COMPLETENESS_DETERIORATION = "EVIDENCE_COMPLETENESS_DETERIORATION"
    EXECUTION_ERROR_INCREASE = "EXECUTION_ERROR_INCREASE"
    SCENARIO_SET_CHANGE = "SCENARIO_SET_CHANGE"
    ENVIRONMENT_DRIFT = "ENVIRONMENT_DRIFT"


class FindingSeverity(str, Enum):
    """Severity classification of comparative findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RegressionVerdict(str, Enum):
    """High-level verdict of comparative regression analysis."""
    REGRESSION = "REGRESSION"
    IMPROVEMENT = "IMPROVEMENT"
    NO_CHANGE = "NO_CHANGE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    INCOMPARABLE = "INCOMPARABLE"


class RegressionFindingV1(ProofshieldBaseModel):
    """Deterministic comparative finding between baseline and candidate campaigns."""

    finding_id: str = Field(..., description="Unique finding identifier (e.g. FND-001)")
    category: FindingCategory = Field(..., description="Category of finding")
    severity: FindingSeverity = Field(..., description="Assessed severity level")
    affected_target: str = Field(..., description="Identifier of affected scenario, metric, or subsystem")
    baseline_value: Any = Field(..., description="Recorded value or status in baseline campaign")
    candidate_value: Any = Field(..., description="Recorded value or status in candidate campaign")
    difference: Any = Field(..., description="Mathematical delta or categorical transition")
    supporting_evidence_references: List[str] = Field(
        default_factory=list,
        description="Evidence and diagnostic references substantiating finding",
    )
    explanation: str = Field(..., description="Deterministic, evidence-grounded explanation")
    is_actionable: bool = Field(..., description="Whether finding requires mitigation or is informational")


class CampaignCompatibilityV1(ProofshieldBaseModel):
    """Assessment of comparability between two campaign executions."""

    is_compatible: bool = Field(..., description="Whether campaigns can be validly compared")
    verdict: str = Field(
        ...,
        description="Compatibility verdict: COMPATIBLE, INSUFFICIENT_DATA, INCOMPATIBLE_SCENARIOS, ENGINE_DRIFT, CONFIG_DRIFT, ENVIRONMENT_DRIFT",
    )
    baseline_scenario_count: int = Field(..., ge=0, description="Scenario count in baseline")
    candidate_scenario_count: int = Field(..., ge=0, description="Scenario count in candidate")
    common_scenario_count: int = Field(..., ge=0, description="Count of overlapping scenarios")
    added_scenarios: List[str] = Field(default_factory=list, description="Scenarios in candidate but not baseline")
    removed_scenarios: List[str] = Field(default_factory=list, description="Scenarios in baseline but not candidate")
    engine_version_baseline: str = Field(..., description="Engine version of baseline run")
    engine_version_candidate: str = Field(..., description="Engine version of candidate run")
    config_drift_detected: bool = Field(default=False, description="Whether execution configuration differed")
    reasons: List[str] = Field(default_factory=list, description="Detailed compatibility explanations")


class CampaignRegressionAnalysisV1(ProofshieldBaseModel):
    """Comprehensive comparative regression intelligence report."""

    schema_version: Literal["v1"] = "v1"
    analysis_id: str = Field(
        ...,
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        description="Unique regression analysis identifier (e.g. REG-20261031-ABCD)",
    )
    baseline_run_id: str = Field(..., description="Baseline campaign run identifier")
    candidate_run_id: str = Field(..., description="Candidate campaign run identifier")
    campaign_id: str = Field(..., description="Evaluated campaign identifier")
    verdict: RegressionVerdict = Field(..., description="Overall comparative verdict")
    compatibility: CampaignCompatibilityV1 = Field(..., description="Compatibility audit between runs")
    findings: List[RegressionFindingV1] = Field(
        default_factory=list,
        description="Detailed list of comparative findings in descending severity order",
    )
    summary_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Breakdown of finding counts by severity (critical, high, medium, low, informational)",
    )
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp (UTC) when regression analysis was performed",
    )
    analysis_digest: str = Field(
        ...,
        description="Canonical SHA-256 digest of deterministic comparative analysis content",
    )


# ── Root Cause Intelligence Models ──────────────────────────────────────────

class RootCausePatternV1(ProofshieldBaseModel):
    """Structured root-cause pattern grouping related diagnostic failures."""

    pattern_id: str = Field(..., description="Unique pattern identifier (e.g. PAT-TELEMETRY-MISSING-01)")
    diagnostic_category: DiagnosticCategory = Field(..., description="Underlying diagnostic category")
    failure_category: Optional[FailureCategory] = Field(default=None, description="Detailed failure category if applicable")
    affected_scenario_count: int = Field(..., ge=1, description="Number of scenarios exhibiting this pattern")
    affected_scenarios: List[str] = Field(..., min_length=1, description="Scenario IDs affected")
    common_evidence_gaps: List[str] = Field(
        default_factory=list,
        description="Identified common gaps (e.g. missing Sysmon EventID 1, missing alert)",
    )
    supporting_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Sample supporting event/alert IDs verifying pattern",
    )
    observed_facts: List[str] = Field(
        ...,
        min_length=1,
        description="Empirical facts directly observed from recorded evidence and diagnostics",
    )
    inferred_explanations: List[str] = Field(
        default_factory=list,
        description="Plausible engineering explanations (clearly demarcated as inferences, not proven causes)",
    )
    confidence: str = Field(
        "definitive",
        description="Confidence level in pattern diagnosis: definitive, likely, or uncertain",
    )


class RootCauseIntelligenceV1(ProofshieldBaseModel):
    """Aggregated cross-scenario root cause intelligence for a campaign execution."""

    schema_version: Literal["v1"] = "v1"
    campaign_id: str = Field(..., description="Referenced campaign identifier")
    campaign_run_id: str = Field(..., description="Referenced campaign run identifier")
    total_issues_analyzed: int = Field(..., ge=0, description="Total non-PASS scenarios evaluated")
    patterns: List[RootCausePatternV1] = Field(
        default_factory=list,
        description="Discovered diagnostic and root-cause patterns",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp (UTC) when root cause analysis was produced",
    )
