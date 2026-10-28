"""Campaign validation and auditable report domain schemas.

Defines versioned models for detection validation campaigns, campaign execution runs,
per-scenario diagnostic results, evidence manifests, root-cause groups,
deterministic comparisons, and replay integrity records.
"""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Literal, Optional
from pydantic import Field, field_validator, model_validator

from proofshield.schemas.common import (
    AttributionStatus,
    DiagnosticCategory,
    FailureCategory,
    ProofshieldBaseModel,
    validate_nesting_depth,
)


class CampaignExecutionPolicy(str, Enum):
    """Execution error-handling policy for campaign runs."""
    CONTINUE_ON_ERROR = "CONTINUE_ON_ERROR"
    STOP_ON_ERROR = "STOP_ON_ERROR"


class CampaignRunStatus(str, Enum):
    """Lifecycle status of a campaign run."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
    FAILED = "FAILED"


class ScenarioRunStatus(str, Enum):
    """Execution status of an individual scenario within a campaign."""
    PASS = "PASS"
    FAILURE = "FAILURE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class ReplayClassification(str, Enum):
    """Formal classification of a campaign replay execution."""
    EXACT_REPLAY = "EXACT_REPLAY"
    EVIDENCE_REEVALUATION = "EVIDENCE_REEVALUATION"
    ENGINE_COMPARISON = "ENGINE_COMPARISON"
    INVALID_MANIFEST = "INVALID_MANIFEST"


class CampaignExecutionConfigV1(ProofshieldBaseModel):
    """Execution configuration for a detection validation campaign."""

    execution_policy: CampaignExecutionPolicy = Field(
        default=CampaignExecutionPolicy.CONTINUE_ON_ERROR,
        description="Policy governing whether execution halts on first scenario error or continues",
    )
    strict_attribution: Optional[bool] = Field(
        default=None,
        description="Opt-in strict token attribution requiring execution token provenance for all scenarios",
    )
    default_alert_grace_period_seconds: int = Field(
        default=3600,
        ge=0,
        le=86400,
        description="Alert correlation grace period in seconds (default 3600)",
    )
    max_scenario_count: int = Field(
        default=500,
        ge=1,
        le=5000,
        description="Upper boundary on allowable scenario count per campaign run",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary execution parameters and tags",
    )

    @field_validator("metadata")
    @classmethod
    def _validate_meta_depth(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        validate_nesting_depth(v, max_depth=16)
        return v


class CampaignDefinitionV1(ProofshieldBaseModel):
    """Detection validation campaign definition (Schema Version 1).

    Declares an ordered collection of validation scenarios to be evaluated as a coherent suite.
    Must not contain arbitrary code, shell commands, or unrestricted plugin definitions.
    """

    schema_version: Literal["v1"] = "v1"
    campaign_id: str = Field(
        ...,
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        description="Stable campaign identifier (e.g. CPG-LINUX-PERSISTENCE-01)",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Human-readable campaign title",
    )
    description: str = Field(
        default="",
        max_length=4096,
        description="Description of the campaign purpose and threat model",
    )
    scenario_ids: List[str] = Field(
        ...,
        min_length=1,
        description="Ordered list of scenario references to evaluate",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Optional categorization tags",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp (UTC) when the campaign was created",
    )
    execution_config: CampaignExecutionConfigV1 = Field(
        default_factory=CampaignExecutionConfigV1,
        description="Campaign execution settings and error handling policy",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional campaign metadata",
    )

    @field_validator("scenario_ids")
    @classmethod
    def _validate_scenarios(cls, scenario_ids: List[str]) -> List[str]:
        if not scenario_ids:
            raise ValueError("Campaign must specify at least one scenario identifier.")
        if len(scenario_ids) > 500:
            raise ValueError(f"Campaign scenario count ({len(scenario_ids)}) exceeds maximum allowed (500).")
        seen = set()
        duplicates = []
        for s in scenario_ids:
            s_clean = s.strip()
            if not s_clean:
                raise ValueError("Scenario identifier cannot be empty or whitespace.")
            if s_clean in seen:
                duplicates.append(s_clean)
            seen.add(s_clean)
        if duplicates:
            raise ValueError(f"Duplicate scenario identifiers in campaign definition: {sorted(set(duplicates))}")
        return scenario_ids

    @field_validator("metadata")
    @classmethod
    def _validate_meta_depth(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        validate_nesting_depth(v, max_depth=16)
        return v

    @model_validator(mode="after")
    def _validate_safe_content(self) -> "CampaignDefinitionV1":
        # Disallow executable command injection keywords in strings
        dangerous_patterns = [
            r"__import__",
            r"os\.system",
            r"subprocess\.",
            r"/bin/sh",
            r"powershell\s+-enc",
        ]
        content_to_check = f"{self.name} {self.description} {json_str_if_any(self.metadata)}"
        for pat in dangerous_patterns:
            if re.search(pat, content_to_check, re.IGNORECASE):
                raise ValueError(f"Potentially hazardous or executable instruction pattern detected: {pat}")
        return self


def json_str_if_any(val: Any) -> str:
    try:
        import json
        return json.dumps(val)
    except Exception:
        return str(val)


class ScenarioCampaignResultV1(ProofshieldBaseModel):
    """Detailed result of an individual scenario execution within a campaign run."""

    scenario_id: str = Field(..., description="Scenario identifier evaluated")
    execution_order: int = Field(..., ge=0, description="0-indexed execution order within the campaign")
    test_run_id: Optional[str] = Field(None, description="Evaluated test run identifier if executed")
    diagnostic_id: Optional[str] = Field(None, description="Diagnostic result record identifier if evaluated")
    predicted_category: Optional[DiagnosticCategory] = Field(
        None,
        description="Primary diagnostic classification computed by the assurance engine",
    )
    failure_category: Optional[FailureCategory] = Field(
        None,
        description="Root-cause classification of failure or pipeline latency",
    )
    status: ScenarioRunStatus = Field(
        ...,
        description="Scenario outcome status within campaign (PASS, FAILURE, INCONCLUSIVE, ERROR, SKIPPED)",
    )
    confidence: str = Field(
        "definitive",
        description="Diagnostic confidence: definitive, likely, or uncertain",
    )
    reason: str = Field(..., min_length=1, description="Deterministic justification for verdict")
    diagnostic_reasons: List[str] = Field(
        default_factory=list,
        description="Additional diagnostic observations",
    )
    supporting_evidence_ids: List[str] = Field(
        default_factory=list,
        description="IDs of events and alerts supporting the result",
    )
    contradictory_evidence_ids: List[str] = Field(
        default_factory=list,
        description="IDs of events contradicting the result",
    )
    checks_performed: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Validation checks performed during evaluation",
    )
    alternative_eliminations: Dict[str, str] = Field(
        default_factory=dict,
        description="Explanations why alternative diagnostic categories were eliminated",
    )
    missing_evidence: bool = Field(
        default=False,
        description="Whether verdict was driven by missing evidence",
    )
    attribution_status: Optional[AttributionStatus] = Field(
        default=None,
        description="Attribution status for test run and evidence",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error detail string if execution or resolution failed",
    )
    error_classification: Optional[str] = Field(
        default=None,
        description="Error category (e.g. SCENARIO_NOT_FOUND, TEST_NOT_EXECUTED, EVALUATION_ERROR)",
    )


class CampaignSummaryV1(ProofshieldBaseModel):
    """Aggregated statistical summary of a campaign execution run."""

    total_scenarios: int = Field(..., ge=0, description="Total declared scenarios in campaign definition")
    executed_scenarios: int = Field(..., ge=0, description="Number of scenarios actually evaluated against test runs")
    unexecuted_scenarios: int = Field(..., ge=0, description="Number of scenarios not executed (missing run or skipped)")
    passed_scenarios: int = Field(..., ge=0, description="Scenarios diagnosed with DiagnosticCategory.PASS")
    failed_scenarios: int = Field(..., ge=0, description="Scenarios diagnosed with a failure category")
    inconclusive_scenarios: int = Field(..., ge=0, description="Scenarios with INCONCLUSIVE outcome")
    error_scenarios: int = Field(..., ge=0, description="Scenarios with ERROR outcome or evaluation exception")
    category_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Counts grouped by DiagnosticCategory value",
    )
    pass_rate: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Pass rate: passed_scenarios / executed_scenarios (None if executed_scenarios == 0)",
    )
    execution_coverage: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Coverage: executed_scenarios / total_scenarios (0.0 if total_scenarios == 0)",
    )
    inconclusive_rate: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Inconclusive rate: inconclusive_scenarios / executed_scenarios (None if executed_scenarios == 0)",
    )
    error_rate: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Error rate: error_scenarios / total_scenarios",
    )
    evidence_completeness: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Proportion of evaluated scenarios with complete evidence (not missing_evidence)",
    )
    precision: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Precision relative to verified independent ground truth (None if ground truth unavailable)",
    )
    recall: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Recall relative to verified independent ground truth (None if ground truth unavailable)",
    )
    f1: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="F1 score relative to verified independent ground truth (None if ground truth unavailable)",
    )
    metrics_notes: List[str] = Field(
        default_factory=list,
        description="Explanations of metric denominators, ground-truth availability, and undefined rates",
    )


class ScenarioEvidenceRefV1(ProofshieldBaseModel):
    """Manifest record referencing the exact evidence items contributing to a scenario result."""

    scenario_id: str = Field(..., description="Referenced scenario ID")
    scenario_hash: str = Field(..., description="Canonical SHA-256 hash of the ScenarioV1 definition")
    test_run_id: Optional[str] = Field(None, description="Referenced TestRunV1 ID")
    test_run_hash: Optional[str] = Field(None, description="Canonical SHA-256 hash of the TestRunV1 record")
    telemetry_event_ids: List[str] = Field(
        default_factory=list,
        description="Normalized telemetry event IDs correlated to the scenario",
    )
    telemetry_event_hashes: Dict[str, str] = Field(
        default_factory=dict,
        description="Canonical SHA-256 hashes of normalized telemetry events (event_id -> hash)",
    )
    alert_ids: List[str] = Field(
        default_factory=list,
        description="Alert IDs correlated to the scenario",
    )
    alert_hashes: Dict[str, str] = Field(
        default_factory=dict,
        description="Canonical SHA-256 hashes of alerts (alert_id -> hash)",
    )
    ground_truth_id: Optional[str] = Field(
        default=None,
        description="GroundTruthV1 ID if independent ground truth exists",
    )
    ground_truth_hash: Optional[str] = Field(
        default=None,
        description="Canonical SHA-256 hash of GroundTruthV1 record if present",
    )
    diagnostic_id: Optional[str] = Field(
        default=None,
        description="DiagnosticResultV1 ID produced by evaluation",
    )


class EvidenceManifestV1(ProofshieldBaseModel):
    """Immutable evidence manifest establishing cryptographic integrity of inputs for a campaign run."""

    manifest_version: Literal["v1"] = "v1"
    campaign_id: str = Field(..., description="Referenced campaign ID")
    campaign_run_id: str = Field(..., description="Referenced campaign run ID")
    canonical_hash_algorithm: Literal["sha256"] = "sha256"
    execution_config_hash: Optional[str] = Field(
        default=None,
        description="Canonical SHA-256 hash of execution configuration settings",
    )
    execution_config_snapshot: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Snapshot of execution configuration settings",
    )
    manifest_hash: str = Field(
        ...,
        description="Canonical SHA-256 hash of all referenced scenario evidence records and configuration",
    )
    scenario_references: List[ScenarioEvidenceRefV1] = Field(
        default_factory=list,
        description="Ordered list of scenario evidence references",
    )
    total_evidence_count: int = Field(
        default=0,
        ge=0,
        description="Total distinct evidence items (events + alerts) indexed in manifest",
    )
    engine_version: str = Field(
        default="v0.1.0",
        description="Version of the assurance engine used for evaluation",
    )
    schema_version: str = Field(
        default="v1",
        description="Platform schema version",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp (UTC) when manifest was generated",
    )


class RootCauseGroupV1(ProofshieldBaseModel):
    """Deterministic grouping of failed or inconclusive scenarios by shared diagnostic cause."""

    root_cause_category: str = Field(
        ...,
        description="Normalized root-cause category (e.g. MISSING_EXPECTED_TELEMETRY, DETECTION_RULE_DID_NOT_TRIGGER)",
    )
    scenario_count: int = Field(..., ge=1, description="Number of scenarios exhibiting this diagnostic cause")
    scenario_ids: List[str] = Field(..., min_length=1, description="Scenarios in this group")
    supporting_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Sample supporting evidence IDs across the affected scenarios",
    )
    explanation: str = Field(..., description="Deterministic, evidence-grounded summary of the root cause")
    confidence: str = Field("definitive", description="Confidence level: definitive or uncertain")


class CampaignRunV1(ProofshieldBaseModel):
    """Executed campaign run record preserving evidence, diagnostics, and deterministic summary."""

    schema_version: Literal["v1"] = "v1"
    run_id: str = Field(
        ...,
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        description="Unique campaign run identifier (e.g. CRUN-20261029-ABCD12)",
    )
    campaign_id: str = Field(..., description="Referenced campaign definition ID")
    campaign_version: str = Field("v1", description="Campaign schema version")
    status: CampaignRunStatus = Field(..., description="Execution status of the campaign run")
    started_at: datetime = Field(..., description="Timestamp (UTC) when execution commenced")
    completed_at: Optional[datetime] = Field(None, description="Timestamp (UTC) when execution completed")
    total_scenarios: int = Field(..., ge=0, description="Total scenario count")
    scenario_results: List[ScenarioCampaignResultV1] = Field(
        default_factory=list,
        description="Per-scenario execution and diagnostic results in declared order",
    )
    summary: CampaignSummaryV1 = Field(..., description="Aggregate summary metrics")
    evidence_manifest: EvidenceManifestV1 = Field(..., description="Canonical evidence manifest")
    root_cause_analysis: List[RootCauseGroupV1] = Field(
        default_factory=list,
        description="Deterministic groupings of failures by underlying root cause",
    )
    errors: List[str] = Field(default_factory=list, description="Campaign-level errors encountered")
    warnings: List[str] = Field(default_factory=list, description="Campaign-level warnings or anomalies")
    is_replay: bool = Field(default=False, description="Whether this run was generated via replay")
    source_run_id: Optional[str] = Field(default=None, description="Source run ID if this is a replay")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Execution environment and run metadata")


class ScenarioRegressionV1(ProofshieldBaseModel):
    """Recorded outcome shift for an individual scenario between two campaign runs."""

    scenario_id: str = Field(..., description="Scenario identifier")
    previous_category: Optional[DiagnosticCategory] = Field(None, description="Category in baseline run")
    current_category: Optional[DiagnosticCategory] = Field(None, description="Category in compared run")
    previous_status: ScenarioRunStatus = Field(..., description="Status in baseline run")
    current_status: ScenarioRunStatus = Field(..., description="Status in compared run")
    transition_type: str = Field(
        ...,
        description="Transition classification: REGRESSION, IMPROVEMENT, INCONCLUSIVE_SHIFT, UNCHANGED, ADDED, REMOVED",
    )
    reason: str = Field(..., description="Deterministic explanation of the transition")


class CampaignComparisonV1(ProofshieldBaseModel):
    """Deterministic comparison report between two campaign runs."""

    comparison_id: str = Field(..., description="Unique comparison identifier")
    base_run_id: str = Field(..., description="Baseline campaign run ID")
    target_run_id: str = Field(..., description="Target campaign run ID")
    campaign_id: str = Field(..., description="Campaign ID evaluated")
    is_equivalent_campaign: bool = Field(
        ...,
        description="True if both runs evaluated the exact same ordered list of scenarios",
    )
    is_equivalent_evidence: bool = Field(
        ...,
        description="True if both runs evaluated identical evidence manifests (matching manifest_hash)",
    )
    comparison_verdict: str = Field(
        ...,
        description="Overall verdict: IDENTICAL, REGRESSION, IMPROVEMENT, DIVERGENT_INPUTS, MIXED",
    )
    regressions: List[ScenarioRegressionV1] = Field(
        default_factory=list,
        description="Scenarios that regressed from PASS to failure, inconclusive, or error",
    )
    improvements: List[ScenarioRegressionV1] = Field(
        default_factory=list,
        description="Scenarios that improved from failure, inconclusive, or error to PASS",
    )
    inconclusive_transitions: List[ScenarioRegressionV1] = Field(
        default_factory=list,
        description="Scenarios transitioning into or out of INCONCLUSIVE",
    )
    added_scenarios: List[str] = Field(
        default_factory=list,
        description="Scenarios present in target run but absent in baseline run",
    )
    removed_scenarios: List[str] = Field(
        default_factory=list,
        description="Scenarios present in baseline run but absent in target run",
    )
    metric_deltas: Dict[str, Optional[float]] = Field(
        default_factory=dict,
        description="Numerical deltas between baseline and target summary metrics",
    )
    evidence_changes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detailed diff of evidence items between baseline and target",
    )
    attribution_changes: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Changes in attribution status per scenario",
    )
    explanations: List[str] = Field(
        default_factory=list,
        description="Deterministic analysis explaining observed differences",
    )
    compared_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp (UTC) when comparison was generated",
    )


class CampaignReplayResultV1(ProofshieldBaseModel):
    """Outcome of replaying a recorded campaign run against preserved evidence."""

    replay_run: CampaignRunV1 = Field(..., description="Newly generated replay campaign run record")
    source_run: CampaignRunV1 = Field(..., description="Original historical campaign run record (preserved)")
    comparison: CampaignComparisonV1 = Field(..., description="Deterministic comparison between original and replay")
    is_exact_replay: bool = Field(..., description="True if evidence manifests, environment, and results match 100%")
    replay_classification: ReplayClassification = Field(
        default=ReplayClassification.EXACT_REPLAY,
        description="Formal classification: EXACT_REPLAY, EVIDENCE_REEVALUATION, ENGINE_COMPARISON, or INVALID_MANIFEST",
    )
    manifest_valid: bool = Field(
        default=True,
        description="True if source evidence manifest passed cryptographic internal hash verification",
    )
    missing_evidence: List[str] = Field(
        default_factory=list,
        description="Evidence items referenced in original run that could not be resolved in store",
    )
    altered_evidence: List[str] = Field(
        default_factory=list,
        description="Evidence items whose canonical hashes differ from original manifest",
    )
    verdict: str = Field(..., description="Replay verdict: EXACT_REPLAY, PARTIAL_REPLAY, or INVALID_REPLAY")
    disclaimer: str = Field(
        default=(
            "Replay verifies deterministic evaluation reproducibility against captured evidence; "
            "it does not re-execute offensive payloads or contact external targets."
        ),
        description="Explicit scope disclaimer",
    )
