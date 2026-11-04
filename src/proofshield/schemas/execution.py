"""Execution runner and evidence schemas for PROOFSHIELD Phase 20."""

from datetime import datetime, timezone
from enum import Enum
import platform
from typing import Any, Dict, List, Literal, Optional
from pydantic import Field, field_validator

from proofshield.schemas.common import (
    EventCategory,
    ProofshieldBaseModel,
    validate_nesting_depth,
)


class RunnerExecutionState(str, Enum):
    """Lifecycle state of an endpoint execution attempt."""
    CREATED = "CREATED"
    VALIDATED = "VALIDATED"
    AUTHORIZED = "AUTHORIZED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class ActionDescriptorV1(ProofshieldBaseModel):
    """Metadata describing an approved registered benign execution action."""
    schema_version: Literal["v1"] = "v1"
    action_id: str = Field(..., min_length=3, description="Stable unique identifier of the registered action")
    version: str = Field("1.0.0", description="Semantic version of the action definition")
    name: str = Field(..., min_length=1, description="Human-readable title of the action")
    description: str = Field(..., description="Summary of action intent and expected observable behaviour")
    supported_platforms: List[str] = Field(default_factory=list, description="Supported operating systems (windows, linux, darwin)")
    expected_observable_category: EventCategory = Field(..., description="Expected primary security telemetry category")
    max_timeout_seconds: float = Field(30.0, gt=0, le=300.0, description="Strict upper bound on execution duration")
    parameter_schema: Dict[str, Any] = Field(default_factory=dict, description="JSON schema describing accepted input parameters")
    cleanup_policy: str = Field("AUTOMATIC_WORKSPACE_CLEANUP", description="Policy governing workspace and artifact cleanup")


class ExecutionRequestV1(ProofshieldBaseModel):
    """Request payload to initiate a controlled benign execution."""
    schema_version: Literal["v1"] = "v1"
    action_id: str = Field(..., min_length=3, description="Registered action identifier to execute")
    scenario_id: Optional[str] = Field(None, description="Optional referenced scenario identifier")
    campaign_id: Optional[str] = Field(None, description="Optional referenced campaign identifier")
    action_parameters: Dict[str, Any] = Field(default_factory=dict, description="Validated parameters for the action")
    target_host: Optional[str] = Field(None, description="Target host identifier (defaults to local host if omitted)")
    target_user: Optional[str] = Field(None, description="Target user context (defaults to current user if omitted)")
    execution_token: Optional[str] = Field(None, description="Optional explicit token; auto-generated if omitted")
    timeout_seconds: Optional[float] = Field(None, gt=0, le=300.0, description="Execution timeout override, bounded by action max_timeout")
    dry_run: bool = Field(False, description="If True, validates authorization and parameters without running action")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary execution metadata")

    @field_validator("metadata", "action_parameters")
    @classmethod
    def _validate_meta_depth(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if v:
            validate_nesting_depth(v, max_depth=16)
        return v


class ExecutionValidationResultV1(ProofshieldBaseModel):
    """Validation report returned before or during controlled execution."""
    schema_version: Literal["v1"] = "v1"
    action_id: str
    action_version: Optional[str] = None
    is_valid: bool = False
    authorized: bool = False
    supported_platform: bool = False
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    expected_observable_category: Optional[EventCategory] = None
    validated_parameters: Dict[str, Any] = Field(default_factory=dict)


class ExecutionEvidenceV1(ProofshieldBaseModel):
    """Immutable execution evidence record capturing endpoint action details (Schema Version 1).

    Provides complete, tamper-auditable provenance separating actual endpoint execution
    from subsequent telemetry observation, alert generation, and diagnostic evaluation.
    """
    schema_version: Literal["v1"] = "v1"
    execution_id: str = Field(..., min_length=3, description="Unique execution attempt identifier")
    scenario_id: Optional[str] = Field(None, description="Referenced scenario identifier")
    test_run_id: Optional[str] = Field(None, description="Referenced TestRunV1 identifier")
    campaign_id: Optional[str] = Field(None, description="Referenced campaign identifier")
    execution_token: str = Field(..., min_length=3, description="Deterministic token for causal attribution")
    target_host: str = Field(..., description="Target hostname or IP where action executed")
    platform: Dict[str, Any] = Field(default_factory=dict, description="OS and platform runtime metadata")
    action_id: str = Field(..., description="Registered action identifier")
    action_version: str = Field(..., description="Version of the executed action")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Sanitized action parameters (secrets strictly excluded)")
    requested_at: datetime = Field(..., description="Timestamp (UTC) when execution was requested")
    started_at: datetime = Field(..., description="Timestamp (UTC) when execution began")
    completed_at: datetime = Field(..., description="Timestamp (UTC) when execution completed")
    duration_seconds: float = Field(..., ge=0.0, description="Elapsed execution time in seconds")
    status: RunnerExecutionState = Field(..., description="Final execution lifecycle state")
    exit_code: Optional[int] = Field(None, description="Subprocess return code if applicable")
    action_result: Dict[str, Any] = Field(default_factory=dict, description="Structured action output data")
    timed_out: bool = Field(False, description="True if execution exceeded timeout boundary")
    error_message: Optional[str] = Field(None, description="Sanitized error message if execution failed")
    error_classification: Optional[str] = Field(None, description="Classification of failure if applicable")
    cleanup_status: str = Field("COMPLETED", description="Cleanup outcome (COMPLETED, FAILED, SKIPPED)")
    cleanup_error: Optional[str] = Field(None, description="Sanitized error message if cleanup failed")
    evidence_references: List[str] = Field(default_factory=list, description="References to created workspace artifacts")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Attribution and audit metadata")
    integrity_hash: Optional[str] = Field(None, description="Deterministic canonical hash of execution record")

    def calculate_integrity_hash(self) -> str:
        """Compute the RFC 8785 canonical deterministic SHA-256 hash of this evidence record."""
        from proofshield.services.canonical import compute_canonical_hash
        data = self.model_dump(exclude={"integrity_hash"})
        return compute_canonical_hash(data)

    def verify_integrity(self) -> bool:
        """Verify that the stored integrity_hash matches the recomputed canonical hash."""
        import secrets
        if not self.integrity_hash:
            return False
        try:
            expected = self.calculate_integrity_hash()
        except (ValueError, TypeError):
            return False
        return secrets.compare_digest(self.integrity_hash, expected)

    @field_validator("metadata", "parameters", "action_result")
    @classmethod
    def _validate_meta_depth(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if v:
            validate_nesting_depth(v, max_depth=16)
        return v
