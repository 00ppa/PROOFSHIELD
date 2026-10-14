"""Ground truth labeling schemas."""

from typing import Any, Dict, Literal, Optional
from pydantic import Field
from proofshield.schemas.common import DiagnosticCategory, ProofshieldBaseModel


class GroundTruthV1(ProofshieldBaseModel):
    """Independent ground truth record (Schema Version 1).

    Ground-truth records are maintained independently from predicted results.
    They specify the expected diagnostic category for a test run, optionally
    with injected faults, and are NEVER modified by the diagnostic engine.
    """

    schema_version: Literal["v1"] = "v1"
    ground_truth_id: str = Field(
        ...,
        min_length=3,
        description="Unique ground truth record identifier",
    )
    run_id: str = Field(
        ...,
        min_length=3,
        description="Reference to the associated test run",
    )
    injected_fault_type: Optional[str] = Field(
        None,
        description="Type of fault injected for this test (e.g. telemetry_drop, rule_disable)",
    )
    expected_diagnostic_category: DiagnosticCategory = Field(
        ...,
        description="The independently verified expected diagnostic outcome",
    )
    verification_method: str = Field(
        ...,
        min_length=1,
        description="Method used to verify ground truth (e.g. manual_inspection, independent_log)",
    )
    verification_evidence: Optional[str] = Field(
        None,
        description="Reference to evidence supporting the ground truth label",
    )
    label_status: str = Field(
        "confirmed",
        description="Status of the label: confirmed, provisional, or disputed",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional ground truth metadata",
    )
