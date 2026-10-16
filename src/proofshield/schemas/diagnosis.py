"""Diagnostic result and evaluation schemas."""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import Field
from proofshield.schemas.common import (
    DiagnosticCategory,
    FailureCategory,
    ProofshieldBaseModel,
)


class DiagnosticResultV1(ProofshieldBaseModel):
    """Detection diagnosis outcome produced by the assurance engine (Schema Version 1).

    Classifies test outcomes using the seven diagnostic categories defined in
    Section 6 of the specification. Every material diagnosis links to supporting
    and contradictory evidence. Insufficient evidence produces an INCONCLUSIVE
    outcome rather than an unsupported conclusion.
    """

    schema_version: Literal["v1"] = "v1"
    diagnostic_id: str = Field(
        ...,
        min_length=3,
        description="Unique identifier for this diagnostic result record",
    )
    test_run_id: str = Field(
        ...,
        min_length=3,
        description="Reference to the evaluated test run record",
    )
    scenario_id: str = Field(
        ...,
        min_length=3,
        description="Reference to the validated scenario",
    )
    predicted_category: DiagnosticCategory = Field(
        ...,
        description="Primary diagnostic classification (one of seven categories from Section 6)",
    )
    failure_category: Optional[FailureCategory] = Field(
        None,
        description="Root-cause classification of failure or pipeline latency",
    )
    confidence: str = Field(
        "definitive",
        description="Confidence level: definitive, likely, or uncertain",
    )
    reason: str = Field(
        ...,
        min_length=1,
        description="Primary deterministic justification for the predicted category",
    )
    diagnostic_reasons: List[str] = Field(
        default_factory=list,
        description="Additional diagnostic reasons and observations",
    )
    supporting_evidence_ids: List[str] = Field(
        default_factory=list,
        description="IDs of events and alerts that support this diagnosis",
    )
    contradictory_evidence_ids: List[str] = Field(
        default_factory=list,
        description="IDs of events or data points that contradict this diagnosis",
    )
    evaluated_at: datetime = Field(
        ...,
        description="Timestamp (UTC) when the diagnostic evaluation occurred",
    )
    engine_version: str = Field(
        "v0.1.0",
        description="Version of the assurance engine rule-set",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Evaluation telemetry, latency calculations, rule match metrics",
    )

    @property
    def checks_performed(self) -> List[Dict[str, Any]]:
        """Structured list of validation checks performed during evaluation."""
        return self.metadata.get("checks_performed", [])

    @property
    def alternative_eliminations(self) -> Dict[str, str]:
        """Deterministic explanations for why alternative diagnostic categories were eliminated."""
        return self.metadata.get("alternative_eliminations", {})

    @property
    def missing_evidence(self) -> bool:
        """Indicates whether the diagnostic verdict was driven by missing evidence."""
        return bool(self.metadata.get("missing_evidence", False))
