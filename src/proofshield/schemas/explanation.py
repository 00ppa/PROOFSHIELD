"""Versioned, evidence-grounded analyst explanation contracts."""

from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import Field

from proofshield.schemas.common import DiagnosticCategory, ProofshieldBaseModel


class ExplanationFactV1(ProofshieldBaseModel):
    fact_id: str = Field(..., min_length=3)
    statement: str = Field(..., min_length=1)
    evidence_ids: List[str] = Field(default_factory=list)


class ExplanationGapV1(ProofshieldBaseModel):
    gap_id: str = Field(..., min_length=3)
    statement: str = Field(..., min_length=1)


class ExplanationHypothesisV1(ProofshieldBaseModel):
    hypothesis_id: str = Field(..., min_length=3)
    statement: str = Field(..., min_length=1)
    confirmed: Literal[False] = False


class AnalystExplanationV1(ProofshieldBaseModel):
    schema_version: Literal["v1"] = "v1"
    explanation_id: str = Field(..., min_length=3)
    diagnostic_id: str = Field(..., min_length=3)
    test_run_id: str = Field(..., min_length=3)
    scenario_id: str = Field(..., min_length=3)
    deterministic_category: DiagnosticCategory
    summary: str = Field(..., min_length=1)
    confirmed_facts: List[ExplanationFactV1] = Field(default_factory=list)
    missing_evidence: List[ExplanationGapV1] = Field(default_factory=list)
    hypotheses: List[ExplanationHypothesisV1] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    source_digest: str = Field(..., min_length=64, max_length=64)
    generator: str = "ProofShield deterministic explanation generator v1"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    explanation_hash: Optional[str] = None
