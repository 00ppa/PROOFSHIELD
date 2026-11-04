"""Versioned evidence-backed single-run report schema."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import Field

from proofshield.schemas.common import DiagnosticCategory, ProofshieldBaseModel


class RunEvidenceReportV1(ProofshieldBaseModel):
    schema_version: Literal["v1"] = "v1"
    report_id: str = Field(..., min_length=3)
    run_id: str = Field(..., min_length=3)
    scenario_id: str = Field(..., min_length=3)
    deterministic_category: DiagnosticCategory
    execution_status: str
    telemetry_count: int = Field(..., ge=0)
    alert_count: int = Field(..., ge=0)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    contradictory_evidence_ids: List[str] = Field(default_factory=list)
    explanation_id: Optional[str] = None
    integrity_verified: bool = False
    integrity_status: Literal["VERIFIED", "UNAVAILABLE", "FAILED"] = "UNAVAILABLE"
    evidence_snapshot: Dict[str, Any] = Field(default_factory=dict)
    diagnostic: Dict[str, Any] = Field(default_factory=dict)
    explanation: Dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    report_hash: Optional[str] = None
