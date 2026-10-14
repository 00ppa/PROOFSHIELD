"""Detection validation scenario schemas."""

from typing import Any, Dict, Literal, Optional
from pydantic import AliasChoices, Field
from proofshield.schemas.common import (
    EventCategory,
    GroundTruthLabel,
    ProofshieldBaseModel,
    ValidationTarget,
)


class ScenarioV1(ProofshieldBaseModel):
    """Detection validation scenario definition (Schema Version 1).

    Specifies the adversary behavior under test, the expected telemetry
    signature, and the independent ground-truth expectation.
    """

    schema_version: Literal["v1"] = "v1"
    scenario_id: str = Field(
        ...,
        description="Unique identifier for the scenario (e.g. SCN-T1059.001-01)",
        min_length=3,
    )
    name: str = Field(..., min_length=1, description="Human-readable scenario title")
    description: str = Field("", description="Detailed summary of the tested technique")
    mitre_technique_id: str = Field(
        ...,
        description="MITRE ATT&CK technique ID (e.g. T1059.001)",
        pattern=r"^T\d{4}(\.\d{3})?$",
    )
    mitre_tactic: str = Field(..., description="MITRE ATT&CK tactic (e.g. Execution)")
    expected_event_category: EventCategory = Field(
        ...,
        description="Primary security event category expected to observe the technique",
    )
    expected_detection_rule_id: Optional[str] = Field(
        None,
        description="Identifier of the detection rule expected to trigger an alert",
    )
    expected_process_name: Optional[str] = Field(
        None,
        description="Target process image name (e.g. powershell.exe)",
    )
    expected_command_pattern: Optional[str] = Field(
        None,
        description="Regex pattern or substring expected in command-line arguments",
    )
    max_acceptable_latency_seconds: int = Field(
        300,
        ge=1,
        description="Maximum seconds between action and pipeline ingestion before marking pipeline latency",
    )
    validation_target: ValidationTarget = Field(
        default=ValidationTarget.EXPECTED_ALERT,
        validation_alias=AliasChoices("validation_target", "ground_truth_label"),
        serialization_alias="validation_target",
        description="Validation capability target under test (EXPECTED_ALERT, EXPECTED_TELEMETRY_ONLY, EXPECTED_BENIGN)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary tags, author info, environment prerequisites",
    )

    @property
    def ground_truth_label(self) -> ValidationTarget:
        """Backwards compatibility alias for validation_target."""
        return self.validation_target
