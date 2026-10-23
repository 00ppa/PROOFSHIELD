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
    expected_destination_ip: Optional[str] = Field(
        None,
        description="Expected destination IP address for network telemetry",
    )
    expected_destination_port: Optional[int] = Field(
        None,
        ge=0,
        le=65535,
        description="Expected destination network port [0-65535]",
    )
    expected_file_path: Optional[str] = Field(
        None,
        description="Expected file path, target filename, or regex/substring pattern for file telemetry",
    )
    expected_file_hash: Optional[str] = Field(
        None,
        description="Expected cryptographic file hash (e.g. SHA256 or MD5)",
    )
    expected_user: Optional[str] = Field(
        None,
        description="Expected user account, username, or UID",
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

    def has_discriminating_signature(self) -> bool:
        """Check whether the scenario defines at least one discriminating signature field.

        A scenario without any discriminating signature field cannot be reliably
        distinguished from ambient background noise of the same event category.
        """
        def _has_value(val: Optional[str]) -> bool:
            return bool(val and val.strip())

        return any(
            [
                _has_value(self.expected_process_name),
                _has_value(self.expected_command_pattern),
                _has_value(self.expected_destination_ip),
                self.expected_destination_port is not None,
                _has_value(self.expected_file_path),
                _has_value(self.expected_file_hash),
                _has_value(self.expected_user),
            ]
        )

    @property
    def ground_truth_label(self) -> ValidationTarget:
        """Backwards compatibility alias for validation_target."""
        return self.validation_target
