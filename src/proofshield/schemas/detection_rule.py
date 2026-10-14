"""Detection rule schemas."""

from typing import Any, Dict, List, Literal, Optional
from pydantic import Field
from proofshield.schemas.common import ProofshieldBaseModel


class DetectionRuleV1(ProofshieldBaseModel):
    """Detection rule definition (Schema Version 1).

    Represents a security detection rule that evaluates telemetry and generates
    alerts. Tracks rule versioning and evaluation backend for reproducibility.
    """

    schema_version: Literal["v1"] = "v1"
    rule_id: str = Field(
        ...,
        min_length=3,
        description="Unique detection rule identifier (e.g. RULE-WIN-PS-CRADLE-01)",
    )
    rule_name: str = Field(
        ...,
        min_length=1,
        description="Human-readable rule name",
    )
    rule_version: str = Field(
        "1.0.0",
        description="Semantic version of the rule definition",
    )
    rule_format: str = Field(
        ...,
        min_length=1,
        description="Rule format (e.g. sigma, wazuh, splunk, custom)",
    )
    rule_content_hash: Optional[str] = Field(
        None,
        description="SHA-256 hash of the rule content for change tracking",
    )
    evaluation_backend: Optional[str] = Field(
        None,
        description="Backend system that evaluates this rule (e.g. wazuh, manual)",
    )
    enabled: bool = Field(
        True,
        description="Whether the rule is currently active",
    )
    rule_content: Optional[str] = Field(
        None,
        description="The actual rule definition content (YAML, JSON, etc.)",
    )
    description: str = Field(
        "",
        description="Description of what the rule detects",
    )
    mitre_technique_ids: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs this rule covers",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional rule metadata",
    )
