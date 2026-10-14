"""Common types, enums, and base configuration for PROOFSHIELD schemas."""

from enum import Enum
from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION: str = "v1"


class ExecutionMode(str, Enum):
    """Execution mode of a detection test run.

    Explicitly identifies whether telemetry originates from synthetic simulation,
    an emulated security testing agent, or a recorded dataset.
    """
    SYNTHETIC_SIMULATION = "SYNTHETIC_SIMULATION"
    EMULATED_AGENT = "EMULATED_AGENT"
    RECORDED_PLAYBACK = "RECORDED_PLAYBACK"
    MANUAL_TEST = "MANUAL_TEST"


class ValidationTarget(str, Enum):
    """Target capability under test declared in a validation scenario.

    Distinguishes scenarios validating detection alerts vs telemetry collection only.
    Independent from external experimental ground truth records (GroundTruthV1).
    """
    EXPECTED_ALERT = "EXPECTED_ALERT"
    EXPECTED_TELEMETRY_ONLY = "EXPECTED_TELEMETRY_ONLY"
    EXPECTED_BENIGN = "EXPECTED_BENIGN"


# Backwards compatibility alias
GroundTruthLabel = ValidationTarget


class DiagnosticOutcome(str, Enum):
    """Deterministic verdict computed by the diagnostic engine."""
    DETECTED = "DETECTED"
    UNDETECTED = "UNDETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class FailureCategory(str, Enum):
    """Root-cause classification of detection or evaluation failure."""
    NONE = "NONE"
    TELEMETRY_MISSING = "TELEMETRY_MISSING"
    PIPELINE_LATENCY = "PIPELINE_LATENCY"
    DETECTION_RULE_MISMATCH = "DETECTION_RULE_MISMATCH"
    ALERT_SUPPRESSED = "ALERT_SUPPRESSED"
    AMBIGUOUS_EVIDENCE = "AMBIGUOUS_EVIDENCE"
    UNSPECIFIED = "UNSPECIFIED"


class EventCategory(str, Enum):
    """Standardised category for normalised security events."""
    PROCESS_CREATION = "PROCESS_CREATION"
    FILE_EVENT = "FILE_EVENT"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    REGISTRY_EVENT = "REGISTRY_EVENT"
    AUTHENTICATION = "AUTHENTICATION"
    OTHER = "OTHER"


class DiagnosticCategory(str, Enum):
    """Primary diagnostic classification per specification Section 6.

    These are application-defined categories, not standardised industry terminology.
    The engine must distinguish a confirmed diagnosis from a likely explanation.
    It must never classify missing evidence as proof of a particular failure.
    """
    PASS = "PASS"
    TEST_NOT_EXECUTED = "TEST_NOT_EXECUTED"
    EXPECTED_TELEMETRY_MISSING = "EXPECTED_TELEMETRY_MISSING"
    DETECTION_NOT_TRIGGERED = "DETECTION_NOT_TRIGGERED"
    ALERT_NOT_CORRELATED = "ALERT_NOT_CORRELATED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class ExecutionStatus(str, Enum):
    """Status of test run execution."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ERROR = "ERROR"


class ProofshieldBaseModel(BaseModel):
    """Base Pydantic model for PROOFSHIELD schema structures."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        populate_by_name=True,
    )
