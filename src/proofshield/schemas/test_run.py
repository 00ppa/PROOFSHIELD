"""Test execution run schemas."""

from datetime import datetime
from typing import Any, Dict, Literal, Optional
from pydantic import Field, model_validator
from proofshield.schemas.common import (
    ExecutionMode,
    ExecutionStatus,
    ProofshieldBaseModel,
)


class TestRunV1(ProofshieldBaseModel):
    """Test execution run record (Schema Version 1).

    Tracks an instance of a scenario execution, telemetry observation window,
    and target host/user context.
    """

    __test__ = False  # Prevents pytest from mistaking this schema for a test suite

    schema_version: Literal["v1"] = "v1"
    run_id: str = Field(..., min_length=3, description="Unique test run identifier")
    scenario_id: str = Field(..., min_length=3, description="Referenced scenario ID")
    execution_mode: ExecutionMode = Field(
        ...,
        description="Explicit provenance of the execution (e.g. SYNTHETIC_SIMULATION)",
    )
    is_synthetic: bool = Field(
        True,
        description="Explicit flag ensuring synthetic/simulated data is never misrepresented as live test execution",
    )
    target_host: str = Field(..., min_length=1, description="Target hostname or IP")
    target_user: str = Field(..., min_length=1, description="Target username / account")
    window_start: datetime = Field(
        ...,
        description="Start timestamp (UTC) of the telemetry correlation window",
    )
    window_end: datetime = Field(
        ...,
        description="End timestamp (UTC) of the telemetry correlation window",
    )
    executed_at: datetime = Field(
        ...,
        description="Timestamp (UTC) when the test execution commenced",
    )
    notes: Optional[str] = Field(None, description="Optional notes or execution comments")
    execution_status: ExecutionStatus = Field(
        ExecutionStatus.COMPLETED,
        description="Current execution status of the test run",
    )
    cleanup_status: Optional[str] = Field(
        None,
        description="Cleanup status after test execution (pending, completed, skipped)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional execution metadata (agent version, OS build, etc.)",
    )

    @model_validator(mode="after")
    def validate_window(self) -> "TestRunV1":
        if self.window_end < self.window_start:
            raise ValueError("window_end must not be earlier than window_start")
        return self
