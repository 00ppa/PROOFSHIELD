"""Base abstractions and protocols for controlled benign execution actions."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from proofshield.execution.workspace import ExecutionWorkspace
from proofshield.schemas.common import EventCategory
from proofshield.schemas.execution import ActionDescriptorV1


@dataclass
class ActionContext:
    """Runtime context delivered to an action during execution."""
    execution_id: str
    execution_token: str
    workspace: ExecutionWorkspace
    parameters: Dict[str, Any]
    timeout_seconds: float


@dataclass
class ActionResult:
    """Structured result returned by an action upon completion."""
    exit_code: Optional[int] = 0
    output_data: Dict[str, Any] = field(default_factory=dict)
    evidence_references: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


class BaseAction(ABC):
    """Abstract base class for all approved benign actions in ProofShield."""

    action_id: str
    version: str = "1.0.0"
    name: str
    description: str
    supported_platforms: List[str] = ["windows", "linux", "darwin"]
    expected_observable_category: EventCategory
    max_timeout_seconds: float = 30.0

    @abstractmethod
    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate, normalize, and sanitize action parameters.

        Raises:
            ValueError: If parameters violate the action schema or safety constraints.
        """
        ...

    @abstractmethod
    def execute(self, ctx: ActionContext) -> ActionResult:
        """Execute the benign action within the provided context.

        Must strictly adhere to:
        - shell=False
        - Workspace containment
        - Respect ctx.timeout_seconds
        - No destructive or privileged operations
        """
        ...

    def cleanup(self, ctx: ActionContext) -> None:
        """Perform action-specific cleanup before workspace destruction."""
        pass

    def get_descriptor(self) -> ActionDescriptorV1:
        """Return the public metadata descriptor for this action."""
        return ActionDescriptorV1(
            action_id=self.action_id,
            version=self.version,
            name=self.name,
            description=self.description,
            supported_platforms=list(self.supported_platforms),
            expected_observable_category=self.expected_observable_category,
            max_timeout_seconds=self.max_timeout_seconds,
            parameter_schema=self.get_parameter_schema(),
            cleanup_policy="AUTOMATIC_WORKSPACE_CLEANUP",
        )

    def get_parameter_schema(self) -> Dict[str, Any]:
        """Return JSON schema describing the expected input parameters."""
        return {"type": "object", "properties": {}}

    def is_platform_supported(self) -> bool:
        """Check if current operating system is supported by this action."""
        current_os = sys.platform.lower()
        if "win32" in current_os or "cygwin" in current_os:
            current_tag = "windows"
        elif "linux" in current_os:
            current_tag = "linux"
        elif "darwin" in current_os:
            current_tag = "darwin"
        else:
            current_tag = current_os

        return current_tag in self.supported_platforms
