"""Thread-safe registry for approved benign execution actions."""

import threading
from typing import Dict, List, Optional

from proofshield.execution.actions.base import BaseAction
from proofshield.execution.actions.file_actions import FileCreateAction, FileModifyReadAction
from proofshield.execution.actions.network_actions import NetworkLoopbackAction
from proofshield.execution.actions.process_actions import ProcessLifecycleAction, ProcessSpawnAction
from proofshield.schemas.execution import ActionDescriptorV1


class ActionRegistry:
    """Registry maintaining approved, typed, benign endpoint actions.

    Guarantees:
    - Only pre-registered actions may be retrieved or executed.
    - Rejects unknown action IDs upfront before any execution attempt.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._actions: Dict[str, BaseAction] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register the built-in approved benign validation actions."""
        self.register(ProcessSpawnAction())
        self.register(ProcessLifecycleAction())
        self.register(FileCreateAction())
        self.register(FileModifyReadAction())
        self.register(NetworkLoopbackAction())

    def register(self, action: BaseAction) -> None:
        """Register an approved action."""
        with self._lock:
            self._actions[action.action_id] = action

    def get(self, action_id: str) -> Optional[BaseAction]:
        """Retrieve an action by ID, or None if not registered."""
        with self._lock:
            return self._actions.get(action_id)

    def require(self, action_id: str) -> BaseAction:
        """Retrieve an action by ID, raising ValueError if not registered."""
        action = self.get(action_id)
        if action is None:
            raise ValueError(f"Unknown or unapproved action ID: '{action_id}'")
        return action

    def has_action(self, action_id: str) -> bool:
        """Check if an action ID is registered."""
        with self._lock:
            return action_id in self._actions

    def list_actions(self) -> List[ActionDescriptorV1]:
        """Return descriptors for all registered actions, sorted by action_id."""
        with self._lock:
            descriptors = [action.get_descriptor() for action in self._actions.values()]
            descriptors.sort(key=lambda d: d.action_id)
            return descriptors

    def list_descriptors(self) -> List[ActionDescriptorV1]:
        """Documented alias for list_actions for contract parity."""
        return self.list_actions()


# Global default registry singleton
_registry_lock = threading.Lock()
_global_registry: Optional[ActionRegistry] = None


def get_default_action_registry() -> ActionRegistry:
    """Return the global ActionRegistry singleton."""
    global _global_registry
    if _global_registry is None:
        with _registry_lock:
            if _global_registry is None:
                _global_registry = ActionRegistry()
    return _global_registry
