"""Approved benign execution actions for PROOFSHIELD Phase 20."""

from proofshield.execution.actions.base import ActionContext, ActionResult, BaseAction
from proofshield.execution.actions.file_actions import FileCreateAction, FileModifyReadAction
from proofshield.execution.actions.network_actions import NetworkLoopbackAction
from proofshield.execution.actions.process_actions import ProcessLifecycleAction, ProcessSpawnAction
from proofshield.execution.actions.registry import ActionRegistry, get_default_action_registry

__all__ = [
    "ActionContext",
    "ActionResult",
    "ActionRegistry",
    "BaseAction",
    "FileCreateAction",
    "FileModifyReadAction",
    "NetworkLoopbackAction",
    "ProcessLifecycleAction",
    "ProcessSpawnAction",
    "get_default_action_registry",
]
