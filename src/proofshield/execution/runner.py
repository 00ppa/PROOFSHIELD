"""Controlled endpoint execution runner for PROOFSHIELD Phase 20.

Bridges controlled benign security action executions with the deterministic
assurance pipeline, ensuring strict causal attribution, workspace isolation,
and rigorous evidence separation.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import logging
import os
import platform
import secrets
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from proofshield.execution.actions.base import ActionContext, ActionResult, BaseAction
from proofshield.execution.actions.registry import ActionRegistry, get_default_action_registry
from proofshield.execution.evidence import sanitize_execution_evidence_fields
from proofshield.execution.process_manager import get_default_process_manager
from proofshield.execution.workspace import ExecutionWorkspace
from proofshield.execution.environment import redact_server_secret
from proofshield.schemas.common import (
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
)
from proofshield.schemas.execution import (
    ExecutionEvidenceV1,
    ExecutionRequestV1,
    ExecutionValidationResultV1,
    RunnerExecutionState,
)
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.base_store import StoreProtocol, to_comparable_utc

logger = logging.getLogger("proofshield.execution.runner")


class ControlledExecutionRunner:
    """Executes pre-approved, benign security actions in isolated environments.

    Guarantees:
    - shell=False strictly enforced across all subprocess executions.
    - Zero arbitrary command or script evaluation.
    - Path containment inside dedicated workspace directories.
    - Unique execution token generated and bound to execution evidence.
    - Seamless linkage to TestRunV1 and downstream deterministic AssuranceEngine.
    - No network I/O or subprocess execution within database transactions.
    - Configurable telemetry observation window with post-execution buffer.
    - Real process lifecycle management and process-tree termination on cancellation/timeout.
    """

    def __init__(
        self,
        store: StoreProtocol,
        registry: Optional[ActionRegistry] = None,
        workspace_base_dir: Optional[Any] = None,
        settling_time_seconds: float = 5.0,
    ) -> None:
        self.store = store
        self.registry = registry or get_default_action_registry()
        self.workspace_base_dir = workspace_base_dir
        self.settling_time_seconds = max(0.0, float(settling_time_seconds))
        self._lock = threading.RLock()
        self._active_executions: Dict[str, RunnerExecutionState] = {}

    def get_runtime_platform_info(self) -> Dict[str, Any]:
        """Collect deterministic runtime platform metadata."""
        return {
            "system": platform.system().lower(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": sys.version.split()[0],
            "hostname": socket.gethostname(),
        }

    def validate_request(self, request: ExecutionRequestV1) -> ExecutionValidationResultV1:
        """Validate an execution request against action schemas and platform requirements."""
        errors: List[str] = []
        warnings: List[str] = []

        action = self.registry.get(request.action_id)
        if action is None:
            return ExecutionValidationResultV1(
                action_id=request.action_id,
                is_valid=False,
                authorized=False,
                supported_platform=False,
                errors=[f"Action '{request.action_id}' is not in the approved action registry."],
            )

        supported_platform = action.is_platform_supported()
        if not supported_platform:
            errors.append(
                f"Action '{request.action_id}' is not supported on platform '{sys.platform}'. "
                f"Supported platforms: {action.supported_platforms}"
            )

        # Check scenario if supplied
        if request.scenario_id:
            scenario = self.store.get_scenario(request.scenario_id)
            if scenario is None:
                errors.append(f"Referenced scenario '{request.scenario_id}' does not exist in store.")
            else:
                # Check category compatibility
                if scenario.expected_event_category != action.expected_observable_category:
                    warnings.append(
                        f"Action observable category '{action.expected_observable_category.value}' "
                        f"differs from scenario expected category '{scenario.expected_event_category.value}'."
                    )

        validated_params: Dict[str, Any] = {}
        try:
            validated_params = action.validate_parameters(request.action_parameters)
        except Exception as exc:
            errors.append(f"Parameter validation failed: {exc}")

        is_valid = len(errors) == 0
        return ExecutionValidationResultV1(
            action_id=request.action_id,
            action_version=action.version,
            is_valid=is_valid,
            authorized=is_valid,
            supported_platform=supported_platform,
            errors=errors,
            warnings=warnings,
            expected_observable_category=action.expected_observable_category,
            validated_parameters=validated_params if is_valid else {},
        )

    def execute(
        self,
        request: ExecutionRequestV1,
        auto_persist: bool = True,
    ) -> Tuple[ExecutionEvidenceV1, Optional[TestRunV1]]:
        """Execute a controlled benign action and persist evidence + test run record."""
        if request.dry_run:
            raise ValueError("dry_run does not execute; use validate_request or /execution/validate")
        serialized_request = request.model_dump_json()
        if redact_server_secret(serialized_request) != serialized_request:
            raise ValueError("Execution token must differ from server secrets; request contains a protected credential")
        requested_at = datetime.now(timezone.utc)

        # Step 1: Validation
        validation = self.validate_request(request)
        if not validation.is_valid:
            err_msg = "; ".join(validation.errors)
            raise ValueError(f"Execution request validation rejected: {err_msg}")

        action = self.registry.require(request.action_id)

        # Step 2: Generate identity and token
        ts_str = requested_at.strftime("%Y%m%d%H%M%S")
        suffix = uuid.uuid4().hex[:6].upper()
        execution_id = f"EXEC-{ts_str}-{suffix}"
        execution_token = request.execution_token or f"tok-exec-{uuid.uuid4().hex[:12]}"

        # Never allow the server bearer secret to become an execution token,
        # where it would otherwise be copied into evidence for attribution.
        server_secret = os.environ.get("PROOFSHIELD_EXEC_TOKEN")
        if server_secret and secrets.compare_digest(execution_token.strip().encode(), server_secret.strip().encode()):
            raise ValueError("Execution token must differ from the server authentication token.")

        target_host = request.target_host or socket.gethostname()
        target_user = request.target_user or os.environ.get("USERNAME") or os.environ.get("USER") or "secops"

        # Step 3: Setup workspace
        workspace = ExecutionWorkspace(execution_id=execution_id, base_dir=self.workspace_base_dir)
        workspace.create()

        # Step 4: Prepare execution context
        timeout = request.timeout_seconds or action.max_timeout_seconds
        timeout = min(timeout, action.max_timeout_seconds)

        ctx = ActionContext(
            execution_id=execution_id,
            execution_token=execution_token,
            workspace=workspace,
            parameters=validation.validated_parameters,
            timeout_seconds=timeout,
        )

        with self._lock:
            self._active_executions[execution_id] = RunnerExecutionState.RUNNING

        started_at = datetime.now(timezone.utc)
        action_result: Optional[ActionResult] = None
        state = RunnerExecutionState.RUNNING
        timed_out = False
        error_msg: Optional[str] = None
        error_classification: Optional[str] = None

        # Step 5: Execute action (OUTSIDE any store transaction)
        try:
            action_result = action.execute(ctx)

            # Check if cancellation occurred during execution
            was_cancelled = False
            with self._lock:
                if self._active_executions.get(execution_id) == RunnerExecutionState.CANCELLED:
                    was_cancelled = True

            if was_cancelled or (action_result.output_data and action_result.output_data.get("cancelled")):
                state = RunnerExecutionState.CANCELLED
                error_msg = "Execution was cancelled"
                error_classification = "EXECUTION_CANCELLED"
            elif action_result.output_data.get("timed_out"):
                state = RunnerExecutionState.TIMED_OUT
                timed_out = True
                error_msg = action_result.error_message or "Execution timed out"
                error_classification = "EXECUTION_TIMEOUT"
            elif action_result.exit_code != 0 or action_result.error_message:
                state = RunnerExecutionState.FAILED
                error_msg = action_result.error_message or f"Exit code {action_result.exit_code}"
                error_classification = "EXECUTION_FAILURE"
            else:
                state = RunnerExecutionState.COMPLETED
        except Exception as exc:
            with self._lock:
                if self._active_executions.get(execution_id) == RunnerExecutionState.CANCELLED:
                    state = RunnerExecutionState.CANCELLED
                    error_msg = "Execution was cancelled"
                    error_classification = "EXECUTION_CANCELLED"
                else:
                    state = RunnerExecutionState.FAILED
                    error_msg = redact_server_secret(f"Unexpected action exception: {exc}")
                    error_classification = "UNEXPECTED_EXCEPTION"
            action_result = ActionResult(exit_code=-1, error_message=error_msg)

        completed_at = datetime.now(timezone.utc)
        duration = max(0.0, (completed_at - started_at).total_seconds())

        # Step 6: Workspace & action cleanup
        cleanup_status = "COMPLETED"
        cleanup_error: Optional[str] = None
        try:
            action.cleanup(ctx)
            ws_status, ws_err = workspace.cleanup()
            if ws_status != "COMPLETED":
                cleanup_status = ws_status
                cleanup_error = ws_err
        except Exception as c_exc:
            cleanup_status = "FAILED"
            cleanup_error = f"Cleanup failed: {c_exc}"

        with self._lock:
            self._active_executions.pop(execution_id, None)

        # Step 7: Build ExecutionEvidenceV1
        sanitized_fields = sanitize_execution_evidence_fields(
            parameters=validation.validated_parameters,
            action_result=action_result.output_data if action_result else {},
            metadata={
                "runner_version": "v1.0.0",
                "custom_metadata": request.metadata,
            },
            evidence_references=action_result.evidence_references if action_result else [],
            error_message=error_msg,
            cleanup_error=cleanup_error,
        )
        evidence = ExecutionEvidenceV1(
            schema_version="v1",
            execution_id=execution_id,
            scenario_id=request.scenario_id,
            test_run_id=f"RUN-{execution_id[5:]}" if request.scenario_id else None,
            campaign_id=request.campaign_id,
            execution_token=execution_token,
            target_host=target_host,
            platform=self.get_runtime_platform_info(),
            action_id=action.action_id,
            action_version=action.version,
            parameters=sanitized_fields["parameters"],
            requested_at=requested_at,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            status=state,
            exit_code=action_result.exit_code if action_result else -1,
            action_result=sanitized_fields["action_result"],
            timed_out=timed_out,
            error_message=sanitized_fields["error_message"],
            error_classification=error_classification,
            cleanup_status=cleanup_status,
            cleanup_error=sanitized_fields["cleanup_error"],
            evidence_references=sanitized_fields["evidence_references"],
            metadata=sanitized_fields["metadata"],
        )

        # Compute canonical integrity hash
        evidence.integrity_hash = evidence.calculate_integrity_hash()

        # Step 8: Build corresponding TestRunV1 ONLY if a valid scenario_id is associated
        test_run: Optional[TestRunV1] = None
        if request.scenario_id:
            test_run_status = (
                ExecutionStatus.COMPLETED if state == RunnerExecutionState.COMPLETED
                else ExecutionStatus.FAILED
            )

            # Observation window includes configurable settling buffer
            win_start = started_at - timedelta(seconds=1)
            win_end = completed_at + timedelta(seconds=self.settling_time_seconds)

            test_run = TestRunV1(
                schema_version="v1",
                run_id=f"RUN-{execution_id[5:]}",
                scenario_id=request.scenario_id,
                execution_mode=ExecutionMode.EMULATED_AGENT,
                is_synthetic=False,
                target_host=target_host,
                target_user=target_user,
                window_start=win_start,
                window_end=win_end,
                executed_at=started_at,
                execution_status=test_run_status,
                cleanup_status=cleanup_status,
                execution_token=execution_token,
                notes=f"Controlled endpoint execution via action '{action.action_id}' (status={state.value})",
                metadata={
                    "execution_id": execution_id,
                    "action_id": action.action_id,
                    "integrity_hash": evidence.integrity_hash,
                    "strict_attribution": True,
                },
            )

        # Step 9: Persist records
        if auto_persist:
            with self.store.transaction():
                self.store.add_execution(evidence)
                if test_run is not None:
                    self.store.add_run(test_run)

        return evidence, test_run

    def execute_with_assurance(
        self,
        request: ExecutionRequestV1,
        orchestrator: Any = None,
        strict_attribution: bool = True,
    ) -> Tuple[ExecutionEvidenceV1, Optional[TestRunV1], Optional[Any], Optional[Any]]:
        """Execute a controlled benign action and orchestrate downstream assurance evaluation.

        Preserves strict separation between execution evidence capture and downstream
        assurance evaluation.
        """
        evidence, test_run = self.execute(request, auto_persist=True)
        if not evidence.verify_integrity():
            raise ValueError(f"Integrity check failed for execution evidence '{evidence.execution_id}'")

        if test_run is None or orchestrator is None:
            return evidence, test_run, None, None

        remaining = (test_run.window_end - datetime.now(timezone.utc)).total_seconds()
        if remaining > 0:
            time.sleep(remaining)
        eval_result, report = orchestrator.evaluate_run_with_orchestration(
            run_id=test_run.run_id,
            strict_attribution=strict_attribution,
        )
        return evidence, test_run, eval_result, report

    def cancel_execution(self, execution_id: str) -> bool:
        """Cancel an ongoing execution and terminate its process tree."""
        with self._lock:
            if execution_id in self._active_executions:
                self._active_executions[execution_id] = RunnerExecutionState.CANCELLED

        mgr = get_default_process_manager()
        cancelled_process = mgr.cancel(execution_id)

        with self._lock:
            return (execution_id in self._active_executions) or cancelled_process
