"""FastAPI router for controlled endpoint execution runner and evidence lifecycle."""

import logging
import os
import secrets
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from proofshield.api.routes_campaigns import sanitize_error_detail
from proofshield.execution.actions.registry import get_default_action_registry
from proofshield.execution.runner import ControlledExecutionRunner
from proofshield.schemas.common import EventCategory
from proofshield.schemas.execution import (
    ActionDescriptorV1,
    ExecutionEvidenceV1,
    ExecutionRequestV1,
    ExecutionValidationResultV1,
    RunnerExecutionState,
)
from proofshield.services.store import get_store

logger = logging.getLogger("proofshield.api.execution")

_bearer_security = HTTPBearer(auto_error=False)


def verify_execution_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_security),
) -> str:
    """Enforce server-side execution authentication via PROOFSHIELD_EXEC_TOKEN.

    Fails closed when the token is not configured on the server.
    Compares tokens using constant-time string comparison to prevent timing attacks.
    """
    configured_token = os.environ.get("PROOFSHIELD_EXEC_TOKEN")
    if not configured_token or not configured_token.strip():
        logger.warning("Execution endpoint rejected: PROOFSHIELD_EXEC_TOKEN is not configured on server.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution subsystem is locked: server execution authentication is not configured (PROOFSHIELD_EXEC_TOKEN is unset).",
        )

    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing execution authorization bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme. Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not secrets.compare_digest(credentials.credentials.strip().encode(), configured_token.strip().encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid execution authorization token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials


router = APIRouter(
    prefix="/api/v1",
    tags=["Endpoint Execution Runner"],
    dependencies=[Depends(verify_execution_auth)],
)

_runner_instance: Optional[ControlledExecutionRunner] = None


def get_runner() -> ControlledExecutionRunner:
    """Retrieve or initialize the execution runner bound to the active store."""
    global _runner_instance
    current_store = get_store()
    if _runner_instance is None or _runner_instance.store is not current_store:
        _runner_instance = ControlledExecutionRunner(store=current_store)
    return _runner_instance


@router.get(
    "/execution/actions",
    response_model=List[ActionDescriptorV1],
    summary="List approved benign execution actions",
    description="Returns all pre-approved benign execution action descriptors available in the registry.",
)
def list_approved_actions(
    category: Optional[EventCategory] = Query(
        None, description="Filter actions by expected observable event category"
    ),
) -> List[ActionDescriptorV1]:
    """List approved actions with optional category filtering."""
    registry = get_default_action_registry()
    descriptors = registry.list_descriptors()
    if category is not None:
        descriptors = [d for d in descriptors if d.expected_observable_category == category]
    return descriptors


@router.get(
    "/execution/actions/{action_id}",
    response_model=ActionDescriptorV1,
    summary="Get approved action descriptor",
    description="Retrieve the descriptor and schema for a specific registered action.",
)
def get_action_descriptor(
    action_id: str,
) -> ActionDescriptorV1:
    """Retrieve action descriptor by action_id."""
    registry = get_default_action_registry()
    action = registry.get(action_id)
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approved action '{action_id}' not found in registry.",
        )
    return action.get_descriptor()


@router.post(
    "/execution/validate",
    response_model=ExecutionValidationResultV1,
    summary="Validate execution request (dry run)",
    description="Validates an execution request against action constraints and platform compatibility without executing it.",
)
def validate_execution_request(
    request: ExecutionRequestV1,
) -> ExecutionValidationResultV1:
    """Validate request without executing any action."""
    runner = get_runner()
    return runner.validate_request(request)


@router.post(
    "/execution/run",
    response_model=ExecutionEvidenceV1,
    summary="Execute a controlled benign security action",
    description="Executes a pre-approved benign action under strict isolation and records tamper-auditable execution evidence.",
)
def run_controlled_execution(
    request: ExecutionRequestV1,
) -> ExecutionEvidenceV1:
    """Execute a benign security action and return immutable execution evidence."""
    runner = get_runner()
    try:
        evidence, _ = runner.execute(request, auto_persist=True)
        return evidence
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=sanitize_error_detail(exc, "Execution validation rejected"),
        )
    except Exception as exc:
        logger.exception("Unexpected failure during controlled execution: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=sanitize_error_detail(exc, "Controlled execution failed"),
        )


@router.get(
    "/execution/records",
    response_model=List[ExecutionEvidenceV1],
    summary="List execution evidence records",
    description="Retrieve persisted execution evidence records matching query criteria.",
)
def list_execution_records(
    scenario_id: Optional[str] = Query(None, description="Filter by scenario ID"),
    test_run_id: Optional[str] = Query(None, alias="run_id", description="Filter by test run ID"),
    execution_token: Optional[str] = Query(None, description="Filter by execution token"),
    status_filter: Optional[RunnerExecutionState] = Query(
        None, alias="status", description="Filter by execution state"
    ),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> List[ExecutionEvidenceV1]:
    """List execution evidence records."""
    store = get_store()
    state_str = status_filter.value if status_filter else None
    records = store.list_executions(
        scenario_id=scenario_id,
        run_id=test_run_id,
        status=state_str,
    )
    if execution_token:
        records = [r for r in records if r.execution_token == execution_token]
    return records[offset : offset + limit]


@router.get(
    "/execution/records/{execution_id}",
    response_model=ExecutionEvidenceV1,
    summary="Get execution evidence record",
    description="Retrieve a single persisted execution evidence record by its unique execution ID.",
)
def get_execution_record(
    execution_id: str,
) -> ExecutionEvidenceV1:
    """Retrieve execution evidence record by execution_id."""
    store = get_store()
    evidence = store.get_execution(execution_id)
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution record '{execution_id}' not found.",
        )
    return evidence


@router.post(
    "/execution/records/{execution_id}/cancel",
    summary="Cancel an active execution",
    description="Attempts to cancel an active running execution attempt.",
)
def cancel_execution(
    execution_id: str,
) -> Dict[str, Any]:
    """Attempt cancellation of an active execution."""
    runner = get_runner()
    cancelled = runner.cancel_execution(execution_id)
    if not cancelled:
        store = get_store()
        existing = store.get_execution(execution_id)
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution '{execution_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Execution '{execution_id}' is not in a cancellable RUNNING state (status: {existing.status.value}).",
        )
    return {"execution_id": execution_id, "status": "CANCELLED"}


@router.get("/execution/active")
def list_active_executions():
    runner = get_runner()
    with runner._lock:
        return [{"execution_id": identifier, "status": state.value}
                for identifier, state in runner._active_executions.items()]
