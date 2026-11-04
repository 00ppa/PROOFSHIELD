"""Authenticated, strict execution and evidence workflow routes."""

from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from proofshield.api.routes_execution import verify_execution_auth
from proofshield.schemas.execution import ExecutionRequestV1
from proofshield.services.store import get_store
from proofshield.services.workflow import AssuranceWorkflow

router = APIRouter(prefix="/api/v1/execution", tags=["Assurance Workflow"], dependencies=[Depends(verify_execution_auth)])


@router.post("/workflow/{source}")
def execute_workflow(source: Literal["elastic", "splunk"], request: ExecutionRequestV1):
    try:
        return AssuranceWorkflow(get_store()).execute(request, source)
    except ValueError as exc:
        raise HTTPException(400, "Workflow configuration or request rejected") from exc
