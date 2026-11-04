"""Elasticsearch connector status and assurance orchestration endpoints."""

import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Path, Query

from proofshield.connectors.elastic import ElasticAlertClient, ElasticConnectorSettings
from proofshield.connectors.transport import public_source_url
from proofshield.services.elastic_orchestrator import ElasticAssuranceOrchestrator
from proofshield.services.store import get_store

router = APIRouter(prefix="/api/v1/elastic", tags=["Elasticsearch Integration"])


@router.get("/status", response_model=Dict[str, Any], summary="Inspect Elasticsearch connector configuration")
def elastic_status() -> Dict[str, Any]:
    configured = bool(os.environ.get("PROOFSHIELD_ELASTIC_URL", "").strip() and os.environ.get("PROOFSHIELD_ELASTIC_API_KEY", "").strip())
    return {
        "enabled": os.environ.get("PROOFSHIELD_ELASTIC_ENABLED", "false").lower() in {"1", "true", "yes", "on"},
        "configured": configured,
        "base_url": public_source_url(os.environ.get("PROOFSHIELD_ELASTIC_URL", "")),
        "api_key_present": bool(os.environ.get("PROOFSHIELD_ELASTIC_API_KEY", "").strip()),
    }


@router.post("/assurance/{run_id}", response_model=Dict[str, Any], summary="Collect Elasticsearch evidence and run assurance")
def elastic_assurance(
    run_id: str = Path(..., pattern=r"^[A-Za-z0-9_\-.]+$", min_length=3, max_length=128),
    strict_attribution: bool = Query(True),
) -> Dict[str, Any]:
    try:
        settings = ElasticConnectorSettings.from_env()
        if not settings.enabled:
            raise ValueError("Elasticsearch connector is disabled")
        result, report = ElasticAssuranceOrchestrator(ElasticAlertClient(settings), get_store()).evaluate_run_with_orchestration(
            run_id, strict_attribution=strict_attribution
        )
        return {"diagnostic": result.model_dump(mode="json"), "orchestration": report.model_dump(mode="json")}
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Elasticsearch configuration or run context is invalid") from exc
