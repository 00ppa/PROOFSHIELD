"""Run report and export endpoints."""

import csv
import io
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Path
from fastapi.responses import PlainTextResponse

from proofshield.schemas.report import RunEvidenceReportV1
from proofshield.services.report import RunReportService
from proofshield.services.store import get_store

router = APIRouter(prefix="/api/v1", tags=["Evidence Reports"])


@router.get("/reports/runs/{run_id}", response_model=RunEvidenceReportV1)
def get_run_report(run_id: str = Path(..., pattern=r"^[A-Za-z0-9_\-.]+$", min_length=3, max_length=128)) -> RunEvidenceReportV1:
    try:
        return RunReportService(get_store()).build(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/reports/runs/{run_id}/export.csv", response_class=PlainTextResponse)
def export_run_report_csv(run_id: str = Path(..., pattern=r"^[A-Za-z0-9_\-.]+$", min_length=3, max_length=128)) -> str:
    try:
        report = RunReportService(get_store()).build(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["field", "value"])
    for key, value in report.model_dump(mode="json").items():
        text = str(value)
        if text.startswith(("=", "+", "-", "@", "\t", "\r")):
            text = "'" + text
        writer.writerow([key, text])
    return output.getvalue()
