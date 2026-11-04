"""Packaged analyst UI; all state comes from real same-origin API endpoints."""

from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(tags=["Analyst UI"])
ROOT = Path(__file__).resolve().parents[1] / "ui"
HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
           "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'"}


@router.get("/ui", include_in_schema=False)
def analyst_ui():
    return FileResponse(ROOT / "index.html", headers=HEADERS)


@router.get("/ui/assets/{name}", include_in_schema=False)
def asset(name: str):
    if name not in {"app.js", "style.css"}:
        raise HTTPException(404)
    return FileResponse(ROOT / name, headers=HEADERS)
