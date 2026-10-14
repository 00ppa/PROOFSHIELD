"""Unit tests for the health check endpoints."""

from fastapi.testclient import TestClient
from proofshield import __version__
from proofshield.schemas.common import SCHEMA_VERSION


def test_root_health_endpoint(test_client: TestClient):
    """Verify GET /health returns 200, valid service payload, and correct version."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "proofshield"
    assert data["version"] == __version__
    assert SCHEMA_VERSION in data["supported_schema_versions"]
    assert "timestamp" in data


def test_versioned_health_endpoint(test_client: TestClient):
    """Verify GET /api/v1/health returns 200 and matches root health probe."""
    response = test_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "proofshield"
    assert data["version"] == __version__
