"""Deployment API authentication and explicit local-development tests."""

from fastapi.testclient import TestClient

from proofshield.main import create_application


def test_api_token_requires_explicit_local_development_opt_in(monkeypatch):
    monkeypatch.delenv("PROOFSHIELD_API_TOKEN", raising=False)
    monkeypatch.setenv("PROOFSHIELD_ALLOW_LOCAL_UNAUTHENTICATED", "true")
    client = TestClient(create_application())
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/scenarios").status_code == 200


def test_missing_api_token_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("PROOFSHIELD_API_TOKEN", raising=False)
    monkeypatch.delenv("PROOFSHIELD_ALLOW_LOCAL_UNAUTHENTICATED", raising=False)
    client = TestClient(create_application())
    assert client.get("/api/v1/health").status_code == 200
    response = client.get("/api/v1/scenarios")
    assert response.status_code == 503
    assert "PROOFSHIELD" not in response.text


def test_configured_api_token_protects_api_routes_but_not_health_or_execution_policy(monkeypatch):
    monkeypatch.setenv("PROOFSHIELD_API_TOKEN", "api-deployment-secret")
    monkeypatch.setenv("PROOFSHIELD_EXEC_TOKEN", "execution-secret")
    client = TestClient(create_application())
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/scenarios").status_code == 401
    assert client.get("/api/v1/scenarios", headers={"Authorization": "Bearer api-deployment-secret"}).status_code != 401
    # Execution keeps its own fail-closed/missing-bearer behavior.
    assert client.get("/api/v1/execution/actions").status_code == 401
