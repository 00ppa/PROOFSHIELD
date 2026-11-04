"""Focused API authentication and access-control regressions."""

from fastapi.testclient import TestClient

from proofshield.main import create_application


PROTECTED_READ_PATHS = (
    "/api/v1/scenarios",
    "/api/v1/runs",
    "/api/v1/rules",
    "/api/v1/alerts",
    "/api/v1/ground-truth",
    "/api/v1/schemas/info",
    "/api/v1/reports/runs/RUN-AUTH-MISSING",
    "/api/v1/elastic/status",
    "/api/v1/splunk/status",
    "/api/v1/research/dataset",
)


def test_sensitive_api_reads_fail_closed_without_deployment_token(monkeypatch):
    monkeypatch.delenv("PROOFSHIELD_API_TOKEN", raising=False)
    monkeypatch.delenv("PROOFSHIELD_ALLOW_LOCAL_UNAUTHENTICATED", raising=False)
    client = TestClient(create_application())

    assert client.get("/api/v1/health").status_code == 200
    for path in PROTECTED_READ_PATHS:
        response = client.get(path)
        assert response.status_code == 503, path
        assert "token" not in response.text.lower()


def test_invalid_deployment_credentials_are_rejected_without_secret_echo(monkeypatch):
    secret = "deployment-secret-canary"
    monkeypatch.setenv("PROOFSHIELD_API_TOKEN", secret)
    client = TestClient(create_application())

    for headers in ({}, {"Authorization": "Bearer wrong-token"}, {"Authorization": "Basic wrong-token"}):
        response = client.get("/api/v1/scenarios", headers=headers)
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert secret not in response.text
        assert "wrong-token" not in response.text


def test_valid_deployment_token_allows_equivalent_sensitive_read_paths(monkeypatch):
    secret = "deployment-secret"
    monkeypatch.setenv("PROOFSHIELD_API_TOKEN", secret)
    client = TestClient(create_application())
    headers = {"Authorization": f"Bearer {secret}"}

    assert client.get("/api/v1/scenarios", headers=headers).status_code == 200
    assert client.get("/api/v1/schemas/info", headers=headers).status_code == 200
    assert client.get("/api/v1/elastic/status", headers=headers).status_code == 200
    assert client.get("/api/v1/splunk/status", headers=headers).status_code == 200


def test_execution_token_boundary_cannot_be_bypassed_with_api_token(monkeypatch):
    monkeypatch.setenv("PROOFSHIELD_API_TOKEN", "deployment-secret")
    monkeypatch.setenv("PROOFSHIELD_EXEC_TOKEN", "execution-secret")
    client = TestClient(create_application())

    assert client.get(
        "/api/v1/execution/actions",
        headers={"Authorization": "Bearer deployment-secret"},
    ).status_code == 401
    authorized = client.get(
        "/api/v1/execution/actions",
        headers={"Authorization": "Bearer execution-secret"},
    )
    assert authorized.status_code == 200


def test_local_unauthenticated_opt_in_cannot_be_used_through_forwarded_request(monkeypatch):
    monkeypatch.delenv("PROOFSHIELD_API_TOKEN", raising=False)
    monkeypatch.setenv("PROOFSHIELD_ALLOW_LOCAL_UNAUTHENTICATED", "true")
    client = TestClient(create_application())

    response = client.get(
        "/api/v1/scenarios",
        headers={"X-Forwarded-For": "203.0.113.10"},
    )
    assert response.status_code == 503
