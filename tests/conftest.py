"""Pytest configuration and shared fixtures for PROOFSHIELD."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from proofshield.main import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = PROJECT_ROOT / "fixtures"


@pytest.fixture
def test_client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def scenarios_jsonl_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "scenarios_v1.jsonl"


@pytest.fixture
def test_runs_jsonl_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "test_runs_v1.jsonl"


@pytest.fixture
def raw_telemetry_valid_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "raw_telemetry_valid_v1.jsonl"


@pytest.fixture
def raw_telemetry_malformed_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "raw_telemetry_malformed_v1.jsonl"


@pytest.fixture
def raw_telemetry_realistic_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "raw_telemetry_realistic_v1.jsonl"


@pytest.fixture
def raw_telemetry_auditd_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "raw_telemetry_auditd_v1.jsonl"


@pytest.fixture
def detection_rules_jsonl_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "detection_rules_v1.jsonl"


@pytest.fixture
def alerts_jsonl_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "alerts_v1.jsonl"


@pytest.fixture
def ground_truth_jsonl_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "ground_truth_v1.jsonl"

