"""Batch 1 regression tests for the five independent audit findings."""

from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys

import pytest

from proofshield.connectors.elastic import ElasticConnectorSettings
from proofshield.schemas.common import EventCategory, ValidationTarget
from proofshield.schemas.scenario import ScenarioV1
from proofshield.services.canonical import compute_canonical_hash
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.report import RunReportService
from proofshield.services.store import InMemoryStore


def _scenario(scenario_id="SCN-B1", rule_id=None):
    return ScenarioV1(
        scenario_id=scenario_id,
        name="Batch 1 scenario",
        mitre_technique_id="T1000",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="test.exe",
        expected_detection_rule_id=rule_id,
        validation_target=(
            ValidationTarget.EXPECTED_ALERT
            if rule_id
            else ValidationTarget.EXPECTED_TELEMETRY_ONLY
        ),
    )


def test_direct_elastic_import_works_in_fresh_subprocess():
    env = os.environ.copy()
    src = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-c", "import proofshield.connectors.elastic"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_elastic_rejects_non_loopback_plain_http_but_allows_local_mock():
    with pytest.raises(ValueError, match="verified HTTPS"):
        ElasticConnectorSettings("http://elastic.example.test:9200", "key")
    local = ElasticConnectorSettings("http://127.0.0.1:9200", "key")
    assert local.base_url == "http://127.0.0.1:9200"


def test_missing_registered_detection_rule_is_inconclusive():
    from tests.test_benchmark import build_benchmark_suite

    case = next(
        item for item in build_benchmark_suite()
        if item.scenario is not None
        and item.scenario.expected_detection_rule_id
        and item.normalized_events
    )
    store = InMemoryStore()
    store.add_scenario(case.scenario)
    store.add_run(case.run)
    for event in case.normalized_events:
        store.add_normalized_event(event)
    for alert in case.alerts:
        store.add_alert(alert)

    result = AssuranceEngine(store).evaluate_run(case.run.run_id)
    assert result.predicted_category.value == "INCONCLUSIVE"
    assert result.metadata["missing_detection_rule"] is True


def test_report_verify_rejects_unavailable_and_hash_invalid_evidence():
    from tests.test_phase23_explanation import _result, _store

    store = _store(InMemoryStore())
    store.add_result(_result())
    report = RunReportService(store).build("RUN-EXPLAIN-01", include_explanation=False)
    assert report.integrity_status == "UNAVAILABLE"
    assert RunReportService.verify(report) is False

    report.integrity_status = "VERIFIED"
    report.integrity_verified = True
    report.evidence_snapshot["run:RUN-EXPLAIN-01"]["hash"] = "invalid"
    report.report_hash = compute_canonical_hash(report.model_dump(exclude={"report_hash"}))
    assert RunReportService.verify(report) is False


def test_inmemory_store_isolation_and_transaction_rollback_are_deep():
    store = InMemoryStore()
    scenario = _scenario()
    store.add_scenario(scenario)
    scenario.name = "caller mutation"
    assert store.get_scenario(scenario.scenario_id).name == "Batch 1 scenario"

    retrieved = store.get_scenario(scenario.scenario_id)
    retrieved.name = "retrieval mutation"
    assert store.get_scenario(scenario.scenario_id).name == "Batch 1 scenario"

    with pytest.raises(RuntimeError):
        with store.transaction():
            store._scenarios[scenario.scenario_id].name = "transaction mutation"
            raise RuntimeError("rollback")
    assert store.get_scenario(scenario.scenario_id).name == "Batch 1 scenario"
