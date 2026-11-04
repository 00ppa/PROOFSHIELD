"""Regressions for the independent acceptance audit's reproduced failures."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import threading

import pytest
from fastapi.testclient import TestClient

from proofshield.connectors.splunk import SplunkClient, SplunkClientError, SplunkConnectorSettings, map_splunk_alert, map_splunk_result_to_raw
from proofshield.execution.environment import build_child_environment
from proofshield.execution.process_manager import ProcessLifecycleManager
from proofshield.execution.runner import ControlledExecutionRunner
from proofshield.main import create_application
from proofshield.schemas.execution import ExecutionRequestV1
from proofshield.schemas.common import DiagnosticCategory
from proofshield.services.canonical import canonical_json_bytes
from proofshield.services.store import InMemoryStore, set_store
from proofshield.services.report import RunReportService
from proofshield.services.evidence_snapshot import persist_diagnosis
from proofshield.services.explanation import EvidenceGroundedExplanationService
from tests.test_splunk_integration_phase21 import _telemetry, _alert, _context
from tests.mock_splunk_server import run_mock_splunk_server


@pytest.mark.parametrize("line", ['{invalid', '[]', '{"error":"failed"}', '{"preview":true,"result":{}}', '{"messages":[{"type":"ERROR","text":"failed"}]}'])
def test_corrupt_export_never_silently_becomes_complete_evidence(line):
    valid = json.dumps({"result": _telemetry()})
    with pytest.raises(SplunkClientError):
        SplunkClient._decode_results(valid + "\n" + line)


@pytest.mark.parametrize("host", ['x") | outputlookup compromised.csv | search host="x', 'host*', 'host\nvalue'])
def test_spl_injection_rejected_before_network(host):
    client = SplunkClient(SplunkConnectorSettings("http://127.0.0.1:1", "test-only"))
    with pytest.raises(ValueError):
        client.search_telemetry(host=host)


def test_spl_quotes_are_escaped_inside_one_literal():
    assert SplunkClient._literal('a"b\\c') == '"a\\"b\\\\c"'


@pytest.mark.parametrize("url", ['http://remote.example:8089', 'file:///etc/passwd', 'https://user:password@example.com', 'https://example.com?token=x'])
def test_splunk_rejects_unsafe_url(url):
    with pytest.raises(ValueError):
        SplunkConnectorSettings(url, "test-only")


def test_missing_timestamp_and_flat_nested_mapping():
    with pytest.raises(ValueError, match="timestamp"):
        map_splunk_result_to_raw({"host": "host", "process.name": "whoami"})
    value = _alert()
    del value["host"]
    value["host.name"] = "HOST-SPLUNK-01"
    assert map_splunk_alert(value).host_id == "HOST-SPLUNK-01"
    raw = {"_cd": "record", "_time": "2026-11-03T10:00:01Z", "_raw": json.dumps(_telemetry())}
    assert map_splunk_result_to_raw(raw).raw_payload == raw


def test_child_environment_is_allowlisted(monkeypatch):
    for key in ['PROOFSHIELD_EXEC_TOKEN', 'PROOFSHIELD_API_TOKEN', 'PROOFSHIELD_SPLUNK_TOKEN', 'PROOFSHIELD_ELASTIC_API_KEY', 'PYTHONPATH', 'LD_PRELOAD']:
        monkeypatch.setenv(key, 'test-secret-not-in-child')
    child = build_child_environment("attribution-token")
    assert child['PROOFSHIELD_EXECUTION_TOKEN'] == 'attribution-token'
    assert 'test-secret-not-in-child' not in child.values()


def test_dry_run_has_no_workspace_or_process_effect(tmp_path):
    runner = ControlledExecutionRunner(InMemoryStore(), workspace_base_dir=tmp_path)
    with pytest.raises(ValueError, match="dry_run"):
        runner.execute(ExecutionRequestV1(action_id='process.spawn_benign', dry_run=True))
    assert list(tmp_path.iterdir()) == []


def test_capacity_is_reserved_during_spawn(monkeypatch, tmp_path):
    entered, release = threading.Event(), threading.Event()
    class Process:
        pid = 1
        returncode = 0
        def poll(self): return None
        def communicate(self, timeout): return ('', '')
    def spawn(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return Process()
    monkeypatch.setattr(subprocess, 'Popen', spawn)
    manager = ProcessLifecycleManager(max_concurrent=1)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(manager.spawn_and_wait, 'one', ['test'], tmp_path, {}, 1)
        assert entered.wait(2)
        try:
            with pytest.raises(RuntimeError, match="Concurrency"):
                manager.spawn_and_wait('two', ['test'], tmp_path, {}, 1)
        finally:
            release.set()
        assert first.result()[0] == 0


@pytest.mark.parametrize('value', [{1: 'a', '1': 'b'}, 9007199254740993, 10**21, object()])
def test_jcs_rejects_out_of_domain_values(value):
    with pytest.raises(ValueError):
        canonical_json_bytes(value)


@pytest.mark.skipif(shutil.which('node') is None, reason='Independent Node reference not installed')
def test_canonical_bytes_match_independent_ecmascript_reference():
    rng = random.Random(8785)
    numbers = []
    for _ in range(20000):
        value = struct.unpack('!d', rng.getrandbits(64).to_bytes(8, 'big'))[0]
        if __import__('math').isfinite(value):
            numbers.append(value)
    data = {'numbers': numbers, '\U0001d11e': [{'z': 'line\n', 'a': '\u000f\b\t\r\f"\\/'}], '\uffff': 'preserve e\u0301'}
    script = """const fs=require('fs');const value=JSON.parse(fs.readFileSync(0,'utf8'));
    function c(v){if(v===null||typeof v!=='object')return JSON.stringify(v);
    if(Array.isArray(v))return '['+v.map(c).join(',')+']';
    return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+c(v[k])).join(',')+'}';}
    process.stdout.write(c(value));"""
    reference = subprocess.run([shutil.which('node'), '-e', script], input=json.dumps(data).encode(), capture_output=True, check=True, timeout=20, env=build_child_environment())
    assert canonical_json_bytes(data) == reference.stdout


def test_missing_execution_is_not_verified_and_evidence_mutation_changes_provenance():
    from tests.test_phase23_explanation import _store, _result
    store = _store(InMemoryStore())
    result = _result()
    persist_diagnosis(store, result)
    report = RunReportService(store).build(result.test_run_id)
    assert report.integrity_status == 'UNAVAILABLE'
    assert not report.integrity_verified
    original = EvidenceGroundedExplanationService(store).explain(result)
    # Stored scenario substitution is a content change even with the same ID.
    store._scenarios[result.scenario_id].name = 'mutated scenario'
    assert RunReportService(store).build(result.test_run_id).integrity_status == 'FAILED'
    with pytest.raises(ValueError, match='changed'):
        EvidenceGroundedExplanationService(store).explain(result)


def test_real_api_collection_error_replaces_previous_result(monkeypatch):
    store = InMemoryStore()
    _context(store)
    set_store(store)
    with run_mock_splunk_server() as mock:
        monkeypatch.setenv('PROOFSHIELD_SPLUNK_URL', mock.base_url)
        monkeypatch.setenv('PROOFSHIELD_SPLUNK_TOKEN', mock.token)
        monkeypatch.setenv('PROOFSHIELD_SPLUNK_TELEMETRY_INDEX', 'telemetry')
        monkeypatch.setenv('PROOFSHIELD_SPLUNK_ALERT_INDEX', 'alerts')
        monkeypatch.setenv('PROOFSHIELD_SPLUNK_ENABLED', 'true')
        monkeypatch.delenv('PROOFSHIELD_API_TOKEN', raising=False)
        mock.server.telemetry = [_telemetry()]
        mock.server.alerts = [_alert()]
        client = TestClient(create_application())
        assert client.post('/api/v1/splunk/assurance/RUN-SPLUNK-01').json()['diagnostic']['predicted_category'] == 'PASS'
        mock.server.fail_status = 401
        assert client.post('/api/v1/splunk/assurance/RUN-SPLUNK-01').json()['diagnostic']['predicted_category'] == 'ERROR'
        assert client.get('/api/v1/evaluation/RUN-SPLUNK-01').json()['predicted_category'] == 'ERROR'
        assert client.get('/api/v1/reports/runs/RUN-SPLUNK-01').json()['deterministic_category'] == 'ERROR'


def test_redirects_are_blocked_and_response_overflow_is_an_error():
    from proofshield.connectors.transport import NoRedirects
    client = SplunkClient(SplunkConnectorSettings('http://127.0.0.1:1', 'test-only'))
    assert any(isinstance(handler, NoRedirects) for handler in client._opener.handlers)
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, maximum): return b' ' * maximum
    class Opener:
        def open(self, *args, **kwargs): return Response()
    client._opener = Opener()
    with pytest.raises(SplunkClientError, match='byte limit'):
        client.search_telemetry()


def test_research_rejects_overlap_tampering_and_false_provenance():
    from proofshield.research.dataset import DatasetCollector, DatasetValidationError
    from proofshield.research.ml import LogisticRegressionBaseline, evaluate_model
    from tests.test_phase22_research import _research_store
    data = DatasetCollector(_research_store()).collect()
    key = data.observations[0].observation_id
    with pytest.raises(DatasetValidationError, match='disjoint'):
        evaluate_model(LogisticRegressionBaseline(), data, [key], [key], 'SPLIT-invalid')
    modified = data.model_copy(deep=True)
    modified.observations[0].feature_vector['execution_completed'] = 99
    with pytest.raises(DatasetValidationError, match='hash'):
        DatasetCollector.validate(modified)
    modified = data.model_copy(deep=True)
    modified.dataset_hash = None
    modified.includes_synthetic = True
    with pytest.raises(DatasetValidationError, match='provenance'):
        DatasetCollector.validate(modified)


def test_related_scenario_and_shared_evidence_cannot_cross_research_split():
    from proofshield.research.dataset import DatasetCollector
    from tests.test_phase22_research import _research_store
    data = DatasetCollector(_research_store()).collect()
    data.dataset_hash = None
    data.observations[1].scenario_id = data.observations[0].scenario_id
    data.observations[2].evidence_references = ['shared-observation']
    data.observations[3].evidence_references = ['shared-observation']
    split = DatasetCollector.split(data, test_fraction=.5)
    held_out = set(split.test_observation_ids)
    assert (data.observations[0].observation_id in held_out) == (data.observations[1].observation_id in held_out)
    assert (data.observations[2].observation_id in held_out) == (data.observations[3].observation_id in held_out)


def test_unsupported_single_class_training_is_not_reported_as_model_quality():
    from proofshield.research.ml import LogisticRegressionBaseline
    with pytest.raises(ValueError, match='two training classes'):
        LogisticRegressionBaseline().fit([[0], [1]], ['PASS', 'PASS'])


def test_spawn_helper_environment_is_isolated_even_when_run_directly(monkeypatch):
    from proofshield.execution.scripts.spawn_child import _child_environment
    monkeypatch.setenv('PROOFSHIELD_API_TOKEN', 'private-service-secret')
    monkeypatch.setenv('PROOFSHIELD_EXEC_TOKEN', 'private-server-secret')
    monkeypatch.setenv('PYTHONPATH', 'untrusted')
    environment = _child_environment()
    assert 'PROOFSHIELD_API_TOKEN' not in environment
    assert 'PROOFSHIELD_EXEC_TOKEN' not in environment
    assert 'PYTHONPATH' not in environment


def test_premature_http_eof_and_missing_final_marker_are_rejected():
    with run_mock_splunk_server() as mock:
        mock.server.telemetry = [_telemetry()]
        mock.server.extra_content_length = 50
        with pytest.raises(SplunkClientError, match='Premature'):
            mock.get_client().search_telemetry()
    with pytest.raises(SplunkClientError, match='final row'):
        SplunkClient._decode_results(json.dumps({'preview':False, 'lastrow':False, 'result':_telemetry()}))


def test_raw_extracted_token_conflicts_are_never_erased():
    for mapper, source in ((map_splunk_result_to_raw, _telemetry()), (map_splunk_alert, _alert())):
        source['_raw'] = json.dumps({'execution_token':'foreign-execution', 'process.command_line':'whoami TOKEN=foreign-execution'})
        with pytest.raises(ValueError, match='Conflicting'):
            mapper(source)


def test_incomplete_collection_cannot_be_bypassed_by_manual_evaluation():
    from proofshield.services.splunk_orchestrator import SplunkAssuranceOrchestrator
    from proofshield.services.evaluation import AssuranceEngine
    store = InMemoryStore()
    _context(store)
    with run_mock_splunk_server() as mock:
        mock.server.telemetry = [_telemetry(), {**_telemetry(), '_cd':'second-event'}]
        mock.server.alerts = [_alert()]
        service = SplunkAssuranceOrchestrator(mock.get_client(max_results=1), store)
        result, report = service.evaluate_run_with_orchestration('RUN-SPLUNK-01', strict_attribution=True)
        assert result.predicted_category == DiagnosticCategory.ERROR
        assert not report.is_complete
        set_store(store)
        client = TestClient(create_application())
        assert client.post('/api/v1/evaluation/RUN-SPLUNK-01?strict_attribution=true').json()['predicted_category'] == 'ERROR'
        assert not store.get_result_for_run('RUN-SPLUNK-01').metadata['collection']['is_complete']
        mock.server.telemetry = [_telemetry()]
        result, report = service.evaluate_run_with_orchestration('RUN-SPLUNK-01', strict_attribution=True)
        assert result.predicted_category == DiagnosticCategory.PASS


def test_unhashable_new_telemetry_replaces_stale_pass_with_error():
    from proofshield.services.splunk_orchestrator import SplunkAssuranceOrchestrator
    store = InMemoryStore()
    _context(store)
    with run_mock_splunk_server() as mock:
        mock.server.telemetry = [_telemetry()]
        mock.server.alerts = [_alert()]
        service = SplunkAssuranceOrchestrator(mock.get_client(), store)
        assert service.evaluate_run_with_orchestration('RUN-SPLUNK-01', strict_attribution=True)[0].predicted_category == DiagnosticCategory.PASS
        mock.server.telemetry = [{**_telemetry(), '_cd':'unhashable', 'counter':9223372036854775808}]
        result, report = service.evaluate_run_with_orchestration('RUN-SPLUNK-01', strict_attribution=True)
        assert result.predicted_category == DiagnosticCategory.ERROR
        assert store.get_raw_event('splunk:raw:unhashable') is None
        assert store.get_result_for_run('RUN-SPLUNK-01').predicted_category == DiagnosticCategory.ERROR


def test_missing_raw_reference_is_explicit_and_never_verified():
    from proofshield.services.splunk_orchestrator import SplunkAssuranceOrchestrator
    store = InMemoryStore()
    _context(store)
    with run_mock_splunk_server() as mock:
        mock.server.telemetry = [_telemetry()]
        mock.server.alerts = [_alert()]
        result, _ = SplunkAssuranceOrchestrator(mock.get_client(), store).evaluate_run_with_orchestration('RUN-SPLUNK-01', strict_attribution=True)
    del store._raw_events['splunk:raw:tel-splunk-01']
    # Even a fresh snapshot must record the broken normalized->raw link.
    persist_diagnosis(store, result)
    report = RunReportService(store).build('RUN-SPLUNK-01')
    assert report.integrity_status != 'VERIFIED'
    assert report.evidence_snapshot['raw:splunk:raw:tel-splunk-01']['missing']
