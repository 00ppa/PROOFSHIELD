"""Opt-in real-browser test over the local API and explicit synthetic SIEM data.

Run with PROOFSHIELD_BROWSER_TESTS=1 and Playwright's Chromium or Edge installed.
The real benign action executes; the mocked telemetry is NOT sensor validation.
"""

from contextlib import contextmanager
import json
import os
import socket
import sys
import threading

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("PROOFSHIELD_BROWSER_TESTS") != "1", reason="Opt-in browser acceptance")


def test_browser_execution_to_report(monkeypatch):
    from playwright.sync_api import sync_playwright, expect
    import uvicorn
    from proofshield.main import create_application
    from proofshield.services.store import InMemoryStore, set_store
    from tests.mock_splunk_server import run_mock_splunk_server

    store = InMemoryStore()
    set_store(store)
    monkeypatch.setenv("PROOFSHIELD_EXEC_TOKEN", "browser-execution-test-only")
    monkeypatch.setenv("PROOFSHIELD_API_TOKEN", "browser-api-test-only")
    with run_mock_splunk_server() as mock:
        for key, value in {"URL": mock.base_url, "TOKEN": mock.token, "ENABLED": "true", "TELEMETRY_INDEX": "telemetry", "ALERT_INDEX": "alerts"}.items():
            monkeypatch.setenv("PROOFSHIELD_SPLUNK_" + key, value)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        config = uvicorn.Config(create_application(), log_level="error", lifespan="off")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
        thread.start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(channel="msedge" if sys.platform == "win32" else "chromium", headless=True)
                try:
                    page = browser.new_page()
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(f"http://127.0.0.1:{port}/ui")
                    page.locator('#apiToken').fill('browser-api-test-only')
                    page.locator('#executionToken').fill('browser-execution-test-only')
                    page.locator('#source').select_option('splunk')
                    def click(identifier):
                        page.locator('#' + identifier).click()
                        expect(page.locator('#state')).to_have_text('Complete', timeout=15000)
                        return json.loads(page.locator('#output').inner_text())
                    assert click('status')['configured']
                    scenario = json.loads(page.locator('#scenario').input_value())
                    scenario['expected_process_name'] = 'whoami.exe' if sys.platform == 'win32' else 'whoami'
                    scenario['validation_target'] = 'EXPECTED_ALERT'
                    scenario['expected_detection_rule_id'] = 'RULE-BROWSER'
                    page.locator('#scenario').fill(json.dumps(scenario))
                    assert click('createScenario')['scenario_id'] == 'SCN-LOCAL-001'
                    page.locator('summary').click()
                    page.locator('#rule').fill(json.dumps({'rule_id':'RULE-BROWSER','rule_name':'Browser synthetic test rule','rule_format':'splunk'}))
                    assert click('createRule')['rule_id'] == 'RULE-BROWSER'
                    assert click('validate')['is_valid']
                    execution = click('execute')
                    assert execution['status'] == 'COMPLETED'
                    run_id = execution['test_run_id']
                    assert run_id == page.locator('#runId').input_value()
                    page.locator('#verification').fill('Synthetic SIEM response fixture defined independently by test')
                    page.locator('#verificationEvidence').fill('tests/test_browser_workflow.py')
                    assert click('groundTruth')['run_id'] == run_id
                    mock.server.telemetry = [{'_cd': 'browser-event', '_time': execution['completed_at'], 'event.category': 'process',
                        'host.name': execution['target_host'], 'process.name': scenario['expected_process_name'],
                        'execution_token': execution['execution_token']}]
                    mock.server.alerts = [{'event_id': 'browser-alert', '_time': execution['completed_at'], 'host': execution['target_host'],
                        'rule_id': 'RULE-BROWSER', 'execution_token': execution['execution_token']}]
                    assert click('collect')['diagnostic']['predicted_category'] == 'PASS'
                    report = click('report')
                    assert report['integrity_status'] == 'VERIFIED'
                    assert report['evidence_snapshot']
                    assert click('explain')['deterministic_category'] == 'PASS'
                    with page.expect_download() as exported:
                        click('export')
                    assert exported.value.suggested_filename == 'proofshield-evidence.json'
                    mock.server.alerts[0]['execution_token'] = 'unrelated'
                    # Same source ID with changed content is rejected, never a stale PASS.
                    assert click('collect')['diagnostic']['predicted_category'] == 'ERROR'
                    assert not errors
                finally:
                    browser.close()
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            listener.close()
