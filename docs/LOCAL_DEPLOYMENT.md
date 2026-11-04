# Local Deployment and Demonstration

## Install

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,research]"
```

`.env.example` documents variable names; the server does not automatically load
dotenv files. Set variables in the invoking shell. Keep real credentials outside
Git. Set `PROOFSHIELD_EXEC_TOKEN` to unlock execution and optionally set the
distinct `PROOFSHIELD_API_TOKEN` for all other API routes. For persistence set
`PROOFSHIELD_STORAGE_BACKEND=sqlite` and a writable `PROOFSHIELD_SQLITE_PATH`.

## Run

```powershell
uvicorn proofshield.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/ui` for the analyst console. The console invokes the real evaluation, explanation, Splunk assurance, and report endpoints.

Alternatively, `py -3.12 scripts/serve.py` starts a source checkout on loopback
port 8000. The static UI is included in package builds. Linux and Windows Python
3.12 CI jobs are configured in `.github/workflows/tests.yml`; Windows was tested
locally. No external deployment is performed by these instructions.

## End-to-end sequence

1. Configure Elasticsearch or Splunk using environment variables; check source status in the UI.
2. Create a scenario and, for EXPECTED_ALERT, its expected detection rule. Match `whoami.exe` on Windows or `whoami` on POSIX. The server is the execution host.
3. Validate and execute an approved action in the UI. `/api/v1/execution/run` returns its run ID. `dry_run=true` is rejected by execution; `/execution/validate` is the side-effect-free route.
4. Author ground truth independently for that run, with verification method/evidence. Then collect via `/api/v1/elastic/assurance/{run_id}` or `/api/v1/splunk/assurance/{run_id}`. The UI explicitly enables strict attribution.
5. Review `/api/v1/evaluation/{run_id}` and `/api/v1/reports/runs/{run_id}`.
6. Generate `/api/v1/explanations/{run_id}` and inspect its evidence references and hypotheses.
7. Download the JSON report/evidence snapshot or `/api/v1/reports/runs/{run_id}/export.csv`.

The authenticated `/api/v1/execution/workflow/{elastic|splunk}` endpoint also
combines controlled execution, settling, collection, diagnosis and report
generation. The split UI workflow permits independent labeling before diagnosis.

Report integrity is `VERIFIED`, `UNAVAILABLE`, or `FAILED`. It binds observed
payload hashes captured with the diagnosis, not just event IDs. A missing execution
record is unavailable, not verified. Digests do not prove sensor truth or resist
an attacker who can rewrite both the payload and its reference digest.

## Verification

```powershell
py -3.12 -m pytest -q
py -3.12 -m pytest -k benchmark -q
py -3.12 scripts/run_research.py
```

Live SIEM tests are optional. The repository’s mock Elastic and Splunk servers provide repeatable offline integration coverage.

For the real browser integration test:

```powershell
python -m pip install playwright
# Windows uses installed Edge. On Linux: python -m playwright install chromium
$env:PROOFSHIELD_BROWSER_TESTS = "1"
py -3.12 -m pytest tests/test_browser_workflow.py -q
```

The browser test runs a real benign action but supplies **synthetic mock SIEM
evidence**. Real environment-token visibility must be verified with the selected
endpoint sensor. Standard Sysmon process creation alone does not export arbitrary
environment variables; absence of an independently captured token must remain
inconclusive under strict attribution, never be filled from test expectations.
