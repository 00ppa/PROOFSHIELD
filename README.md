# PROOFSHIELD

**PROOFSHIELD** is an open, local-first, deterministic cybersecurity detection-assurance and failure-diagnosis platform. It evaluates the efficacy of detection engineering pipelines, isolates root-cause telemetry and alerting gaps (e.g. sensor blackouts, pipeline latency, alert routing misattribution, and rule logic silence), and provides verifiable assurance metrics without executing intrusive commands or relying on third-party cloud services.

- **Author & Maintainer**: FS ([@00ppa](https://github.com/00ppa))
- **Status**: Research Prototype (v0.1.0)
- **Test Suite**: 499/499 passing automated tests across 33 modules (6s runtime)
- **Benchmark**: 25 controlled benchmark scenarios (BM-01 to BM-25) + 12-case fault matrix (FT-01 to FT-12)
- **Architecture Specification**: Detailed specifications in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Key Capabilities

1. **Deterministic Root-Cause Failure Diagnosis**:
   Instead of reporting an ambiguous binary pass/fail, PROOFSHIELD evaluates collected evidence across a deterministic 6-step pipeline to classify outcomes into one of **7 formal diagnostic categories**:
   - `PASS`: Expected telemetry observed, detection rule fired, and alert correlated to testing window.
   - `TEST_NOT_EXECUTED`: Test execution failed or errored before generating intended activity.
   - `EXPECTED_TELEMETRY_MISSING`: Telemetry was not observed within the window or failed to match the expected signature (e.g. sensor uninstalled or pipeline dropped logs).
   - `DETECTION_NOT_TRIGGERED`: Telemetry was captured on the target host, but the detection rule failed to fire in the monitoring system.
   - `ALERT_NOT_CORRELATED`: The detection rule fired, but the resulting alert could not be linked to the run (e.g., misrouted hostname or out-of-window arrival).
   - `INCONCLUSIVE`: Telemetry or alerting evidence is present but contradictory, untimestamped, or lacks a rule definition.
   - `ERROR`: Evaluation could not proceed due to missing entity or configuration failure.

2. **Causal Confounding Resolution (BM-25 & Strict Attribution)**:
   Existing validation tools rely solely on spatio-temporal correlation (host + time window). In active environments, unrelated concurrent background tasks on the same host can trigger the expected rule, causing a **false PASS** (False Discovery Rate = 5.0% on the benchmark). PROOFSHIELD introduces **strict execution-token attribution**, binding ephemeral tokens across execution, telemetry, and alerts to eliminate confounding and achieve an **FDR of 0.0%**.

3. **Strict Evidence Segregation & Independent Ground Truth**:
   Ground-truth labels are independently authored and decoupled from engine outputs. Diagnostic predictions never overwrite or alter ground-truth records.

4. **Preservation Guarantees**:
   The telemetry normalisation layer guarantees that original raw identifiers (`raw_event_id`, `source_event_id`) and timestamps (`source_timestamp`) are preserved intact across Sysmon, generic EDR, and fallback formats.

5. **Local-First & Zero Paid Dependencies**:
   Built natively on Python 3.12, FastAPI, Pydantic v2, and pytest. Evaluates entirely in-memory or with local SQLite storage without requiring external cloud accounts or paid vendor APIs.

6. **Multidimensional Evidence Signatures & False-PASS Prevention**:
   Extends scenario validation contracts beyond process names to network connections (`expected_destination_ip`, `expected_destination_port`), file modifications (`expected_file_path`, `expected_file_hash`), and user identities (`expected_user`). Underspecified attack scenarios lacking discriminating signatures are prevented from falsely passing on ambient background activity, deterministically returning `INCONCLUSIVE`.

7. **Opt-In API Telemetry Persistence Bridge**:
   Provides explicit, safe telemetry persistence across REST ingestion routes (`POST /api/v1/telemetry/raw`, `POST /api/v1/telemetry/normalize`, `POST /api/v1/ingest/jsonl`) via `store=true` (default: `store=false`). Supports fault-isolated streaming JSONL batch import with accurate line-level error reporting, atomic all-or-nothing transactions via `atomic=true`, and full parity across both in-memory and persistent SQLite storage backends.

8. **Detection Validation Campaign Engine, Replay & Auditable Evidence (Phase 16)**:
   Orchestrates multi-scenario validation campaigns with deterministic execution ordering, failure isolation policies (`CONTINUE_ON_ERROR` vs `STOP_ON_ERROR`), RFC 8785 canonical evidence manifest hashing (SHA-256), non-destructive replay against immutable captured evidence, regression comparisons (`CampaignComparisonV1`), and root-cause grouping across detection pipelines.

9. **Campaign Assurance Intelligence & Regression Analysis (Phase 17)**:
   Transforms recorded campaign executions into structured detection assurance intelligence:
   - **`CampaignAssuranceReportV1`**: Non-destructive report aggregation with explicit mathematical metrics (`detection_success_rate`, `detection_failure_rate`, `telemetry_availability_rate`, `evidence_completeness_rate`, `alert_correlation_rate`, `inconclusive_rate`, `execution_coverage`), 7-category diagnostic distribution, evidence quality audit, and RFC 8785 canonical SHA-256 digest with retrieval tamper detection.
   - **`CampaignRegressionAnalyzer`**: Evaluates comparability (detecting disjoint scenarios, configuration drift, and engine drift), identifies regressions vs improvements with explicit severities and actionability, and deterministically resolves comparative verdicts (`REGRESSION`, `IMPROVEMENT`, `NO_CHANGE`, `INSUFFICIENT_DATA`, `INCOMPARABLE`).
   - **`RootCauseIntelligenceService`**: Aggregates failure patterns while strictly separating empirically observed facts from plausible inferred explanations.
   - **Full Dual-Backend Persistence & REST API**: Extends both `InMemoryStore` and `SQLiteStore` with `campaign_assurance_reports` table, and exposes versioned `/api/v1` endpoints for report compilation, retrieval, regression comparison, and root-cause intelligence.

---

## Quickstart: Interactive Terminal Demo

To see PROOFSHIELD evaluate nominal detection and isolate real pipeline failure modes in real time:

```bash
# Clone the repository
git clone https://github.com/00ppa/PROOFSHIELD.git
cd PROOFSHIELD

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1

# Install package and dependencies
pip install -e .

# Run the interactive terminal demonstration
python scripts/demo.py
```

### Demonstration Output
```text
==============================================================================
 PROOFSHIELD - Deterministic Detection Assurance & Failure Diagnosis
 Architecture Layer 5 Engine Demo | Author: FS (@00ppa)
==============================================================================

Case 1: Nominal Detection Assurance (Baseline Pass)
------------------------------------------------------------------------------
  Scenario:       PowerShell Download Cradle Execution [T1059.001]
  Target Host:    WORKSTATION-01 (Observation Window: 10:00:00Z - 10:05:00Z)
  Telemetry:      Sysmon Event 1 observed (powershell.exe, Net.WebClient cradle)
  Alert Ingest:   Wazuh alert ALT-WAZ-20261012-001 for RULE-WIN-PS-CRADLE-01
  Ground Truth:   PASS
  Engine Verdict:  [ PASS ]  (Confidence: definitive)
  Evidence IDs:   NORM-B63B1A8DDEF2, ALT-WAZ-20261012-001
  Root Cause:     Expected telemetry observed and detection alert verified and correlated

Case 2: Root-Cause Isolation -- SIEM Alert Routing Fault
------------------------------------------------------------------------------
  Scenario:       LSASS Process Memory Dump via Procdump [T1003.001]
  Target Host:    DC-PROD-01 (procdump.exe -ma lsass.exe executed)
  Telemetry:      EDR process creation captured on DC-PROD-01
  SIEM Incident:  Detection rule fired, but alert was routed to DC-PROD-02 (wrong host)
  Engine Verdict:  [ ALERT_NOT_CORRELATED ]  (Confidence: likely)
  Diagnosis:      Alert from expected rule RULE-WIN-LSASS-DUMP-01 exists in monitoring system, but could not be correlated to this test run's host or time window
  Value:          Distinguishes SIEM routing failure from detection rule logic failure.

Case 3: Root-Cause Isolation -- Telemetry Pipeline Blackout
------------------------------------------------------------------------------
  Execution:      Simulated PowerShell attack executed on WORKSTATION-99
  Sensor State:   Sensor stopped / pipeline dropped all raw logs (0 events ingested)
  Engine Verdict:  [ EXPECTED_TELEMETRY_MISSING ]  (Confidence: likely)
  Diagnosis:      No telemetry events observed within the test run observation window
  Value:          Prevents blaming SIEM detection rules when endpoint sensor is dead.

Case 4: Root-Cause Isolation -- Silent Detection Rule Failure
------------------------------------------------------------------------------
  Telemetry:      Process creation verified on WORKSTATION-01 matching signature
  SIEM State:     Detection rule RULE-WIN-PS-CRADLE-01 was silent (failed to fire)
  Engine Verdict:  [ DETECTION_NOT_TRIGGERED ]  (Confidence: likely)
  Diagnosis:      Expected detection rule RULE-WIN-PS-CRADLE-01 did not trigger
  Value:          Pinpoints rule logic defect because telemetry presence is proven.

Case 5: Research Innovation -- Concurrent Alert Confounding (BM-25)
------------------------------------------------------------------------------
  Attack Event:    Executed with token TOK-ATK-DEMO; detection rule was silent.
  Background Task: Triggered rule RULE-WIN-PS-CRADLE-01 with token TOK-BG-ADMIN.
  Default Mode:    [ PASS ]  <- FALSE PASS (Confounding Blind Spot)
                 Spatio-temporal correlation attributes the background alert to the attack.
  Strict Mode:     [ DETECTION_NOT_TRIGGERED ]  <- ACCURATE DIAGNOSIS (FDR = 0.0%)
                 Token mismatch rejects spurious alert; accurately flags rule as silent.

==============================================================================
 DEMONSTRATION EVALUATION SCORECARD
==============================================================================
Case                   | Scenario            | Ground Truth           | Predicted                  | Result
-----------------------------------------------------------------------------------------------------------
1. Nominal Pass        | T1059.001 PS Cradle | PASS                   | PASS                       | PASS
2. Routing Fault       | T1003.001 LSASS Dump | ALERT_NOT_CORRELATED   | ALERT_NOT_CORRELATED       | PASS
3. Telemetry Drop      | T1059.001 PS Cradle | EXPECTED_TELEMETRY_MISSING | EXPECTED_TELEMETRY_MISSING | PASS
4. Silent Rule         | T1059.001 PS Cradle | DETECTION_NOT_TRIGGERED | DETECTION_NOT_TRIGGERED    | PASS
5. Confounding (Def)   | BM-25 Concurrency   | DETECTION_NOT_TRIGGERED | PASS (Confounded)          | CONF
5. Strict Attr         | BM-25 Concurrency   | DETECTION_NOT_TRIGGERED | DETECTION_NOT_TRIGGERED    | PASS
-----------------------------------------------------------------------------------------------------------
  Execution Time:     2.9 ms (in-memory deterministic evaluation)
  Regression Suite:    110/110 passing automated tests across 8 test suites
  Benchmark Coverage:  25 controlled scenarios (BM-01 to BM-25)
  Strict Mode FDR:     0.0% false-diagnosis rate on synthetic benchmark
==============================================================================
```

---

## Repository Structure

```text
PROOFSHIELD/
├── docs/
│   ├── ARCHITECTURE.md                 # Complete 7-layer architecture specification & Mermaid diagrams
│   └── PROOFSHIELD_LEARNING_GUIDE.md   # Architectural concepts & implementation walkthrough
├── fixtures/                           # Synthetic JSONL test datasets
│   ├── alerts_v1.jsonl                 # Security alerts (Wazuh, Sigma, EDR)
│   ├── detection_rules_v1.jsonl        # Sigma & Wazuh detection rules
│   ├── ground_truth_v1.jsonl           # Independent ground-truth expectation records
│   ├── raw_telemetry_malformed_v1.jsonl# Malformed lines for error-isolation testing
│   ├── raw_telemetry_valid_v1.jsonl    # Valid Sysmon & EDR raw events
│   ├── scenarios_v1.jsonl              # Test scenario definitions with ground truth
│   └── test_runs_v1.jsonl              # Synthetic execution records
├── scripts/
│   ├── demo.py                         # Standalone interactive terminal demonstration
│   └── run_benchmark.py                # Automated benchmark runner across storage backends
├── src/
│   └── proofshield/
│       ├── __init__.py                 # Package metadata and version definition
│       ├── main.py                     # FastAPI application factory & entry point
│       ├── api/                        # Layer 6 REST endpoints
│       │   ├── routes_campaigns.py     # Campaign CRUD, execution, replay, report & comparison routes
│       │   ├── routes_evaluation.py    # Diagnostic evaluation & entity CRUD routes
│       │   ├── routes_health.py        # Health probe endpoints
│       │   └── routes_telemetry.py     # Ingestion & normalisation routes
│       ├── normalisation/              # Layer 3 Telemetry normalisation
│       │   ├── base.py                 # BaseNormaliser abstract contract
│       │   └── engine.py               # Sysmon, Generic EDR, Fallback normalisers & token extraction
│       ├── schemas/                    # Layer 1 Versioned Pydantic models
│       │   ├── alert.py                # AlertV1 schema
│       │   ├── campaign.py             # CampaignDefinitionV1, CampaignRunV1, Manifest, Comparison schemas
│       │   ├── common.py               # Shared enums, diagnostic categories, base model
│       │   ├── detection_rule.py       # DetectionRuleV1 schema
│       │   ├── diagnosis.py            # DiagnosticResultV1 schema (7 categories)
│       │   ├── ground_truth.py         # GroundTruthV1 schema
│       │   ├── scenario.py             # ScenarioV1 schema
│       │   ├── telemetry.py            # RawTelemetryEventV1 & NormalizedTelemetryEventV1
│       │   └── test_run.py             # TestRunV1 schema
│       ├── services/                   # Layer 5 Assurance Engine & Layer 2 Storage
│       │   ├── base_store.py           # StoreProtocol definition including campaign interfaces
│       │   ├── campaign_comparison.py  # Deterministic campaign run regression & diff engine
│       │   ├── campaign_engine.py      # Layer 7 Detection Validation Campaign Engine & Replay
│       │   ├── canonical.py            # RFC 8785 canonical JSON serialization & SHA-256 hashing
│       │   ├── evaluation.py           # Layer 5 Deterministic Assurance Engine
│       │   ├── sqlite_store.py         # SQLiteStore persistent implementation with WAL & savepoints
│       │   └── store.py                # Layer 2 In-memory entity store & correlation engine
│       └── storage/                    # Layer 2 Streaming JSONL
│           └── jsonl_loader.py         # Streaming JSONL reader & schema validator
├── tests/                              # Comprehensive test suite (451 tests across 29 modules)
│   ├── conftest.py                     # Shared pytest fixtures
│   ├── test_campaign_adversarial.py    # Adversarial nesting, script injection & idempotency tests
│   ├── test_campaign_api.py            # FastAPI campaign routes, replay & comparison tests
│   ├── test_campaign_audit_phase16_1.py# Phase 16.1 RFC 8785, content-hash manifest & immutability audit
│   ├── test_campaign_comparison.py     # Deterministic comparison, regressions, improvements & deltas
│   ├── test_campaign_engine.py         # Campaign runner, failure isolation, determinism & root-cause
│   ├── test_campaign_replay.py         # Replay verification, altered/missing evidence & immutability
│   ├── test_campaign_schemas.py        # Schema validation, regex constraints & metric denominators
│   ├── test_campaign_storage.py        # Campaign storage parity across InMemoryStore and SQLiteStore
│   ├── ...                             # 20 additional baseline test modules
│   └── test_token_attribution.py       # Execution-token attribution & strict verification
├── pyproject.toml                      # Standard Python packaging configuration
├── requirements.txt                    # Pinned core and dev dependencies
└── README.md                           # Platform documentation and local instructions
```

---

## Running the REST API

Start the local FastAPI development server:

```bash
# Using uvicorn
uvicorn proofshield.main:app --host 127.0.0.1 --port 8000 --reload

# Or via Python module
python -m proofshield.main
```

- **Interactive OpenAPI Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check Endpoint**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### Storage Configuration & Local Persistence

PROOFSHIELD provides pluggable storage with an in-memory fast path by default and an optional file-backed SQLite adapter for persistent local runs.

#### Configuration Environment Variables

| Variable | Allowed Values | Default | Description |
|---|---|---|---|
| `PROOFSHIELD_STORAGE_BACKEND` | `memory`, `sqlite` | `memory` | Active storage backend adapter. Invalid backend names raise a configuration error. |
| `PROOFSHIELD_SQLITE_PATH` | Valid file path | `proofshield.db` | Target SQLite database file path. |
| `PROOFSHIELD_DB_PATH` | Valid file path | (alias) | Secondary alias for `PROOFSHIELD_SQLITE_PATH`. |

#### Running with Persistence

```bash
# In-Memory Mode (default - fast, ephemeral)
uvicorn proofshield.main:app --reload

# Persistent SQLite Mode (POSIX)
export PROOFSHIELD_STORAGE_BACKEND=sqlite
export PROOFSHIELD_SQLITE_PATH=proofshield.db
uvicorn proofshield.main:app --reload

# Persistent SQLite Mode (PowerShell)
$env:PROOFSHIELD_STORAGE_BACKEND = "sqlite"
$env:PROOFSHIELD_SQLITE_PATH = "proofshield.db"
uvicorn proofshield.main:app --reload
```

> **Operational Safety**: PROOFSHIELD uses FastAPI application lifespan management to validate database paths at startup and clean up resources at shutdown. Startup failures are immediate and visible; PROOFSHIELD will **never** silently fall back from configured SQLite persistence to in-memory storage upon connection or schema initialization failure. Runtime database and WAL artifacts (`*.db`, `*.db-wal`, `*.db-shm`) are excluded from version control.

Example Diagnostic Evaluation API Call:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/evaluation/RUN-20261012-001?strict_attribution=true"
```

Response:
```json
{
  "schema_version": "v1",
  "diagnostic_id": "DIAG-A8B9C0D1E2F3",
  "test_run_id": "RUN-20261012-001",
  "scenario_id": "SCN-T1059.001-01",
  "predicted_category": "PASS",
  "confidence": "definitive",
  "reason": "Expected telemetry observed and detection alert verified and correlated",
  "diagnostic_reasons": [
    "Matched 1 telemetry event(s)",
    "Correlated 1 alert(s) from rule RULE-WIN-PS-CRADLE-01"
  ],
  "supporting_evidence_ids": ["NORM-1DE0F6F2F50B", "ALT-WAZ-20261012-001"],
  "contradictory_evidence_ids": [],
  "evaluated_at": "2026-10-16T03:20:00Z",
  "engine_version": "v0.1.0",
  "metadata": {
    "attribution": {
      "status": "verified",
      "strict_attribution": true,
      "cryptographic_proof": false,
      "disclaimer": "Execution token attribution verifies provenance linkage, not cryptographic non-repudiation."
    }
  }
}
```

---

## Detection Validation Campaigns (Phase 16)

Phase 16 introduces **Detection Validation Campaigns**, an automated engine that groups individual scenarios into reproducible validation suites, executes the deterministic assurance workflow across each scenario, cryptographically fingerprints collected evidence into an **auditable evidence manifest**, and supports non-destructive replays and regression comparisons.

### Beginner Explanation: The End-to-End Campaign Workflow

If you are learning how PROOFSHIELD works, here is the complete journey of how validation data flows through the system, from authoring a campaign to comparing runs:

`Campaign Definition → Scenario Evaluation → Evidence Capture → Run Persistence → Report → Replay → Comparison`

#### Step-by-Step Walkthrough with a Concrete 3-Scenario Example

Imagine a security team wants to validate three detection behaviors in their environment:
1. **Scenario 1: `SCN-PS-CRADLE` (PowerShell Download Cradle)**
   - Expected: Telemetry observed + Wazuh rule `RULE-WIN-PS-CRADLE-01` fires + Alert arrives on `WS-01`.
   - What happens: The endpoint sensor captures the PowerShell command line, and Wazuh emits the alert.
   - Outcome: **`PASS`**.
2. **Scenario 2: `SCN-LSASS-DUMP` (Procdump LSASS Memory Access)**
   - Expected: Telemetry observed + Alert correlated to target host `DC-PROD-01`.
   - What happens: Telemetry is observed, and the detection rule fires, but the SIEM misroutes the alert to hostname `DC-PROD-02`.
   - Outcome: **`ALERT_NOT_CORRELATED`** (The rule worked, but SIEM alert routing failed).
3. **Scenario 3: `SCN-NET-RECON` (Internal Port Scan / Reconnaissance)**
   - Expected: Network telemetry captured on `WS-02` + Port scan alert correlated.
   - What happens: The endpoint sensor on `WS-02` was stopped or the pipeline dropped logs (0 network events recorded).
   - Outcome: **`EXPECTED_TELEMETRY_MISSING`** (Sensor blackout; rule never had telemetry to inspect).

Here is how PROOFSHIELD processes these three scenarios step-by-step:

1. **Campaign Definition (`CampaignDefinitionV1`)**
   In `src/proofshield/schemas/campaign.py`, you define a campaign `CAMP-PROD-VALIDATION-01` listing `ordered_scenario_ids = ["SCN-PS-CRADLE", "SCN-LSASS-DUMP", "SCN-NET-RECON"]`. You configure execution policy `CONTINUE_ON_ERROR` so that a failure in one scenario does not stop the others.

2. **Scenario Evaluation (`AssuranceEngine.evaluate_run`)**
   The `CampaignEngine` (`src/proofshield/services/campaign_engine.py`) takes each scenario in declared order, looks up the corresponding `TestRunV1`, and invokes `AssuranceEngine.evaluate_run(test_run_id)`. The Assurance Engine checks:
   - Did the test run execute?
   - Is telemetry present within the target host and observation window?
   - Does the telemetry match the process/network/file signature?
   - Did the expected detection rule fire?
   - Is the resulting alert correlated in time and space?

3. **Evidence Capture & Manifest Hashing (`EvidenceManifestV1` & `canonical_sha256`)**
   Every piece of evidence supporting or contradicting each verdict is captured. All scenario definitions, test runs, normalized telemetry event payloads, alert payloads, ground-truth records, and execution configuration are canonicalized into an `EvidenceManifestV1` ([canonical.py](file:///D:/PROOFSHIELD/src/proofshield/services/canonical.py)). A deterministic SHA-256 digest is computed over the RFC 8785 canonical JSON bytes.

   > [!IMPORTANT]
   > **Integrity Scope & Threat Model**:
   > - **What ProofShield implements today**: Hash verification computes a deterministic SHA-256 digest over canonical evidence bytes and compares evidence payloads against stored manifest hashes during replay. This detects accidental data modification, entity substitution, or record drift relative to the stored reference digest.
   > - **Limits of local SHA-256 hashing**: SHA-256 alone does not prevent adversarial tampering if an attacker possesses write permissions to both the evidence records and their stored manifest digest, as an attacker could recompute a valid hash over forged inputs.
   > - **Future hardening**: Stronger tamper resistance requires independently protected reference digests—for example, via access-controlled append-only storage, an out-of-band audit logging system, or cryptographic digital signatures backed by a protected private signing key.
   > - **Authenticity vs Truthfulness**: Even a valid digital signature or matching hash proves only that a specific payload or signing key created the record; it does not by itself prove that the original endpoint telemetry was truthful, unevaded, or faithfully captured by the sensor.

4. **Run Persistence (`InMemoryStore` or `SQLiteStore`)**
   The entire execution record—including start/end timestamps, per-scenario results, root-cause groups, summary metrics, and the evidence manifest—is saved atomically as a `CampaignRunV1`. In SQLite mode, this is committed to `campaign_runs` with foreign key integrity.

5. **Deterministic Report & Root-Cause Grouping (`CampaignSummaryV1`)**
   The engine aggregates findings:
   - Scenarios: 3 total, 3 executed (100% coverage).
   - `pass_rate`: 1 / 3 (33.3%).
   - Root-cause grouping:
     - Group 1: `ALERT_CORRELATION_FAILURE` affects 1 scenario (`SCN-LSASS-DUMP`).
     - Group 2: `MISSING_EXPECTED_TELEMETRY` affects 1 scenario (`SCN-NET-RECON`).
   This immediately tells detection engineers: "1 rule passed, 1 rule worked but alert routing is broken, and 1 sensor is dead."

6. **Replay Engine (`CampaignEngine.replay_campaign_run`)**
   Weeks later, detection engineers patch the SIEM routing rules and want to verify their evaluation logic without re-executing attacks. They call `POST /api/v1/campaign-runs/{run_id}/replay`. PROOFSHIELD loads the historical evidence manifest, verifies all evidence records exist in the store, and creates a *new* replay run (`is_replay=True`) linked to the original `source_run_id`. The original historical run is never overwritten.

7. **Run Comparison (`CampaignComparisonEngine.compare_runs`)**
   The engineers compare the original run with a new run using `GET /api/v1/campaign-runs/{run_id}/compare/{other_run_id}`. The engine reports:
   - `regressions`: [] (nothing broke).
   - `improvements`: [`SCN-LSASS-DUMP`] (moved from `ALERT_NOT_CORRELATED` to `PASS` after routing fix).
   - `manifest_match`: `False` (new alerts ingested).

---

## Running Automated Tests

Run the full pytest suite:

```bash
pytest -v
```

All **110 tests pass in ~0.30 seconds**:
1. `tests/test_api_endpoints.py` (12 tests): Schema catalog, raw event ingestion, multi-line JSONL streaming API, and end-to-end evaluation workflow via REST endpoints.
2. `tests/test_benchmark.py` (6 tests): Comprehensive 25-scenario benchmark (BM-01 to BM-25), metric denominators, ground-truth oracle verification, and causal confounding audit.
3. `tests/test_evaluation.py` (19 tests): Deterministic Layer 5 Assurance Engine evaluation across all 7 diagnostic categories, running status guards, historical alert scoping, and latency classification.
4. `tests/test_fault_matrix.py` (12 tests): Fault-Injection Matrix (FT-01 through FT-12) evaluating nominal passes, sensor blackouts, rule mismatches, alert routing faults, and IP isolation.
5. `tests/test_health.py` (2 tests): Root `/health` and versioned `/api/v1/health` response accuracy.
6. `tests/test_jsonl_import.py` (8 tests): Streaming JSONL validation, round-trip serialization, and line-isolated error handling across all schemas.
7. `tests/test_normalisation.py` (5 tests): Sysmon Event 1 process extraction, Event 3 network extraction, Generic EDR parsing, and source ID/timestamp preservation across providers.
8. `tests/test_schemas.py` (11 tests): Schema validation, MITRE ATT&CK regex enforcement, time window validation, and independent ground-truth decoupling.
9. `tests/test_store.py` (10 tests): In-memory entity CRUD operations, reset isolation, safe IP matching, and NetBIOS/FQDN host correlation.
10. `tests/test_token_attribution.py` (25 tests): Token extraction precedence, conflict detection, strict attribution nominal pass, missing/conflicting token handling, grace-window boundary guards, and BM-25 resolution.

---

## Reproducing Benchmark Results (Phase 7)

PROOFSHIELD includes an automated benchmark runner (`scripts/run_benchmark.py`) that evaluates the deterministic Assurance Engine against the versioned 25-scenario benchmark corpus (BM-01 to BM-25). It measures root-cause isolation fidelity, evidence validation, and causal attribution across multiple storage engines.

### Benchmark Runner CLI Usage

The benchmark runner supports multiple storage backends, human-readable summary formatting, and machine-readable JSON exports:

```bash
# Basic usage with in-memory storage (default)
python scripts/run_benchmark.py --backend memory

# Execute benchmark with in-memory SQLite backend
python scripts/run_benchmark.py --backend sqlite

# Execute benchmark with isolated temporary file-backed SQLite databases
python scripts/run_benchmark.py --backend sqlite_file
```

#### CLI Options Reference

| Option | Flag | Allowed Values | Default | Description |
|---|---|---|---|---|
| `--backend` | `-b` | `memory`, `sqlite`, `sqlite_file` | `memory` | Storage backend adapter used for isolating each benchmark scenario. |
| `--output` | `-o` | Valid file path | `None` | Path where the structured JSON report will be saved. Parent directories are created automatically. |
| `--quiet` | `-q` | Flag | `False` | Suppresses the stdout tabular summary. When combined with `--output`, execution is silent. When used without `--output`, prints raw JSON to stdout. |

#### Generating Machine-Readable JSON Reports

To generate a reproducible JSON benchmark report for regression tracking, CI/CD verification, or external tooling:

```bash
# Output JSON report while printing summary scorecard to stdout
python scripts/run_benchmark.py --backend memory --output artifacts/benchmark_report.json

# Silent JSON generation for automated CI pipelines
python scripts/run_benchmark.py --backend sqlite --output artifacts/benchmark_report.json --quiet

# Stream raw JSON report directly to stdout for piping (e.g. jq)
python scripts/run_benchmark.py --backend memory --quiet | jq .aggregate_metrics
```

The resulting JSON report records:
- **Environment Metadata**: `benchmark_version` ("7.0.0"), `corpus_version` ("2.2"), Python runtime version, OS platform, timestamp, and active backend.
- **Per-Case Outcomes**: For each of the 25 scenarios, records `expected_category`, `predicted_category`, agreement (`correct`), `confidence`, `reason`, `injected_fault`, evidence counts, and `evidence_valid`.
- **Aggregate Metrics**: Summary metrics, precision/recall/F1 per category, unexecuted rate, and coverage.
- **Confusion Matrix**: Full $7 \times 7$ categorical confusion matrix.
- **Metric Definitions**: Formal formulas, numerators, denominators, and zero-denominator handling rules.
- **Known Limitations**: Explicit architectural boundaries.

---

### Diagnostic Quality Metrics & Denominators

All benchmark metrics are computed dynamically from actual predictions using strict mathematical definitions. Inconclusive outcomes are treated as valid diagnostic states rather than missing data:

| Metric | Mathematical Formula | Numerator & Denominator Definitions | Synthetic Baseline Value |
|---|---|---|---|
| **Diagnostic Accuracy** | $\frac{\text{Correct}}{\text{Total}}$ | **Numerator**: Test runs where predicted category matches ground truth.<br>**Denominator**: Total evaluated test runs ($N = 25$).<br>*Edge case*: Returns `0.0` if $N = 0$. | `0.9600` (24/25) |
| **False-Diagnosis Rate (FDR)** | $\frac{\text{False Confident}}{\text{Total Confident}}$ | **Numerator**: Confident predictions ($\hat{y} \ne \text{INCONCLUSIVE}$) that disagree with ground truth ($y \ne \hat{y}$).<br>**Denominator**: Total confident predictions ($\hat{y} \ne \text{INCONCLUSIVE}$). `INCONCLUSIVE` outcomes are excluded from both numerator and denominator.<br>*Edge case*: Returns `0.0` if total confident predictions equal 0. | `0.0500` (1/20 in default mode)<br>`0.0000` (0/20 in strict attribution mode) |
| **Inconclusive Rate (IR)** | $\frac{\text{Inconclusive}}{\text{Total}}$ | **Numerator**: Test runs classified as `INCONCLUSIVE` due to ambiguous evidence (missing alert timestamps, running status, or unspecified rules).<br>**Denominator**: Total evaluated test runs ($N = 25$).<br>*Edge case*: Returns `0.0` if $N = 0$. | `0.2000` (5/25: BM-04, BM-11, BM-12, BM-19, BM-20) |
| **Coverage** | $\frac{\text{Total Confident}}{\text{Total}}$ | **Numerator**: Test runs receiving a confident diagnosis ($\hat{y} \ne \text{INCONCLUSIVE}$).<br>**Denominator**: Total evaluated test runs ($N = 25$). Note: $\text{Coverage} + \text{Inconclusive Rate} = 1.0$.<br>*Edge case*: Returns `0.0` if $N = 0$. | `0.8000` (20/25) |
| **Evidence Completeness** | $\frac{\text{Valid Evidence}}{\text{Total}}$ | **Numerator**: Test runs where all referenced evidence IDs exist in the store and strictly satisfy category substantiation rules without causal contamination (`validate_evidence_support()`).<br>**Denominator**: Total evaluated test runs ($N = 25$).<br>*Edge case*: Returns `0.0` if $N = 0$. | `0.9600` (24/25: BM-25 fails evidence support) |

Additionally, the runner computes **Unexecuted Rate** ($\frac{\text{Unexecuted Count}}{\text{Total}} = 2/25 = 0.0800$) and per-category **Precision**, **Recall**, and **F1** scores with zero-division handling (returning `1.0` if both precision/recall denominators are 0 for absent categories).

---

### BM-25 Causal Confounding Analysis & Limitations

#### The Causal Confounding Problem
In standard detection validation tools, evaluation relies entirely on **spatio-temporal correlation**: if an alert matching the expected detection rule arrives on the target host within the test execution window, the run is marked as `PASS`.

Scenario **BM-25** establishes a rigorous counterexample to this heuristic:
1. A test attack (e.g. simulated PowerShell cradle, PID 4001) executes on host `WS-TARGET-01`.
2. The detection rule is **silent** for this attack (pipeline defect or evasion).
3. Simultaneously, an unrelated legitimate administrative script (PID 9999) executes on `WS-TARGET-01` within the identical time window and fires the expected detection rule (`RULE-SIGMA-CRADLE-01`).
4. Under default spatio-temporal correlation, the Assurance Engine correlates the background alert to the attack run and emits `PASS`. This represents a **false pass** (a false diagnosis), resulting in an FDR of 5.0% (1/20).

BM-25 empirically demonstrates that **host and time co-occurrence cannot establish causal linkage**.

#### Resolution via Strict Attribution
PROOFSHIELD resolves this epistemic gap via **execution-token attribution** (evaluated in `tests/test_token_attribution.py`):
- Unique ephemeral tokens (`token_id`) are embedded into the attack process invocation, telemetry events, and emitted alerts.
- In strict attribution mode (`strict_attribution=true`), the Assurance Engine verifies token continuity across all evidence.
- The spurious background alert from PID 9999 is rejected because its token does not match the test run.
- The engine accurately isolates rule silence and returns `DETECTION_NOT_TRIGGERED`, achieving **0.0% FDR** (0/20).

#### Synthetic Scope vs. Real-World Diagnostic Boundaries
- **Synthetic Benchmark Fidelity**: The 96.0% default accuracy (24/25) and 100% strict attribution accuracy demonstrate the formal correctness of PROOFSHIELD's decision boundaries, fault-isolation invariants, and database parity under controlled conditions.
- **Real-World Scope Disclaimer**: Synthetic benchmark performance does **not** guarantee equivalent accuracy in live enterprise environments. Live SOC environments encounter unmodeled telemetry transport drops, clock drift, middlebox NAT rewriting, delayed SIEM indexing pipelines, and asynchronous alert deduplication that lie outside the synthetic corpus. PROOFSHIELD's benchmark measures architectural soundness, not commercial operational infallibility.

---

## Research Validity & Scope Disclaimers

- **Synthetic vs. Real-World Scope**: All benchmark evaluations (BM-01 to BM-25 and FT-01 to FT-12) are conducted against controlled synthetic datasets and fault-injection models to rigorously verify decision boundaries, failure isolation, and correlation invariants. They demonstrate algorithmic validity and pipeline defect isolation; they do not claim empirical validation on live corporate enterprise SOC telemetry.
- **Execution Provenance vs. Cryptographic Proof**: Execution-token attribution provides execution provenance linking test runs, telemetry, and alerts. It does not claim cryptographic non-repudiation or formal philosophic causality.

---

## Authorship & Academic Citation

PROOFSHIELD was conceived, designed, and implemented by **FS** ([@00ppa](https://github.com/00ppa)).

If you reference or build upon this work in academic research, benchmark studies, or detection engineering evaluations, please cite:

```bibtex
@software{proofshield2026,
  author       = {FS},
  title        = {{PROOFSHIELD: Cybersecurity Detection Assurance and Failure-Diagnosis Platform}},
  year         = {2026},
  publisher    = {GitHub},
  howpublished = {\url{https://github.com/00ppa/PROOFSHIELD}},
  version      = {0.1.0}
}
```

---

## Intellectual Property & Commercial Reservation

Copyright &copy; 2026 FS ([@00ppa](https://github.com/00ppa)). All rights reserved.

This repository is made available for academic research, peer review, and professional portfolio evaluation. Commercialization, proprietary integration, software-as-a-service (SaaS) deployment, or redistribution of this software or substantial portions thereof requires explicit written authorization from the author.
