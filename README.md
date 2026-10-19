# PROOFSHIELD

**PROOFSHIELD** is an open, local-first, deterministic cybersecurity detection-assurance and failure-diagnosis platform. It evaluates the efficacy of detection engineering pipelines, isolates root-cause telemetry and alerting gaps (e.g. sensor blackouts, pipeline latency, alert routing misattribution, and rule logic silence), and provides verifiable assurance metrics without executing intrusive commands or relying on third-party cloud services.

- **Author & Maintainer**: FS ([@00ppa](https://github.com/00ppa))
- **Status**: Research Prototype (v0.1.0)
- **Test Suite**: 110/110 passing automated tests across 10 modules (0.3s runtime)
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
   Built natively on Python 3.12, FastAPI, Pydantic v2, and pytest. Evaluates entirely in-memory without requiring external cloud accounts or paid vendor APIs.

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
│   └── ARCHITECTURE.md                 # Complete 6-layer architecture specification & Mermaid diagrams
├── fixtures/                           # Synthetic JSONL test datasets
│   ├── alerts_v1.jsonl                 # Security alerts (Wazuh, Sigma, EDR)
│   ├── detection_rules_v1.jsonl        # Sigma & Wazuh detection rules
│   ├── ground_truth_v1.jsonl           # Independent ground-truth expectation records
│   ├── raw_telemetry_malformed_v1.jsonl# Malformed lines for error-isolation testing
│   ├── raw_telemetry_valid_v1.jsonl    # Valid Sysmon & EDR raw events
│   ├── scenarios_v1.jsonl              # Test scenario definitions with ground truth
│   └── test_runs_v1.jsonl              # Synthetic execution records
├── scripts/
│   └── demo.py                         # Standalone interactive terminal demonstration
├── src/
│   └── proofshield/
│       ├── __init__.py                 # Package metadata and version definition
│       ├── main.py                     # FastAPI application factory & entry point
│       ├── api/                        # Layer 6 REST endpoints
│       │   ├── routes_evaluation.py    # Diagnostic evaluation & entity CRUD routes
│       │   ├── routes_health.py        # Health probe endpoints
│       │   └── routes_telemetry.py     # Ingestion & normalisation routes
│       ├── normalisation/              # Layer 3 Telemetry normalisation
│       │   ├── base.py                 # BaseNormaliser abstract contract
│       │   └── engine.py               # Sysmon, Generic EDR, Fallback normalisers & token extraction
│       ├── schemas/                    # Layer 1 Versioned Pydantic models
│       │   ├── alert.py                # AlertV1 schema
│       │   ├── common.py               # Shared enums, diagnostic categories, base model
│       │   ├── detection_rule.py       # DetectionRuleV1 schema
│       │   ├── diagnosis.py            # DiagnosticResultV1 schema (7 categories)
│       │   ├── ground_truth.py         # GroundTruthV1 schema
│       │   ├── scenario.py             # ScenarioV1 schema
│       │   ├── telemetry.py            # RawTelemetryEventV1 & NormalizedTelemetryEventV1
│       │   └── test_run.py             # TestRunV1 schema
│       ├── services/                   # Layer 5 Assurance Engine & Layer 2 Storage
│       │   ├── evaluation.py           # Layer 5 Deterministic Assurance Engine
│       │   └── store.py                # Layer 2 In-memory entity store & correlation engine
│       └── storage/                    # Layer 2 Streaming JSONL
│           └── jsonl_loader.py         # Streaming JSONL reader & schema validator
├── tests/                              # Comprehensive test suite (110 tests)
│   ├── conftest.py                     # Shared pytest fixtures
│   ├── test_api_endpoints.py           # 12 tests: REST API contracts & evaluation routes
│   ├── test_benchmark.py               # 6 tests: 25-case benchmark suite (BM-01 to BM-25)
│   ├── test_evaluation.py              # 19 tests: Layer 5 Assurance Engine core logic
│   ├── test_fault_matrix.py            # 12 tests: Phase 2 Fault-Injection Matrix (FT-01 to FT-12)
│   ├── test_health.py                  # 2 tests: Health check probes
│   ├── test_jsonl_import.py            # 8 tests: JSONL parsing & streaming validation
│   ├── test_normalisation.py           # 5 tests: Telemetry normalisers & attribute preservation
│   ├── test_schemas.py                 # 11 tests: Schema validation & constraint enforcement
│   ├── test_store.py                   # 10 tests: Entity store CRUD, host matching & indexing
│   └── test_token_attribution.py       # 25 tests: Execution-token attribution & strict verification
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
