# PROOFSHIELD

**PROOFSHIELD** is an open, local-first, deterministic cybersecurity detection assurance and failure-diagnosis platform. It evaluates the efficacy of detection engineering pipelines, isolates root-cause telemetry gaps (e.g. logging disabled, pipeline latency, rule field mismatches, alert suppression), and provides verifiable assurance metrics without executing harmful commands or relying on third-party paid services.

---

## Architectural Principles & Development Rules

1. **Local-First & Zero Paid Dependencies**: Built natively on Python 3.12, FastAPI, Pydantic v2, and pytest. Runs completely locally without third-party cloud services.
2. **Strict Evidence Segregation**: Raw telemetry records, normalized events, scenario ground truth, detection rules, alerts, and diagnostic outcomes remain decoupled across independent data models.
3. **Independent Ground Truth**: Ground-truth labels are authored with test scenarios and are **never** overwritten or altered by diagnostic engine outputs.
4. **Deterministic Evaluation (Layer 5 Assurance Engine)**: Diagnostic evaluation uses rule-based determinism against explicit evidence. Ambiguous or contradictory evidence yields an `INCONCLUSIVE` verdict rather than unsupported guesswork.
5. **Preservation Guarantees**: The normalisation layer strictly preserves original source-event identifiers and source timestamps across all formats.
6. **Provenance & Safety**: All test runs explicitly declare whether data originates from synthetic simulation or emulated agents. No intrusive commands or shell scripts are ever executed from imported telemetry.
7. **Seven Diagnostic Categories (Spec Section 6)**:
   - `PASS`: Expected telemetry observed, detection triggered, alert correlated to testing window.
   - `TEST_NOT_EXECUTED`: Test execution failed or errored before producing intended behaviour.
   - `EXPECTED_TELEMETRY_MISSING`: Telemetry not observed within window or did not match expected signature.
   - `DETECTION_NOT_TRIGGERED`: Telemetry present, but expected detection rule did not fire.
   - `ALERT_NOT_CORRELATED`: Alert exists from expected rule but cannot be linked to test run (host or window mismatch).
   - `INCONCLUSIVE`: Telemetry present but ambiguous, contradictory, or lacks rule definition for verdict.
   - `ERROR`: Evaluation could not proceed due to missing entity or configuration error.

---

## Repository Structure

```text
PROOFSHIELD/
├── fixtures/                           # Synthetic JSONL test datasets
│   ├── alerts_v1.jsonl                 # Security alerts (Wazuh, EDR)
│   ├── detection_rules_v1.jsonl        # Sigma & Wazuh detection rules
│   ├── ground_truth_v1.jsonl           # Independent ground-truth expectation records
│   ├── raw_telemetry_malformed_v1.jsonl# Malformed lines for error-isolation testing
│   ├── raw_telemetry_valid_v1.jsonl    # Valid Sysmon & EDR raw events
│   ├── scenarios_v1.jsonl              # Test scenario definitions with ground truth
│   └── test_runs_v1.jsonl              # Synthetic execution records
├── src/
│   └── proofshield/
│       ├── __init__.py
│       ├── main.py                     # FastAPI application factory & entry point
│       ├── api/
│       │   ├── __init__.py
│       │   ├── routes_evaluation.py    # Diagnostic evaluation & entity CRUD routes
│       │   ├── routes_health.py        # Health probe endpoints
│       │   └── routes_telemetry.py     # Ingestion & normalisation routes
│       ├── normalisation/
│       │   ├── __init__.py
│       │   ├── base.py                 # BaseNormaliser abstract contract
│       │   └── engine.py               # Sysmon, Generic EDR & Fallback normalisers
│       ├── schemas/
│       │   ├── __init__.py
│       │   ├── alert.py                # AlertV1 schema
│       │   ├── common.py               # Shared enums, categories, and base model
│       │   ├── detection_rule.py       # DetectionRuleV1 schema
│       │   ├── diagnosis.py            # DiagnosticResultV1 schema (7 categories)
│       │   ├── ground_truth.py         # GroundTruthV1 schema
│       │   ├── scenario.py             # ScenarioV1 schema
│       │   ├── telemetry.py            # RawTelemetryEventV1 & NormalizedTelemetryEventV1
│       │   └── test_run.py             # TestRunV1 schema
│       ├── services/
│       │   ├── __init__.py
│       │   ├── evaluation.py           # Layer 5 Deterministic Assurance Engine
│       │   └── store.py                # In-memory entity store & correlation engine
│       └── storage/
│           ├── __init__.py
│           └── jsonl_loader.py         # Streaming JSONL reader & schema validator
├── tests/                              # Automated test suite (54 tests)
│   ├── conftest.py
│   ├── test_api_endpoints.py
│   ├── test_evaluation.py
│   ├── test_health.py
│   ├── test_jsonl_import.py
│   ├── test_normalisation.py
│   ├── test_schemas.py
│   └── test_store.py
├── pyproject.toml                      # Standard Python packaging configuration
├── requirements.txt                    # Pinned core and dev dependencies
└── README.md                           # Platform documentation and local instructions
```

---

## Core Versioned Schemas (v1)

- **`ScenarioV1`**: Defines adversary behavior under test (e.g. MITRE ATT&CK technique), expected event categories, detection rule targets, and the capability `validation_target` (`EXPECTED_ALERT`, `EXPECTED_TELEMETRY_ONLY`, `EXPECTED_BENIGN`).
- **`TestRunV1`**: Defines the execution instance, target endpoint/user, observation time window, execution status, and provenance (`execution_mode` such as `SYNTHETIC_SIMULATION` with mandatory `is_synthetic` boolean flag).
- **`RawTelemetryEventV1`**: Immutable evidence container preserving the original payload dictionary, `source_event_id`, and `source_timestamp`.
- **`NormalizedTelemetryEventV1`**: Canonical schema (`PROCESS_CREATION`, `NETWORK_CONNECTION`, etc.) with mapped process, hash, and network fields while strictly maintaining references to `raw_event_id`, preserved `source_event_id`, and original `source_timestamp`.
- **`DetectionRuleV1`**: Versioned detection rule record tracking rule formats (Sigma, Wazuh, Splunk), content hashes, and target evaluation backends.
- **`AlertV1`**: Security monitoring alert record correlated to test runs by host (supporting NetBIOS and FQDN) and temporal window.
- **`DiagnosticResultV1`**: Deterministic verdict classifying outcomes into one of the 7 diagnostic categories, with `confidence` level, detailed `diagnostic_reasons`, and explicit lists of `supporting_evidence_ids` and `contradictory_evidence_ids`.
- **`GroundTruthV1`**: Independently authored expectation records for measuring diagnostic classification accuracy against controlled attack executions or fault injections.

---

## Local Setup & Installation

### Prerequisites
- Python 3.11 or Python 3.12 installed on your system.

### 1. Create and Activate Virtual Environment

```bash
# Windows (PowerShell)
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Dependencies and Editable Package

```bash
pip install -r requirements.txt
pip install -e .
```

---

## Running the Application Locally

Start the local FastAPI development server:

```bash
# Using uvicorn CLI
uvicorn proofshield.main:app --host 127.0.0.1 --port 8000 --reload

# Or directly via Python module
python -m proofshield.main
```

Once running:
- **Interactive OpenAPI Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc API Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check Endpoint**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health) or [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

Example Diagnostic Evaluation API Call:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/evaluation/RUN-20261012-001
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
  "supporting_evidence_ids": ["RAW-SYS-20261012-001", "ALT-WAZ-20261012-001"],
  "contradictory_evidence_ids": [],
  "evaluated_at": "2026-10-13T00:50:00Z",
  "engine_version": "v0.1.0",
  "metadata": {}
}
```

---

## Running Automated Tests

Run the complete pytest test suite:

```bash
pytest -v
```

All 70 tests validate:
1. `test_health.py`: Root `/health` and versioned `/api/v1/health` response accuracy.
2. `test_schemas.py`: Schema validation, MITRE ATT&CK regex enforcement, time window validation, and independent ground truth decoupling for all 8 schemas.
3. `test_jsonl_import.py`: Streaming JSONL validation, round-trip serialization, and line-isolated error handling across scenarios, runs, telemetry, rules, alerts, and ground truth.
4. `test_normalisation.py`: Sysmon Event 1 process extraction, Event 3 network extraction, Generic EDR parsing, and source ID/timestamp preservation across providers.
5. `test_store.py`: In-memory entity CRUD operations, reset isolation, safe IP matching, and NetBIOS/FQDN host correlation.
6. `test_evaluation.py`: Deterministic Layer 5 Assurance Engine evaluation across all 7 diagnostic categories.
7. `test_fault_matrix.py`: Phase 2 Fault-Injection Benchmark Suite (FT-01 through FT-12) evaluating nominal passes, sensor blackout, rule mismatch, alert routing/window failures, running status guards, and IP boundary isolation.
8. `test_api_endpoints.py`: Schema catalog metadata, raw event ingestion, multi-line JSONL streaming API validation, and end-to-end evaluation workflow via REST endpoints.
