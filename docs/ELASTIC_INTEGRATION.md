# Elasticsearch Integration Subsystem (Phase 19)

## 1. Overview

PROOFSHIELD operates downstream of detection systems, comparing adversary execution against what the detection system observed and alerted on.

The Elasticsearch Integration Subsystem provides:
1. **Raw Telemetry Ingestion & Retrieval**: Bounded retrieval of security telemetry events from Elasticsearch (e.g. `logs-*`, Elastic Agent, Beats, Winlogbeat, Sysmon-on-ECS).
2. **Deterministic ECS Normalization**: Canonical normalization via `ECSNormaliser` adhering to `BaseNormaliser`, mapping Elastic Common Schema (ECS) events into canonical `NormalizedTelemetryEventV1` while preserving immutable raw evidence and extracting execution tokens.
3. **Alert Ingestion**: Pure mapping of Kibana Alerting documents and legacy signals into canonical `AlertV1` records.
4. **Assurance Orchestration**: `ElasticAssuranceOrchestrator` bridges Elasticsearch retrieval, ProofShield storage (`StoreProtocol`), normalization, and evaluation (`AssuranceEngine`).
5. **Strict Failure Isolation**: Complete differentiation between:
   - Missing telemetry (`EXPECTED_TELEMETRY_MISSING`)
   - Failed retrieval / auth failure (`DiagnosticCategory.ERROR`)
   - Truncated retrieval (`is_truncated = True`, status `TRUNCATED`)
   - Detection rule not triggered (`DETECTION_NOT_TRIGGERED`)
   - Unattributed / mismatched alert (`INCONCLUSIVE` / `MISMATCHED`)
   - Fully verified detection (`PASS`)

---

## 2. Configuration & Environment Variables

The subsystem is configured using `ElasticConnectorSettings`:

| Environment Variable | Default | Purpose |
|----------------------|---------|---------|
| `PROOFSHIELD_ELASTIC_URL` | `""` | Base Elasticsearch URL (`http://` or `https://`) |
| `PROOFSHIELD_ELASTIC_API_KEY` | `""` | Elasticsearch API key (strictly redacted in `repr`) |
| `PROOFSHIELD_ELASTIC_INDEX` | `.alerts-security.alerts-*` | Alert index pattern |
| `PROOFSHIELD_ELASTIC_TELEMETRY_INDEX` | `logs-*` | Telemetry index pattern |
| `PROOFSHIELD_ELASTIC_TIMEOUT` | `10.0` | Request timeout in seconds |
| `PROOFSHIELD_ELASTIC_MAX_RESULTS` | `100` | Upper limit on retrieved documents |
| `PROOFSHIELD_ELASTIC_CA_CERT` | `None` | Path to custom CA certificate for TLS verification |
| `PROOFSHIELD_ELASTIC_ENABLED` | `false` | Enable/disable connector |

### Security & Redaction Policy
- `repr(ElasticConnectorSettings)` always returns `api_key='***REDACTED***'`.
- All HTTP error diagnostics pass through `_extract_http_diagnostic()`, which scrubs credentials and bearer tokens.
- Telemetry payloads pass through recursive `_sanitize_metadata()` with a 32-level depth limit and cycle detection, preserving forensic non-secret keys (e.g., `_id`, `_hash`, `_algorithm`) while redacting cleartext passwords and authorization tokens.

---

## 3. Telemetry Retrieval Subsystem

Implemented in `src/proofshield/connectors/elastic.py`:

### `search_telemetry(...) -> ElasticTelemetryBatch`
- **Time Bounding**: Queries `@timestamp` using `gte` and `lte` ISO-8601 UTC bounds.
- **Filtering**: Supports filtering by `host` (`host.hostname`, `host.name`, `host.id`, `agent.hostname`), `process_name`, and raw Lucene `query_string`.
- **Pagination**: Implements `search_after` using composite tie-breaker sort `[{"@timestamp": "asc"}, {"_id": "asc"}]`.
- **Truncation Detection**:
  - Compares `hits.total.value` against retrieved hit count.
  - Inspects `hits.total.relation == "gte"`.
  - Sets `batch.is_truncated = True` and `status = TelemetryRetrievalStatus.TRUNCATED`.
  - Raises `ElasticClientError` when `raise_on_truncation=True`.
- **Transient Retry Resilience**:
  - Automatically retries on HTTP 429 (Too Many Requests), 502, 503, 504, and socket timeouts with exponential backoff.
  - Never retries non-retryable client errors (HTTP 400, 401, 403, 404).

### `fetch_raw_telemetry(...) -> List[RawTelemetryEventV1]`
Maps hits into canonical raw telemetry models:
- `raw_event_id`: Prefixed as `elastic:raw:{_id}`.
- `source_format`: `"elastic_ecs"`.
- `source_timestamp`: Normalized UTC timestamp from `@timestamp`.
- `raw_payload`: Fully preserved, credential-sanitized source dictionary.

### `poll_and_ingest_telemetry(...) -> List[RawTelemetryEventV1]`
- Persists raw telemetry records into `StoreProtocol.add_raw_event()`.
- Idempotently ignores duplicates when `skip_duplicates=True`.
- Supports atomic transaction boundaries when `atomic=True`.
- **Decoupled Network I/O**: Elasticsearch HTTP queries are executed prior to opening any database transaction (`store.transaction()`), guaranteeing that network latency, retries, and rate-limiting never hold database locks.

---

## 4. ECS Telemetry Normalization

Implemented in `src/proofshield/normalisation/ecs.py` (`ECSNormaliser`):

### Mapping Specification
- **Event Category**:
  - Declared `event.category` of `"process"` or actions like `"process_started"` -> `EventCategory.PROCESS_CREATION`.
  - Declared `event.category` of `"network"` or dataset `"network"` -> `EventCategory.NETWORK_CONNECTION`.
  - Declared `event.category` of `"file"` -> `EventCategory.FILE_EVENT`.
  - Declared `event.category` of `"authentication"` / `"iam"` -> `EventCategory.AUTHENTICATION`.
  - Declared `event.category` of `"registry"` -> `EventCategory.REGISTRY_EVENT`.
  - Heuristic fallback based on process presence -> `EventCategory.PROCESS_CREATION`, else `OTHER`.
  - **Evidence Integrity**: Destination IP and port are strictly zeroed out (`None`) when category is not `NETWORK_CONNECTION`.
- **Host & User**:
  - Host resolved from `host.hostname`, `host.name`, `host.id`, or `agent.hostname`.
  - User resolved as `DOMAIN\username` when `user.domain` is present, or `user.name`.
- **Process & Command Line**:
  - `process_path` from `process.executable`.
  - `process_name` from `process.name` or basename of `process.executable`.
  - `command_line` from `process.command_line`, falling back to joined `process.args`.
  - Parent process details extracted similarly from `process.parent.*`.
- **Execution Token Extraction**:
  - Structured candidates scanned from `labels`, `custom`, `tags`, and top-level `execution_token`.
  - Unstructured regex patterns scanned across `command_line`, `message`, and `event.original`.
  - Strict conflict detection: returns `"CONFLICT"` if candidate tokens differ across fields.

---

## 5. Assurance Orchestrator

Implemented in `src/proofshield/services/elastic_orchestrator.py` (`ElasticAssuranceOrchestrator`):

### Key Workflows & Reliability Features
1. **`ingest_for_run(run_id, ...)`**:
   - Calculates correlation window: `[window_start - buffer, window_end + buffer]` for telemetry, `[window_start, window_end + grace_period]` for alerts.
   - Ingests raw telemetry into `StoreProtocol`.
   - Normalizes raw telemetry via `NormalisationEngine` and persists `NormalizedTelemetryEventV1`.
   - Ingests and persists security alerts with configurable alert settling.
   - Emits an `ElasticOrchestrationReport` with exact persistence metrics and error tracking.
2. **Explicit Normalization Outcome Tracking (`NormalizationStatus`)**:
   - `COMPLETE`: All retrieved raw events were successfully normalized.
   - `PARTIAL`: Some raw events failed normalization, while others succeeded.
   - `FAILED`: Normalization failed for all raw events.
   - `EMPTY`: No telemetry hits returned from Elasticsearch.
   - `SKIPPED`: Telemetry normalization was disabled.
   - **Evidence Preservation**: All successfully collected raw events are always persisted regardless of normalization outcomes. Valid normalized events in partial batches are persisted.
   - **Pipeline Integrity**: Any partial or full normalization failure marks `report.is_complete = False` and logs errors to `report.normalization_errors`.
3. **Configurable Alert Settling Policy**:
   - `alert_settling_delay_seconds` (default: 0.0): Optional initial pause before the first alert poll.
   - `alert_settling_poll_interval_seconds` (default: 1.0): Time interval between consecutive polls when alerts are not yet available.
   - `alert_settling_max_polls` (default: 1): Maximum number of polling attempts.
   - `sleep_fn`: Injectable callable (`Callable[[float], None]`) allowing deterministic, zero-delay testing without real wall-clock sleeps.
   - Differentiates wall-clock settling delay from Elasticsearch query window expansion (`alert_grace_period_seconds`).
   - Aborts settling immediately on non-retryable authentication errors (HTTP 401/403).
4. **`evaluate_run_with_orchestration(run_id, ...)`**:
   - If Elasticsearch retrieval failed (HTTP 401/403/500/timeout), query results were truncated, or normalization failed/partially failed, creates an explicit `DiagnosticResultV1(predicted_category=DiagnosticCategory.ERROR)` with detailed diagnostic reasons.
   - Prevents misclassifying internal pipeline or normalization faults as false `EXPECTED_TELEMETRY_MISSING` or false `PASS`.
   - If retrieval and normalization succeeded, invokes `AssuranceEngine.evaluate_run(run_id)`.

---

## 6. Offline Mock Environment & Acceptance Testing

Implemented in `tests/mock_elastic_server.py`:
- Purely offline, threaded `http.server` running on ephemeral `127.0.0.1:0`.
- Simulates Elasticsearch 8.x `POST /{index}/_search`.
- Validates `Authorization: ApiKey` headers.
- Simulates `search_after` pagination with sort tokens.
- Injects transient HTTP 429/502/503 errors and tests automatic recovery.
- Simulates `hits.total.relation: "gte"` truncation.
- Simulates delayed alerts across sequential query polls.

### Verified Acceptance Scenarios (`tests/test_elastic_integration_phase19.py`)
- **Scenario A**: Full pipeline success -> token matches -> `PASS`.
- **Scenario B**: Telemetry missing in Elasticsearch -> `EXPECTED_TELEMETRY_MISSING`.
- **Scenario C**: Telemetry present, no alerts triggered -> `DETECTION_NOT_TRIGGERED`.
- **Scenario D**: Elasticsearch communication/auth failure -> explicit `ERROR` verdict (never false `PASS`).
- **Scenario E**: Mismatched execution token under strict attribution -> `INCONCLUSIVE` (never false `PASS`).
- **Scenario F**: Query window truncation -> `is_truncated = True`, status `TRUNCATED`.
- **Transaction Decoupling**: Network I/O occurs strictly outside SQLite/InMemory transactions.
- **Partial Normalization Failure**: Preserves raw and partial normalized events; produces explicit `ERROR`.
- **Full Normalization Failure**: Preserves raw events; produces explicit `ERROR`.
- **Alert Settling**: Bounded polling with configurable settling delay and poll interval.
- **Settling Auth Abort**: Immediate abort on HTTP 401/403 without spinning remaining polls.
- **Resilience**: Transparent recovery from HTTP 429 rate limiting.
- **Pagination**: Multi-page traversal with `search_after`.
- **Security**: Credential redaction in telemetry payload.
- **Parity**: Identical persistence behavior on `InMemoryStore` and `SQLiteStore`.

