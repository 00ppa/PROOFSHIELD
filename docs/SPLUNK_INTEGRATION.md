# Splunk Integration

ProofShield’s Splunk connector is read-only and feeds the same canonical pipeline as Elasticsearch:

```text
Splunk REST export search -> RawTelemetryEventV1 -> NormalisationEngine ->
NormalizedTelemetryEventV1 -> AlertV1 -> AssuranceEngine
```

## Configuration

Set these environment variables before starting the service:

```powershell
$env:PROOFSHIELD_SPLUNK_ENABLED = "true"
$env:PROOFSHIELD_SPLUNK_URL = "https://splunk.example:8089"
$env:PROOFSHIELD_SPLUNK_TOKEN = "<bearer-token>"
$env:PROOFSHIELD_SPLUNK_TELEMETRY_INDEX = "main"
$env:PROOFSHIELD_SPLUNK_ALERT_INDEX = "alerts"
$env:PROOFSHIELD_SPLUNK_VERIFY_TLS = "true"
```

Verified HTTPS is mandatory outside explicit loopback HTTP test connections.
Redirects are refused, avoiding credential forwarding to other origins. Token
configuration is never stored in evidence or returned by status endpoints.

## API

- `GET /api/v1/splunk/status` reports non-secret configuration state.
- `POST /api/v1/splunk/assurance/{run_id}?strict_attribution=true` retrieves bounded telemetry and alerts, persists raw and normalized evidence, and invokes the deterministic Assurance Engine.

The connector uses `/services/search/jobs/export` with bounded `count`,
`earliest_time`, and `latest_time` (default last five minutes; maximum seven days).
It requests limit+1 results to distinguish a full page from actual truncation.
The response body is limited to 8 MiB; overflow, malformed JSON, preview records,
server messages and invalid envelopes fail closed. Authentication failures are
not retried; transient HTTP failures use bounded backoff.

Freeform SPL is forbidden. Index/sourcetype identifiers are validated and host,
process and rule values are escaped as literals. Use a read-only Splunk service
role. Configure the actual alert index (default `notable`), not an internal log
index. Source collection failures persist an ERROR diagnosis, replacing stale
successful results for subsequent report/explanation requests.

## Result mapping

Splunk identifiers use index-qualified `_cd`, `event_id`, or a content digest.
Original result envelopes, including `_raw`, remain in `RawTelemetryEventV1`.
`SplunkNormaliser` adapts nested/flattened ECS fields and supported Windows
EventCodes (1, 3, 11), including JSON-string `_raw`, before invoking the existing
ECS normalizer. Missing source time/host or unsupported event types cannot be
invented from collection time. Additional source-specific mappings require
representative records and regression tests.

`SplunkAssuranceOrchestrator` adapts the Splunk client to the existing Elastic
evidence-orchestration implementation. Both invoke the same AssuranceEngine;
there is no second diagnostic policy. Conflicting duplicate evidence IDs fail
collection rather than overwriting prior raw evidence.

## Local verification

```powershell
py -3.12 -m pytest tests/test_splunk_integration_phase21.py -q
```

The repository includes an offline HTTP mock. Optional live testing requires
`PROOFSHIELD_SPLUNK_LIVE=1` plus credentials, and searches a bounded one-minute
window. No live Splunk tests have been claimed as passed without a live service.
