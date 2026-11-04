# ProofShield Threat Model and Security Boundaries

## Assets

- Controlled execution authentication secret.
- Execution evidence and integrity hashes.
- Raw and normalized telemetry.
- Independent ground-truth labels.
- Detection alerts and analyst explanations.
- SIEM credentials and connection metadata.

## Trust boundaries

1. The FastAPI service and its configured local store.
2. Controlled endpoint subprocesses.
3. Elasticsearch or Splunk retrieval APIs.
4. Imported telemetry and alert payloads.
5. Analyst/browser clients.

## Controls implemented

- Execution routes require a bearer token and fail closed when the execution secret is unset.
- `PROOFSHIELD_API_TOKEN` protects all non-public, non-execution API routes; missing deployment credentials fail closed.
- Approved actions use allowlisted profiles, absolute executable resolution, `shell=False`, bounded parameters, and process lifecycle tracking.
- Child environments are allowlisted: server, API and SIEM credentials and
  Python/loader injection variables are absent. Helper interpreters use `-I`.
- Raw telemetry remains separate from normalized telemetry and expected ground truth.
- Strict execution-token attribution prevents host/time-only false PASS outcomes.
- Connectors use bounded retrieval, TLS verification by default, credential redaction, and explicit retrieval-error states.
- Canonical input validation rejects unsafe integer domains and non-string keys.
- Diagnosis-time snapshots bind run/scenario/rule, raw/normalized/alert and
  execution contents. Reports expose verified/unavailable/failed integrity.
- Splunk rejects redirects, freeform SPL, malformed/preview responses and oversized
  responses; TLS is mandatory outside literal loopback tests.
- Explanations and ML outputs cannot modify deterministic diagnoses.

## Known limitations

- Process groups and `taskkill /T` are not OS-level sandboxes; detached processes may evade termination. Job Objects, cgroups, or namespaces are future hardening options.
- Workspace path validation has a theoretical symlink/junction TOCTOU race between resolution and file creation.
- SHA-256 stored beside its payload does not protect against an attacker who can rewrite both.
- v1 manifests do not yet have a dedicated `execution_evidence_hashes` mapping.
- The API remains single-tenant. Local unauthenticated access requires an explicit local-development opt-in; deployed access requires `PROOFSHIELD_API_TOKEN`.
- Splunk and Elasticsearch live integration correctness depends on source permissions, field mappings, clock synchronization, and configured query indexes.
- Research model metrics on synthetic data are not operational performance claims.
- Imported evidence and independently authored labels remain operator assertions.
  A matching attribution token is not a digital signature from the endpoint.
