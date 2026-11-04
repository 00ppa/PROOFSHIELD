# Integration and Acceptance Report

## Acceptance status

**Acceptance in progress.** A green regression suite does not by itself establish
the full Phase 20–24 acceptance criteria. Independent security review and
adversarial acceptance checks must close before this document can report final
completion.

## Baseline reconciliation

- Started on `master`, HEAD `27fc726` (Phase 19).
- Existing Phase 20 changes were uncommitted and have been preserved.
- Initial baseline: 599 passed, 2 optional live-Elastic skips.
- No staging, commits, pushes, or deployment to an external service performed.

## Verified checkpoints

- Execution environment regression coverage was added for action spawning,
  lifecycle management, and Windows cancellation helpers.
- Published RFC 8785 Appendix B and Unicode tests pass. The serializer's Python
  extension domain is not proof of universal JCS conformance.
- Splunk mock HTTP integration and controlled execution integration run locally.
- Explanations persist through in-memory and SQLite storage.
- The analyst page calls actual backend routes; complete UI acceptance remains
  under review.
- Full-suite checkpoint: 628 passed, 2 skipped; later edits require revalidation.
- Benchmark tests: 70 passed. SQLite benchmark CLI: 24/25 in legacy non-strict
  mode. BM-25 remains a deliberately documented host/time confounding case;
  passing benchmark tests is not 100% diagnostic accuracy.
- Phase 19 integration and persistence tests: 42 passed.
- Source/test/script byte compilation: passed.
- Packaging metadata dry run: passed after moving runtime dependencies out of
  `[project.urls]` into `[project]`.
- Installed-environment `pip check`: passed.

## Architecture and implemented work

```
Scenarios / independent labels -> controlled local execution -> execution evidence
Elasticsearch or Splunk -> shared collection orchestration -> raw store
    -> source adapters / canonical normalization -> strict attribution
    -> existing deterministic AssuranceEngine -> persisted diagnosis + input hashes
    -> evidence report + analyst explanation -> same-origin UI / JSON / CSV
Stored observations + independent labels -> isolated research dataset/models
```

| Milestone | Implementation |
|---|---|
| 20.2 | Child environment allowlist, isolated helpers, dry-run rejection, atomic process capacity, canonical-domain validation and independent Node reference tests |
| 21 | Read-only bounded Splunk export client, safe query literals/transport, original raw result preservation, field adapter, shared orchestration, mock/live-test hooks |
| 22 | Provenance/hash validation, independently labeled rows, grouped splits, optional scikit-learn Logistic Regression/Random Forest/Isolation Forest, JSON model state and metrics |
| 23 | Local deterministic explanation service, fact/gap/hypothesis separation, content-bound provenance, in-memory/SQLite persistence and API |
| 24 | Optional global API auth, strict connected UI, execution/collection/report lifecycle, evidence bundles and CSV, adversarial/API/browser tests, packaging and local deployment |

The explanation layer is deterministic and local; no paid LLM is required or
silently invoked. The research layer is optional and cannot override assurance.

## Research evidence

The bundled fixture dataset contains only **three synthetic observations**, with
two training records and one test record. Training contains only PASS while the
test record is DETECTION_NOT_TRIGGERED. The final research runner correctly
returns **INSUFFICIENT_DATA** for both classifiers rather than manufacturing a
performance claim. Unit fixtures exercise genuine model fitting, calibration
metrics and anomaly scoring, but are not operational evaluation results.
Real observations and independently verified labels remain required for research
conclusions. There is no claimed production ML accuracy.

Repeated fixture experiments now produce equal dataset and model hashes after
assigning stable fixture-normalization IDs and excluding collection wall-clock
time from the dataset content digest.

## Protected-file exception

`pyproject.toml` was changed for justified installation requirements: `dependencies`
was incorrectly placed in the URL table, research needs an optional scikit-learn
extra, and the browser assets must be included in installed wheels. A wheel was
built successfully and its UI/helper contents and dependency metadata inspected.
The other protected files remain
unchanged: `src/proofshield/__init__.py`, `.coderabbit.yaml`, and
`docs/PROOFSHIELD_LEARNING_GUIDE.md`.

## Environment boundary

Windows workspace ACL inspection found inherited full-control entries for the
current account, Administrators, and SYSTEM. Process-tree termination is not an
OS sandbox; filesystem validation/write races and locally rewritable digest
references remain limitations. No live SIEM credentials or real sensor evidence
have been supplied for this execution of acceptance tests.

## Independent audit trail

The first independent read-only review returned **NOT ACCEPTED**, reproducing
13 defects despite a green baseline. It identified malformed Splunk responses,
non-strict UI evaluation, SPL injection, redirect credential forwarding, false
integrity verification, side-effecting dry runs, inherited service credentials,
unpersisted collection errors, process-capacity races, invalid canonical input
domains, research leakage, field mapping errors, and overbroad supporting evidence.

Remediation added strict parsing/transport, content-bound evidence snapshots,
persisted collection status, isolated children, atomic capacity, explicit JSON
domain rejection, grouped/validated model evaluation and a full connected UI.
`tests/test_acceptance_adversarial.py` covers the reproduced cases. An independent
source/test re-review was requested after these fixes; its final findings must be
recorded before acceptance.

## Deployment and remaining external dependencies

See [LOCAL_DEPLOYMENT.md](LOCAL_DEPLOYMENT.md). Source launch:
`py -3.12 scripts/serve.py`, then `http://127.0.0.1:8000/ui`.

- Live Elasticsearch/Splunk credentials, configured rule/index mappings and a
  sensor that independently exposes execution tokens are needed for live-lab
  acceptance. Mock/browser success is not proof of sensor coverage.
- A representative real labeled dataset is needed for defensible research
  evaluation; the bundled three-row fixture cannot provide it.
- Job Objects/cgroups, stronger filesystem race containment and independently
  protected digest references remain documented hardening boundaries.
- Commit/push authorization has not been given. All work is local and unstaged.

## Changed-file inventory

This includes the pre-existing uncommitted Phase 20 files preserved and remediated
in place. `M` denotes changes to tracked files; `??` denotes untracked additions
relative to Phase 19. No files were staged.

```text
M .gitignore
M README.md
M docs/ARCHITECTURE.md
M pyproject.toml
M src/proofshield/api/__init__.py
M src/proofshield/api/routes_evaluation.py
M src/proofshield/connectors/__init__.py
M src/proofshield/main.py
M src/proofshield/normalisation/ecs.py
M src/proofshield/normalisation/engine.py
M src/proofshield/schemas/__init__.py
M src/proofshield/services/__init__.py
M src/proofshield/services/base_store.py
M src/proofshield/services/canonical.py
M src/proofshield/services/elastic_orchestrator.py
M src/proofshield/services/sqlite_store.py
M src/proofshield/services/store.py
?? .env.example
?? .github/workflows/tests.yml
?? docs/COMPLETION_REPORT.md
?? docs/ENDPOINT_EXECUTION_RUNNER.md
?? docs/LOCAL_DEPLOYMENT.md
?? docs/RESEARCH_ML.md
?? docs/SPLUNK_INTEGRATION.md
?? docs/THREAT_MODEL.md
?? scripts/run_research.py
?? scripts/serve.py
?? src/proofshield/api/auth.py
?? src/proofshield/api/routes_elastic.py
?? src/proofshield/api/routes_execution.py
?? src/proofshield/api/routes_explanation.py
?? src/proofshield/api/routes_reports.py
?? src/proofshield/api/routes_research.py
?? src/proofshield/api/routes_splunk.py
?? src/proofshield/api/routes_ui.py
?? src/proofshield/api/routes_workflow.py
?? src/proofshield/connectors/splunk.py
?? src/proofshield/connectors/transport.py
?? src/proofshield/execution/__init__.py
?? src/proofshield/execution/actions/__init__.py
?? src/proofshield/execution/actions/base.py
?? src/proofshield/execution/actions/file_actions.py
?? src/proofshield/execution/actions/network_actions.py
?? src/proofshield/execution/actions/process_actions.py
?? src/proofshield/execution/actions/registry.py
?? src/proofshield/execution/environment.py
?? src/proofshield/execution/process_manager.py
?? src/proofshield/execution/runner.py
?? src/proofshield/execution/scripts/__init__.py
?? src/proofshield/execution/scripts/exit_with_code.py
?? src/proofshield/execution/scripts/sleep_and_exit.py
?? src/proofshield/execution/scripts/spawn_child.py
?? src/proofshield/execution/workspace.py
?? src/proofshield/normalisation/splunk.py
?? src/proofshield/research/__init__.py
?? src/proofshield/research/dataset.py
?? src/proofshield/research/ml.py
?? src/proofshield/schemas/execution.py
?? src/proofshield/schemas/explanation.py
?? src/proofshield/schemas/report.py
?? src/proofshield/schemas/research.py
?? src/proofshield/services/evidence_snapshot.py
?? src/proofshield/services/explanation.py
?? src/proofshield/services/report.py
?? src/proofshield/services/splunk_orchestrator.py
?? src/proofshield/services/workflow.py
?? src/proofshield/ui/app.js
?? src/proofshield/ui/index.html
?? src/proofshield/ui/style.css
?? tests/mock_splunk_server.py
?? tests/test_acceptance_adversarial.py
?? tests/test_browser_workflow.py
?? tests/test_end_to_end_phase24.py
?? tests/test_endpoint_execution_runner.py
?? tests/test_phase20_2_remediation.py
?? tests/test_phase22_research.py
?? tests/test_phase23_explanation.py
?? tests/test_phase24_api_auth.py
?? tests/test_phase24_reports_ui.py
?? tests/test_splunk_integration_phase21.py
?? tests/test_splunk_live.py
```
