# Controlled Endpoint Execution Runner & Evidence Lifecycle (Phase 20 & 20.1)

## 1. Architectural Overview

PROOFSHIELD is a detection assurance and failure-diagnosis platform. It evaluates whether detection engineering controls function accurately without executing intrusive attacks, downloading remote scripts, or destabilizing production endpoints.

The Controlled Endpoint Execution Runner provides a safe, deterministic subsystem that initiates predefined, benign security validation scenarios on local endpoints, records immutable forensic execution evidence, and integrates with the deterministic assurance pipeline:

```
Scenario → Campaign → Controlled Execution → Execution Evidence → Telemetry Retrieval → Alert Correlation → Deterministic Assurance → Diagnostic Result
```

### Core Architecture Invariants
1. **Local-First & Safe by Construction**:
   - Subprocess execution strictly enforces `shell=False` across all actions.
   - Zero arbitrary shell commands, scripts, code evaluation, privilege escalation, or destructive filesystem modifications.
   - Filesystem paths are checked against dedicated workspace roots; the local filesystem race boundary is documented below.
   - Network interactions are strictly constrained to loopback destinations (`127.0.0.1`, `::1`, `localhost`).
   - System executables are resolved to immutable canonical paths within operating-system system directories (`C:\Windows\System32`, `/usr/bin`). Untrusted PATH entries and Current Working Directories are never searched.
2. **Server-Side Execution API Authorization**:
   - Every endpoint under `/api/v1/execution/*` requires bearer-token authorization.
   - The execution subsystem fails closed when server authentication (`PROOFSHIELD_EXEC_TOKEN`) is not configured.
3. **Strict Evidence Separation**:
   - Execution evidence (`ExecutionEvidenceV1`) captures what the runner actually attempted and executed on the endpoint.
   - Execution is not proof of telemetry observation, and process exit code 0 is not proof of detection success.
   - Raw telemetry, normalized telemetry, SIEM alerts, and diagnostic evaluations remain strictly distinct canonical evidence entities.
4. **Deterministic Token Attribution**:
   - A unique execution token (e.g. `tok-exec-<uuid>`) is generated and bound to every execution attempt.
   - Native system binaries are never altered with synthetic command-line flags (such as `--execution-token`); the token is passed via controlled environment variables (`PROOFSHIELD_EXECUTION_TOKEN`) and explicit evidence channels.
   - Downstream normalisers extract supported token fields via `extract_execution_token()`. The sensor must independently capture the token; normalizers never copy an expected execution token into observed telemetry. Sysmon alone does not generally expose process environment variables.
   - Host/timestamp co-occurrence alone never constitutes causal detection attribution under strict attribution.
5. **Decoupled Database Transactions**:
   - Database transactions remain extremely narrow.
   - Subprocess execution, socket connections, and sleep intervals never run inside active database transactions.
6. **Storage Parity**:
   - Both `InMemoryStore` and `SQLiteStore` implement identical execution CRUD and filtering semantics, raising consistent `ValueError` exceptions on duplicate IDs.

---

## 2. Server-Side Execution Authorization & Threat Model

### Threat Model
The execution runner executes binaries and creates files on the host where ProofShield is running. Without authentication, any network client with HTTP reachability to ProofShield could trigger process execution. ProofShield treats execution API routes as a privileged administrative surface.

### Authentication Mechanism
- Protected route prefix: `/api/v1/execution/*`
- Required scheme: `Authorization: Bearer <TOKEN>`
- Configuration source: `PROOFSHIELD_EXEC_TOKEN` environment variable
- Fail-Closed Policy: If `PROOFSHIELD_EXEC_TOKEN` is unset or blank, all execution routes immediately return `HTTP 503 Service Unavailable` with a descriptive message explaining that the subsystem is locked.
- Missing Credentials: Returns `HTTP 401 Unauthorized` with `WWW-Authenticate: Bearer` header.
- Invalid Credentials: Compares token in constant time (`secrets.compare_digest`) to prevent side-channel timing attacks; returns `HTTP 401 Unauthorized`.
- Non-Execution Routes: Unrelated API routes (e.g. scenarios, health, normalisation) remain unaffected.

---

## 3. Approved Execution Profile Model

To prevent command injection, parameter tampering, and binary substitution, freeform process execution and blacklisting are replaced with a **strict execution-profile model**. Callers select a registered, approved profile with strongly-typed, bounded parameters.

### Canonical Executable Resolution Policy
Naked binary names (`whoami`, `hostname`) are never passed directly to the operating system's search path.
- **Windows**:
  - The runner queries `%SystemRoot%\System32` (or `C:\Windows\System32`).
  - Executables must exist in `System32` and are resolved to absolute paths (e.g., `C:\Windows\System32\whoami.exe`).
  - CWD search is completely bypassed.
- **POSIX**:
  - The runner verifies canonical locations (`/usr/bin/whoami`, `/bin/hostname`, `/usr/bin/uname`).
  - Fallback locations must start with `/bin/` or `/usr/bin/`.

### Approved Execution Profiles

| Profile Name | Target Executable | Canonical Path | Accepted Parameters | Description |
| :--- | :--- | :--- | :--- | :--- |
| `whoami` | `whoami` | `C:\Windows\System32\whoami.exe` or `/usr/bin/whoami` | None | Queries identity to test discovery detection rules. |
| `hostname` | `hostname` | `C:\Windows\System32\hostname.exe` or `/bin/hostname` | None | Queries endpoint hostname. |
| `uname` | `uname` | `/usr/bin/uname` (`-s`) or Windows platform stub | None | Queries OS kernel/system metadata. |
| `echo` | `cmd.exe` or `/bin/echo` | `C:\Windows\System32\cmd.exe` or `/bin/echo` | None | Emits benign test message. |
| `exit_with_code` | Controlled script | `scripts/exit_with_code.py` | `exit_code: int` (0–255) | Exits cleanly with requested returncode to test error handling. |
| `sleep` | Controlled script | `scripts/sleep_and_exit.py` | `duration_seconds: float` (0.0–60.0) | Sleeps for bounded duration to test lifecycle and timeouts. |
| `process_tree` | Controlled script | `scripts/spawn_child.py` | None | Spawns child process to test tree cancellation. |

### Prohibited Actions & Adversarial Defense
- `python -c` or arbitrary code execution through Python is strictly forbidden.
- Free-form arguments are never passed to executables; dangerous forms are rejected and legacy harmless arguments are ignored.
- Shell execution (`shell=True`) is permanently disabled.
- Shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `<`, `>`) in any parameter trigger immediate rejection.

---

## 4. Real Process Lifecycle Management & Tree Cancellation

### Process Management Architecture
The runner employs a dedicated `ProcessLifecycleManager` utilizing `subprocess.Popen` rather than blocking `subprocess.run`:

1. **Process Tracking**:
   - Each active execution is registered by its unique `execution_id`, tracking process handle, PID, start time, timeout, and cancellation state.
2. **Process Group Isolation**:
   - Windows: Spawns processes with `creationflags = subprocess.CREATE_NEW_PROCESS_GROUP`.
   - POSIX: Spawns processes with `start_new_session = True` (own process group).
3. **Process-Tree Cancellation**:
   - When `cancel_execution(execution_id)` is invoked, the manager identifies the child PID and forcefully terminates all descendants:
     - Windows: Executes canonical `C:\Windows\System32\taskkill.exe /PID <pid> /T /F`.
     - POSIX: Issues `os.killpg(pgid, signal.SIGKILL)`.
    - Termination covers tracked descendants; deliberately detached processes may evade process-group containment.
4. **Race-Safe State Transitions**:
   - If a process finishes or exits after cancellation has been requested, the cancellation status is preserved and **never overwritten** by `COMPLETED` or `FAILED`.
5. **Concurrency Limits**:
    - An atomic semaphore (`max_concurrent = 5`) limits concurrently admitted process spawns. This is a resource bound, not a general denial-of-service guarantee.

---

## 5. Filesystem Workspace Containment

Each execution attempt runs within a private, dedicated temporary directory:

- Root directory: `%TEMP%\proofshield_executions\<execution_id>\`
- All created and modified files are resolved via `ExecutionWorkspace.resolve_path(relative_path)`.
- Traversal checks verify that the canonical path is strictly relative to `workspace_dir`.
- Symlink escapes, absolute paths, and drive indicators are rejected upfront.
- Workspaces are created exclusively (no reuse) with mode 0700 on POSIX. On the
  inspected Windows host, inherited ACL entries grant full control to the current
  account, Administrators, and SYSTEM. Same-user attackers remain outside the
  containment guarantee.
- `FileCreateAction` requires `filename`, enforces a regex whitelist `^[A-Za-z0-9_\-\.]+$`, and limits content to 1,048,576 bytes (1 MB).

---

## 6. Observation Window & Settling Semantics

To accommodate SIEM, collector, and network buffering latency, ProofShield decouples the process runtime duration from the telemetry observation window:

- `evidence.started_at` & `evidence.completed_at`: Record the actual physical duration of the endpoint action.
- `test_run.window_start`: Set to `started_at - 1.0s` to account for minor clock skew.
- `test_run.window_end`: Set to `completed_at + settling_time_seconds` (default: 5.0 seconds).
- Service-coordinated execution waits through this window before collection.
  This accommodates a configured settling interval, not an arbitrary ingestion
  delay guarantee. Event timestamps remain distinct from collector arrival time.

---

## 7. Execution-to-Assurance Integration & Orchestration Boundary

### Lifecycle Call Graph

```mermaid
flowchart TD
    subgraph Execution Subsystem
        A[POST /api/v1/execution/run] -->|Verify Bearer Auth| B[ControlledExecutionRunner.execute]
        B --> C[ProcessLifecycleManager.spawn_and_wait]
        C --> D[ExecutionEvidenceV1 Created]
        D --> E[Compute RFC 8785 Canonical Hash]
        E --> F[Store.add_execution & Store.add_run]
    end

    subgraph Explicit Orchestration Boundary
        F --> G[ControlledExecutionRunner.execute_with_assurance]
        G --> H[evidence.verify_integrity]
        H --> I[ElasticAssuranceOrchestrator.evaluate_run_with_orchestration]
    end

    subgraph Assurance Subsystem
        I --> J[Fetch Bounded Telemetry & Alerts]
        J --> K[Normalize Telemetry with Token Attribution]
        K --> L[AssuranceEngine.evaluate_run]
        L --> M[Deterministic DiagnosticResultV1]
    end
```

### Deterministic Verdict Principles:
- A process exit code of 0 **never** independently produces an assurance `PASS`.
- If execution fails or times out, `test_run.execution_status` is marked `FAILED`, which the `AssuranceEngine` diagnoses as `TEST_NOT_EXECUTED`.
- If execution succeeds but no telemetry is retrieved, the diagnosis is `EXPECTED_TELEMETRY_MISSING`.
- If telemetry arrives with matching token but no alert is found, the diagnosis is `DETECTION_NOT_TRIGGERED`.
- EXPECTED_ALERT requires matched alert evidence; EXPECTED_TELEMETRY_ONLY can
  PASS without an alert. Neither target treats process completion as detection.

---

## 8. Evidence Integrity Limitations & Canonical Serialization

ProofShield computes a deterministic SHA-256 hash over the JSON-compatible
`ExecutionEvidenceV1` fields (excluding `integrity_hash`) using the project’s
RFC 8785-compatible JCS serializer.

### Verification Methods:
- `evidence.calculate_integrity_hash() -> str`: Deterministically computes canonical digest.
- `evidence.verify_integrity() -> bool`: Verifies record integrity using constant-time string comparison.

The serializer is regression-tested against published RFC 8785 number, ordering,
escaping, and surrogate-handling vectors, plus independent comparisons with the
ECMAScript/Node.js number formatter. The application also accepts datetime,
set, and Pydantic values before converting them to JSON-compatible values; those
application conversions are outside the RFC’s native JSON data model.

### Threat Model Limitation:
- A SHA-256 integrity hash detects unintended record mutation, accidental tampering, or bit rot.
- It **does not prove authenticity or non-repudiation** against a database writer who has full permissions to update both the evidence payload and its stored digest.
- For high-assurance environments, store backups and append-only cryptographic logging are recommended.

### Secret isolation and containment limitations

- Child environments allow only required OS/temp/locale variables and the
  attribution token. Server/API/SIEM secrets and Python/loader injection variables
  are excluded. Controlled Python helpers use `-I` isolation.
- `PROOFSHIELD_EXECUTION_TOKEN` is an attribution identifier deliberately present
  in evidence; it is not the server bearer secret. Requests reusing configured
  service secrets are rejected before execution.
- Process groups and Windows process-tree termination are containment aids, not
  operating-system sandboxes. A deliberately detached process may evade them;
  Windows Job Objects or Linux cgroups/namespaces are future hardening options.
- Workspace validation resolves paths before writing. A malicious local actor
  with write access could theoretically exploit a symlink/junction replacement
  between validation and creation. Stronger no-follow file creation and
  restrictive per-workspace ACLs remain future hardening work.
- The current v1 evidence manifest represents execution evidence through linked
  test-run metadata and hashes. A dedicated `execution_evidence_hashes` mapping
  requires a future versioned manifest schema.

### Canonical compatibility policy

Published vectors are sourced from https://www.rfc-editor.org/rfc/rfc8785.txt
(Appendix B, Sections 3.2.2–3.2.4). A regression test compares canonical bytes for
20,000 seeded IEEE-754 samples plus nested Unicode structures against Node.js.
This demonstrates tested conformance within the accepted input domain, not a
formal proof over all inputs.

Safe JSON integer values, binary64 floats, strings and string-keyed objects retain
their prior serialized bytes. Arbitrary integers outside ±9007199254740991,
non-string object keys and unsupported Python objects are now rejected. This
prevents duplicate-key coercion and non-JCS integers. Legacy stored evidence in
that invalid domain is **not silently migrated or rehashed**; export and inspect
it using the prior version before an explicit versioned migration. Python
datetime/set/model adapters remain application conversions with existing bytes.

---

## 9. Local Configuration & Testing Guide

### Environment Setup
Set the execution token before starting ProofShield:
```powershell
$env:PROOFSHIELD_EXEC_TOKEN = "your-secure-secret-token"
```

### API Invocations via `curl`

**1. List Approved Actions:**
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/execution/actions" \
     -H "Authorization: Bearer your-secure-secret-token"
```

**2. Validate Execution Request (Dry Run):**
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/execution/validate" \
     -H "Authorization: Bearer your-secure-secret-token" \
     -H "Content-Type: application/json" \
     -d '{"schema_version":"v1","action_id":"process.spawn_benign","action_parameters":{"executable":"whoami"}}'
```

**3. Execute Controlled Benign Action:**
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/execution/run" \
     -H "Authorization: Bearer your-secure-secret-token" \
     -H "Content-Type: application/json" \
     -d '{"schema_version":"v1","action_id":"process.spawn_benign","action_parameters":{"executable":"whoami"}}'
```

### Running Test Verification Suites
```powershell
# Phase 20 & 20.1 Test Suite
$env:PYTHONPATH="D:\PROOFSHIELD"; .\.venv\Scripts\pytest tests/test_endpoint_execution_runner.py -v

# Benchmark Test Suite
$env:PYTHONPATH="D:\PROOFSHIELD"; .\.venv\Scripts\pytest -k "benchmark" -q

# Full Repository Test Suite
$env:PYTHONPATH="D:\PROOFSHIELD"; .\.venv\Scripts\pytest -q
```
