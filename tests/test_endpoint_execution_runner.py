"""Comprehensive unit, integration, adversarial, and security test suite for
PROOFSHIELD Phase 20: Controlled Endpoint Execution Runner & Evidence Lifecycle.
"""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Generator, List, Optional
import uuid

# Ensure repository root is on sys.path for test imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from proofshield.execution import (
    ActionContext,
    ActionRegistry,
    ActionResult,
    BaseAction,
    ControlledExecutionRunner,
    ExecutionWorkspace,
    FileCreateAction,
    FileModifyReadAction,
    NetworkLoopbackAction,
    ProcessLifecycleAction,
    ProcessSpawnAction,
    get_default_action_registry,
)
from proofshield.execution.process_manager import get_default_process_manager
from proofshield.execution import process_manager as process_manager_module
from proofshield.execution.actions.process_actions import _sanitize_output
from proofshield.execution.environment import (
    EXECUTION_TOKEN_ENV,
    SERVER_EXECUTION_SECRET_ENV,
    build_child_environment,
)
from proofshield.main import app
from proofshield.schemas.alert import AlertV1
from proofshield.schemas.common import (
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    ValidationTarget,
)
from proofshield.schemas.detection_rule import DetectionRuleV1
from proofshield.schemas.execution import (
    ActionDescriptorV1,
    ExecutionEvidenceV1,
    ExecutionRequestV1,
    ExecutionValidationResultV1,
    RunnerExecutionState,
)
from proofshield.schemas.scenario import ScenarioV1
from proofshield.schemas.telemetry import NormalizedTelemetryEventV1
from proofshield.schemas.test_run import TestRunV1
from proofshield.services.base_store import StoreProtocol
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore, close_store, get_store, set_store


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def in_memory_store() -> InMemoryStore:
    """Fresh in-memory store instance."""
    store = InMemoryStore()
    set_store(store)
    return store


@pytest.fixture
def sqlite_store(tmp_path: Path) -> Generator[SQLiteStore, None, None]:
    """Fresh file-backed SQLiteStore instance."""
    db_file = tmp_path / "execution_test.db"
    store = SQLiteStore(db_file)
    set_store(store)
    yield store
    store.close()


@pytest.fixture(params=["in_memory", "sqlite"])
def parameterized_store(request, tmp_path: Path) -> Generator[StoreProtocol, None, None]:
    """Yields both InMemoryStore and SQLiteStore for parity tests."""
    if request.param == "in_memory":
        s = InMemoryStore()
        set_store(s)
        yield s
        s.reset()
    else:
        db_file = tmp_path / f"parity_{uuid.uuid4().hex[:6]}.db"
        s = SQLiteStore(db_file)
        set_store(s)
        yield s
        s.close()


@pytest.fixture
def test_client(monkeypatch) -> TestClient:
    """FastAPI TestClient fixture configured with execution auth token."""
    token = "test-secret-token-xyz-123"
    monkeypatch.setenv("PROOFSHIELD_EXEC_TOKEN", token)
    set_store(InMemoryStore())
    client = TestClient(app)
    client.headers["Authorization"] = f"Bearer {token}"
    return client


def create_sample_scenario(scenario_id: str = "SCEN-BENIGN-001") -> ScenarioV1:
    """Create a valid sample scenario for execution testing."""
    proc = "whoami.exe" if sys.platform == "win32" else "whoami"
    return ScenarioV1(
        schema_version="v1",
        scenario_id=scenario_id,
        name="Benign Endpoint Execution Assurance Validation",
        description="Validates that benign process execution produces observable telemetry and correlated alerts",
        mitre_technique_id="T1082",
        mitre_tactic="Discovery",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_detection_rule_id="RULE-BENIGN-001",
        expected_process_name=proc,
        max_acceptable_latency_seconds=30.0,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )


def create_sample_rule(rule_id: str = "RULE-BENIGN-001") -> DetectionRuleV1:
    """Create a sample detection rule."""
    return DetectionRuleV1(
        schema_version="v1",
        rule_id=rule_id,
        rule_name="Benign System Discovery Execution",
        rule_version="1.0.0",
        rule_format="sigma",
        rule_content_hash="hash0123456789abcdef",
        evaluation_backend="elasticsearch",
        enabled=True,
        rule_content='process.name == "whoami" or process.name == "whoami.exe"',
        description="Detects execution of whoami discovery tool",
        mitre_technique_ids=["T1082"],
        metadata={},
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Action Registry Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase20ActionRegistry:
    """Verify registry population, metadata retrieval, and validation boundaries."""

    def test_default_registry_contains_approved_actions(self):
        registry = get_default_action_registry()
        assert registry.has_action("process.spawn_benign")
        assert registry.has_action("process.lifecycle_watch")
        assert registry.has_action("file.create_temporary")
        assert registry.has_action("file.modify_read")
        assert registry.has_action("network.loopback_check")

        actions = registry.list_actions()
        assert len(actions) >= 5
        action_ids = [a.action_id for a in actions]
        assert "process.spawn_benign" in action_ids
        assert "file.create_temporary" in action_ids

        # Verify descriptor parity
        descriptors = registry.list_descriptors()
        assert len(descriptors) == len(actions)

    def test_unknown_action_rejection(self):
        registry = get_default_action_registry()
        assert registry.get("arbitrary.malicious_action") is None
        with pytest.raises(ValueError, match="Unknown or unapproved action ID"):
            registry.require("arbitrary.malicious_action")

    def test_unsupported_platform_rejected(self, monkeypatch):
        registry = get_default_action_registry()
        action = registry.require("process.spawn_benign")

        monkeypatch.setattr(sys, "platform", "freebsd12")
        assert action.is_platform_supported() is False

    def test_invalid_parameters_rejected(self):
        action = ProcessSpawnAction()
        with pytest.raises(ValueError, match="not in the approved safety allowlist"):
            action.validate_parameters({"executable": "arbitrary_malware.exe"})

        with pytest.raises(ValueError, match="additional_args must be a list"):
            action.validate_parameters({"executable": "hostname", "additional_args": "invalid_string_args"})

    def test_missing_required_parameters_rejected(self):
        file_action = FileCreateAction()
        with pytest.raises(ValueError, match="Parameter 'filename' is required"):
            file_action.validate_parameters({})

    def test_parameter_bounds_and_content_size_limits(self):
        file_action = FileCreateAction()
        oversized_content = "X" * (2 * 1024 * 1024)  # 2MB > 1MB limit
        with pytest.raises(ValueError, match="exceeds 1048576 byte limit"):
            file_action.validate_parameters({"filename": "test.txt", "content": oversized_content})


# ─────────────────────────────────────────────────────────────────────────────
# 2. Execution Lifecycle Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase20ExecutionLifecycle:
    """Verify execution states, timeout termination, cancellation, and cleanup."""

    def test_successful_execution_lifecycle(self, in_memory_store: InMemoryStore):
        scenario = create_sample_scenario("SCEN-LIFE-001")
        in_memory_store.add_scenario(scenario)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-LIFE-001",
            action_parameters={"executable": "hostname"},
        )

        evidence, test_run = runner.execute(req)

        assert evidence.status == RunnerExecutionState.COMPLETED
        assert evidence.exit_code == 0
        assert evidence.duration_seconds >= 0.0
        assert evidence.execution_token.startswith("tok-exec-")
        assert evidence.cleanup_status == "COMPLETED"
        assert evidence.integrity_hash is not None
        assert len(evidence.integrity_hash) == 64

        assert test_run is not None
        assert test_run.execution_status == ExecutionStatus.COMPLETED
        assert test_run.execution_token == evidence.execution_token
        assert test_run.scenario_id == "SCEN-LIFE-001"

    def test_execution_failure_handling(self, in_memory_store: InMemoryStore):
        """Using approved controlled exit profile to test deliberate non-zero exit code."""
        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            action_parameters={
                "profile": "exit_with_code",
                "exit_code": 42,
            },
        )

        evidence, test_run = runner.execute(req)

        assert evidence.status == RunnerExecutionState.FAILED
        assert evidence.exit_code == 42
        assert evidence.error_classification == "EXECUTION_FAILURE"
        assert evidence.cleanup_status == "COMPLETED"

    def test_execution_timeout_lifecycle(self, in_memory_store: InMemoryStore):
        """Using approved controlled sleep profile to test bounded timeout termination."""
        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            action_parameters={
                "profile": "sleep",
                "duration_seconds": 10.0,
            },
            timeout_seconds=0.5,
        )

        evidence, test_run = runner.execute(req)

        assert evidence.status == RunnerExecutionState.TIMED_OUT
        assert evidence.timed_out is True
        assert evidence.error_classification == "EXECUTION_TIMEOUT"
        assert evidence.cleanup_status == "COMPLETED"

    def test_workspace_cleanup_failure_resilience(self, in_memory_store: InMemoryStore, monkeypatch):
        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            action_parameters={"executable": "hostname"},
        )

        # Mock workspace cleanup to fail
        def failing_cleanup(self):
            return "FAILED", "Simulated permission denied during workspace rmtree"

        monkeypatch.setattr(ExecutionWorkspace, "cleanup", failing_cleanup)

        evidence, _ = runner.execute(req)

        assert evidence.status == RunnerExecutionState.COMPLETED
        assert evidence.cleanup_status == "FAILED"
        assert "Simulated permission denied" in (evidence.cleanup_error or "")
        # Record must still be persisted safely
        persisted = in_memory_store.get_execution(evidence.execution_id)
        assert persisted is not None
        assert persisted.execution_id == evidence.execution_id


# ─────────────────────────────────────────────────────────────────────────────
# 3. Security Boundaries Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase20SecurityBoundaries:
    """Rigorous verification of process isolation, shell=False, and path traversal rejection."""

    def test_shell_is_strictly_false(self, in_memory_store: InMemoryStore, monkeypatch):
        """Verify that subprocess invocation enforces shell=False and argument lists."""
        called_popen = False

        original_popen = subprocess.Popen

        def spy_popen(*args, **kwargs):
            nonlocal called_popen
            called_popen = True
            # Assert shell=False
            assert kwargs.get("shell") is False, "CRITICAL: shell must strictly be False"
            # Assert command is passed as array of args, not raw shell string
            cmd = args[0] if args else kwargs.get("args")
            assert isinstance(cmd, list), f"CRITICAL: args must be a list, got {type(cmd)}"
            return original_popen(*args, **kwargs)

        monkeypatch.setattr(subprocess, "Popen", spy_popen)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            action_parameters={"executable": "hostname"},
        )
        evidence, _ = runner.execute(req)
        assert called_popen is True
        assert evidence.status == RunnerExecutionState.COMPLETED

    def test_arbitrary_binary_execution_blocked(self, in_memory_store: InMemoryStore):
        runner = ControlledExecutionRunner(store=in_memory_store)
        for dangerous_binary in ["curl", "bash", "cmd.exe", "powershell.exe", "nc", "net.exe"]:
            req = ExecutionRequestV1(
                action_id="process.spawn_benign",
                action_parameters={"executable": dangerous_binary},
            )
            validation = runner.validate_request(req)
            assert validation.is_valid is False
            assert any("not in the approved safety allowlist" in err for err in validation.errors)

            with pytest.raises(ValueError, match="validation rejected"):
                runner.execute(req)

    def test_path_traversal_strictly_rejected(self, in_memory_store: InMemoryStore):
        runner = ControlledExecutionRunner(store=in_memory_store)
        for dangerous_path in [
            "../outside.txt",
            "../../etc/passwd",
            "..\\..\\windows\\system32\\calc.exe",
            "sub/../../escape.txt",
        ]:
            req = ExecutionRequestV1(
                action_id="file.create_temporary",
                action_parameters={"filename": dangerous_path, "content": "payload"},
            )
            validation = runner.validate_request(req)
            assert validation.is_valid is False
            assert any("without directory separators" in err or "illegal characters" in err for err in validation.errors)

    def test_workspace_resolve_path_containment(self, tmp_path: Path):
        ws = ExecutionWorkspace(execution_id="EXEC-TEST-001", base_dir=tmp_path)
        ws.create()

        # Valid relative path inside workspace
        valid_path = ws.resolve_path("data.txt")
        assert valid_path.is_relative_to(ws.workspace_path)

        # Absolute path rejected
        with pytest.raises(ValueError, match="absolute paths are forbidden"):
            ws.resolve_path(str(tmp_path / "other.txt"))

        # Parent directory traversal rejected
        with pytest.raises(ValueError, match="Path traversal outside workspace root rejected"):
            ws.resolve_path("../escape.txt")

        ws.cleanup()

    def test_symlink_escape_rejection(self, tmp_path: Path):
        ws = ExecutionWorkspace(execution_id="EXEC-TEST-SYM", base_dir=tmp_path)
        ws.create()

        outside_dir = tmp_path / "outside_zone"
        outside_dir.mkdir(parents=True, exist_ok=True)
        outside_file = outside_dir / "secret.txt"
        outside_file.write_text("classified")

        link_path = ws.workspace_path / "sym_link.txt"
        try:
            os.symlink(str(outside_file), str(link_path))
            with pytest.raises(ValueError, match="outside workspace root"):
                ws.resolve_path("sym_link.txt")
        except (OSError, NotImplementedError):
            pass
        finally:
            ws.cleanup()

    def test_non_loopback_network_strictly_rejected(self, in_memory_store: InMemoryStore):
        runner = ControlledExecutionRunner(store=in_memory_store)
        for forbidden_host in ["8.8.8.8", "1.1.1.1", "192.168.1.50", "google.com", "10.0.0.1"]:
            req = ExecutionRequestV1(
                action_id="network.loopback_check",
                action_parameters={"target_host": forbidden_host},
            )
            validation = runner.validate_request(req)
            assert validation.is_valid is False
            assert any("Non-loopback network connection rejected" in err for err in validation.errors)

            with pytest.raises(ValueError, match="validation rejected"):
                runner.execute(req)

    def test_no_subprocess_executed_inside_transaction(self, in_memory_store: InMemoryStore, monkeypatch):
        """Confirm that actions run outside store.transaction() to prevent blocking DB locks."""
        tx_held = False

        orig_tx = in_memory_store.transaction
        from contextlib import contextmanager

        @contextmanager
        def spy_tx():
            nonlocal tx_held
            tx_held = True
            try:
                with orig_tx():
                    yield
            finally:
                tx_held = False

        monkeypatch.setattr(in_memory_store, "transaction", spy_tx)

        orig_execute_action = ProcessSpawnAction.execute

        def spy_execute_action(self, ctx):
            assert tx_held is False, "CRITICAL: Subprocess executed inside active DB transaction!"
            return orig_execute_action(self, ctx)

        monkeypatch.setattr(ProcessSpawnAction, "execute", spy_execute_action)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            action_parameters={"executable": "hostname"},
        )
        runner.execute(req)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Attribution Contract Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase20AttributionContract:
    """Verify execution token binding, propagation, and strict causal assurance."""

    def test_token_binding_and_evidence_correlation(self, in_memory_store: InMemoryStore):
        custom_token = "tok-custom-secops-999"
        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            action_parameters={"executable": "hostname"},
            execution_token=custom_token,
        )

        evidence, _ = runner.execute(req)

        assert evidence.execution_token == custom_token
        # Pass token through environment variable without altering native command arguments
        assert evidence.action_result.get("environment_token") == custom_token
        assert evidence.action_result.get("execution_token") == custom_token

    def test_strict_attribution_verdict_pass(self, in_memory_store: InMemoryStore):
        """When execution token matches between TestRun, Telemetry, and Alert -> PASS."""
        scenario = create_sample_scenario("SCEN-ATTR-001")
        rule = create_sample_rule("RULE-BENIGN-001")
        in_memory_store.add_scenario(scenario)
        in_memory_store.add_rule(rule)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-ATTR-001",
            action_parameters={"executable": "whoami"},
        )
        evidence, test_run = runner.execute(req)
        assert test_run is not None
        assert evidence.status == RunnerExecutionState.COMPLETED

        # Add matching normalized telemetry with the same execution token
        now = test_run.window_start + timedelta(seconds=1)
        telemetry = NormalizedTelemetryEventV1(
            schema_version="v1",
            normalized_event_id="NORM-ATTR-001",
            raw_event_id="RAW-ATTR-001",
            source_event_id="SRC-ATTR-001",
            source_timestamp=now,
            normalized_timestamp=now,
            event_category=EventCategory.PROCESS_CREATION,
            host=test_run.target_host,
            user=test_run.target_user,
            process_name=scenario.expected_process_name,
            process_path=f"C:\\Windows\\System32\\{scenario.expected_process_name}",
            command_line=f"{scenario.expected_process_name} --execution-token={test_run.execution_token}",
            execution_token=test_run.execution_token,
        )
        in_memory_store.add_normalized_event(telemetry)

        # Add matching alert with the same execution token
        alert = AlertV1(
            schema_version="v1",
            alert_id="ALERT-ATTR-001",
            source_alert_id="SRC-ALT-ATTR-1",
            source_type="wazuh",
            alert_timestamp=now + timedelta(seconds=1),
            ingested_at=now + timedelta(seconds=1),
            host_id=test_run.target_host,
            rule_reference=rule.rule_id,
            alert_title="Benign Discovery Detected",
            severity="low",
            execution_token=test_run.execution_token,
        )
        in_memory_store.add_alert(alert)

        engine = AssuranceEngine(store=in_memory_store)
        diag = engine.evaluate_run(test_run.run_id, strict_attribution=True)

        assert diag.predicted_category == DiagnosticCategory.PASS
        assert alert.alert_id in diag.supporting_evidence_ids
        assert telemetry.normalized_event_id in diag.supporting_evidence_ids

    def test_missing_token_produces_inconclusive_or_failure(self, in_memory_store: InMemoryStore):
        """When strict_attribution is True and telemetry lacks token, attribution is rejected."""
        scenario = create_sample_scenario("SCEN-ATTR-002")
        rule = create_sample_rule("RULE-BENIGN-001")
        in_memory_store.add_scenario(scenario)
        in_memory_store.add_rule(rule)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-ATTR-002",
            action_parameters={"executable": "whoami"},
        )
        _, test_run = runner.execute(req)
        assert test_run is not None

        # Telemetry matches host and process but has NO token
        now = test_run.window_start + timedelta(seconds=1)
        telemetry = NormalizedTelemetryEventV1(
            schema_version="v1",
            normalized_event_id="NORM-NO-TOKEN",
            raw_event_id="RAW-NO-TOKEN",
            source_event_id="SRC-NO-TOKEN",
            source_timestamp=now,
            normalized_timestamp=now,
            event_category=EventCategory.PROCESS_CREATION,
            host=test_run.target_host,
            user=test_run.target_user,
            process_name=scenario.expected_process_name,
            command_line=scenario.expected_process_name,
            execution_token=None,
        )
        in_memory_store.add_normalized_event(telemetry)

        engine = AssuranceEngine(store=in_memory_store)
        diag = engine.evaluate_run(test_run.run_id, strict_attribution=True)

        # Under strict attribution, missing token in telemetry fails causal attribution
        assert diag.predicted_category != DiagnosticCategory.PASS

    def test_conflicting_token_rejected(self, in_memory_store: InMemoryStore):
        """Telemetry carrying a token from a different run must not attribute to this run."""
        scenario = create_sample_scenario("SCEN-ATTR-003")
        rule = create_sample_rule("RULE-BENIGN-001")
        in_memory_store.add_scenario(scenario)
        in_memory_store.add_rule(rule)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-ATTR-003",
            action_parameters={"executable": "whoami"},
        )
        _, test_run = runner.execute(req)
        assert test_run is not None

        # Telemetry has conflicting foreign token
        now = test_run.window_start + timedelta(seconds=1)
        telemetry = NormalizedTelemetryEventV1(
            schema_version="v1",
            normalized_event_id="NORM-CONFLICT",
            raw_event_id="RAW-CONFLICT",
            source_event_id="SRC-CONFLICT",
            source_timestamp=now,
            normalized_timestamp=now,
            event_category=EventCategory.PROCESS_CREATION,
            host=test_run.target_host,
            user=test_run.target_user,
            process_name=scenario.expected_process_name,
            command_line=scenario.expected_process_name,
            execution_token="tok-foreign-run-conflict",
        )
        in_memory_store.add_normalized_event(telemetry)

        engine = AssuranceEngine(store=in_memory_store)
        diag = engine.evaluate_run(test_run.run_id, strict_attribution=True)
        assert diag.predicted_category != DiagnosticCategory.PASS


# ─────────────────────────────────────────────────────────────────────────────
# 5. Persistence Parity Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase20PersistenceParity:
    """Verify InMemoryStore and SQLiteStore parity, transactions, rollback, and durability."""

    def test_store_crud_parity(self, parameterized_store: StoreProtocol):
        now = datetime.now(timezone.utc)
        evidence = ExecutionEvidenceV1(
            schema_version="v1",
            execution_id="EXEC-PARITY-001",
            scenario_id="SCEN-001",
            test_run_id="RUN-001",
            campaign_id="CAMP-001",
            execution_token="tok-exec-parity-001",
            target_host="secops-node-1",
            platform={"system": "windows", "release": "10"},
            action_id="process.spawn_benign",
            action_version="1.0.0",
            parameters={"executable": "hostname"},
            requested_at=now,
            started_at=now,
            completed_at=now + timedelta(seconds=1),
            duration_seconds=1.0,
            status=RunnerExecutionState.COMPLETED,
            exit_code=0,
            action_result={"stdout": "secops-node-1"},
            timed_out=False,
            cleanup_status="COMPLETED",
            integrity_hash="abcdef0123456789" * 4,
        )

        parameterized_store.add_execution(evidence)

        retrieved = parameterized_store.get_execution("EXEC-PARITY-001")
        assert retrieved is not None
        assert retrieved.execution_id == "EXEC-PARITY-001"
        assert retrieved.execution_token == "tok-exec-parity-001"
        assert retrieved.status == RunnerExecutionState.COMPLETED
        assert retrieved.integrity_hash == "abcdef0123456789" * 4

        # Query list
        listed = parameterized_store.list_executions(scenario_id="SCEN-001")
        assert len(listed) == 1
        assert listed[0].execution_id == "EXEC-PARITY-001"

    def test_sqlite_reopen_durability(self, tmp_path: Path):
        db_file = tmp_path / "durability.db"
        store1 = SQLiteStore(db_file)

        now = datetime.now(timezone.utc)
        evidence = ExecutionEvidenceV1(
            schema_version="v1",
            execution_id="EXEC-DURABLE-001",
            execution_token="tok-exec-durable-001",
            target_host="host1",
            action_id="process.spawn_benign",
            action_version="1.0.0",
            requested_at=now,
            started_at=now,
            completed_at=now,
            duration_seconds=0.1,
            status=RunnerExecutionState.COMPLETED,
            exit_code=0,
            integrity_hash="1122334455667788" * 4,
        )
        store1.add_execution(evidence)
        store1.close()

        # Reopen with new instance
        store2 = SQLiteStore(db_file)
        retrieved = store2.get_execution("EXEC-DURABLE-001")
        assert retrieved is not None
        assert retrieved.execution_id == "EXEC-DURABLE-001"
        assert retrieved.integrity_hash == "1122334455667788" * 4
        store2.close()

    def test_transaction_rollback_parity(self, parameterized_store: StoreProtocol):
        now = datetime.now(timezone.utc)
        evidence = ExecutionEvidenceV1(
            schema_version="v1",
            execution_id="EXEC-ROLLBACK-001",
            execution_token="tok-exec-rollback-001",
            target_host="host1",
            action_id="process.spawn_benign",
            action_version="1.0.0",
            requested_at=now,
            started_at=now,
            completed_at=now,
            duration_seconds=0.1,
            status=RunnerExecutionState.COMPLETED,
            integrity_hash="aabbccddeeff0011" * 4,
        )

        try:
            with parameterized_store.transaction():
                parameterized_store.add_execution(evidence)
                raise RuntimeError("Simulated transaction failure")
        except RuntimeError:
            pass

        assert parameterized_store.get_execution("EXEC-ROLLBACK-001") is None

    def test_duplicate_execution_id_rejected(self, parameterized_store: StoreProtocol):
        now = datetime.now(timezone.utc)
        evidence = ExecutionEvidenceV1(
            schema_version="v1",
            execution_id="EXEC-DUP-001",
            execution_token="tok-exec-dup-001",
            target_host="host1",
            action_id="process.spawn_benign",
            action_version="1.0.0",
            requested_at=now,
            started_at=now,
            completed_at=now,
            duration_seconds=0.1,
            status=RunnerExecutionState.COMPLETED,
            integrity_hash="9988776655443322" * 4,
        )
        parameterized_store.add_execution(evidence)

        with pytest.raises(ValueError, match="already exists"):
            parameterized_store.add_execution(evidence)


# ─────────────────────────────────────────────────────────────────────────────
# 6. End-to-End Assurance Pipeline Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase20EndToEndPipeline:
    """Verify complete lifecycle: Scenario -> Execution -> Telemetry -> Alert -> Assurance."""

    def test_full_pipeline_pass(self, in_memory_store: InMemoryStore):
        # 1. Register scenario and detection rule
        scenario = create_sample_scenario("SCEN-E2E-001")
        rule = create_sample_rule("RULE-BENIGN-001")
        in_memory_store.add_scenario(scenario)
        in_memory_store.add_rule(rule)

        # 2. Run controlled execution
        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-E2E-001",
            action_parameters={"executable": "whoami"},
        )
        evidence, test_run = runner.execute(req)
        assert test_run is not None
        assert evidence.status == RunnerExecutionState.COMPLETED

        # 3. Telemetry arrives with token
        telemetry = NormalizedTelemetryEventV1(
            schema_version="v1",
            normalized_event_id="NORM-E2E-001",
            raw_event_id="RAW-E2E-001",
            source_event_id="SRC-E2E-001",
            source_timestamp=test_run.window_start + timedelta(seconds=1),
            normalized_timestamp=test_run.window_start + timedelta(seconds=1),
            event_category=EventCategory.PROCESS_CREATION,
            host=test_run.target_host,
            user=test_run.target_user,
            process_name=scenario.expected_process_name,
            process_path=f"C:\\Windows\\System32\\{scenario.expected_process_name}",
            command_line=f"{scenario.expected_process_name} --execution-token={test_run.execution_token}",
            execution_token=test_run.execution_token,
        )
        in_memory_store.add_normalized_event(telemetry)

        # 4. Correlated alert arrives
        alert = AlertV1(
            schema_version="v1",
            alert_id="ALERT-E2E-001",
            source_alert_id="SRC-ALT-E2E-1",
            source_type="wazuh",
            alert_timestamp=test_run.window_start + timedelta(seconds=2),
            ingested_at=test_run.window_start + timedelta(seconds=2),
            host_id=test_run.target_host,
            rule_reference=rule.rule_id,
            alert_title="Benign Discovery Detected",
            severity="low",
            execution_token=test_run.execution_token,
        )
        in_memory_store.add_alert(alert)

        # 5. Deterministic Assurance
        engine = AssuranceEngine(store=in_memory_store)
        diag = engine.evaluate_run(test_run.run_id, strict_attribution=True)

        assert diag.predicted_category == DiagnosticCategory.PASS
        assert alert.alert_id in diag.supporting_evidence_ids
        assert telemetry.normalized_event_id in diag.supporting_evidence_ids

    def test_telemetry_missing_pipeline_verdict(self, in_memory_store: InMemoryStore):
        scenario = create_sample_scenario("SCEN-E2E-MISSING-TELEM")
        rule = create_sample_rule("RULE-BENIGN-001")
        in_memory_store.add_scenario(scenario)
        in_memory_store.add_rule(rule)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-E2E-MISSING-TELEM",
            action_parameters={"executable": "whoami"},
        )
        evidence, test_run = runner.execute(req)
        assert test_run is not None
        assert evidence.status == RunnerExecutionState.COMPLETED

        # Zero telemetry ingested
        engine = AssuranceEngine(store=in_memory_store)
        diag = engine.evaluate_run(test_run.run_id, strict_attribution=True)

        assert diag.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    def test_alert_missing_pipeline_verdict(self, in_memory_store: InMemoryStore):
        scenario = create_sample_scenario("SCEN-E2E-MISSING-ALERT")
        rule = create_sample_rule("RULE-BENIGN-001")
        in_memory_store.add_scenario(scenario)
        in_memory_store.add_rule(rule)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-E2E-MISSING-ALERT",
            action_parameters={"executable": "whoami"},
        )
        evidence, test_run = runner.execute(req)
        assert test_run is not None
        assert evidence.status == RunnerExecutionState.COMPLETED

        # Telemetry ingested with token, but no alert exists
        telemetry = NormalizedTelemetryEventV1(
            schema_version="v1",
            normalized_event_id="NORM-NO-ALERT",
            raw_event_id="RAW-NO-ALERT",
            source_event_id="SRC-NO-ALERT",
            source_timestamp=test_run.window_start + timedelta(seconds=1),
            normalized_timestamp=test_run.window_start + timedelta(seconds=1),
            event_category=EventCategory.PROCESS_CREATION,
            host=test_run.target_host,
            user=test_run.target_user,
            process_name=scenario.expected_process_name,
            process_path=f"C:\\Windows\\System32\\{scenario.expected_process_name}",
            command_line=f"{scenario.expected_process_name} --execution-token={test_run.execution_token}",
            execution_token=test_run.execution_token,
        )
        in_memory_store.add_normalized_event(telemetry)

        engine = AssuranceEngine(store=in_memory_store)
        diag = engine.evaluate_run(test_run.run_id, strict_attribution=True)

        assert diag.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED

    def test_controlled_execution_to_elastic_orchestrator(self, in_memory_store: InMemoryStore):
        """Verify complete pipeline from endpoint execution runner through Elastic orchestrator to PASS."""
        from proofshield.connectors.elastic import ElasticAlertClient
        from proofshield.services.elastic_orchestrator import ElasticAssuranceOrchestrator
        from tests.mock_elastic_server import run_mock_elastic_server
        from tests.test_elastic_integration_phase19 import make_ecs_alert_hit, make_ecs_telemetry_hit

        scenario = create_sample_scenario("SCEN-ELASTIC-ORCH-01")
        rule = create_sample_rule("RULE-BENIGN-001")
        in_memory_store.add_scenario(scenario)
        in_memory_store.add_rule(rule)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-ELASTIC-ORCH-01",
            action_parameters={"executable": "whoami"},
        )
        evidence, test_run = runner.execute(req)
        assert test_run is not None
        assert evidence.status == RunnerExecutionState.COMPLETED

        with run_mock_elastic_server() as mock:
            hit_ts = (test_run.executed_at + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            mock.set_telemetry_hits([
                make_ecs_telemetry_hit(
                    hit_id="hit-tel-01",
                    timestamp=hit_ts,
                    hostname=test_run.target_host,
                    process_name=scenario.expected_process_name,
                    token=test_run.execution_token,
                )
            ])
            mock.set_alert_hits([
                make_ecs_alert_hit(
                    hit_id="hit-alert-01",
                    timestamp=hit_ts,
                    hostname=test_run.target_host,
                    rule_id=rule.rule_id,
                    token=test_run.execution_token,
                )
            ])

            client = mock.get_client()
            orchestrator = ElasticAssuranceOrchestrator(client=client, store=in_memory_store)
            eval_result, report = orchestrator.evaluate_run_with_orchestration(
                run_id=test_run.run_id,
                strict_attribution=True,
            )

            assert report.is_complete is True
            assert eval_result.predicted_category == DiagnosticCategory.PASS


# ─────────────────────────────────────────────────────────────────────────────
# 7. HTTP API Endpoint Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase20ApiEndpoints:
    """Verify HTTP API contracts, dry-run validation, and execution endpoints."""

    def test_api_list_actions(self, test_client: TestClient):
        res = test_client.get("/api/v1/execution/actions")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        action_ids = [a["action_id"] for a in data]
        assert "process.spawn_benign" in action_ids
        assert "file.create_temporary" in action_ids

    def test_api_get_action_descriptor(self, test_client: TestClient):
        res = test_client.get("/api/v1/execution/actions/process.spawn_benign")
        assert res.status_code == 200
        data = res.json()
        assert data["action_id"] == "process.spawn_benign"
        assert data["expected_observable_category"] == EventCategory.PROCESS_CREATION.value

        # Unknown action returns 404
        not_found = test_client.get("/api/v1/execution/actions/unknown.action")
        assert not_found.status_code == 404

    def test_api_validate_request(self, test_client: TestClient):
        # Valid request
        payload = {
            "schema_version": "v1",
            "action_id": "process.spawn_benign",
            "action_parameters": {"executable": "hostname"},
        }
        res = test_client.post("/api/v1/execution/validate", json=payload)
        assert res.status_code == 200
        val = res.json()
        assert val["is_valid"] is True
        assert val["authorized"] is True

        # Invalid request with non-whitelisted binary
        bad_payload = {
            "schema_version": "v1",
            "action_id": "process.spawn_benign",
            "action_parameters": {"executable": "curl"},
        }
        res_bad = test_client.post("/api/v1/execution/validate", json=bad_payload)
        assert res_bad.status_code == 200
        val_bad = res_bad.json()
        assert val_bad["is_valid"] is False
        assert len(val_bad["errors"]) > 0

    def test_api_run_execution(self, test_client: TestClient):
        payload = {
            "schema_version": "v1",
            "action_id": "process.spawn_benign",
            "action_parameters": {"executable": "hostname"},
        }
        res = test_client.post("/api/v1/execution/run", json=payload)
        assert res.status_code == 200
        evidence = res.json()
        assert evidence["status"] == "COMPLETED"
        assert evidence["exit_code"] == 0
        assert "integrity_hash" in evidence

        exec_id = evidence["execution_id"]

        # Retrieve via GET /execution/records/{execution_id}
        get_res = test_client.get(f"/api/v1/execution/records/{exec_id}")
        assert get_res.status_code == 200
        assert get_res.json()["execution_id"] == exec_id

        # List records
        list_res = test_client.get("/api/v1/execution/records")
        assert list_res.status_code == 200
        records = list_res.json()
        assert any(r["execution_id"] == exec_id for r in records)

    def test_api_run_rejected_with_400(self, test_client: TestClient):
        payload = {
            "schema_version": "v1",
            "action_id": "process.spawn_benign",
            "action_parameters": {"executable": "powershell.exe"},
        }
        res = test_client.post("/api/v1/execution/run", json=payload)
        assert res.status_code == 400
        assert "rejected" in res.json()["detail"].lower()

    def test_api_cancel_execution(self, test_client: TestClient):
        # Cancellation of non-existent execution returns 404
        res = test_client.post("/api/v1/execution/records/EXEC-NONEXISTENT/cancel")
        assert res.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 8. Security Hardening, Process Lifecycle & Tampering Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase20SecurityHardening:
    """Verify endpoint authentication, executable pinning, real cancellation, and evidence tampering."""

    def test_unauthorized_api_requests_rejected(self):
        """All execution routes must reject unauthenticated requests with 401."""
        client = TestClient(app)  # No authorization header
        os.environ["PROOFSHIELD_EXEC_TOKEN"] = "valid-token-1234"

        routes_to_test = [
            ("GET", "/api/v1/execution/actions"),
            ("GET", "/api/v1/execution/actions/process.spawn_benign"),
            ("POST", "/api/v1/execution/validate"),
            ("POST", "/api/v1/execution/run"),
            ("GET", "/api/v1/execution/records"),
            ("GET", "/api/v1/execution/records/EXEC-123"),
            ("POST", "/api/v1/execution/records/EXEC-123/cancel"),
        ]

        for method, route in routes_to_test:
            if method == "GET":
                res = client.get(route)
            else:
                res = client.post(route, json={})
            assert res.status_code == 401, f"Route {route} failed to reject unauthenticated request"
            assert "WWW-Authenticate" in res.headers

    def test_invalid_bearer_token_rejected(self):
        """Invalid credentials must return 401 Unauthorized."""
        client = TestClient(app)
        os.environ["PROOFSHIELD_EXEC_TOKEN"] = "valid-token-1234"
        client.headers["Authorization"] = "Bearer wrong-token-5678"

        res = client.get("/api/v1/execution/actions")
        assert res.status_code == 401
        assert "invalid" in res.json()["detail"].lower()

    def test_unconfigured_auth_fails_closed(self, monkeypatch):
        """When PROOFSHIELD_EXEC_TOKEN is unset, execution subsystem fails closed with 503."""
        monkeypatch.delenv("PROOFSHIELD_EXEC_TOKEN", raising=False)
        client = TestClient(app)
        client.headers["Authorization"] = "Bearer test"

        res = client.get("/api/v1/execution/actions")
        assert res.status_code == 503
        assert "not configured" in res.json()["detail"].lower()

    def test_server_secret_is_removed_from_all_action_child_environments(
        self, in_memory_store: InMemoryStore, monkeypatch
    ):
        """Approved process actions may receive only the separate execution token."""
        captured = []

        class CaptureManager:
            def spawn_and_wait(self, **kwargs):
                captured.append(kwargs)
                return 0, "", "", False, False

        monkeypatch.setenv(SERVER_EXECUTION_SECRET_ENV, "server-secret-never-child")
        monkeypatch.setattr(
            "proofshield.execution.actions.process_actions.get_default_process_manager",
            lambda: CaptureManager(),
        )

        workspace = ExecutionWorkspace("EXEC-ENV-AUDIT")
        workspace.create()
        try:
            for action, parameters in (
                (ProcessSpawnAction(), {"profile": "whoami"}),
                (ProcessLifecycleAction(), {}),
            ):
                action.execute(
                    ActionContext(
                        execution_id="EXEC-ENV-AUDIT",
                        execution_token="execution-token-only",
                        workspace=workspace,
                        parameters=parameters,
                        timeout_seconds=1.0,
                    )
                )
        finally:
            workspace.cleanup()

        assert len(captured) == 2
        for call in captured:
            assert SERVER_EXECUTION_SECRET_ENV not in call["env"]
            assert call["env"][EXECUTION_TOKEN_ENV] == "execution-token-only"

    def test_process_manager_filters_secret_before_real_child_spawn(self, monkeypatch):
        """The lifecycle manager remains safe even when handed a copied environment."""
        monkeypatch.setenv(SERVER_EXECUTION_SECRET_ENV, "server-secret-never-child")
        env = os.environ.copy()
        command = [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('PROOFSHIELD_EXEC_TOKEN', '<absent>'))",
        ]
        result = process_manager_module.ProcessLifecycleManager(max_concurrent=1).spawn_and_wait(
            execution_id="EXEC-ENV-MANAGER",
            cmd_args=command,
            cwd=Path.cwd(),
            env=env,
            timeout_seconds=5.0,
        )
        assert result[0] == 0
        assert result[1].strip() == "<absent>"

    def test_windows_taskkill_path_filters_secret(self, monkeypatch, tmp_path):
        """The Windows cancellation helper must not inherit the bearer secret."""
        captured = {}

        class Result:
            returncode = 0

        def fake_run(*args, **kwargs):
            captured.update(kwargs)
            return Result()

        monkeypatch.setenv(SERVER_EXECUTION_SECRET_ENV, "server-secret-never-taskkill")
        monkeypatch.setattr(process_manager_module, "_IS_WINDOWS", True)
        (tmp_path / "taskkill.exe").touch()
        monkeypatch.setattr(process_manager_module, "_get_system32_path", lambda: tmp_path)
        monkeypatch.setattr(process_manager_module.subprocess, "run", fake_run)
        assert process_manager_module.terminate_process_tree(12345) is True
        assert SERVER_EXECUTION_SECRET_ENV not in captured["env"]

    def test_child_output_redacts_server_secret(self, monkeypatch):
        """Unexpected secret output cannot be persisted in execution evidence."""
        monkeypatch.setenv(SERVER_EXECUTION_SECRET_ENV, "server-secret-output")
        assert _sanitize_output("prefix server-secret-output suffix") == (
            "prefix [REDACTED_SECRET] suffix"
        )

    def test_server_secret_cannot_be_persisted_as_execution_token(
        self, in_memory_store: InMemoryStore, monkeypatch
    ):
        """The authentication secret cannot be reused as attribution evidence."""
        monkeypatch.setenv(SERVER_EXECUTION_SECRET_ENV, "server-secret-evidence")
        runner = ControlledExecutionRunner(store=in_memory_store)
        request = ExecutionRequestV1(
            action_id="process.spawn_benign",
            execution_token="server-secret-evidence",
            action_parameters={"profile": "whoami"},
        )
        with pytest.raises(ValueError, match="must differ"):
            runner.execute(request)

    def test_adversarial_arbitrary_python_code_injection_rejected(self, in_memory_store: InMemoryStore):
        """Arbitrary python code execution via -c must be strictly rejected."""
        runner = ControlledExecutionRunner(store=in_memory_store)
        malicious_requests = [
            {"executable": "python", "additional_args": ["-c", "import os; os.system('echo pwned')"]},
            {"executable": "python", "additional_args": ["-c", "__import__('subprocess').call(['calc.exe'])"]},
            {"executable": "python", "additional_args": ["-c", "raise SystemExit(1)"]},
        ]
        for params in malicious_requests:
            req = ExecutionRequestV1(action_id="process.spawn_benign", action_parameters=params)
            validation = runner.validate_request(req)
            assert validation.is_valid is False
            assert any("Arbitrary code execution" in err for err in validation.errors)

    def test_adversarial_shell_metacharacters_rejected(self, in_memory_store: InMemoryStore):
        """Shell operators and metacharacters must be rejected even with shell=False."""
        runner = ControlledExecutionRunner(store=in_memory_store)
        for bad_arg in ["; whoami", "| calc", "& net user", "`id`", "$(id)"]:
            req = ExecutionRequestV1(
                action_id="process.spawn_benign",
                action_parameters={"executable": "hostname", "additional_args": [bad_arg]},
            )
            validation = runner.validate_request(req)
            assert validation.is_valid is False
            assert any("Dangerous character" in err for err in validation.errors)

    def test_evidence_integrity_tampering_detected(self):
        """Execution evidence hash must fail verification when payload fields are mutated."""
        now = datetime.now(timezone.utc)
        evidence = ExecutionEvidenceV1(
            schema_version="v1",
            execution_id="EXEC-TAMPER-001",
            execution_token="tok-tamper-001",
            target_host="localhost",
            action_id="process.spawn_benign",
            action_version="1.0.0",
            requested_at=now,
            started_at=now,
            completed_at=now,
            duration_seconds=0.5,
            status=RunnerExecutionState.COMPLETED,
            exit_code=0,
        )
        evidence.integrity_hash = evidence.calculate_integrity_hash()
        assert evidence.verify_integrity() is True

        # Tampering with exit code
        evidence.exit_code = 999
        assert evidence.verify_integrity() is False

        # Restoring exit code
        evidence.exit_code = 0
        assert evidence.verify_integrity() is True

        # Tampering with execution token
        evidence.execution_token = "tok-forged"
        assert evidence.verify_integrity() is False

    def test_real_process_tree_cancellation_terminates_descendants(self, in_memory_store: InMemoryStore):
        """Cancellation must actively terminate the running process and its child processes."""
        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            action_parameters={"profile": "process_tree"},
            timeout_seconds=30.0,
        )

        # Launch in background thread
        exec_thread = None
        evidence_holder: Dict[str, Any] = {}

        def run_target():
            ev, _ = runner.execute(req)
            evidence_holder["evidence"] = ev

        import threading
        t = threading.Thread(target=run_target)
        t.start()

        # Wait briefly for process to spawn and write child PID
        time.sleep(1.0)

        # Find active execution ID
        active_ids = list(runner._active_executions.keys())
        assert len(active_ids) == 1
        active_id = active_ids[0]

        # Read child PID from workspace
        ws = ExecutionWorkspace(execution_id=active_id)
        child_pid_file = ws.workspace_dir / "child_pid.txt"
        child_pid = None
        if child_pid_file.exists():
            try:
                child_pid = int(child_pid_file.read_text(encoding="utf-8").strip())
            except Exception:
                pass

        # Trigger cancellation
        cancelled = runner.cancel_execution(active_id)
        assert cancelled is True

        t.join(timeout=5.0)
        assert not t.is_alive()

        ev = evidence_holder.get("evidence")
        assert ev is not None
        assert ev.status == RunnerExecutionState.CANCELLED

        # Verify child process is dead
        if child_pid is not None:
            time.sleep(0.5)
            if sys.platform == "win32":
                chk = subprocess.run(["tasklist", "/FI", f"PID eq {child_pid}"], capture_output=True, text=True)
                assert str(child_pid) not in chk.stdout
            else:
                try:
                    os.kill(child_pid, 0)
                    is_alive = True
                except OSError:
                    is_alive = False
                assert is_alive is False

    def test_observation_window_post_execution_buffer(self, in_memory_store: InMemoryStore):
        """Observation window must include settling buffer beyond process completion time."""
        scenario = create_sample_scenario("SCEN-OBS-001")
        in_memory_store.add_scenario(scenario)

        runner = ControlledExecutionRunner(store=in_memory_store, settling_time_seconds=5.0)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-OBS-001",
            action_parameters={"executable": "whoami"},
        )
        evidence, test_run = runner.execute(req)
        assert test_run is not None

        # Process completion vs window end
        delta = (test_run.window_end - evidence.completed_at).total_seconds()
        assert delta >= 4.9, f"Observation window did not include settling buffer: delta={delta}"

        # Late telemetry arriving 2 seconds after process exit is within window
        late_ts = evidence.completed_at + timedelta(seconds=2.0)
        assert test_run.window_start <= late_ts <= test_run.window_end

    def test_execute_with_assurance_service_orchestration(self, in_memory_store: InMemoryStore):
        """Explicit orchestration boundary coordinates execution and assurance evaluation."""
        from proofshield.services.elastic_orchestrator import ElasticAssuranceOrchestrator
        from tests.mock_elastic_server import run_mock_elastic_server
        from tests.test_elastic_integration_phase19 import make_ecs_alert_hit, make_ecs_telemetry_hit

        scenario = create_sample_scenario("SCEN-ORCH-INTEG-01")
        rule = create_sample_rule("RULE-BENIGN-001")
        in_memory_store.add_scenario(scenario)
        in_memory_store.add_rule(rule)

        runner = ControlledExecutionRunner(store=in_memory_store)
        req = ExecutionRequestV1(
            action_id="process.spawn_benign",
            scenario_id="SCEN-ORCH-INTEG-01",
            action_parameters={"executable": "whoami"},
        )

        with run_mock_elastic_server() as mock:
            client = mock.get_client()
            orchestrator = ElasticAssuranceOrchestrator(client=client, store=in_memory_store)

            # Pre-seed mock hits
            hit_ts = (datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            # We don't have token in advance, but mock can return dynamic or we use execute_with_assurance
            evidence, test_run, eval_result, report = runner.execute_with_assurance(
                req,
                orchestrator=orchestrator,
                strict_attribution=False,
            )

            assert evidence.verify_integrity() is True
            assert test_run is not None
            assert report is not None
            assert eval_result is not None
