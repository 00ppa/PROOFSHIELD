"""Adversarial tests for the Batch 2 execution-evidence sanitization boundary."""

from pathlib import Path

from proofshield.execution.evidence import (
    REDACTED_CONTENT,
    REDACTED_SENSITIVE,
    sanitize_execution_evidence_fields,
)
from proofshield.execution.runner import ControlledExecutionRunner
from proofshield.schemas.execution import ExecutionRequestV1
from proofshield.services.store import InMemoryStore


def test_sanitizer_redacts_nested_content_credentials_and_inline_secrets():
    canaries = [
        "FILE-CONTENT-CANARY-7f8e",
        "PASSWORD-CANARY-1a2b",
        "INLINE-CANARY-3c4d",
    ]
    fields = sanitize_execution_evidence_fields(
        parameters={
            "filename": "safe.txt",
            "content": canaries[0],
            "nested": {"password": canaries[1], "safe_note": "retain-me"},
        },
        action_result={"stdout": f"password={canaries[2]}", "safe_count": 3},
        metadata={"custom": {"api_key": canaries[1], "operator_note": "retain-me"}},
        evidence_references=["safe-reference.txt"],
        error_message=None,
        cleanup_error=None,
    )
    serialized = str(fields)
    assert all(canary not in serialized for canary in canaries)
    assert fields["parameters"]["content"] == REDACTED_CONTENT
    assert fields["parameters"]["nested"]["password"] == REDACTED_SENSITIVE
    assert fields["parameters"]["nested"]["safe_note"] == "retain-me"
    assert fields["action_result"]["safe_count"] == 3
    assert fields["metadata"]["custom"]["operator_note"] == "retain-me"


def test_file_content_and_sensitive_metadata_never_enter_persisted_evidence(tmp_path: Path):
    content_canary = "RAW-FILE-CONTENT-CANARY-9e8f"
    password_canary = "NESTED-PASSWORD-CANARY-7d6c"
    metadata_canary = "METADATA-SECRET-CANARY-5b4a"
    store = InMemoryStore()
    runner = ControlledExecutionRunner(store=store, workspace_base_dir=tmp_path, settling_time_seconds=0)
    request = ExecutionRequestV1(
        action_id="file.create_temporary",
        action_parameters={
            "filename": "safe-artifact.txt",
            "content": content_canary,
            "content_prefix": "PREFIX-CANARY-4a3b",
            "unexpected": {"password": password_canary},
        },
        metadata={
            "safe_metadata": "retain-me",
            "nested": {"password": password_canary, "api_key": metadata_canary},
        },
    )

    evidence, _ = runner.execute(request)
    serialized = evidence.model_dump_json()

    assert all(canary not in serialized for canary in (content_canary, password_canary, metadata_canary, "PREFIX-CANARY-4a3b"))
    assert evidence.parameters["filename"] == "safe-artifact.txt"
    assert evidence.parameters["content"] == REDACTED_CONTENT
    assert evidence.parameters["content_prefix"] == REDACTED_CONTENT
    assert evidence.metadata["custom_metadata"]["safe_metadata"] == "retain-me"
    assert evidence.metadata["custom_metadata"]["nested"]["password"] == REDACTED_SENSITIVE
    assert evidence.verify_integrity() is True

    persisted = store.get_execution(evidence.execution_id)
    assert persisted is not None
    assert persisted.model_dump_json() == serialized
    assert persisted.verify_integrity() is True


def test_legitimate_file_creation_metadata_remains_available(tmp_path: Path):
    store = InMemoryStore()
    runner = ControlledExecutionRunner(store=store, workspace_base_dir=tmp_path, settling_time_seconds=0)
    evidence, _ = runner.execute(
        ExecutionRequestV1(
            action_id="file.create_temporary",
            action_parameters={"filename": "legitimate.txt"},
        )
    )

    assert evidence.status.value == "COMPLETED"
    assert evidence.action_result["file_size"] > 0
    assert evidence.action_result["execution_token"] == evidence.execution_token
    assert evidence.parameters["filename"] == "legitimate.txt"
    assert evidence.verify_integrity() is True
