"""Controlled, benign filesystem validation actions."""

from pathlib import Path
import re
from typing import Any, Dict, List

from proofshield.execution.actions.base import ActionContext, ActionResult, BaseAction
from proofshield.schemas.common import EventCategory


class FileCreateAction(BaseAction):
    """Creates a temporary benign file inside the isolated execution workspace."""

    action_id = "file.create_temporary"
    version = "1.0.0"
    name = "Temporary File Creation"
    description = (
        "Creates a controlled benign text file strictly inside the ProofShield workspace, "
        "writing metadata and the execution token to produce observable file creation telemetry."
    )
    supported_platforms = ["windows", "linux", "darwin"]
    expected_observable_category = EventCategory.FILE_EVENT
    max_timeout_seconds = 10.0

    def get_parameter_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Relative filename to create inside the workspace",
                    "default": "proofshield_test_artifact.txt",
                },
                "content_prefix": {
                    "type": "string",
                    "description": "Optional harmless prefix text; excluded from persisted execution evidence",
                    "default": "PROOFSHIELD_BENIGN_VALIDATION",
                },
                "content": {
                    "type": ["string", "null"],
                    "description": "Optional file content; execution-only and never persisted in evidence",
                },
            },
        }

    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if "filename" not in params or not str(params["filename"]).strip():
            raise ValueError("Parameter 'filename' is required")

        raw_name = str(params["filename"]).strip()
        # Reject traversal attempts immediately
        if ".." in raw_name or "/" in raw_name or "\\" in raw_name or ":" in raw_name:
            raise ValueError(f"Filename must be a simple relative name without directory separators: '{raw_name}'")

        if not re.match(r"^[A-Za-z0-9_\-\.]+$", raw_name):
            raise ValueError(f"Filename contains illegal characters: '{raw_name}'")

        # Content is intentionally accepted for the controlled file action but
        # is redacted by the centralized evidence boundary before persistence.
        content = params.get("content")
        if content is not None:
            if not isinstance(content, (str, bytes)):
                raise ValueError("Parameter 'content' must be a string or bytes")
            size = len(content.encode("utf-8")) if isinstance(content, str) else len(content)
            if size > 1048576:
                raise ValueError(f"Content size {size} exceeds 1048576 byte limit")

        prefix = str(params.get("content_prefix", "PROOFSHIELD_BENIGN_VALIDATION")).strip()
        if len(prefix) > 512:
            raise ValueError("content_prefix exceeds 512 character boundary")

        return {
            "filename": raw_name,
            "content": content,
            "content_prefix": prefix,
        }

    def execute(self, ctx: ActionContext) -> ActionResult:
        params = self.validate_parameters(ctx.parameters)
        target_path = ctx.workspace.resolve_path(params["filename"])

        if params.get("content") is not None:
            raw_c = params["content"]
            if isinstance(raw_c, str):
                content_to_write = f"{raw_c}\n[EXECUTION_TOKEN:{ctx.execution_token}]\n"
                target_path.write_text(content_to_write, encoding="utf-8")
            else:
                target_path.write_bytes(raw_c)
        else:
            content_to_write = (
                f"PROOFSHIELD BENIGN SECURITY VALIDATION ARTIFACT\n"
                f"Prefix: {params['content_prefix']}\n"
                f"Execution-ID: {ctx.execution_id}\n"
                f"TOKEN: {ctx.execution_token}\n"
                f"[EXECUTION_TOKEN:{ctx.execution_token}]\n"
            )
            target_path.write_text(content_to_write, encoding="utf-8")

        try:
            file_size = target_path.stat().st_size
            return ActionResult(
                exit_code=0,
                output_data={
                    "file_path": str(target_path),
                    "file_size": file_size,
                    "execution_token": ctx.execution_token,
                },
                evidence_references=[str(target_path)],
                error_message=None,
            )
        except Exception as exc:
            return ActionResult(
                exit_code=-1,
                output_data={"file_path": str(target_path)},
                error_message=f"File creation failed: {exc}",
            )

    def cleanup(self, ctx: ActionContext) -> None:
        params = self.validate_parameters(ctx.parameters)
        try:
            target_path = ctx.workspace.resolve_path(params["filename"])
            if target_path.exists():
                target_path.unlink(missing_ok=True)
        except Exception:
            pass


class FileModifyReadAction(BaseAction):
    """Writes, mutates, and reads a benign file in the workspace to test file modification telemetry."""

    action_id = "file.modify_read"
    version = "1.0.0"
    name = "Benign File Mutation & Read"
    description = "Writes a file, appends an update containing the token, and reads it back to test modification telemetry."
    supported_platforms = ["windows", "linux", "darwin"]
    expected_observable_category = EventCategory.FILE_EVENT
    max_timeout_seconds = 10.0

    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        raw_name = str(params.get("filename", "proofshield_mutate.txt")).strip()
        if ".." in raw_name or "/" in raw_name or "\\" in raw_name or ":" in raw_name:
            raise ValueError(f"Filename must be a simple relative name without directory separators: '{raw_name}'")
        return {"filename": raw_name}

    def execute(self, ctx: ActionContext) -> ActionResult:
        params = self.validate_parameters(ctx.parameters)
        target_path = ctx.workspace.resolve_path(params["filename"])

        try:
            # Step 1: Initial write
            target_path.write_text(f"Initial content [TOKEN:{ctx.execution_token}]\n", encoding="utf-8")
            # Step 2: Mutation append
            with open(target_path, "a", encoding="utf-8") as f:
                f.write(f"Updated content with execution token: {ctx.execution_token}\n")
            # Step 3: Read back
            read_back = target_path.read_text(encoding="utf-8")
            token_present = ctx.execution_token in read_back

            return ActionResult(
                exit_code=0 if token_present else 1,
                output_data={
                    "file_path": str(target_path),
                    "token_verified": token_present,
                    "bytes_read": len(read_back.encode("utf-8")),
                },
                evidence_references=[str(target_path)],
                error_message=None if token_present else "Token verification failed on read-back",
            )
        except Exception as exc:
            return ActionResult(
                exit_code=-1,
                output_data={"file_path": str(target_path)},
                error_message=f"File mutation failed: {exc}",
            )

    def cleanup(self, ctx: ActionContext) -> None:
        params = self.validate_parameters(ctx.parameters)
        try:
            target_path = ctx.workspace.resolve_path(params["filename"])
            if target_path.exists():
                target_path.unlink(missing_ok=True)
        except Exception:
            pass
