"""Controlled, benign process execution actions with strict profile boundaries."""

from datetime import datetime, timezone
import os
import math
from pathlib import Path
import shutil
import sys
from typing import Any, Dict, List, Optional

from proofshield.execution.actions.base import ActionContext, ActionResult, BaseAction
from proofshield.execution.environment import build_child_environment, redact_server_secret
from proofshield.execution.process_manager import get_default_process_manager
from proofshield.schemas.common import EventCategory

SCRIPTS_DIR = (Path(__file__).parent.parent / "scripts").resolve()

_IS_WINDOWS = sys.platform.startswith("win32") or sys.platform.startswith("cygwin")


def _get_system32_path() -> Path:
    """Return the canonical Windows System32 directory."""
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or "C:\\Windows"
    return (Path(root) / "System32").resolve()


def _resolve_canonical_binary(target: str) -> List[str]:
    """Resolve an approved target binary to its immutable canonical absolute path.

    Never searches the current working directory or untrusted user directories.
    """
    target = target.strip().lower()
    if target.endswith(".exe"):
        target = target[:-4]

    if _IS_WINDOWS:
        sys32 = _get_system32_path()
        if target == "whoami":
            bin_path = sys32 / "whoami.exe"
            if bin_path.exists():
                return [str(bin_path)]
            resolved = shutil.which("whoami.exe")
            if resolved and Path(resolved).resolve().parent == sys32:
                return [resolved]
            raise ValueError(f"Canonical Windows binary for 'whoami' not found in {sys32}")

        if target == "hostname":
            bin_path = sys32 / "hostname.exe"
            if bin_path.exists():
                return [str(bin_path)]
            resolved = shutil.which("hostname.exe")
            if resolved and Path(resolved).resolve().parent == sys32:
                return [resolved]
            raise ValueError(f"Canonical Windows binary for 'hostname' not found in {sys32}")

        if target == "echo":
            cmd_path = sys32 / "cmd.exe"
            if not cmd_path.exists():
                raise ValueError("Canonical cmd.exe is unavailable")
            return [str(cmd_path), "/d", "/c", "echo", "ProofShield benign validation"]

        if target == "uname":
            # Windows fallback: run controlled python script to output platform
            helper = SCRIPTS_DIR / "sleep_and_exit.py"
            return [sys.executable, "-I", str(helper), "0.01"]

    else:
        # POSIX
        if target == "whoami":
            for candidate in ["/usr/bin/whoami", "/bin/whoami"]:
                if Path(candidate).exists():
                    return [candidate]
            resolved = shutil.which("whoami")
            if resolved and (resolved.startswith("/bin/") or resolved.startswith("/usr/bin/")):
                return [resolved]
            return ["/usr/bin/whoami"]

        if target == "hostname":
            for candidate in ["/bin/hostname", "/usr/bin/hostname"]:
                if Path(candidate).exists():
                    return [candidate]
            resolved = shutil.which("hostname")
            if resolved and (resolved.startswith("/bin/") or resolved.startswith("/usr/bin/")):
                return [resolved]
            return ["/bin/hostname"]

        if target == "uname":
            for candidate in ["/usr/bin/uname", "/bin/uname"]:
                if Path(candidate).exists():
                    return [candidate, "-s"]
            return ["/usr/bin/uname", "-s"]

        if target == "echo":
            for candidate in ["/bin/echo", "/usr/bin/echo"]:
                if Path(candidate).exists():
                    return [candidate, "ProofShield benign validation"]
            return ["/bin/echo", "ProofShield benign validation"]

    raise ValueError(f"Executable target '{target}' cannot be canonically resolved on platform '{sys.platform}'")


def _sanitize_output(text: Optional[str]) -> str:
    """Bounded, secret-scrubbed string representation."""
    if not text:
        return ""
    cleaned = redact_server_secret(text.strip())
    return cleaned[:4096]


class ProcessSpawnAction(BaseAction):
    """Executes a strictly approved benign profile with causal environment token embedding."""

    action_id = "process.spawn_benign"
    version = "1.0.0"
    name = "Controlled Benign Process Spawn"
    description = (
        "Spawns an approved benign system binary (whoami, hostname, echo) with shell=False, "
        "embedding the execution token in a controlled environment variable to produce observable process creation telemetry."
    )
    supported_platforms = ["windows", "linux", "darwin"]
    expected_observable_category = EventCategory.PROCESS_CREATION
    max_timeout_seconds = 15.0

    def get_parameter_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "executable": {
                    "type": "string",
                    "description": "Benign binary or profile to execute ('whoami', 'hostname', 'echo', 'uname')",
                    "default": "whoami",
                },
                "profile": {
                    "type": "string",
                    "description": "Approved execution profile ('whoami', 'hostname', 'echo', 'uname', 'exit_with_code', 'sleep', 'process_tree')",
                },
                "exit_code": {
                    "type": "integer",
                    "description": "Explicit integer exit code for controlled exit profile (0-255)",
                },
                "duration_seconds": {
                    "type": "number",
                    "description": "Duration for controlled sleep profile (0.0-60.0)",
                },
                "additional_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Forbidden for public execution; strictly validated for backward compatibility",
                    "default": [],
                },
            },
        }

    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        raw_args = params.get("additional_args", [])
        if raw_args is not None and not isinstance(raw_args, list):
            raise ValueError("additional_args must be a list of strings")

        # Check for arbitrary code execution attempts via python -c
        if raw_args:
            for arg in raw_args:
                s_arg = str(arg).strip()
                if s_arg == "-c" or s_arg.startswith("-c"):
                    raise ValueError(
                        "Arbitrary code execution via 'python -c' or inline scripts is forbidden. "
                        "Use approved execution profiles."
                    )
                if any(char in s_arg for char in (";", "&", "|", "`", "$", "\n", "\r", "<", ">")):
                    raise ValueError(f"Dangerous character in argument rejected: '{s_arg}'")
                if len(s_arg) > 256:
                    raise ValueError("Argument exceeds 256 character safety limit")

        # Determine target profile or binary
        profile = params.get("profile")
        executable = params.get("executable")

        if profile is None and executable is not None:
            norm_exec = str(executable).strip().lower()
            if norm_exec.endswith(".exe"):
                norm_exec = norm_exec[:-4]

            # Block dangerous binaries upfront
            forbidden = {"curl", "bash", "cmd", "powershell", "nc", "net", "sh", "wscript", "cscript"}
            if norm_exec in forbidden:
                raise ValueError(
                    f"Executable '{norm_exec}' is not in the approved safety allowlist: "
                    "['echo', 'hostname', 'python', 'uname', 'whoami']"
                )

            valid_targets = {"whoami", "hostname", "echo", "uname", "python"}
            if norm_exec not in valid_targets:
                raise ValueError(
                    f"Executable '{norm_exec}' is not in the approved safety allowlist: {sorted(valid_targets)}"
                )

            # Map executable to profile
            if norm_exec in {"whoami", "hostname", "echo", "uname"}:
                profile = norm_exec
            elif norm_exec == "python":
                if "exit_code" in params:
                    profile = "exit_with_code"
                elif "duration_seconds" in params:
                    profile = "sleep"
                elif raw_args:
                    raise ValueError(
                        "Arbitrary code execution via 'python -c' or freeform arguments is forbidden. "
                        "Use approved execution profiles."
                    )
                else:
                    profile = "python_version"

        if profile is None:
            profile = "whoami"

        profile = str(profile).strip().lower()
        approved_profiles = {
            "whoami",
            "hostname",
            "echo",
            "uname",
            "python_version",
            "exit_with_code",
            "sleep",
            "process_tree",
        }
        if profile not in approved_profiles:
            raise ValueError(f"Unknown or unapproved execution profile '{profile}'. Approved: {sorted(approved_profiles)}")

        validated: Dict[str, Any] = {"profile": profile}

        if profile == "exit_with_code":
            raw_code = params.get("exit_code", 0)
            try:
                code_int = int(raw_code)
                if code_int < 0 or code_int > 255:
                    raise ValueError
                validated["exit_code"] = code_int
            except (ValueError, TypeError):
                raise ValueError("Parameter 'exit_code' must be an integer between 0 and 255")

        elif profile in {"sleep", "process_tree"}:
            raw_dur = params.get("duration_seconds", 0.1)
            try:
                dur_float = float(raw_dur)
                if not math.isfinite(dur_float) or dur_float < 0.0 or dur_float > 60.0:
                    raise ValueError
                validated["duration_seconds"] = dur_float
            except (ValueError, TypeError):
                raise ValueError("Parameter 'duration_seconds' must be a float between 0.0 and 60.0")

        return validated

    def execute(self, ctx: ActionContext) -> ActionResult:
        params = self.validate_parameters(ctx.parameters)
        profile = params["profile"]

        cmd_args: List[str] = []

        if profile in {"whoami", "hostname", "echo", "uname"}:
            cmd_args = _resolve_canonical_binary(profile)

        elif profile == "python_version":
            cmd_args = [sys.executable, "-I", "--version"]

        elif profile == "exit_with_code":
            script = SCRIPTS_DIR / "exit_with_code.py"
            cmd_args = [sys.executable, "-I", str(script), str(params["exit_code"])]

        elif profile == "sleep":
            script = SCRIPTS_DIR / "sleep_and_exit.py"
            cmd_args = [sys.executable, "-I", str(script), str(params["duration_seconds"])]

        elif profile == "process_tree":
            script = SCRIPTS_DIR / "spawn_child.py"
            cmd_args = [sys.executable, "-I", str(script)]

        timeout = min(ctx.timeout_seconds, self.max_timeout_seconds)

        # Pass execution token through controlled environment variable
        env = build_child_environment(execution_token=ctx.execution_token)

        mgr = get_default_process_manager()

        exit_code, stdout, stderr, timed_out, cancelled = mgr.spawn_and_wait(
            execution_id=ctx.execution_id,
            cmd_args=cmd_args,
            cwd=ctx.workspace.workspace_dir,
            env=env,
            timeout_seconds=timeout,
        )

        error_message: Optional[str] = None
        if cancelled:
            error_message = "Execution was cancelled"
        elif timed_out:
            error_message = f"Process execution timed out after {timeout} seconds"
        elif exit_code != 0:
            error_message = f"Process exited with return code {exit_code}"

        return ActionResult(
            exit_code=exit_code,
            output_data={
                "command": " ".join(cmd_args),
                "profile": profile,
                "stdout": _sanitize_output(stdout),
                "stderr": _sanitize_output(stderr),
                "execution_token": ctx.execution_token,
                "environment_token": ctx.execution_token,
                "timed_out": timed_out,
                "cancelled": cancelled,
                "argv": list(cmd_args),
            },
            evidence_references=[],
            error_message=error_message,
        )


class ProcessLifecycleAction(BaseAction):
    """Monitors benign child process lifecycle transitions using controlled scripts."""

    action_id = "process.lifecycle_watch"
    version = "1.0.0"
    name = "Benign Process Lifecycle Watch"
    description = "Spawns a harmless child process that sleeps briefly and exits, recording process lifecycle events."
    supported_platforms = ["windows", "linux", "darwin"]
    expected_observable_category = EventCategory.PROCESS_CREATION
    max_timeout_seconds = 10.0

    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        duration = float(params.get("sleep_duration_seconds", 0.05))
        if not math.isfinite(duration) or duration < 0.0 or duration > 2.0:
            raise ValueError("sleep_duration_seconds must be between 0.0 and 2.0 seconds")
        return {"sleep_duration_seconds": duration}

    def execute(self, ctx: ActionContext) -> ActionResult:
        params = self.validate_parameters(ctx.parameters)
        sleep_dur = params["sleep_duration_seconds"]

        script = SCRIPTS_DIR / "sleep_and_exit.py"
        cmd_args = [
            sys.executable,
            "-I",
            str(script),
            str(sleep_dur),
        ]

        timeout = min(ctx.timeout_seconds, self.max_timeout_seconds)

        env = build_child_environment(execution_token=ctx.execution_token)

        mgr = get_default_process_manager()
        exit_code, stdout, stderr, timed_out, cancelled = mgr.spawn_and_wait(
            execution_id=ctx.execution_id,
            cmd_args=cmd_args,
            cwd=ctx.workspace.workspace_dir,
            env=env,
            timeout_seconds=timeout,
        )

        error_message: Optional[str] = None
        if cancelled:
            error_message = "Process lifecycle execution was cancelled"
        elif timed_out:
            error_message = f"Process lifecycle execution timed out after {timeout} seconds"
        elif exit_code != 0:
            error_message = f"Process exited with return code {exit_code}"

        return ActionResult(
            exit_code=exit_code,
            output_data={
                "command": " ".join(cmd_args),
                "stdout": _sanitize_output(stdout),
                "stderr": _sanitize_output(stderr),
                "sleep_duration": sleep_dur,
                "execution_token": ctx.execution_token,
                "environment_token": ctx.execution_token,
                "timed_out": timed_out,
                "cancelled": cancelled,
                "argv": list(cmd_args),
            },
            error_message=error_message,
        )
