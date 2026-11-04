"""Execution workspace isolation and directory safety boundaries."""

import logging
import os
from pathlib import Path
import shutil
import tempfile
import re
from typing import Optional, Tuple

logger = logging.getLogger("proofshield.execution.workspace")


class ExecutionWorkspace:
    """Dedicated temporary workspace directory for a controlled execution.

    Guarantees:
    - All file creation and mutation are constrained strictly within this directory.
    - Prevents directory traversal (e.g., ../ escaping) and symlink resolution escapes.
    - Tracks cleanup status deterministically.
    """

    def __init__(self, execution_id: str, base_dir: Optional[Path] = None) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,128}", execution_id):
            raise ValueError("Invalid workspace execution identifier")
        self.execution_id = execution_id
        root_base = base_dir or (Path(tempfile.gettempdir()) / "proofshield_executions")
        self.workspace_dir = (root_base / execution_id).resolve()
        self._created = False

    @property
    def workspace_path(self) -> Path:
        """Documented alias for workspace_dir for contract consistency."""
        return self.workspace_dir

    def create(self) -> Path:
        """Create the isolated workspace directory."""
        self.workspace_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.workspace_dir.mkdir(mode=0o700, exist_ok=False)
        self._created = True
        return self.workspace_dir

    def resolve_path(self, relative_path: str) -> Path:
        """Safely resolve a relative path within the workspace directory.

        Raises:
            ValueError: If the resolved path attempts to escape the workspace directory.
        """
        # Ensure path is not absolute or driving to another drive letter
        p = Path(relative_path)
        if p.is_absolute() or relative_path.startswith("/") or relative_path.startswith("\\"):
            raise ValueError(f"Path traversal rejected: absolute paths are forbidden: '{relative_path}'")

        resolved = (self.workspace_dir / p).resolve()
        try:
            resolved.relative_to(self.workspace_dir)
        except ValueError:
            raise ValueError(
                f"Path traversal outside workspace root rejected: '{relative_path}' resolves outside workspace directory."
            )

        return resolved

    def cleanup(self) -> Tuple[str, Optional[str]]:
        """Remove the workspace directory and all contained artifacts.

        Returns:
            Tuple of (cleanup_status, error_message). Status is 'COMPLETED' or 'FAILED'.
        """
        if not self.workspace_dir.exists():
            return "COMPLETED", None

        try:
            shutil.rmtree(self.workspace_dir, ignore_errors=False)
            return "COMPLETED", None
        except Exception as exc:
            err_msg = f"Failed to clean workspace {self.workspace_dir}: {exc}"
            logger.warning(err_msg)
            # Try once with ignore_errors as fallback
            try:
                shutil.rmtree(self.workspace_dir, ignore_errors=True)
            except Exception:
                pass
            return "FAILED", err_msg
