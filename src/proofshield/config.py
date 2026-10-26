"""Configuration settings and environment variable management for PROOFSHIELD.

Provides explicit configuration for storage backends (in-memory vs SQLite) and database paths,
with validation, fail-fast error reporting, and no silent fallbacks.
"""

from enum import Enum
import os
from pathlib import Path
from typing import Optional, Union


class StorageBackend(str, Enum):
    """Supported storage backend options."""
    MEMORY = "memory"
    SQLITE = "sqlite"


def parse_storage_backend(val: Optional[str]) -> StorageBackend:
    """Parse and validate storage backend identifier from environment or config string.

    Defaults to MEMORY when None or empty string.
    Raises ValueError on unrecognized backend values.
    """
    if val is None or not str(val).strip():
        return StorageBackend.MEMORY

    cleaned = str(val).strip().lower().replace("-", "_")
    if cleaned in ("memory", "in_memory"):
        return StorageBackend.MEMORY
    if cleaned in ("sqlite", "sqlite3"):
        return StorageBackend.SQLITE

    raise ValueError(
        f"Unsupported storage backend: '{val}'. Supported backends are 'memory' and 'sqlite'."
    )


def validate_sqlite_path(path_val: Union[str, Path]) -> str:
    """Validate SQLite database path.

    Rejects empty paths, paths pointing to directories, or paths with invalid parent paths.
    """
    s = str(path_val).strip()
    if not s:
        raise ValueError("SQLite database path cannot be empty or whitespace.")

    if "\0" in s:
        raise ValueError("SQLite database path cannot contain null bytes.")

    if s == ":memory:":
        return s

    if s.startswith("file:") and "mode=memory" in s:
        return s

    p = Path(s).resolve()
    if p.exists() and p.is_dir():
        raise ValueError(f"SQLite database path cannot be an existing directory: {s}")

    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        raise ValueError(
            f"Cannot create directory for SQLite database path '{s}': {exc}"
        ) from exc

    return s


class StorageSettings:
    """Immutable configuration for PROOFSHIELD storage."""

    def __init__(
        self,
        storage_backend: Union[str, StorageBackend] = StorageBackend.MEMORY,
        sqlite_path: Union[str, Path] = "proofshield.db",
    ) -> None:
        if isinstance(storage_backend, StorageBackend):
            self.storage_backend = storage_backend
        else:
            self.storage_backend = parse_storage_backend(storage_backend)

        if self.storage_backend == StorageBackend.SQLITE:
            self.sqlite_path = validate_sqlite_path(sqlite_path)
        else:
            self.sqlite_path = str(sqlite_path).strip() if sqlite_path else "proofshield.db"

    @classmethod
    def from_env(cls) -> "StorageSettings":
        """Load storage settings from environment variables."""
        backend_env = os.environ.get("PROOFSHIELD_STORAGE_BACKEND")
        path_env = os.environ.get("PROOFSHIELD_SQLITE_PATH")
        if path_env is None:
            path_env = os.environ.get("PROOFSHIELD_DB_PATH")
        if path_env is None:
            path_env = "proofshield.db"

        return cls(
            storage_backend=backend_env,
            sqlite_path=path_env,
        )

    def __repr__(self) -> str:
        return (
            f"StorageSettings(storage_backend={self.storage_backend.value!r}, "
            f"sqlite_path={self.sqlite_path!r})"
        )


_settings_instance: Optional[StorageSettings] = None


def get_settings() -> StorageSettings:
    """Get the active storage configuration singleton (loaded from environment)."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = StorageSettings.from_env()
    return _settings_instance


def reset_settings() -> None:
    """Reset the cached storage settings singleton. Used in tests."""
    global _settings_instance
    _settings_instance = None
