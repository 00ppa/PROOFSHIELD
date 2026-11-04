"""Process lifecycle, concurrency, and process-tree termination manager."""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
from typing import Dict, List, Optional, Tuple

from proofshield.execution.environment import build_child_environment

logger = logging.getLogger("proofshield.execution.process_manager")

_IS_WINDOWS = sys.platform.startswith("win32") or sys.platform.startswith("cygwin")


def _get_system32_path() -> Path:
    """Return the canonical Windows System32 directory."""
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or "C:\\Windows"
    return (Path(root) / "System32").resolve()


def terminate_process_tree(pid: int) -> bool:
    """Forcefully terminate a process and all its child descendants."""
    if pid <= 0:
        return False

    success = False
    if _IS_WINDOWS:
        try:
            taskkill = _get_system32_path() / "taskkill.exe"
            if not taskkill.exists():
                return False
            taskkill_cmd = str(taskkill)

            res = subprocess.run(
                [taskkill_cmd, "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=5.0,
                env=build_child_environment(),
            )
            success = res.returncode == 0
        except Exception as exc:
            logger.warning("taskkill failed for PID %d: %s", pid, exc)
    else:
        try:
            pgid = os.getpgid(pid)
            os.killpg(pgid, signal.SIGKILL)
            success = True
        except ProcessLookupError:
            success = True
        except Exception as exc:
            logger.warning("killpg failed for PID %d: %s", pid, exc)
            try:
                os.kill(pid, signal.SIGKILL)
                success = True
            except Exception:
                pass

    return success


class ActiveProcess:
    """Encapsulates a live subprocess and its lifecycle state."""

    def __init__(
        self,
        execution_id: str,
        popen: subprocess.Popen,
        timeout_seconds: float,
    ) -> None:
        self.execution_id = execution_id
        self.popen = popen
        self.pid = popen.pid
        self.timeout_seconds = timeout_seconds
        self.started_at = datetime.now(timezone.utc)
        self.completed_at: Optional[datetime] = None
        self.cancelled = False
        self.timed_out = False
        self.exit_code: Optional[int] = None
        self.stdout: str = ""
        self.stderr: str = ""


class ProcessLifecycleManager:
    """Manages child process execution, tree termination, and concurrency."""

    def __init__(self, max_concurrent: int = 5) -> None:
        self.max_concurrent = max_concurrent
        self._lock = threading.RLock()
        self._active: Dict[str, ActiveProcess] = {}
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def is_running(self, execution_id: str) -> bool:
        with self._lock:
            proc = self._active.get(execution_id)
            if proc is None:
                return False
            return proc.popen.poll() is None

    def get_active_count(self) -> int:
        with self._lock:
            # Purge dead processes
            dead = [eid for eid, p in self._active.items() if p.popen.poll() is not None]
            for eid in dead:
                self._active.pop(eid, None)
            return len(self._active)

    def spawn_and_wait(
        self,
        execution_id: str,
        cmd_args: List[str],
        cwd: Path,
        env: Dict[str, str],
        timeout_seconds: float,
    ) -> Tuple[int, str, str, bool, bool]:
        """Spawn a process under strict lifecycle management and wait for its completion.

        Returns:
            Tuple of (exit_code, stdout, stderr, timed_out, cancelled)
        """
        if not self._slots.acquire(blocking=False):
            raise RuntimeError(f"Concurrency limit ({self.max_concurrent}) exceeded")

        creationflags = 0
        start_new_session = False
        if _IS_WINDOWS:
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            start_new_session = True

        try:
            popen = subprocess.Popen(
                cmd_args,
                shell=False,
                cwd=str(cwd),
                env=build_child_environment(base_environment=env),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=creationflags,
                start_new_session=start_new_session,
            )
        except BaseException:
            self._slots.release()
            raise

        active = ActiveProcess(
            execution_id=execution_id,
            popen=popen,
            timeout_seconds=timeout_seconds,
        )

        with self._lock:
            self._active[execution_id] = active

        timed_out = False
        stdout = ""
        stderr = ""
        exit_code = -1

        try:
            raw_out, raw_err = popen.communicate(timeout=timeout_seconds)
            stdout = raw_out or ""
            stderr = raw_err or ""
            exit_code = popen.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            active.timed_out = True
            terminate_process_tree(popen.pid)
            try:
                raw_out, raw_err = popen.communicate(timeout=2.0)
                stdout = raw_out or ""
                stderr = raw_err or ""
            except Exception:
                popen.kill()
                popen.communicate(timeout=2.0)
            exit_code = -1
        except Exception as exc:
            terminate_process_tree(popen.pid)
            stderr = f"Process management failure: {exc}"
            exit_code = -1
        finally:
            active.completed_at = datetime.now(timezone.utc)
            with self._lock:
                self._active.pop(execution_id, None)
            self._slots.release()

        is_cancelled = active.cancelled
        return exit_code, stdout, stderr, timed_out, is_cancelled

    def cancel(self, execution_id: str) -> bool:
        """Immediately cancel an ongoing execution by terminating its process tree."""
        with self._lock:
            active = self._active.get(execution_id)
            if active is None:
                return False
            active.cancelled = True
            terminate_process_tree(active.pid)
            try:
                active.popen.kill()
            except Exception:
                pass
            return True

    def cancel_all(self):
        """Best-effort cleanup for all tracked children during service shutdown."""
        with self._lock:
            identifiers = list(self._active)
        for identifier in identifiers:
            self.cancel(identifier)


# Global default process manager
_process_manager = ProcessLifecycleManager()


def get_default_process_manager() -> ProcessLifecycleManager:
    return _process_manager
