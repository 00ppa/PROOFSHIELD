"""Controlled test script: spawns a child process tree to test cancellation termination."""

from pathlib import Path
import os
import subprocess
import sys
import time


def _child_environment():
    """Defensively remove the server secret before creating the grandchild."""
    allowed = {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "TZ", "PROOFSHIELD_EXECUTION_TOKEN"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    return env

def main() -> None:
    # Resolve helper script
    helper = Path(__file__).parent / "sleep_and_exit.py"
    child = subprocess.Popen([sys.executable, "-I", str(helper), "30"], env=_child_environment())

    # Write child PID to a known file in cwd so tests can verify child termination
    pid_file = Path("child_pid.txt")
    try:
        pid_file.write_text(str(child.pid), encoding="utf-8")
    except Exception:
        pass

    try:
        child.wait()
    except Exception:
        pass

if __name__ == "__main__":
    main()
