"""Controlled test script: sleeps for a bounded duration and exits with 0."""

import sys
import time

def main() -> None:
    duration = 0.1
    if len(sys.argv) >= 2:
        try:
            duration = float(sys.argv[1])
            duration = max(0.0, min(60.0, duration))
        except ValueError:
            duration = 0.1
    time.sleep(duration)
    sys.exit(0)

if __name__ == "__main__":
    main()
