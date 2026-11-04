"""Controlled test script: exits cleanly with a requested integer exit code."""

import sys

def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(0)
    try:
        code = int(sys.argv[1])
        # Bound exit code to valid range [0, 255]
        code = max(0, min(255, code))
        sys.exit(code)
    except ValueError:
        sys.exit(1)

if __name__ == "__main__":
    main()
