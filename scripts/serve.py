"""Start the local service from a source checkout or installed package.

Usage: py -3.12 scripts/serve.py
Environment is configured by the invoking shell; no credentials are written.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("proofshield.main:app", host="127.0.0.1", port=8000)
