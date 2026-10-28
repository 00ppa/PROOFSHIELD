"""RFC 8785 (JSON Canonicalization Scheme - JCS) serialization and hashing.

Provides deterministic canonical serialization and SHA-256 fingerprinting conforming
to RFC 8785 (JCS) for auditable evidence integrity.

Key Invariants:
1. Whitespace: No whitespace outside JSON string literals (separators: comma and colon).
2. Property Sorting: Object keys are sorted lexicographically by UTF-16 code units
   (sequences of 16-bit code units, matching ECMAScript 5.1 and RFC 8785 Section 3.2.3).
3. Number Serialization: Formatted according to ECMAScript 7.1.12.1 (RFC 8785 Section 3.2.2.3):
   - Integers serialize without decimal point or exponent (e.g. 1.0 -> "1").
   - Negative zero (-0.0) serializes as "0".
   - Exponential representations use lowercase 'e' with explicit '+' for positive exponents.
   - Fixed decimal representation is used when exponent is in [-5, 20].
   - NaN and Infinity are strictly rejected with ValueError.
4. String Escaping: Quotation marks, reverse solidus, and control characters (U+0000..U+001F)
   are escaped; all other Unicode characters are preserved as raw UTF-8 (RFC 8785 Section 3.2.2.2).
5. Integrity Scope & Threat Model:
   - What ProofShield implements: Canonical SHA-256 digests bound in EvidenceManifestV1
     enable detection of differences or record corruption relative to the stored digest during replay.
   - Boundary & Limitation: SHA-256 alone does not prevent adversarial tampering if an attacker
     has write access to modify both the evidence payload and its stored digest in the database/store,
     as they could recompute the canonical hash over modified records.
   - Future Hardening: Stronger tamper resistance requires independently protected reference digests,
     such as access-controlled append-only ledgers, an out-of-band audit logging system, or digital
     signatures backed by a hardware/cloud-managed private signing key.
   - Authenticity vs Truthfulness: A digital signature or cryptographic hash proves only that a particular
     key signed the data or that data matches a reference digest; it does not prove that the underlying
     endpoint telemetry was truthful or unevaded at the time of OS capture.
"""

from datetime import datetime, timezone
import hashlib
import json
import math
from typing import Any, Dict, List, Union
from pydantic import BaseModel


def ecmascript_float(x: float) -> str:
    """Format a floating-point number according to ECMAScript 7.1.12.1 (RFC 8785 Section 3.2.2.3).

    Raises:
        ValueError: If x is NaN or Infinity (forbidden in RFC 8785).
    """
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and Infinity are not permitted in RFC 8785 canonical JSON.")
    if x == 0.0:
        return "0"

    sign = "-" if math.copysign(1.0, x) < 0 else ""
    x = abs(x)

    # In Python 3.8+, str(x) uses David Gay's dtoa to produce the shortest decimal
    # representation that rounds back to the same IEEE 754 float.
    s = str(x)
    if "e" in s:
        mantissa_s, exp_s = s.split("e")
        exp = int(exp_s)
    else:
        parts = s.split(".")
        int_part = parts[0]
        frac_part = parts[1] if len(parts) > 1 else ""
        if frac_part == "0" and len(parts) > 1:
            frac_part = ""
        digits = int_part + frac_part
        digits = digits.lstrip("0")
        if not digits:
            return "0"
        if int_part != "0":
            n = len(int_part)
        else:
            leading_zeros = len(parts[1]) - len(digits)
            n = -leading_zeros
        exp = n - 1
        mantissa_s = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")

    m_parts = mantissa_s.split(".")
    digits = m_parts[0] + (m_parts[1] if len(m_parts) > 1 else "")
    k = len(digits)
    n = exp + 1

    if k <= n <= 21:
        res = digits + ("0" * (n - k))
    elif 0 < n <= 21:
        res = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        res = "0." + ("0" * (-n)) + digits
    else:
        exp_val = n - 1
        exp_sign = "+" if exp_val >= 0 else "-"
        exp_str = f"e{exp_sign}{abs(exp_val)}"
        if k == 1:
            res = digits + exp_str
        else:
            res = digits[0] + "." + digits[1:] + exp_str

    return sign + res


def canonical_jcs_serialize(val: Any) -> str:
    """Serialize a Python data structure into RFC 8785 (JCS) canonical JSON string."""
    if isinstance(val, BaseModel):
        return canonical_jcs_serialize(val.model_dump(mode="json"))

    if val is None:
        return "null"

    if isinstance(val, bool):
        return "true" if val else "false"

    if isinstance(val, int):
        return str(val)

    if isinstance(val, float):
        return ecmascript_float(val)

    if isinstance(val, str):
        try:
            val.encode("utf-8")
        except UnicodeEncodeError as err:
            raise ValueError(f"Unpaired surrogates or invalid Unicode not permitted in RFC 8785: {err}") from err
        return json.dumps(val, ensure_ascii=False)

    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        else:
            val = val.astimezone(timezone.utc)
        return json.dumps(val.isoformat(), ensure_ascii=False)

    if isinstance(val, (list, tuple)):
        return "[" + ",".join(canonical_jcs_serialize(item) for item in val) + "]"

    if isinstance(val, (set, frozenset)):
        # Deterministically sort sets by serialized UTF-8 bytes
        items = [canonical_jcs_serialize(item) for item in val]
        items.sort(key=lambda s: s.encode("utf-8"))
        return "[" + ",".join(items) + "]"

    if isinstance(val, dict):
        # RFC 8785 Section 3.2.3: Keys compared as sequences of UTF-16 code units
        try:
            sorted_keys = sorted(val.keys(), key=lambda k: str(k).encode("utf-16-be"))
        except UnicodeEncodeError as err:
            raise ValueError(f"Unpaired surrogates or invalid Unicode in key not permitted in RFC 8785: {err}") from err
        return "{" + ",".join(
            json.dumps(str(k), ensure_ascii=False) + ":" + canonical_jcs_serialize(val[k])
            for k in sorted_keys
        ) + "}"

    # Fallback for unrecognized types: convert to str then JSON string
    return json.dumps(str(val), ensure_ascii=False)


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize an object or dictionary into deterministic canonical UTF-8 JSON bytes (RFC 8785)."""
    return canonical_jcs_serialize(obj).encode("utf-8")


def compute_canonical_hash(obj: Any) -> str:
    """Compute the SHA-256 hex digest of the RFC 8785 canonical JSON bytes of an entity."""
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


# Explicit aliases
canonical_json = canonical_json_bytes
canonical_sha256 = compute_canonical_hash
