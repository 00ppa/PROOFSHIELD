"""Phase 20.2 regression tests for canonical evidence serialization."""

import json
import struct

import pytest

from proofshield.services.canonical import canonical_json_bytes, canonical_jcs_serialize, ecmascript_float


def test_rfc8785_number_boundaries_and_negative_zero():
    cases = {
        1.0: "1",
        -0.0: "0",
        0.000001: "0.000001",
        1e-7: "1e-7",
        1e20: "100000000000000000000",
        1e21: "1e+21",
        -1.234e-7: "-1.234e-7",
        1.234e-5: "0.00001234",
    }
    for value, expected in cases.items():
        assert ecmascript_float(value) == expected


def test_rfc8785_published_appendix_b_vectors_are_stable():
    vectors = [
        ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ]
    for raw_bits, expected in vectors:
        value = struct.unpack("!d", bytes.fromhex(raw_bits))[0]
        assert ecmascript_float(value) == expected


def test_rfc8785_utf16_property_order_and_exact_sample_bytes():
    data = json.loads(
        '{"\\u20ac":"Euro Sign","\\r":"Carriage Return",'
        '"\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",'
        '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",'
        '"\\u00f6":"Latin Small Letter O With Diaeresis"}'
    )
    serialized = canonical_jcs_serialize(data)
    expected_values = [
        "Carriage Return",
        "One",
        "Control",
        "Latin Small Letter O With Diaeresis",
        "Euro Sign",
        "Emoji: Grinning Face",
        "Hebrew Letter Dalet With Dagesh",
    ]
    positions = [serialized.index(value) for value in expected_values]
    assert positions == sorted(positions)

    expected_hex = (
        "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62657273223a"
        "5b3333333333333333332e333333333333332c31652b33302c342e352c302e3030322c31652d3237"
        "5d2c22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d"
    )
    sample = json.loads(bytes.fromhex(expected_hex).decode("utf-8"))
    assert canonical_json_bytes(sample) == bytes.fromhex(expected_hex)


@pytest.mark.parametrize("value", ["\ud800", "\udfff"])
def test_rfc8785_rejects_unpaired_surrogates(value):
    with pytest.raises(ValueError, match="Unpaired surrogates"):
        canonical_jcs_serialize(value)
