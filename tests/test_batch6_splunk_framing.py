"""Regression coverage for Splunk export framing and completion markers."""

import json
import pytest

from proofshield.connectors.splunk import SplunkClient, SplunkClientError


def test_empty_export_without_final_marker_is_rejected():
    """An empty body is incomplete, not a valid empty export."""
    with pytest.raises(SplunkClientError, match="final row marker"):
        SplunkClient._decode_results("")


@pytest.mark.parametrize("raw", ["   \n", json.dumps({"preview": False, "lastrow": False})])
def test_empty_or_incomplete_export_without_final_marker_is_rejected(raw):
    with pytest.raises(SplunkClientError, match="final row marker"):
        SplunkClient._decode_results(raw)


def test_valid_empty_export_has_explicit_final_marker():
    raw = json.dumps({"preview": False, "lastrow": True})
    assert SplunkClient._decode_results(raw) == []


def test_malformed_completion_marker_is_rejected():
    with pytest.raises(SplunkClientError, match="completion marker"):
        SplunkClient._decode_results(json.dumps({"lastrow": "true"}))


def test_data_after_final_marker_is_rejected():
    first = {"preview": False, "lastrow": True}
    second = {"preview": False, "lastrow": True, "result": {"event_id": "late"}}
    with pytest.raises(SplunkClientError, match="after final export row"):
        SplunkClient._decode_results("\n".join(json.dumps(item) for item in (first, second)))
