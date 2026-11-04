"""Bind diagnostic inputs by content without changing existing v1 manifests."""

from proofshield.services.canonical import compute_canonical_hash


def diagnostic_hash(result):
    payload = result.model_dump(mode="json")
    payload["metadata"] = {key: value for key, value in payload["metadata"].items()
                           if key not in {"evidence_snapshot_v1", "diagnostic_content_hash"}}
    return compute_canonical_hash(payload)


def capture_inputs(store, run_id):
    run = store.get_run(run_id)
    if run is None:
        raise ValueError("Run unavailable for evidence snapshot")
    records = {}
    def add(kind, identifier, value):
        if value is not None:
            payload = value.model_dump(mode="json")
            try:
                digest = compute_canonical_hash(payload)
                records[f"{kind}:{identifier}"] = {"kind": kind, "id": identifier, "payload": payload, "hash": digest}
            except (ValueError, TypeError):
                records[f"{kind}:{identifier}"] = {"kind": kind, "id": identifier,
                    "payload_json": value.model_dump_json(), "hash": None, "hash_error": True}
        else:
            records[f"{kind}:{identifier}"] = {"kind": kind, "id": identifier, "payload": None,
                                               "hash": None, "missing": True}
    add("run", run_id, run)
    scenario = store.get_scenario(run.scenario_id)
    add("scenario", run.scenario_id, scenario)
    if scenario and scenario.expected_detection_rule_id:
        add("rule", scenario.expected_detection_rule_id, store.get_rule(scenario.expected_detection_rule_id))
    events = store.get_events_for_run(run)
    # Include out-of-window rule alerts too: they can support ALERT_NOT_CORRELATED.
    alerts = store.get_alerts_for_run(run)
    if scenario and scenario.expected_detection_rule_id:
        alerts += store.list_alerts_for_rule(scenario.expected_detection_rule_id)
    for event in events:
        add("normalized", event.normalized_event_id, event)
        add("raw", event.raw_event_id, store.get_raw_event(event.raw_event_id))
    for alert in alerts:
        add("alert", alert.alert_id, alert)
    for execution in store.list_executions(run_id=run_id):
        add("execution", execution.execution_id, execution)
    return records


def persist_diagnosis(store, result, collection=None):
    """Attach a snapshot at evaluation time; errors replace stale successful results."""
    if collection is not None:
        result.metadata["collection"] = collection.model_dump(mode="json")
    else:
        previous = store.get_result_for_run(result.test_run_id)
        if previous and "collection" in previous.metadata:
            result.metadata.setdefault("collection", previous.metadata["collection"])
    if store.get_run(result.test_run_id) is not None:
        inputs = capture_inputs(store, result.test_run_id)
        if any(item.get("hash_error") for item in inputs.values()):
            from proofshield.schemas.common import DiagnosticCategory
            result.predicted_category = DiagnosticCategory.ERROR
            result.reason = "Evidence content is outside the supported canonical integrity domain"
            result.confidence = "uncertain"
            result.supporting_evidence_ids = []
            result.metadata["integrity_error"] = True
        result.metadata["evidence_snapshot_v1"] = {key: item["hash"] for key, item in inputs.items()}
        result.metadata["diagnostic_content_hash"] = diagnostic_hash(result)
    return store.add_result(result)


def verify_inputs(store, result):
    records = capture_inputs(store, result.test_run_id)
    expected = result.metadata.get("evidence_snapshot_v1")
    if not expected:
        return "UNAVAILABLE", records
    actual = {key: item["hash"] for key, item in records.items()}
    if expected != actual or result.metadata.get("diagnostic_content_hash") != diagnostic_hash(result):
        return "FAILED", records
    if any(item.get("hash_error") for item in records.values()):
        return "FAILED", records
    if any(item.get("missing") for item in records.values()):
        return "UNAVAILABLE", records
    run = store.get_run(result.test_run_id)
    executions = store.list_executions(run_id=run.run_id)
    if not executions:
        return "UNAVAILABLE", records
    for execution in executions:
        if (not execution.verify_integrity() or execution.test_run_id != run.run_id
                or execution.scenario_id != run.scenario_id or execution.execution_token != run.execution_token
                or run.metadata.get("integrity_hash") != execution.integrity_hash):
            return "FAILED", records
    return "VERIFIED", records
