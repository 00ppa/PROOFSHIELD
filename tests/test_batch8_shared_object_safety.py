"""Regression coverage for Batch 7's internal read-only correlation path."""

from copy import deepcopy

import pytest
from pydantic import BaseModel

from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore

from tests.test_batch7_detection_performance import _alert, _context, _event


class _NestedEvidence(BaseModel):
    value: str


def _stores(tmp_path):
    memory_store, run, start = _context()
    sqlite_store = SQLiteStore(tmp_path / "batch8-safety.db")
    sqlite_store.add_scenario(memory_store.get_scenario(run.scenario_id))
    sqlite_store.add_rule(memory_store.get_rule("RULE-BATCH7"))
    sqlite_store.add_run(memory_store.get_run(run.run_id))
    return [(memory_store, run, start), (sqlite_store, run, start)]


@pytest.mark.parametrize("backend", ["in_memory", "sqlite"])
def test_copy_false_retrieval_cannot_mutate_stored_nested_evidence(backend, tmp_path):
    stores = _stores(tmp_path)
    store, run, start = stores[0 if backend == "in_memory" else 1]
    try:
        event = _event(f"N-BATCH8-{backend}", start)
        event.hashes["sha256"] = "original-hash"
        event.extra_attributes["nested"] = {"value": "original-event"}
        event.extra_attributes["items"] = [{"value": "original-list"}]
        alert = _alert(f"A-BATCH8-{backend}", start)
        alert.metadata["nested"] = {"value": "original-alert"}
        store.add_normalized_event(event)
        store.add_alert(alert)

        returned_event = store.get_events_for_run(run, copy=False)[0]
        returned_alert = store.list_alerts_for_rule("RULE-BATCH7", copy=False)[0]
        with pytest.raises(TypeError):
            returned_event.host = "MUTATED-HOST"
        with pytest.raises(TypeError):
            returned_alert.host_id = "MUTATED-HOST"
        with pytest.raises(TypeError):
            returned_event.hashes["sha256"] = "mutated-hash"
        with pytest.raises(TypeError):
            returned_event.extra_attributes["nested"]["value"] = "mutated-event"
        with pytest.raises(TypeError):
            returned_event.extra_attributes["items"][0]["value"] = "mutated-list"
        with pytest.raises(TypeError):
            returned_alert.metadata["nested"]["value"] = "mutated-alert"

        stored_event = store.get_normalized_event(event.normalized_event_id)
        stored_alert = store.get_alert(alert.alert_id)
        assert stored_event.host == "HOST-BATCH7"
        assert stored_event.hashes["sha256"] == "original-hash"
        assert stored_event.extra_attributes == {
            "nested": {"value": "original-event"},
            "items": [{"value": "original-list"}],
        }
        assert stored_alert.host_id == "HOST-BATCH7"
        assert stored_alert.metadata["nested"]["value"] == "original-alert"
    finally:
        store.close()
        if backend == "in_memory":
            stores[1][0].close()


@pytest.mark.parametrize("backend", ["in_memory", "sqlite"])
def test_repeated_evaluation_does_not_change_evidence_or_cross_contaminate_runs(backend, tmp_path):
    stores = _stores(tmp_path)
    store, run, start = stores[0 if backend == "in_memory" else 1]
    try:
        store.add_normalized_event(_event(f"N-BATCH8-{backend}", start))
        store.add_alert(_alert(f"A-BATCH8-{backend}", start))
        before_event = deepcopy(store.get_normalized_event(f"N-BATCH8-{backend}").model_dump())
        before_alert = deepcopy(store.get_alert(f"A-BATCH8-{backend}").model_dump())
        engine = AssuranceEngine(store)

        first = engine.evaluate_run(run.run_id)
        second = engine.evaluate_run(run.run_id)

        assert first.predicted_category == second.predicted_category
        assert first.supporting_evidence_ids == second.supporting_evidence_ids
        assert store.get_normalized_event(f"N-BATCH8-{backend}").model_dump() == before_event
        assert store.get_alert(f"A-BATCH8-{backend}").model_dump() == before_alert
    finally:
        store.close()
        if backend == "in_memory":
            stores[1][0].close()


@pytest.mark.parametrize("backend", ["in_memory", "sqlite"])
def test_evidence_ids_remain_scoped_when_two_runs_share_a_store(backend, tmp_path):
    stores = _stores(tmp_path)
    store, run_one, start = stores[0 if backend == "in_memory" else 1]
    try:
        scenario_one = store.get_scenario(run_one.scenario_id)
        run_two = run_one.model_copy(
            update={
                "run_id": f"RUN-BATCH8-TWO-{backend}",
                "target_host": "HOST-BATCH8-TWO",
            }
        )
        scenario_two = scenario_one.model_copy(
            update={
                "scenario_id": f"SCN-BATCH8-TWO-{backend}",
                "name": "Batch 8 second scenario",
            }
        )
        run_two.scenario_id = scenario_two.scenario_id
        store.add_scenario(scenario_two)
        store.add_run(run_two)

        event_one = _event(f"N-BATCH8-ONE-{backend}", start)
        alert_one = _alert(f"A-BATCH8-ONE-{backend}", start)
        event_two = _event(f"N-BATCH8-TWO-{backend}", start)
        event_two.host = run_two.target_host
        alert_two = _alert(f"A-BATCH8-TWO-{backend}", start)
        alert_two.host_id = run_two.target_host
        store.add_normalized_event(event_one)
        store.add_alert(alert_one)
        store.add_normalized_event(event_two)
        store.add_alert(alert_two)

        first = AssuranceEngine(store).evaluate_run(run_one.run_id)
        second = AssuranceEngine(store).evaluate_run(run_two.run_id)

        assert first.supporting_evidence_ids == [event_one.normalized_event_id, alert_one.alert_id]
        assert second.supporting_evidence_ids == [event_two.normalized_event_id, alert_two.alert_id]
    finally:
        store.close()
        if backend == "in_memory":
            stores[1][0].close()


def test_nested_pydantic_payload_is_read_only_in_fast_path():
    store, run, start = _context()
    event = _event("N-BATCH8-NESTED", start)
    event.extra_attributes["nested_model"] = _NestedEvidence(value="original")
    store.add_normalized_event(event)

    nested = store.get_events_for_run(run, copy=False)[0].extra_attributes["nested_model"]
    with pytest.raises(TypeError):
        nested.value = "mutated"

    assert store.get_normalized_event(event.normalized_event_id).extra_attributes["nested_model"].value == "original"
