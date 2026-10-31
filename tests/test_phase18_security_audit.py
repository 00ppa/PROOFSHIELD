"""Phase 18: Security, Reliability, and Integrity Audit Regression Suite.

Covers:
1. API Security & Information Disclosure Prevention:
   - Sanitization of internal absolute filesystem paths across all evaluation and telemetry routes.
   - Validation and rejection of malformed or traversal path parameters.
2. Denial-of-Service & Resource Exhaustion Defenses:
   - Recursion depth bounding in RFC 8785 canonical serialization (preventing RecursionError crashes).
   - Nesting depth validation across core schemas (ScenarioV1, TestRunV1, DetectionRuleV1, GroundTruthV1).
3. Storage Concurrency & ACID Integrity:
   - Thread-safe lazy singleton initialization under high concurrent contention.
   - Atomic rollback of nested savepoints on persistence errors.
   - Enforcement of foreign key constraints (PRAGMA foreign_keys = ON).
4. Evidence and Assurance Integrity:
   - Cryptographic tamper detection on stored assurance reports.
   - Manifest integrity failure detection when evidence is tampered post-hoc.
5. Diagnostic Reliability:
   - Partial failure isolation during campaign execution.
   - Strict factual segregation in root-cause intelligence.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import sqlite3
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from proofshield.api.routes_campaigns import sanitize_error_detail
from proofshield.main import create_application
from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    DiagnosticCategory,
    EventCategory,
    GroundTruthV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
    ValidationTarget,
)
from proofshield.schemas.assurance_report import EvidenceVerificationStatus
from proofshield.schemas.campaign import (
    CampaignDefinitionV1,
    CampaignExecutionConfigV1,
    CampaignExecutionPolicy,
    ScenarioRunStatus,
)
from proofshield.services.assurance_report import CampaignAssuranceReportGenerator
from proofshield.services.campaign_engine import CampaignEngine
from proofshield.services.canonical import canonical_jcs_serialize, compute_canonical_hash
from proofshield.services.root_cause import RootCauseIntelligenceService
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore, close_store, get_store, reset_store, set_store


# ── 1. Information Disclosure & Error Sanitization Tests ───────────────────────


def test_sanitize_error_detail_redacts_windows_and_posix_paths():
    """Verify that sanitize_error_detail redacts Windows, UNC, and POSIX paths while preserving surrounding text."""
    # 1. Windows standard drive path
    exc1 = ValueError(r"Database locked at D:\PROOFSHIELD\data\proofshield.db with error")
    clean1 = sanitize_error_detail(exc1, prefix="Storage error")
    assert r"D:\PROOFSHIELD" not in clean1
    assert "Storage error: Database locked at [REDACTED_PATH] with error" == clean1

    # 2. Windows Program Files (x86) path with spaces and parentheses
    exc2 = OSError(r"Error in C:\Program Files (x86)\ProofShield\db.sqlite: database is locked")
    clean2 = sanitize_error_detail(exc2, prefix="IO error")
    assert "Program Files (x86)" not in clean2
    assert "IO error: Error in [REDACTED_PATH]: database is locked" == clean2

    # 3. Windows path containing @ symbol (e.g. Active Directory user domain)
    exc3 = ValueError(r"Failed to open C:\Users\user@domain\proofshield.db: permission denied")
    clean3 = sanitize_error_detail(exc3, prefix="Auth error")
    assert "user@domain" not in clean3
    assert "Auth error: Failed to open [REDACTED_PATH]: permission denied" == clean3

    # 4. UNC network path
    exc4 = OSError(r"UNC path \\server\share\proofshield.db failed to sync")
    clean4 = sanitize_error_detail(exc4, prefix="Network error")
    assert r"\\server\share" not in clean4
    assert "Network error: UNC path [REDACTED_PATH] failed to sync" == clean4

    # 5. POSIX system and application directory paths
    exc5 = OSError("Cannot write to /var/lib/proofshield/db.sqlite: disk full")
    clean5 = sanitize_error_detail(exc5, prefix="POSIX error")
    assert "/var/lib" not in clean5
    assert "POSIX error: Cannot write to [REDACTED_PATH]: disk full" == clean5

    exc6 = OSError("Failed to write /app/data/proofshield.db during flush")
    clean6 = sanitize_error_detail(exc6, prefix="Container error")
    assert "/app/data" not in clean6
    assert "Container error: Failed to write [REDACTED_PATH] during flush" == clean6

    # 6. Windows forward-slash path
    exc7 = ValueError("Forward slash C:/Users/test/proofshield.db error")
    clean7 = sanitize_error_detail(exc7, prefix="Error")
    assert "C:/Users/test" not in clean7
    assert "Error: Forward slash [REDACTED_PATH] error" == clean7

    # 7. Preservation of surrounding error text with complex punctuation
    exc8 = RuntimeError(r"Prefix text: cannot access C:\Program Files (x86)\ProofShield\db.sqlite with error code 5 (disk locked) - retry later.")
    clean8 = sanitize_error_detail(exc8, prefix="Operation failed")
    assert "Operation failed: Prefix text: cannot access [REDACTED_PATH] with error code 5 (disk locked) - retry later." == clean8


def test_routes_evaluation_sanitizes_paths_in_conflict_errors(monkeypatch):
    """Verify that routes_evaluation sanitizes absolute paths in HTTP 409 conflict errors."""
    app = create_application()
    client = TestClient(app)

    # Monkeypatch store.add_scenario to simulate a SQLite error containing an internal path
    store = get_store()
    def fake_add_scenario(scen):
        raise sqlite3.OperationalError(r"disk error in file D:\PROOFSHIELD\proofshield.db: table locked")
    monkeypatch.setattr(store, "add_scenario", fake_add_scenario)

    payload = {
        "scenario_id": "SCN-TEST-INFO-01",
        "name": "Test Scenario",
        "mitre_technique_id": "T1059.001",
        "mitre_tactic": "Execution",
        "expected_event_category": "PROCESS_CREATION",
        "validation_target": "EXPECTED_ALERT",
    }
    resp = client.post("/api/v1/scenarios", json=payload)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert r"D:\PROOFSHIELD" not in detail
    assert "[REDACTED_PATH]" in detail


def test_routes_evaluation_path_parameter_validation():
    """Path parameters must reject invalid characters, length violations, and traversal attempts with 422."""
    app = create_application()
    client = TestClient(app)

    # 1. Invalid characters rejected with 422
    for invalid_id in ("SCN-TEST!", "SCN;DROP", "SCN$TEST", "SCN TEST", "SCN@TEST"):
        resp = client.get(f"/api/v1/scenarios/{invalid_id}")
        assert resp.status_code == 422, f"Expected 422 for invalid identifier '{invalid_id}', got {resp.status_code}"

    # 2. Identifiers shorter than min_length=3 rejected with 422
    for short_id in ("a", "ab", "12"):
        resp = client.get(f"/api/v1/scenarios/{short_id}")
        assert resp.status_code == 422, f"Expected 422 for short identifier '{short_id}', got {resp.status_code}"

    # 3. Identifiers longer than max_length=128 rejected with 422
    long_id = "A" * 129
    resp = client.get(f"/api/v1/scenarios/{long_id}")
    assert resp.status_code == 422, f"Expected 422 for long identifier, got {resp.status_code}"

    # 4. Valid identifier formats correctly pass validation and reach the store (returning 404 when absent)
    for valid_id in ("SCN-T1059.001-01", "BM-01", "RUN-20261101-ABC", "A" * 128):
        resp = client.get(f"/api/v1/scenarios/{valid_id}")
        assert resp.status_code == 404, f"Expected 404 (not found) for valid identifier '{valid_id}', got {resp.status_code}"


# ── 2. Denial-of-Service & Resource Exhaustion Tests ──────────────────────────


def test_canonical_jcs_serialize_bounds_recursion_depth():
    """canonical_jcs_serialize must raise ValueError on extreme nesting, not crash with RecursionError."""
    nested = {}
    curr = nested
    for _ in range(80):
        curr["child"] = {}
        curr = curr["child"]

    with pytest.raises(ValueError, match="maximum nesting depth"):
        canonical_jcs_serialize(nested, max_depth=64)


def test_core_schemas_reject_deeply_nested_metadata():
    """ScenarioV1, TestRunV1, DetectionRuleV1, and GroundTruthV1 must reject deeply nested metadata."""
    deep_metadata = {"level1": {"level2": {"level3": {}}}}
    curr = deep_metadata["level1"]["level2"]["level3"]
    for i in range(20):
        curr[f"sub_{i}"] = {}
        curr = curr[f"sub_{i}"]

    # 1. ScenarioV1
    with pytest.raises(ValidationError, match="maximum allowed limit"):
        ScenarioV1(
            scenario_id="SCN-DEEP-01",
            name="Deep Scenario",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            validation_target=ValidationTarget.EXPECTED_ALERT,
            metadata=deep_metadata,
        )

    # 2. TestRunV1
    with pytest.raises(ValidationError, match="maximum allowed limit"):
        TestRunV1(
            run_id="RUN-DEEP-01",
            scenario_id="SCN-01",
            execution_mode="SYNTHETIC_SIMULATION",
            target_host="host-01",
            target_user="admin",
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            executed_at=datetime.now(timezone.utc),
            metadata=deep_metadata,
        )

    # 3. DetectionRuleV1
    with pytest.raises(ValidationError, match="maximum allowed limit"):
        DetectionRuleV1(
            rule_id="RULE-DEEP-01",
            rule_name="Deep Rule",
            rule_format="sigma",
            metadata=deep_metadata,
        )

    # 4. GroundTruthV1
    with pytest.raises(ValidationError, match="maximum allowed limit"):
        GroundTruthV1(
            ground_truth_id="GT-DEEP-01",
            run_id="RUN-01",
            expected_diagnostic_category=DiagnosticCategory.PASS,
            verification_method="manual_inspection",
            metadata=deep_metadata,
        )


# ── 3. Storage Concurrency & ACID Integrity Tests ─────────────────────────────


def test_get_store_thread_safe_concurrent_initialization():
    """Concurrent calls to get_store() from multiple threads must return the exact same singleton instance."""
    close_store()

    instances = []
    def worker():
        s = get_store()
        instances.append(s)

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(worker) for _ in range(32)]
        for f in futures:
            f.result()

    assert len(instances) == 32
    first_instance = instances[0]
    for inst in instances:
        assert inst is first_instance


def test_sqlite_savepoint_atomic_rollback_on_partial_failure():
    """Verify that an inner savepoint error rolls back cleanly without leaving partial records."""
    store = SQLiteStore(":memory:")
    scenario = ScenarioV1(
        scenario_id="SCN-TX-01",
        name="Tx Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-TX-01",
        scenario_id="SCN-TX-01",
        execution_mode="SYNTHETIC_SIMULATION",
        target_host="host-01",
        target_user="admin",
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        executed_at=datetime.now(timezone.utc),
    )
    store.add_run(run)

    # Attempt atomic transaction where second insert deliberately fails with duplicate key
    try:
        with store.transaction():
            rule = DetectionRuleV1(rule_id="RULE-TX-01", rule_name="Rule 1", rule_format="sigma")
            store.add_rule(rule)
            # Duplicate rule insertion fails
            store.add_rule(rule)
    except ValueError:
        pass

    # Verify that the entire transaction rolled back and rule was not committed
    assert store.get_rule("RULE-TX-01") is None
    store.close()


def test_sqlite_foreign_key_enforcement():
    """SQLiteStore must enforce PRAGMA foreign_keys = ON and restrict deleting parent scenarios."""
    store = SQLiteStore(":memory:")
    scenario = ScenarioV1(
        scenario_id="SCN-FK-01",
        name="FK Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scenario)

    run = TestRunV1(
        run_id="RUN-FK-01",
        scenario_id="SCN-FK-01",
        execution_mode="SYNTHETIC_SIMULATION",
        target_host="host-01",
        target_user="admin",
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        executed_at=datetime.now(timezone.utc),
    )
    store.add_run(run)

    # Attempt direct SQL deletion of parent scenario; must raise IntegrityError due to RESTRICT
    with pytest.raises(sqlite3.IntegrityError):
        with store.transaction() as cur:
            cur.execute("DELETE FROM scenarios WHERE scenario_id = 'SCN-FK-01';")

    store.close()


# ── 4. Evidence & Report Tamper Detection Tests ────────────────────────────────


def test_assurance_report_tamper_detection():
    """Verify that tampering with an assurance report field invalidates its canonical digest."""
    store = InMemoryStore()
    set_store(store)

    scen = ScenarioV1(
        scenario_id="SCN-TAMPER-01",
        name="Tamper Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scen)

    run = TestRunV1(
        run_id="RUN-TAMPER-01",
        scenario_id="SCN-TAMPER-01",
        execution_mode="SYNTHETIC_SIMULATION",
        target_host="host-01",
        target_user="admin",
        window_start=datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 11, 1, 10, 5, 0, tzinfo=timezone.utc),
        executed_at=datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc),
    )
    store.add_run(run)

    cdef = CampaignDefinitionV1(
        campaign_id="CPG-TAMPER",
        name="Tamper Test Campaign",
        scenario_ids=["SCN-TAMPER-01"],
    )
    store.add_campaign(cdef)

    engine = CampaignEngine(store)
    crun = engine.execute_campaign("CPG-TAMPER")

    generator = CampaignAssuranceReportGenerator(store)
    report = generator.generate_report(crun.run_id)
    store.add_assurance_report(report)

    # Verify initial report integrity is valid
    assert CampaignAssuranceReportGenerator.verify_report_integrity(report) is True

    # Tamper with the report (simulate malicious database modification)
    tampered_report = report.model_copy(deep=True)
    tampered_report.execution_summary.successful_executions = 9999  # Modified!

    # Verify tampering is immediately detected
    assert CampaignAssuranceReportGenerator.verify_report_integrity(tampered_report) is False

    # Test via API endpoint: tampered report must raise HTTP 500 integrity compromised
    app = create_application()
    client = TestClient(app)

    # Replace stored report with tampered version in store
    store._assurance_reports[report.report_id] = tampered_report

    resp = client.get(f"/api/v1/campaign-assurance-reports/{report.report_id}")
    assert resp.status_code == 500
    assert "Report integrity compromised" in resp.json()["detail"]


# ── 5. Campaign Execution Partial Failure Resilience ──────────────────────────


def test_campaign_execution_resilience_on_scenario_evaluation_exception(monkeypatch):
    """If one scenario throws an evaluation exception, the engine must record an ERROR and continue."""
    store = InMemoryStore()
    set_store(store)

    for i in (1, 2):
        store.add_scenario(
            ScenarioV1(
                scenario_id=f"SCN-RESIL-{i}",
                name=f"Resilience Scenario {i}",
                mitre_technique_id="T1059.001",
                mitre_tactic="Execution",
                expected_event_category=EventCategory.PROCESS_CREATION,
                validation_target=ValidationTarget.EXPECTED_ALERT,
            )
        )
        store.add_run(
            TestRunV1(
                run_id=f"RUN-RESIL-{i}",
                scenario_id=f"SCN-RESIL-{i}",
                execution_mode="SYNTHETIC_SIMULATION",
                target_host="host-01",
                target_user="admin",
                window_start=datetime.now(timezone.utc),
                window_end=datetime.now(timezone.utc),
                executed_at=datetime.now(timezone.utc),
            )
        )

    cdef = CampaignDefinitionV1(
        campaign_id="CPG-RESIL",
        name="Resilience Campaign",
        scenario_ids=["SCN-RESIL-1", "SCN-RESIL-2"],
        execution_config=CampaignExecutionConfigV1(execution_policy=CampaignExecutionPolicy.CONTINUE_ON_ERROR),
    )
    store.add_campaign(cdef)

    # Monkeypatch AssuranceEngine.evaluate_run to fail ONLY on SCN-RESIL-1's run
    from proofshield.services.evaluation import AssuranceEngine
    orig_eval = AssuranceEngine.evaluate_run

    def flaky_eval(self, run_id, strict_attribution=None):
        if run_id == "RUN-RESIL-1":
            raise RuntimeError("Simulated transient evaluation explosion")
        return orig_eval(self, run_id, strict_attribution=strict_attribution)

    monkeypatch.setattr(AssuranceEngine, "evaluate_run", flaky_eval)

    engine = CampaignEngine(store)
    crun = engine.execute_campaign("CPG-RESIL")

    # The campaign must not crash; SCN-RESIL-1 must be ERROR, SCN-RESIL-2 must be evaluated
    assert len(crun.scenario_results) == 2
    assert crun.scenario_results[0].status == ScenarioRunStatus.ERROR
    assert "Simulated transient evaluation explosion" in crun.errors[0]
    assert crun.scenario_results[1].scenario_id == "SCN-RESIL-2"


def test_root_cause_intelligence_factual_segregation():
    """Root-cause intelligence must strictly separate observed facts from inferred explanations."""
    store = InMemoryStore()
    set_store(store)

    # Create scenario with missing telemetry
    scen = ScenarioV1(
        scenario_id="SCN-RC-01",
        name="Root Cause Scenario",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scen)
    run = TestRunV1(
        run_id="RUN-RC-01",
        scenario_id="SCN-RC-01",
        execution_mode="SYNTHETIC_SIMULATION",
        target_host="host-01",
        target_user="admin",
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        executed_at=datetime.now(timezone.utc),
    )
    store.add_run(run)

    cdef = CampaignDefinitionV1(
        campaign_id="CPG-RC",
        name="RC Campaign",
        scenario_ids=["SCN-RC-01"],
    )
    store.add_campaign(cdef)

    engine = CampaignEngine(store)
    crun = engine.execute_campaign("CPG-RC")

    rc_service = RootCauseIntelligenceService(store)
    rc_intel = rc_service.analyze_campaign_run(crun.run_id)

    assert len(rc_intel.patterns) > 0
    pattern = rc_intel.patterns[0]
    # Check that observed facts and inferred explanations are distinct lists
    assert len(pattern.observed_facts) > 0
    assert len(pattern.inferred_explanations) > 0
    assert any("expected telemetry" in fact.lower() for fact in pattern.observed_facts)
    assert any("potential causes" in expl.lower() for expl in pattern.inferred_explanations)

