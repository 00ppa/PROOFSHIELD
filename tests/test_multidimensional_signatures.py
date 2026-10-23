"""Adversarial and regression tests for Phase 9A multidimensional evidence signatures.

Verifies:
1. Expected network destination IP and port matching.
2. Correct destination IP but wrong port (rejection).
3. Correct port but wrong destination IP (rejection).
4. Unrelated DNS background traffic rejection.
5. Unrelated web background traffic rejection.
6. Underspecified scenario handling (INCONCLUSIVE guard).
7. File event with incorrect path rejection.
8. File event with expected path match.
9. Hash mismatch rejection.
10. Hash match acceptance.
11. User identity filtering and domain-prefix matching.
12. Multiple candidate events with background noise discrimination.
13. Strict execution-token attribution on network events.
14. Strict execution-token attribution rejection of mismatched network alert.
15. Boundary timestamp exclusion outside observation window.
16. Backwards compatibility for process-only scenarios.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
import pytest

from proofshield.schemas import (
    AlertV1,
    DetectionRuleV1,
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
    ScenarioV1,
    TestRunV1,
)
from proofshield.schemas.common import (
    AttributionStatus,
    DiagnosticCategory,
    EventCategory,
    ExecutionMode,
    ExecutionStatus,
    ValidationTarget,
)
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.store import InMemoryStore


@pytest.fixture
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture
def engine(store: InMemoryStore) -> AssuranceEngine:
    return AssuranceEngine(store)


def _make_run(
    run_id: str,
    scenario_id: str,
    t0: datetime,
    host: str = "WS-TARGET-01",
    token: str = None,
) -> TestRunV1:
    return TestRunV1(
        run_id=run_id,
        scenario_id=scenario_id,
        execution_mode=ExecutionMode.SYNTHETIC_SIMULATION,
        is_synthetic=True,
        target_host=host,
        target_user="corp\\secops",
        window_start=t0,
        window_end=t0 + timedelta(minutes=10),
        executed_at=t0,
        execution_status=ExecutionStatus.COMPLETED,
        execution_token=token,
    )


def _make_alert(
    alert_id: str,
    rule_reference: str,
    host_id: str,
    timestamp: datetime,
    token: Optional[str] = None,
) -> AlertV1:
    return AlertV1(
        alert_id=alert_id,
        source_alert_id=f"SRC-{alert_id}",
        source_type="sysmon",
        rule_reference=rule_reference,
        host_id=host_id,
        alert_timestamp=timestamp,
        execution_token=token,
    )


def test_network_destination_and_port_match_pass(store: InMemoryStore, engine: AssuranceEngine):
    """1. Verify that matching network destination IP and port produces a PASS."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-NET-PASS",
        name="Outbound C2 Network Beacon",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_ip="198.51.100.50",
        expected_destination_port=4444,
        expected_detection_rule_id="RULE-C2-PORT-4444",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scn)

    run = _make_run("RUN-NET-PASS", scn.scenario_id, t0)
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NET-01",
        raw_event_id="RAW-NET-01",
        source_event_id="1001",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.NETWORK_CONNECTION,
        host=run.target_host,
        network_destination_ip="198.51.100.50",
        network_destination_port=4444,
    )
    store.add_normalized_event(event)

    alert = _make_alert(
        "ALT-NET-01",
        "RULE-C2-PORT-4444",
        run.target_host,
        t0 + timedelta(minutes=3),
    )
    store.add_alert(alert)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS
    assert "NORM-NET-01" in res.supporting_evidence_ids
    assert "ALT-NET-01" in res.supporting_evidence_ids


def test_network_correct_ip_wrong_port_telemetry_missing(store: InMemoryStore, engine: AssuranceEngine):
    """2. Verify that matching IP with wrong port fails matching and yields EXPECTED_TELEMETRY_MISSING."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-NET-WRONG-PORT",
        name="C2 on 4444",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_ip="198.51.100.50",
        expected_destination_port=4444,
        expected_detection_rule_id="RULE-C2-PORT-4444",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-NET-WRONG-PORT", scn.scenario_id, t0)
    store.add_run(run)

    # Event connected to expected IP but port 80 instead of 4444
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NET-WRONG-PORT",
        raw_event_id="RAW-01",
        source_event_id="1002",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.NETWORK_CONNECTION,
        host=run.target_host,
        network_destination_ip="198.51.100.50",
        network_destination_port=80,
    )
    store.add_normalized_event(event)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert any("Expected destination port: 4444" in r for r in res.diagnostic_reasons)


def test_network_correct_port_wrong_ip_telemetry_missing(store: InMemoryStore, engine: AssuranceEngine):
    """3. Verify that matching port with wrong destination IP fails matching."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-NET-WRONG-IP",
        name="C2 on 4444",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_ip="198.51.100.50",
        expected_destination_port=4444,
        expected_detection_rule_id="RULE-C2-PORT-4444",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-NET-WRONG-IP", scn.scenario_id, t0)
    store.add_run(run)

    # Event connected to port 4444 on a benign internal IP
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NET-WRONG-IP",
        raw_event_id="RAW-01",
        source_event_id="1003",
        source_timestamp=t0 + timedelta(minutes=2),
        normalized_timestamp=t0 + timedelta(minutes=2),
        event_category=EventCategory.NETWORK_CONNECTION,
        host=run.target_host,
        network_destination_ip="10.0.0.5",
        network_destination_port=4444,
    )
    store.add_normalized_event(event)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert any("Expected destination IP: 198.51.100.50" in r for r in res.diagnostic_reasons)


def test_network_unrelated_dns_traffic_rejected(store: InMemoryStore, engine: AssuranceEngine):
    """4. Verify that ordinary ambient DNS traffic (port 53) cannot satisfy an adversary network scenario."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-NET-C2",
        name="Exfiltration to Remote Host",
        mitre_technique_id="T1048.003",
        mitre_tactic="Exfiltration",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_ip="198.51.100.200",
        expected_destination_port=8443,
        expected_detection_rule_id="RULE-EXFIL-8443",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-DNS-NOISE", scn.scenario_id, t0)
    store.add_run(run)

    # Ambient DNS query to 1.1.1.1:53 during the window
    dns_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-DNS-01",
        raw_event_id="RAW-DNS-01",
        source_event_id="5353",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.NETWORK_CONNECTION,
        host=run.target_host,
        network_destination_ip="1.1.1.1",
        network_destination_port=53,
    )
    store.add_normalized_event(dns_event)

    # SIEM fires a rule for something else
    store.add_alert(
        _make_alert(
            "ALT-FAKE",
            "RULE-EXFIL-8443",
            run.target_host,
            t0 + timedelta(minutes=2),
        )
    )

    res = engine.evaluate_run(run.run_id)
    # The DNS traffic must NOT be matched, so expected telemetry is missing
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING
    assert any("8443" in reason for reason in res.diagnostic_reasons)
    assert any("198.51.100.200" in reason for reason in res.diagnostic_reasons)


def test_network_unrelated_web_traffic_rejected(store: InMemoryStore, engine: AssuranceEngine):
    """5. Verify that unrelated HTTPS web browsing (port 443) is rejected when scenario expects C2 port 8080."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-NET-8080",
        name="C2 on 8080",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_port=8080,
        expected_detection_rule_id="RULE-C2-8080",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-WEB-NOISE", scn.scenario_id, t0)
    store.add_run(run)

    # Normal Google/CDN browsing
    web_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-WEB-01",
        raw_event_id="RAW-01",
        source_event_id="44301",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.NETWORK_CONNECTION,
        host=run.target_host,
        network_destination_ip="142.250.190.46",
        network_destination_port=443,
    )
    store.add_normalized_event(web_event)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING


def test_underspecified_scenario_returns_inconclusive(store: InMemoryStore, engine: AssuranceEngine):
    """6. Verify that an underspecified alert scenario (no discriminating fields) returns INCONCLUSIVE."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-UNDERSPECIFIED",
        name="Underspecified Network Scenario",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        # Intentionally no process, no command, no IP, no port, no path, no hash, no user
        expected_detection_rule_id="RULE-UNDERSPEC",
        validation_target=ValidationTarget.EXPECTED_ALERT,
    )
    store.add_scenario(scn)
    run = _make_run("RUN-UNDERSPEC", scn.scenario_id, t0)
    store.add_run(run)

    # Add ambient event
    store.add_normalized_event(
        NormalizedTelemetryEventV1(
            normalized_event_id="NORM-AMBIENT-01",
            raw_event_id="RAW-01",
            source_event_id="1",
            source_timestamp=t0 + timedelta(minutes=1),
            normalized_timestamp=t0 + timedelta(minutes=1),
            event_category=EventCategory.NETWORK_CONNECTION,
            host=run.target_host,
            network_destination_ip="10.0.0.1",
            network_destination_port=80,
        )
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res.confidence == "uncertain"
    assert res.metadata.get("underspecified_scenario") is True
    assert "lacks a discriminating signature" in res.reason


def test_file_event_wrong_path_rejected(store: InMemoryStore, engine: AssuranceEngine):
    """7. Verify that a file event with the wrong path fails scenario matching."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-FILE-HOSTS",
        name="Hosts File Tampering",
        mitre_technique_id="T1565.001",
        mitre_tactic="Impact",
        expected_event_category=EventCategory.FILE_EVENT,
        expected_file_path=r"etc/hosts",
        expected_detection_rule_id="RULE-HOSTS-MOD",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-FILE-WRONG", scn.scenario_id, t0)
    store.add_run(run)

    # Event wrote to an unrelated temp file
    file_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-FILE-TEMP",
        raw_event_id="RAW-01",
        source_event_id="1101",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.FILE_EVENT,
        host=run.target_host,
        process_path=r"C:\Users\test\AppData\Local\Temp\junk.tmp",
    )
    store.add_normalized_event(file_event)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING


def test_file_event_expected_path_pass(store: InMemoryStore, engine: AssuranceEngine):
    """8. Verify that a file event matching the expected path passes."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-FILE-HOSTS-PASS",
        name="Hosts File Modification",
        mitre_technique_id="T1565.001",
        mitre_tactic="Impact",
        expected_event_category=EventCategory.FILE_EVENT,
        expected_file_path=r"etc/hosts",
        expected_detection_rule_id="RULE-HOSTS-MOD",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-FILE-PASS", scn.scenario_id, t0)
    store.add_run(run)

    file_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-FILE-HOSTS",
        raw_event_id="RAW-01",
        source_event_id="1102",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.FILE_EVENT,
        host=run.target_host,
        process_path=r"C:\Windows\System32\drivers\etc\hosts",
    )
    store.add_normalized_event(file_event)

    store.add_alert(
        _make_alert(
            "ALT-HOSTS-01",
            "RULE-HOSTS-MOD",
            run.target_host,
            t0 + timedelta(minutes=2),
        )
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS
    assert "NORM-FILE-HOSTS" in res.supporting_evidence_ids


def test_file_hash_mismatch_rejected(store: InMemoryStore, engine: AssuranceEngine):
    """9. Verify that a hash mismatch fails matching."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-HASH-CHECK",
        name="Known Malicious Tool Hash",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_file_hash="deadbeef12345678",
        expected_detection_rule_id="RULE-MAL-HASH",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-HASH-WRONG", scn.scenario_id, t0)
    store.add_run(run)

    # Event has a different SHA256 hash
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-HASH-WRONG",
        raw_event_id="RAW-01",
        source_event_id="101",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="tool.exe",
        hashes={"sha256": "cafebabe87654321"},
    )
    store.add_normalized_event(event)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING


def test_file_hash_match_pass(store: InMemoryStore, engine: AssuranceEngine):
    """10. Verify that matching hash succeeds and produces PASS."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-HASH-PASS",
        name="Known Malicious Tool Hash",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_file_hash="deadbeef12345678",
        expected_detection_rule_id="RULE-MAL-HASH",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-HASH-PASS", scn.scenario_id, t0)
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-HASH-MATCH",
        raw_event_id="RAW-01",
        source_event_id="101",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="tool.exe",
        hashes={"sha256": "deadbeef12345678", "md5": "11223344"},
    )
    store.add_normalized_event(event)

    store.add_alert(
        _make_alert(
            "ALT-HASH-01",
            "RULE-MAL-HASH",
            run.target_host,
            t0 + timedelta(minutes=2),
        )
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS


def test_user_filtering_match_and_mismatch(store: InMemoryStore, engine: AssuranceEngine):
    """11. Verify user matching handles domain prefixes and rejects mismatched accounts."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-USER-AUTH",
        name="Privileged Admin Logon",
        mitre_technique_id="T1078.002",
        mitre_tactic="Initial Access",
        expected_event_category=EventCategory.AUTHENTICATION,
        expected_user="admin_svc",
        expected_detection_rule_id="RULE-PRIV-LOGON",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-USER-TEST", scn.scenario_id, t0)
    store.add_run(run)

    # Ambient logon by SYSTEM
    store.add_normalized_event(
        NormalizedTelemetryEventV1(
            normalized_event_id="NORM-SYS-LOGON",
            raw_event_id="RAW-01",
            source_event_id="4624",
            source_timestamp=t0 + timedelta(minutes=1),
            normalized_timestamp=t0 + timedelta(minutes=1),
            event_category=EventCategory.AUTHENTICATION,
            host=run.target_host,
            user="NT AUTHORITY\\SYSTEM",
        )
    )

    # Targeted logon by CORP\admin_svc
    store.add_normalized_event(
        NormalizedTelemetryEventV1(
            normalized_event_id="NORM-ADMIN-LOGON",
            raw_event_id="RAW-02",
            source_event_id="4625",
            source_timestamp=t0 + timedelta(minutes=2),
            normalized_timestamp=t0 + timedelta(minutes=2),
            event_category=EventCategory.AUTHENTICATION,
            host=run.target_host,
            user="CORP\\admin_svc",
        )
    )

    store.add_alert(
        _make_alert(
            "ALT-AUTH-01",
            "RULE-PRIV-LOGON",
            run.target_host,
            t0 + timedelta(minutes=3),
        )
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS
    # Verify ONLY the admin logon was matched, not the SYSTEM logon
    assert "NORM-ADMIN-LOGON" in res.supporting_evidence_ids
    assert "NORM-SYS-LOGON" not in res.supporting_evidence_ids


def test_multiple_candidate_events_with_background_noise(store: InMemoryStore, engine: AssuranceEngine):
    """12. Verify that discriminating signatures accurately isolate target activity amid dense network noise."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-C2-ISOLATE",
        name="C2 Beacon Isolation",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_ip="198.51.100.50",
        expected_destination_port=4444,
        expected_detection_rule_id="RULE-C2",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-NOISE-SUITE", scn.scenario_id, t0)
    store.add_run(run)

    # 4 background noise events
    noise = [
        ("DNS-1", "8.8.8.8", 53),
        ("DNS-2", "1.1.1.1", 53),
        ("WEB-1", "142.250.190.46", 443),
        ("SSH-1", "10.0.0.99", 22),
    ]
    for idx, (nid, ip, port) in enumerate(noise, start=1):
        store.add_normalized_event(
            NormalizedTelemetryEventV1(
                normalized_event_id=f"NORM-NOISE-{idx}",
                raw_event_id=f"RAW-{idx}",
                source_event_id=str(idx),
                source_timestamp=t0 + timedelta(minutes=idx),
                normalized_timestamp=t0 + timedelta(minutes=idx),
                event_category=EventCategory.NETWORK_CONNECTION,
                host=run.target_host,
                network_destination_ip=ip,
                network_destination_port=port,
            )
        )

    # 1 genuine C2 event
    store.add_normalized_event(
        NormalizedTelemetryEventV1(
            normalized_event_id="NORM-C2-GENUINE",
            raw_event_id="RAW-99",
            source_event_id="99",
            source_timestamp=t0 + timedelta(minutes=5),
            normalized_timestamp=t0 + timedelta(minutes=5),
            event_category=EventCategory.NETWORK_CONNECTION,
            host=run.target_host,
            network_destination_ip="198.51.100.50",
            network_destination_port=4444,
        )
    )

    store.add_alert(
        _make_alert(
            "ALT-C2-01",
            "RULE-C2",
            run.target_host,
            t0 + timedelta(minutes=6),
        )
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS
    assert res.supporting_evidence_ids == ["NORM-C2-GENUINE", "ALT-C2-01"]


def test_strict_token_attribution_with_network_event(store: InMemoryStore, engine: AssuranceEngine):
    """13. Verify strict token attribution links network event with matching token."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    token = "TOK-NET-ATTRIB-01"
    scn = ScenarioV1(
        scenario_id="SCN-NET-STRICT",
        name="Network C2 Strict",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_ip="198.51.100.50",
        expected_destination_port=4444,
        expected_detection_rule_id="RULE-C2",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-NET-STRICT", scn.scenario_id, t0, token=token)
    store.add_run(run)

    store.add_normalized_event(
        NormalizedTelemetryEventV1(
            normalized_event_id="NORM-NET-TOK",
            raw_event_id="RAW-01",
            source_event_id="1",
            source_timestamp=t0 + timedelta(minutes=2),
            normalized_timestamp=t0 + timedelta(minutes=2),
            event_category=EventCategory.NETWORK_CONNECTION,
            host=run.target_host,
            network_destination_ip="198.51.100.50",
            network_destination_port=4444,
            execution_token=token,
        )
    )

    store.add_alert(
        _make_alert(
            "ALT-NET-TOK",
            "RULE-C2",
            run.target_host,
            t0 + timedelta(minutes=3),
            token=token,
        )
    )

    res = engine.evaluate_run(run.run_id, strict_attribution=True)
    assert res.predicted_category == DiagnosticCategory.PASS
    assert res.metadata["attribution"]["status"] == AttributionStatus.VERIFIED.value


def test_strict_token_attribution_rejects_mismatched_network_alert(store: InMemoryStore, engine: AssuranceEngine):
    """14. Verify strict mode rejects mismatched alert on target network host, exposing silent rule."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    attack_token = "TOK-ATTACK-99"
    noise_token = "TOK-NOISE-01"

    scn = ScenarioV1(
        scenario_id="SCN-NET-STRICT-REJECT",
        name="Network C2 Rejection",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_ip="198.51.100.50",
        expected_destination_port=4444,
        expected_detection_rule_id="RULE-C2",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-STRICT-REJECT", scn.scenario_id, t0, token=attack_token)
    store.add_run(run)

    store.add_normalized_event(
        NormalizedTelemetryEventV1(
            normalized_event_id="NORM-NET-ATK",
            raw_event_id="RAW-01",
            source_event_id="1",
            source_timestamp=t0 + timedelta(minutes=2),
            normalized_timestamp=t0 + timedelta(minutes=2),
            event_category=EventCategory.NETWORK_CONNECTION,
            host=run.target_host,
            network_destination_ip="198.51.100.50",
            network_destination_port=4444,
            execution_token=attack_token,
        )
    )

    # An alert fires on this host, but belongs to an unrelated background task
    store.add_alert(
        _make_alert(
            "ALT-NOISE",
            "RULE-C2",
            run.target_host,
            t0 + timedelta(minutes=3),
            token=noise_token,
        )
    )

    res = engine.evaluate_run(run.run_id, strict_attribution=True)
    assert res.predicted_category == DiagnosticCategory.DETECTION_NOT_TRIGGERED
    assert "ALT-NOISE" not in res.supporting_evidence_ids


def test_boundary_timestamps_outside_window(store: InMemoryStore, engine: AssuranceEngine):
    """15. Verify that network events occurring strictly outside the window are not matched."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-NET-WINDOW",
        name="Window Test",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_ip="198.51.100.50",
        expected_destination_port=4444,
    )
    store.add_scenario(scn)
    run = _make_run("RUN-NET-WINDOW", scn.scenario_id, t0)  # window: 10:00 to 10:10
    store.add_run(run)

    # Event occurs at 09:59:59 (1 second before window)
    store.add_normalized_event(
        NormalizedTelemetryEventV1(
            normalized_event_id="NORM-EARLY",
            raw_event_id="RAW-01",
            source_event_id="1",
            source_timestamp=t0 - timedelta(seconds=1),
            normalized_timestamp=t0 - timedelta(seconds=1),
            event_category=EventCategory.NETWORK_CONNECTION,
            host=run.target_host,
            network_destination_ip="198.51.100.50",
            network_destination_port=4444,
        )
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING


def test_backward_compatibility_pure_process_scenario(store: InMemoryStore, engine: AssuranceEngine):
    """16. Verify that traditional process scenarios continue to function with full fidelity."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-PROC-COMPAT",
        name="PowerShell Execution",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_command_pattern=r"whoami",
        expected_detection_rule_id="RULE-WHOAMI",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-PROC-COMPAT", scn.scenario_id, t0)
    store.add_run(run)

    store.add_normalized_event(
        NormalizedTelemetryEventV1(
            normalized_event_id="NORM-PROC-01",
            raw_event_id="RAW-01",
            source_event_id="1",
            source_timestamp=t0 + timedelta(minutes=2),
            normalized_timestamp=t0 + timedelta(minutes=2),
            event_category=EventCategory.PROCESS_CREATION,
            host=run.target_host,
            process_name="powershell.exe",
            command_line="powershell.exe whoami /priv",
        )
    )

    store.add_alert(
        _make_alert(
            "ALT-PROC-01",
            "RULE-WHOAMI",
            run.target_host,
            t0 + timedelta(minutes=3),
        )
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS
    assert "NORM-PROC-01" in res.supporting_evidence_ids
    assert "ALT-PROC-01" in res.supporting_evidence_ids


def test_cross_domain_user_collision_rejected(store: InMemoryStore, engine: AssuranceEngine):
    """17. Adversarial: CORPA\\alice must not match CORPB\\alice even though bare username is identical."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-USER-DOMAIN-COLLISION",
        name="Domain Specific Privileged Execution",
        mitre_technique_id="T1078.002",
        mitre_tactic="Defense Evasion",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="powershell.exe",
        expected_user=r"CORPA\alice",
        expected_detection_rule_id="RULE-CORPA-EXEC",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-USER-DOMAIN", scn.scenario_id, t0)
    store.add_run(run)

    # Telemetry from a different domain (CORPB)
    wrong_user_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-CORPB-USER",
        raw_event_id="RAW-01",
        source_event_id="1",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        user=r"CORPB\alice",
    )
    store.add_normalized_event(wrong_user_event)

    store.add_alert(
        _make_alert("ALT-USER-01", "RULE-CORPA-EXEC", run.target_host, t0 + timedelta(minutes=2))
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    # Now add event from the correct domain (CORPA)
    correct_user_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-CORPA-USER",
        raw_event_id="RAW-02",
        source_event_id="2",
        source_timestamp=t0 + timedelta(minutes=1, seconds=30),
        normalized_timestamp=t0 + timedelta(minutes=1, seconds=30),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="powershell.exe",
        user=r"CORPA\alice",
    )
    store.add_normalized_event(correct_user_event)

    res_pass = engine.evaluate_run(run.run_id)
    assert res_pass.predicted_category == DiagnosticCategory.PASS
    assert "NORM-CORPA-USER" in res_pass.supporting_evidence_ids


def test_file_path_extension_suffix_collision_rejected(store: InMemoryStore, engine: AssuranceEngine):
    """18. Adversarial: /etc/hosts.bak must not satisfy expected_file_path='/etc/hosts'."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-PATH-SUFFIX-BAK",
        name="Hosts File Modification",
        mitre_technique_id="T1565.001",
        mitre_tactic="Impact",
        expected_event_category=EventCategory.FILE_EVENT,
        expected_file_path=r"/etc/hosts",
        expected_detection_rule_id="RULE-HOSTS-MOD",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-PATH-BAK", scn.scenario_id, t0)
    store.add_run(run)

    # Event touched /etc/hosts.bak (backup file, not /etc/hosts)
    bak_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-FILE-BAK",
        raw_event_id="RAW-01",
        source_event_id="1101",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.FILE_EVENT,
        host=run.target_host,
        extra_attributes={"TargetFilename": "/etc/hosts.bak"},
    )
    store.add_normalized_event(bak_event)

    store.add_alert(
        _make_alert("ALT-HOSTS-BAK", "RULE-HOSTS-MOD", run.target_host, t0 + timedelta(minutes=2))
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING

    # Now add event touching exact /etc/hosts
    exact_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-FILE-EXACT",
        raw_event_id="RAW-02",
        source_event_id="1102",
        source_timestamp=t0 + timedelta(minutes=1, seconds=10),
        normalized_timestamp=t0 + timedelta(minutes=1, seconds=10),
        event_category=EventCategory.FILE_EVENT,
        host=run.target_host,
        extra_attributes={"TargetFilename": "/etc/hosts"},
    )
    store.add_normalized_event(exact_event)

    res_pass = engine.evaluate_run(run.run_id)
    assert res_pass.predicted_category == DiagnosticCategory.PASS
    assert "NORM-FILE-EXACT" in res_pass.supporting_evidence_ids


def test_file_event_does_not_match_process_executable(store: InMemoryStore, engine: AssuranceEngine):
    """19. Adversarial: On file events with target file attributes, process_path (the executable) must not match expected_file_path."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-FILE-VS-PROC",
        name="Cmd Target File Write",
        mitre_technique_id="T1565.001",
        mitre_tactic="Impact",
        expected_event_category=EventCategory.FILE_EVENT,
        expected_file_path=r"cmd.exe",
        expected_detection_rule_id="RULE-CMD-FILE",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-FILE-VS-PROC", scn.scenario_id, t0)
    store.add_run(run)

    # An event where cmd.exe wrote to bad.txt.
    # The file being accessed is bad.txt; cmd.exe is the executable image.
    file_event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-FILE-WRITE-01",
        raw_event_id="RAW-01",
        source_event_id="11",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.FILE_EVENT,
        host=run.target_host,
        process_path=r"C:\Windows\System32\cmd.exe",
        process_name="cmd.exe",
        extra_attributes={"TargetFilename": r"C:\Windows\Temp\bad.txt"},
    )
    store.add_normalized_event(file_event)

    store.add_alert(
        _make_alert("ALT-CMD-01", "RULE-CMD-FILE", run.target_host, t0 + timedelta(minutes=2))
    )

    # Scenario expects file path "cmd.exe", but the file touched was "bad.txt"
    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING


def test_file_hash_with_algorithm_prefix_matched(store: InMemoryStore, engine: AssuranceEngine):
    """20. Adversarial: Hash with algo prefix (sha256:...) matches event hashes['sha256'], and wrong algo is rejected."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    h_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Scenario 1 specifies sha256 algorithm prefix
    scn_sha = ScenarioV1(
        scenario_id="SCN-HASH-ALGO-SHA",
        name="SHA256 Match",
        mitre_technique_id="T1204.002",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_file_hash=f"sha256:{h_sha256}",
        expected_detection_rule_id="RULE-HASH-01",
    )
    store.add_scenario(scn_sha)
    run_sha = _make_run("RUN-HASH-SHA", scn_sha.scenario_id, t0)
    store.add_run(run_sha)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-HASH-ALGO-01",
        raw_event_id="RAW-01",
        source_event_id="1",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host=run_sha.target_host,
        process_name="binary.exe",
        hashes={"sha256": h_sha256, "md5": "d41d8cd98f00b204e9800998ecf8427e"},
    )
    store.add_normalized_event(event)

    store.add_alert(
        _make_alert("ALT-HASH-01", "RULE-HASH-01", run_sha.target_host, t0 + timedelta(minutes=2))
    )

    res_sha = engine.evaluate_run(run_sha.run_id)
    assert res_sha.predicted_category == DiagnosticCategory.PASS
    assert "NORM-HASH-ALGO-01" in res_sha.supporting_evidence_ids

    # Scenario 2 specifies md5 prefix with sha256 value (mismatched algorithm)
    scn_wrong_algo = ScenarioV1(
        scenario_id="SCN-HASH-WRONG-ALGO",
        name="Wrong Algo Prefix",
        mitre_technique_id="T1204.002",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_file_hash=f"md5:{h_sha256}",
        expected_detection_rule_id="RULE-HASH-01",
    )
    store.add_scenario(scn_wrong_algo)
    run_wrong = _make_run("RUN-HASH-WRONG", scn_wrong_algo.scenario_id, t0)
    store.add_run(run_wrong)

    res_wrong = engine.evaluate_run(run_wrong.run_id)
    assert res_wrong.predicted_category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING


def test_underspecified_whitespace_string_guard(store: InMemoryStore, engine: AssuranceEngine):
    """21. Adversarial: Whitespace-only string fields must not bypass has_discriminating_signature guard."""
    scn = ScenarioV1(
        scenario_id="SCN-WHITESPACE-GUARD",
        name="Whitespace Evasion Attempt",
        mitre_technique_id="T1059.001",
        mitre_tactic="Execution",
        expected_event_category=EventCategory.PROCESS_CREATION,
        expected_process_name="   ",  # Blank whitespace string
        expected_detection_rule_id="RULE-UNDERSPEC",
    )
    assert scn.has_discriminating_signature() is False

    store.add_scenario(scn)
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    run = _make_run("RUN-WHITESPACE-GUARD", scn.scenario_id, t0)
    store.add_run(run)

    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NOISE-WS",
        raw_event_id="RAW-01",
        source_event_id="1",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.PROCESS_CREATION,
        host=run.target_host,
        process_name="svchost.exe",
    )
    store.add_normalized_event(event)

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.INCONCLUSIVE
    assert res.metadata.get("underspecified_scenario") is True


def test_ip_address_ipv6_canonical_matching(store: InMemoryStore, engine: AssuranceEngine):
    """22. Adversarial: Compressed and uncompressed IPv6 representations must match canonically."""
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    scn = ScenarioV1(
        scenario_id="SCN-IPV6-CANONICAL",
        name="C2 Communication over IPv6",
        mitre_technique_id="T1071.001",
        mitre_tactic="Command and Control",
        expected_event_category=EventCategory.NETWORK_CONNECTION,
        expected_destination_ip="2001:db8:85a3::8a2e:370:7334",  # Compressed
        expected_destination_port=443,
        expected_detection_rule_id="RULE-C2-IPV6",
    )
    store.add_scenario(scn)
    run = _make_run("RUN-IPV6", scn.scenario_id, t0)
    store.add_run(run)

    # Telemetry logger reports uncompressed IPv6 representation
    event = NormalizedTelemetryEventV1(
        normalized_event_id="NORM-NET-IPV6",
        raw_event_id="RAW-01",
        source_event_id="3",
        source_timestamp=t0 + timedelta(minutes=1),
        normalized_timestamp=t0 + timedelta(minutes=1),
        event_category=EventCategory.NETWORK_CONNECTION,
        host=run.target_host,
        network_destination_ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        network_destination_port=443,
    )
    store.add_normalized_event(event)

    store.add_alert(
        _make_alert("ALT-IPV6-01", "RULE-C2-IPV6", run.target_host, t0 + timedelta(minutes=2))
    )

    res = engine.evaluate_run(run.run_id)
    assert res.predicted_category == DiagnosticCategory.PASS
    assert "NORM-NET-IPV6" in res.supporting_evidence_ids


def test_nested_transaction_in_memory_and_sqlite():
    """23. Adversarial: Nested transactions roll back inner failure without aborting outer committed state."""
    from proofshield.services.sqlite_store import SQLiteStore

    for store_cls in (InMemoryStore, SQLiteStore):
        s = store_cls()
        scn1 = ScenarioV1(
            scenario_id="SCN-TX-1",
            name="Outer Scenario",
            mitre_technique_id="T1059",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="outer.exe",
        )
        scn2 = ScenarioV1(
            scenario_id="SCN-TX-2",
            name="Inner Scenario",
            mitre_technique_id="T1059",
            mitre_tactic="Execution",
            expected_event_category=EventCategory.PROCESS_CREATION,
            expected_process_name="inner.exe",
        )

        with s.transaction():
            s.add_scenario(scn1)
            try:
                with s.transaction():
                    s.add_scenario(scn2)
                    raise ValueError("Inner failure midway through transaction")
            except ValueError:
                pass  # Inner transaction aborted and rolled back

        # After outer transaction successfully commits:
        assert s.get_scenario("SCN-TX-1") is not None
        assert s.get_scenario("SCN-TX-2") is None

