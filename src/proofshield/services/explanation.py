"""Evidence-grounded analyst explanations that cannot change assurance results."""

from __future__ import annotations

from typing import List
import uuid

from proofshield.schemas.common import DiagnosticCategory
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.explanation import (
    AnalystExplanationV1,
    ExplanationFactV1,
    ExplanationGapV1,
    ExplanationHypothesisV1,
)
from proofshield.services.base_store import StoreProtocol
from proofshield.services.canonical import compute_canonical_hash
from proofshield.services.evidence_snapshot import verify_inputs


class EvidenceGroundedExplanationService:
    """Renders only facts available in stored evidence and the deterministic result."""

    def __init__(self, store: StoreProtocol) -> None:
        self.store = store

    def explain(self, result: DiagnosticResultV1) -> AnalystExplanationV1:
        run = self.store.get_run(result.test_run_id)
        scenario = self.store.get_scenario(result.scenario_id)
        if run is None or scenario is None:
            raise ValueError("Cannot explain a diagnostic result without its run and scenario")
        integrity, evidence = verify_inputs(self.store, result)
        if integrity == "FAILED":
            raise ValueError("Evidence changed since diagnosis; re-evaluation is required")
        events = self.store.get_events_for_run(run)
        alerts = self.store.get_alerts_for_run(run)
        execution = next((item for item in self.store.list_executions(run_id=run.run_id)), None)
        facts: List[ExplanationFactV1] = [
            ExplanationFactV1(
                fact_id="FACT-DIAGNOSTIC",
                statement=f"The deterministic Assurance Engine classified this run as {result.predicted_category.value}.",
                evidence_ids=[result.diagnostic_id],
            ),
            ExplanationFactV1(
                fact_id="FACT-EXECUTION-STATUS",
                statement=f"The test run execution status is {run.execution_status.value}.",
                evidence_ids=[run.run_id] + ([execution.execution_id] if execution else []),
            ),
            ExplanationFactV1(
                fact_id="FACT-TELEMETRY-COUNT",
                statement=f"{len(events)} normalized telemetry event(s) are correlated to the run window and host.",
                evidence_ids=[event.normalized_event_id for event in events],
            ),
            ExplanationFactV1(
                fact_id="FACT-ALERT-COUNT",
                statement=f"{len(alerts)} alert(s) are correlated to the run window and host.",
                evidence_ids=[alert.alert_id for alert in alerts],
            ),
        ]
        gaps: List[ExplanationGapV1] = []
        hypotheses: List[ExplanationHypothesisV1] = []
        category = result.predicted_category
        if category == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING:
            gaps.append(ExplanationGapV1(gap_id="GAP-TELEMETRY", statement="Required matching normalized telemetry was not established."))
            hypotheses.append(ExplanationHypothesisV1(hypothesis_id="HYP-PIPELINE", statement="A sensor, collection, or normalization fault may explain the missing telemetry; this is not confirmed by the available evidence."))
        elif category == DiagnosticCategory.DETECTION_NOT_TRIGGERED:
            gaps.append(ExplanationGapV1(gap_id="GAP-ALERT", statement="No reliably correlated alert from the expected detection rule was established."))
            hypotheses.append(ExplanationHypothesisV1(hypothesis_id="HYP-RULE", statement="The detection rule or alert pipeline may not have triggered; the diagnosis does not prove which internal component failed."))
        elif category == DiagnosticCategory.ALERT_NOT_CORRELATED:
            gaps.append(ExplanationGapV1(gap_id="GAP-ATTRIBUTION", statement="An alert was observed, but execution attribution was not sufficient for a PASS."))
        elif category == DiagnosticCategory.INCONCLUSIVE:
            gaps.append(ExplanationGapV1(gap_id="GAP-AMBIGUITY", statement="The evidence is ambiguous or incomplete, so a reliable causal diagnosis was not established."))
        elif category == DiagnosticCategory.ERROR:
            gaps.append(ExplanationGapV1(gap_id="GAP-SYSTEM", statement="The assurance workflow encountered a system, integration, or processing error."))
        summary = self._summary(category, run.execution_status.value, len(events), len(alerts), result.reason)
        source = {
            "diagnostic": result.model_dump(),
            "run": run.model_dump(),
            "scenario": scenario.model_dump(),
            "evidence": evidence,
        }
        explanation = AnalystExplanationV1(
            explanation_id=f"EXPL-{uuid.uuid4().hex[:12].upper()}",
            diagnostic_id=result.diagnostic_id,
            test_run_id=result.test_run_id,
            scenario_id=result.scenario_id,
            deterministic_category=category,
            summary=summary,
            confirmed_facts=facts,
            missing_evidence=gaps,
            hypotheses=hypotheses,
            evidence_references=list(dict.fromkeys(result.supporting_evidence_ids + result.contradictory_evidence_ids + [run.run_id])),
            source_digest=compute_canonical_hash(source),
        )
        explanation.explanation_hash = compute_canonical_hash(explanation.model_dump(exclude={"explanation_hash"}))
        return explanation

    @staticmethod
    def _summary(category: DiagnosticCategory, status: str, event_count: int, alert_count: int, reason: str) -> str:
        if category == DiagnosticCategory.PASS:
            return f"The stored deterministic diagnosis is PASS. {reason} Candidate counts ({event_count} telemetry, {alert_count} alerts) are not causal support; see the diagnostic's supporting evidence IDs."
        return f"Execution status was {status}; the deterministic diagnosis is {category.value}. {reason}"

    @staticmethod
    def verify(explanation: AnalystExplanationV1) -> bool:
        if not explanation.explanation_hash:
            return False
        import secrets
        expected = compute_canonical_hash(explanation.model_dump(exclude={"explanation_hash"}))
        return secrets.compare_digest(explanation.explanation_hash, expected)
