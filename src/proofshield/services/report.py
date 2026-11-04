"""Integrity-verifiable reports assembled from stored run evidence."""

from __future__ import annotations

import uuid

from proofshield.schemas.report import RunEvidenceReportV1
from proofshield.services.base_store import StoreProtocol
from proofshield.services.canonical import compute_canonical_hash
from proofshield.services.explanation import EvidenceGroundedExplanationService
from proofshield.services.evidence_snapshot import verify_inputs


class RunReportService:
    def __init__(self, store: StoreProtocol) -> None:
        self.store = store

    def build(self, run_id: str, include_explanation: bool = True) -> RunEvidenceReportV1:
        run = self.store.get_run(run_id)
        if run is None:
            raise ValueError(f"Test run not found: {run_id}")
        scenario = self.store.get_scenario(run.scenario_id)
        if scenario is None:
            raise ValueError(f"Scenario not found: {run.scenario_id}")
        result = self.store.get_result_for_run(run_id)
        if result is None:
            raise ValueError(f"Diagnostic result not found for run: {run_id}")
        events = self.store.get_events_for_run(run)
        alerts = self.store.get_alerts_for_run(run)
        integrity_status, snapshot = verify_inputs(self.store, result)
        explanation_id = None
        explanation = None
        if include_explanation and integrity_status != "FAILED":
            explanation = EvidenceGroundedExplanationService(self.store).explain(result)
            existing = self.store.list_explanations(run_id)
            if existing and existing[-1].source_digest == explanation.source_digest and EvidenceGroundedExplanationService.verify(existing[-1]):
                explanation_id = existing[-1].explanation_id
                explanation = existing[-1]
            else:
                self.store.add_explanation(explanation)
                explanation_id = explanation.explanation_id
        report = RunEvidenceReportV1(
            report_id=f"REPORT-{uuid.uuid4().hex[:12].upper()}",
            run_id=run_id,
            scenario_id=run.scenario_id,
            deterministic_category=result.predicted_category,
            execution_status=run.execution_status.value,
            telemetry_count=len(events),
            alert_count=len(alerts),
            supporting_evidence_ids=result.supporting_evidence_ids,
            contradictory_evidence_ids=result.contradictory_evidence_ids,
            explanation_id=explanation_id,
            integrity_verified=integrity_status == "VERIFIED",
            integrity_status=integrity_status,
            evidence_snapshot=snapshot,
            diagnostic=result.model_dump(mode="json"),
            explanation=explanation.model_dump(mode="json") if explanation else {},
        )
        report.report_hash = compute_canonical_hash(report.model_dump(exclude={"report_hash"}))
        return report

    @staticmethod
    def verify(report: RunEvidenceReportV1) -> bool:
        if not report.report_hash:
            return False
        if report.integrity_status != "VERIFIED" or not report.integrity_verified:
            return False
        import secrets
        if not secrets.compare_digest(report.report_hash, compute_canonical_hash(report.model_dump(exclude={"report_hash"}))):
            return False
        if not report.evidence_snapshot:
            return False
        for item in report.evidence_snapshot.values():
            if not isinstance(item, dict) or item.get("missing") or item.get("hash_error"):
                return False
            if item.get("payload") is None or not item.get("hash"):
                return False
            if item["hash"] != compute_canonical_hash(item["payload"]):
                return False
        return True
