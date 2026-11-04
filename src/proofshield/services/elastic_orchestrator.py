"""Elastic Assurance Orchestrator for PROOFSHIELD.

Bridges Elasticsearch telemetry and alert ingestion with ProofShield storage,
normalization, and deterministic evaluation engines.

Coordinates bounded query retrieval, idempotent persistence, deterministic
ECS normalization, and explicit evidence failure state isolation.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import uuid

from pydantic import Field

from proofshield.connectors.elastic import (
    ElasticAlertClient,
    ElasticClientError,
    ElasticTelemetryBatch,
    TelemetryRetrievalStatus,
)
from proofshield.normalisation.engine import NormalisationEngine
from proofshield.schemas.alert import AlertV1
from proofshield.schemas.common import (
    AttributionStatus,
    DiagnosticCategory,
    FailureCategory,
    ProofshieldBaseModel,
)
from proofshield.schemas.diagnosis import DiagnosticResultV1
from proofshield.schemas.telemetry import (
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
)
from proofshield.services.base_store import StoreProtocol, to_comparable_utc
from proofshield.services.evaluation import AssuranceEngine


class NormalizationStatus(str, Enum):
    """Outcome status for telemetry normalization."""
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    EMPTY = "EMPTY"
    SKIPPED = "SKIPPED"


class ElasticOrchestratorSettings(ProofshieldBaseModel):
    """Configuration settings for the Elastic Assurance Orchestrator."""
    telemetry_buffer_seconds: float = 30.0
    alert_grace_period_seconds: float = 60.0
    alert_settling_delay_seconds: float = 0.0
    alert_settling_poll_interval_seconds: float = 1.0
    alert_settling_max_polls: int = 1
    max_telemetry_results: int = 1000
    max_alert_results: int = 500
    raise_on_truncation: bool = False
    batch_size: int = 100
    max_retries: int = 2


class ElasticOrchestrationReport(ProofshieldBaseModel):
    """Execution report capturing evidence retrieval and persistence metrics."""
    orchestration_id: str
    campaign_id: Optional[str] = None
    test_run_id: Optional[str] = None
    telemetry_status: TelemetryRetrievalStatus = TelemetryRetrievalStatus.EMPTY
    alerts_status: str = "EMPTY"  # COMPLETE, EMPTY, TRUNCATED, FAILED
    normalization_status: NormalizationStatus = NormalizationStatus.EMPTY
    normalization_errors: List[str] = Field(default_factory=list)
    raw_telemetry_persisted: int = 0
    normalized_telemetry_persisted: int = 0
    alerts_persisted: int = 0
    duplicate_raw_count: int = 0
    duplicate_alert_count: int = 0
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    errors: List[str] = Field(default_factory=list)
    is_complete: bool = True


class ElasticAssuranceOrchestrator:
    """Orchestrates evidence collection, normalization, and evaluation from Elastic.

    Guarantees:
    - Never converts Elasticsearch connection, authentication, or query errors
      into false PASS or silent EXPECTED_TELEMETRY_MISSING verdicts.
    - Idempotently persists both raw and normalized telemetry to maintain evidence trail.
    - Preserves uncertainty and flags truncation if query window limits are reached.
    - Bridges cleanly to AssuranceEngine for downstream root-cause diagnosis.
    """

    source_name = "Elasticsearch"

    def __init__(
        self,
        client: ElasticAlertClient,
        store: StoreProtocol,
        normaliser: Optional[NormalisationEngine] = None,
        assurance_engine: Optional[AssuranceEngine] = None,
        settings: Optional[ElasticOrchestratorSettings] = None,
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> None:
        self.client = client
        self.store = store
        self.normaliser = normaliser or NormalisationEngine()
        self.assurance_engine = assurance_engine or AssuranceEngine(store=store)
        self.settings = settings or ElasticOrchestratorSettings()
        self.sleep_fn: Callable[[float], None] = sleep_fn if sleep_fn is not None else time.sleep

    def ingest_for_run(
        self,
        run_id: str,
        fetch_telemetry: bool = True,
        fetch_alerts: bool = True,
        normalize_telemetry: bool = True,
    ) -> ElasticOrchestrationReport:
        """Poll Elasticsearch for telemetry and alerts relevant to a test run and ingest them.

        Computes query window based on run.started_at, run.completed_at, and configured
        telemetry and alert buffer times.
        """
        run = self.store.get_run(run_id)
        if run is None:
            raise ValueError(f"Cannot orchestrate ingestion for non-existent test run: {run_id}")

        scenario = self.store.get_scenario(run.scenario_id) if run.scenario_id else None

        # Derive query window from run timestamps
        run_start = to_comparable_utc(getattr(run, "window_start", getattr(run, "started_at", None)))
        run_end = to_comparable_utc(getattr(run, "window_end", getattr(run, "completed_at", None)))

        tel_start = run_start - timedelta(seconds=self.settings.telemetry_buffer_seconds)
        tel_end = run_end + timedelta(seconds=self.settings.telemetry_buffer_seconds)

        alert_start = run_start
        alert_end = run_end + timedelta(seconds=self.settings.alert_grace_period_seconds)

        host = getattr(run, "target_host", getattr(run, "host_id", None))
        rule_id = getattr(scenario, "expected_detection_rule_id", None) or getattr(scenario, "expected_rule_reference", None)
        rule_ids = [rule_id] if rule_id else None

        report = ElasticOrchestrationReport(
            orchestration_id=f"ORCH-{uuid.uuid4().hex[:12].upper()}",
            test_run_id=run_id,
            window_start=tel_start,
            window_end=max(tel_end, alert_end),
        )

        # 1. Ingest Telemetry
        if fetch_telemetry:
            self._ingest_telemetry_bounded(
                report=report,
                start_time=tel_start,
                end_time=tel_end,
                host=host,
                normalize_telemetry=normalize_telemetry,
            )

        # 2. Ingest Alerts
        if fetch_alerts:
            self._ingest_alerts_bounded(
                report=report,
                start_time=alert_start,
                end_time=alert_end,
                host=host,
                rule_ids=rule_ids,
            )

        return report

    def ingest_campaign_evidence(
        self,
        campaign_id: str,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        hosts: Optional[Sequence[str]] = None,
        rule_ids: Optional[Sequence[str]] = None,
        fetch_telemetry: bool = True,
        fetch_alerts: bool = True,
        normalize_telemetry: bool = True,
    ) -> ElasticOrchestrationReport:
        """Poll Elasticsearch for evidence across an entire campaign or multi-host window."""
        report = ElasticOrchestrationReport(
            orchestration_id=f"ORCH-CAMP-{uuid.uuid4().hex[:12].upper()}",
            campaign_id=campaign_id,
            window_start=window_start,
            window_end=window_end,
        )

        host_target = hosts[0] if (hosts and len(hosts) == 1) else None

        if fetch_telemetry:
            self._ingest_telemetry_bounded(
                report=report,
                start_time=window_start,
                end_time=window_end,
                host=host_target,
                normalize_telemetry=normalize_telemetry,
            )

        if fetch_alerts:
            self._ingest_alerts_bounded(
                report=report,
                start_time=window_start,
                end_time=window_end,
                host=host_target,
                rule_ids=rule_ids,
            )

        return report

    def evaluate_run_with_orchestration(
        self,
        run_id: str,
        strict_attribution: Optional[bool] = None,
        fetch_telemetry: bool = True,
        fetch_alerts: bool = True,
    ) -> Tuple[DiagnosticResultV1, ElasticOrchestrationReport]:
        """Orchestrate ingestion and immediately run deterministic diagnostic evaluation.

        If Elasticsearch evidence retrieval failed, creates a protective diagnostic result
        with DiagnosticCategory.ERROR and does not perform false inference.
        """
        report = self.ingest_for_run(
            run_id=run_id,
            fetch_telemetry=fetch_telemetry,
            fetch_alerts=fetch_alerts,
            normalize_telemetry=True,
        )

        run = self.store.get_run(run_id)
        scenario_id = run.scenario_id if run else "UNKNOWN"

        # If evidence retrieval failed or normalization failed/partial, do not produce false verdict
        if (
            not report.is_complete
            or report.telemetry_status == TelemetryRetrievalStatus.FAILED
            or report.normalization_status in (NormalizationStatus.FAILED, NormalizationStatus.PARTIAL)
        ):
            err_msg = "; ".join(report.errors) if report.errors else f"{self.source_name} evidence retrieval failed"
            result = DiagnosticResultV1(
                schema_version="v1",
                diagnostic_id=f"DIAG-ERR-{uuid.uuid4().hex[:12].upper()}",
                test_run_id=run_id,
                scenario_id=scenario_id,
                predicted_category=DiagnosticCategory.ERROR,
                failure_category=FailureCategory.UNSPECIFIED,
                confidence="uncertain",
                reason=f"Evidence collection failed from {self.source_name}: {err_msg}",
                diagnostic_reasons=report.errors,
                evaluated_at=datetime.now(timezone.utc),
                metadata={
                    "attribution": {
                        "status": AttributionStatus.INCONCLUSIVE.value,
                        "strict_attribution": strict_attribution,
                        "retrieval_error": err_msg,
                        "normalization_status": report.normalization_status.value,
                    }
                },
            )
            from proofshield.services.evidence_snapshot import persist_diagnosis
            persist_diagnosis(self.store, result, report)
            return result, report

        # Retrieval succeeded, run deterministic evaluation
        from proofshield.services.evidence_snapshot import persist_diagnosis
        with self.store.transaction():
            eval_result = self.assurance_engine.evaluate_run(run_id=run_id, strict_attribution=strict_attribution,
                                                           collection_report=report.model_dump(mode="json"))
            persist_diagnosis(self.store, eval_result, report)
        return eval_result, report

    def _ingest_telemetry_bounded(
        self,
        report: ElasticOrchestrationReport,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        host: Optional[str],
        normalize_telemetry: bool,
    ) -> None:
        """Internal helper to retrieve and persist raw & normalized telemetry."""
        try:
            batch: ElasticTelemetryBatch = self.client.search_telemetry(
                start_time=start_time,
                end_time=end_time,
                host=host,
                limit=self.settings.max_telemetry_results,
                raise_on_truncation=self.settings.raise_on_truncation,
                batch_size=self.settings.batch_size,
                max_retries=self.settings.max_retries,
            )
            report.telemetry_status = batch.status

            if batch.is_truncated:
                report.is_complete = False
                report.errors.append(
                    f"Telemetry query truncated: {batch.total_matched} total events matched "
                    f"but retrieval limit was {len(batch.hits)}"
                )

            if not batch.hits:
                if not normalize_telemetry:
                    report.normalization_status = NormalizationStatus.SKIPPED
                else:
                    report.normalization_status = NormalizationStatus.EMPTY
                return

            raw_events = self.client.map_hits_to_raw_telemetry(batch.hits)
            from proofshield.services.canonical import compute_canonical_hash
            for raw_ev in raw_events:
                compute_canonical_hash(raw_ev)
            raw_persisted = 0
            raw_dups = 0

            norm_events_to_persist: List[NormalizedTelemetryEventV1] = []
            norm_successes = 0
            norm_failures = 0

            for raw_ev in raw_events:
                existing = self.store.get_raw_event(raw_ev.raw_event_id)
                if existing is not None:
                    if existing.raw_payload != raw_ev.raw_payload or existing.source_timestamp != raw_ev.source_timestamp:
                        raise ValueError("Conflicting contents for an existing raw evidence identifier")
                    raw_dups += 1
                    raw_ev = existing
                else:
                    self.store.add_raw_event(raw_ev)
                    raw_persisted += 1

                if normalize_telemetry:
                    try:
                        previous = next((item for item in self.store.list_normalized_events()
                                         if item.raw_event_id == raw_ev.raw_event_id), None) if existing is not None else None
                        norm_ev = previous or self.normaliser.normalize(raw_ev)
                        norm_events_to_persist.append(norm_ev)
                        norm_successes += 1
                    except Exception as n_err:
                        norm_failures += 1
                        err_str = f"Normalisation error for raw event {raw_ev.raw_event_id}: {n_err}"
                        report.errors.append(err_str)
                        report.normalization_errors.append(err_str)

            report.raw_telemetry_persisted += raw_persisted
            report.duplicate_raw_count += raw_dups

            # Determine normalization status
            if not normalize_telemetry:
                report.normalization_status = NormalizationStatus.SKIPPED
            elif norm_failures > 0 and norm_successes == 0:
                report.normalization_status = NormalizationStatus.FAILED
                report.is_complete = False
            elif norm_failures > 0 and norm_successes > 0:
                report.normalization_status = NormalizationStatus.PARTIAL
                report.is_complete = False
            elif norm_successes > 0:
                report.normalization_status = NormalizationStatus.COMPLETE
            else:
                report.normalization_status = NormalizationStatus.EMPTY

            norm_persisted = 0
            for norm_ev in norm_events_to_persist:
                compute_canonical_hash(norm_ev)
                existing_norm = self.store.get_normalized_event(norm_ev.normalized_event_id)
                if existing_norm is None:
                    self.store.add_normalized_event(norm_ev)
                    norm_persisted += 1

            report.normalized_telemetry_persisted += norm_persisted

        except ElasticClientError as exc:
            report.telemetry_status = TelemetryRetrievalStatus.FAILED
            report.is_complete = False
            report.normalization_status = NormalizationStatus.FAILED if normalize_telemetry else NormalizationStatus.SKIPPED
            report.errors.append(f"Telemetry retrieval failed: {exc}")
        except Exception as exc:
            report.telemetry_status = TelemetryRetrievalStatus.FAILED
            report.is_complete = False
            report.normalization_status = NormalizationStatus.FAILED if normalize_telemetry else NormalizationStatus.SKIPPED
            report.errors.append(f"Unexpected error during telemetry ingestion: {exc}")

    def _ingest_alerts_bounded(
        self,
        report: ElasticOrchestrationReport,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        host: Optional[str],
        rule_ids: Optional[Sequence[str]],
    ) -> None:
        """Internal helper to retrieve and persist alerts with bounded settling policy."""
        # Initial settling pause before the first poll
        if self.settings.alert_settling_delay_seconds > 0:
            self.sleep_fn(self.settings.alert_settling_delay_seconds)

        max_polls = max(1, self.settings.alert_settling_max_polls)
        for poll_idx in range(max_polls):
            try:
                alerts = self.client.fetch_and_map_alerts(
                    start_time=start_time,
                    end_time=end_time,
                    host=host,
                    rule_ids=rule_ids,
                    limit=self.settings.max_alert_results,
                    deduplicate=True,
                    raise_on_truncation=self.settings.raise_on_truncation,
                    batch_size=self.settings.batch_size,
                )
                from proofshield.services.canonical import compute_canonical_hash
                for alert in alerts:
                    compute_canonical_hash(alert)

                if self.client.last_search_truncated:
                    report.alerts_status = "TRUNCATED"
                    report.is_complete = False
                    report.errors.append(
                        f"Alert search truncated: {self.client.last_search_total} total alerts matched"
                    )
                else:
                    report.alerts_status = "COMPLETE" if alerts else "EMPTY"

                alert_persisted = 0
                alert_dups = 0

                for alert in alerts:
                    existing = self.store.get_alert(alert.alert_id)
                    if existing is not None:
                        if existing.model_dump(exclude={"ingested_at"}) != alert.model_dump(exclude={"ingested_at"}):
                            raise ValueError("Conflicting contents for an existing alert identifier")
                        alert_dups += 1
                    else:
                        self.store.add_alert(alert)
                        alert_persisted += 1

                report.alerts_persisted += alert_persisted
                report.duplicate_alert_count += alert_dups

                # If alerts were found, settling is complete
                if alerts:
                    return

                # If no alerts found and more polls remain, wait and poll again
                if poll_idx < max_polls - 1:
                    if self.settings.alert_settling_poll_interval_seconds > 0:
                        self.sleep_fn(self.settings.alert_settling_poll_interval_seconds)

            except ElasticClientError as exc:
                status_code = getattr(exc, "status_code", None)
                is_auth_error = status_code in (401, 403) or "401" in str(exc) or "403" in str(exc)
                if is_auth_error or poll_idx == max_polls - 1:
                    report.alerts_status = "FAILED"
                    report.is_complete = False
                    report.errors.append(f"Alert retrieval failed: {exc}")
                    break
                # Transient error before final poll; wait and retry
                if self.settings.alert_settling_poll_interval_seconds > 0:
                    self.sleep_fn(self.settings.alert_settling_poll_interval_seconds)
            except Exception as exc:
                report.alerts_status = "FAILED"
                report.is_complete = False
                report.errors.append(f"Unexpected error during alert ingestion: {exc}")
                break


# Alias
ElasticOrchestrator = ElasticAssuranceOrchestrator
