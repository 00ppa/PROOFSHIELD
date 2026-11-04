from proofshield.services.assurance_report import (
    CampaignAssuranceReportGenerator,
    compute_assurance_report_digest,
)
from proofshield.services.base_store import StoreProtocol
from proofshield.services.evaluation import AssuranceEngine
from proofshield.services.explanation import EvidenceGroundedExplanationService
from proofshield.services.regression_analyzer import (
    CampaignRegressionAnalyzer,
    compute_regression_analysis_digest,
)
from proofshield.services.report import RunReportService
from proofshield.services.root_cause import RootCauseIntelligenceService
from proofshield.services.sqlite_store import SQLiteStore
from proofshield.services.store import InMemoryStore, close_store, get_store, reset_store, set_store

__all__ = [
    "AssuranceEngine",
    "CampaignAssuranceReportGenerator",
    "CampaignRegressionAnalyzer",
    "ElasticAssuranceOrchestrator",
    "ElasticOrchestrationReport",
    "ElasticOrchestrator",
    "ElasticOrchestratorSettings",
    "EvidenceGroundedExplanationService",
    "InMemoryStore",
    "NormalizationStatus",
    "RootCauseIntelligenceService",
    "RunReportService",
    "SQLiteStore",
    "StoreProtocol",
    "SplunkAssuranceOrchestrator",
    "SplunkNormalizationStatus",
    "SplunkOrchestrationReport",
    "SplunkOrchestrator",
    "SplunkOrchestratorSettings",
    "close_store",
    "compute_assurance_report_digest",
    "compute_regression_analysis_digest",
    "get_store",
    "reset_store",
    "set_store",
]


def __getattr__(name):
    """Load connector orchestrators lazily to keep package imports acyclic."""
    if name in {
        "ElasticAssuranceOrchestrator",
        "ElasticOrchestrationReport",
        "ElasticOrchestrator",
        "ElasticOrchestratorSettings",
        "NormalizationStatus",
    }:
        from proofshield.services import elastic_orchestrator

        return getattr(elastic_orchestrator, name)
    if name in {
        "SplunkAssuranceOrchestrator",
        "SplunkNormalizationStatus",
        "SplunkOrchestrationReport",
        "SplunkOrchestrator",
        "SplunkOrchestratorSettings",
    }:
        from proofshield.services import splunk_orchestrator

        return getattr(splunk_orchestrator, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
