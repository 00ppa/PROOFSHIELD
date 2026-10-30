"""Deterministic Root-Cause Intelligence Service.

Phase 17 implementation providing:
- Structured aggregation of diagnostic failures across campaign scenarios
- Identification of recurring failure patterns (missing telemetry, unlinked alerts, rule misfires)
- Strict segregation of observed empirical facts from inferred explanations
- Non-conjectural evidence tracking to support independent analyst verification
"""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set

from proofshield.schemas.assurance_report import (
    RootCauseIntelligenceV1,
    RootCausePatternV1,
)
from proofshield.schemas.campaign import (
    CampaignRunV1,
    ScenarioCampaignResultV1,
    ScenarioRunStatus,
)
from proofshield.schemas.common import DiagnosticCategory, FailureCategory
from proofshield.services.base_store import StoreProtocol


class RootCauseIntelligenceService:
    """Analyzes and clusters diagnostic failures across campaign executions."""

    def __init__(self, store: StoreProtocol) -> None:
        self.store = store

    def analyze_campaign_run(self, run_id: str) -> RootCauseIntelligenceV1:
        """Produce structured root-cause intelligence for a campaign execution run.

        Raises:
            ValueError: If the campaign run is not found in the store.
        """
        run = self.store.get_campaign_run(run_id)
        if run is None:
            raise ValueError(f"Campaign run not found: {run_id}")

        return self.analyze_scenario_results(run.campaign_id, run.run_id, run.scenario_results)

    def analyze_scenario_results(
        self,
        campaign_id: str,
        campaign_run_id: str,
        scenario_results: List[ScenarioCampaignResultV1],
    ) -> RootCauseIntelligenceV1:
        """Aggregate scenario failures and anomalies into verifiable root-cause patterns."""
        # Filter for non-PASS scenarios
        issue_results = [r for r in scenario_results if r.status != ScenarioRunStatus.PASS]

        # Group scenarios by (DiagnosticCategory, FailureCategory)
        groups: Dict[tuple, List[ScenarioCampaignResultV1]] = defaultdict(list)
        for r in issue_results:
            cat = r.predicted_category or DiagnosticCategory.INCONCLUSIVE
            f_cat = r.failure_category
            groups[(cat, f_cat)].append(r)

        patterns: List[RootCausePatternV1] = []
        pattern_seq = 1

        for (cat, f_cat), items in sorted(groups.items(), key=lambda x: (x[0][0].value, str(x[0][1]), len(x[1]))):
            affected_ids = sorted([item.scenario_id for item in items])
            affected_count = len(affected_ids)

            evidence_ids: List[str] = []
            for item in items:
                evidence_ids.extend(item.supporting_evidence_ids)
                evidence_ids.extend(item.contradictory_evidence_ids)
            unique_evidence_ids = sorted(list(set(evidence_ids)))[:10]

            observed_facts: List[str] = []
            inferred_explanations: List[str] = []
            common_evidence_gaps: List[str] = []
            confidence = "definitive"

            # Formulate pattern specifics based on diagnostic category
            if cat == DiagnosticCategory.EXPECTED_TELEMETRY_MISSING:
                common_evidence_gaps.append("Missing expected endpoint event stream within test time window")
                observed_facts.append(
                    f"{affected_count} scenario(s) had test runs completed, but expected telemetry events matching scenario criteria were not found in store."
                )
                inferred_explanations.append(
                    "Potential causes include: EDR sensor uninstalled or stopped, audit policy disabled on target, or network drop between agent and ingest."
                )
                confidence = "definitive"

            elif cat == DiagnosticCategory.DETECTION_NOT_TRIGGERED:
                common_evidence_gaps.append("Alert missing from SIEM/EDR detection rule evaluation")
                observed_facts.append(
                    f"{affected_count} scenario(s) generated verified endpoint telemetry, but the configured detection rule did not emit an alert."
                )
                inferred_explanations.append(
                    "Potential causes include: Detection rule logic syntax mismatch, rule suppressed by tuning exclusion, or alert pipeline ingestion delay exceeding test window."
                )
                confidence = "definitive"

            elif cat == DiagnosticCategory.ALERT_NOT_CORRELATED:
                common_evidence_gaps.append("Alert temporal window or hostname mismatch")
                observed_facts.append(
                    f"{affected_count} scenario(s) had alerts matching the detection rule, but the alerts occurred outside the execution time window or on a mismatched host."
                )
                inferred_explanations.append(
                    "Potential causes include: Clock skew between sensor and analysis server, asynchronous pipeline buffering, or host identifier resolution failure (e.g. NetBIOS vs FQDN)."
                )
                confidence = "likely"

            elif cat == DiagnosticCategory.INCONCLUSIVE:
                common_evidence_gaps.append("Ambiguous or contradictory evidence records")
                observed_facts.append(
                    f"{affected_count} scenario(s) produced inconclusive outcomes due to missing discriminatory signatures or ambiguous candidates."
                )
                inferred_explanations.append(
                    "Potential causes include: Test scenario lacks distinctive command-line regex, or multiple overlapping test runs executed concurrently without execution token isolation."
                )
                confidence = "uncertain"

            elif cat == DiagnosticCategory.TEST_NOT_EXECUTED:
                common_evidence_gaps.append("No active test run recorded")
                observed_facts.append(
                    f"{affected_count} scenario(s) declared in campaign definition had no matching TestRunV1 record or were skipped by execution policy."
                )
                inferred_explanations.append(
                    "Potential causes include: Scenario runner failed prior to payload execution, or harness orchestrator skipped scenario."
                )
                confidence = "definitive"

            elif cat == DiagnosticCategory.ERROR:
                observed_facts.append(
                    f"{affected_count} scenario(s) halted due to evaluation or entity configuration error."
                )
                for item in items[:3]:
                    if item.error_message:
                        observed_facts.append(f"Scenario '{item.scenario_id}' error: {item.error_message}")
                inferred_explanations.append(
                    "Potential causes include: Missing scenario reference, invalid schema payload, or internal store error."
                )
                confidence = "definitive"

            else:
                observed_facts.append(
                    f"{affected_count} scenario(s) evaluated with diagnostic category '{cat.value}'."
                )
                confidence = "likely"

            # Deterministic Pattern ID
            pat_code = cat.value.replace("_", "-")
            pat_id = f"PAT-{pat_code}-{pattern_seq:02d}"
            pattern_seq += 1

            patterns.append(
                RootCausePatternV1(
                    pattern_id=pat_id,
                    diagnostic_category=cat,
                    failure_category=f_cat,
                    affected_scenario_count=affected_count,
                    affected_scenarios=affected_ids,
                    common_evidence_gaps=common_evidence_gaps,
                    supporting_evidence_ids=unique_evidence_ids,
                    observed_facts=observed_facts,
                    inferred_explanations=inferred_explanations,
                    confidence=confidence,
                )
            )

        return RootCauseIntelligenceV1(
            schema_version="v1",
            campaign_id=campaign_id,
            campaign_run_id=campaign_run_id,
            total_issues_analyzed=len(issue_results),
            patterns=patterns,
            generated_at=datetime.now(timezone.utc),
        )

