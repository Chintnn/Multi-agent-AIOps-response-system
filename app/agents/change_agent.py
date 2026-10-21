"""Change candidates come from supplied history; the LLM evaluates relevance."""
from app.incident_tools import retrieve_changes
from app.agents.context import compact_findings, compact_telemetry_records, compact_evidence_refs, compact_incident
from app.evidence_tools import query_evidence, result_refs
from app.llm import invoke_structured
from app.models import (AgentFinding, ChangeAnalysis, ChangeInvestigationInput, EvidenceQueryState,
                        IncidentInput, SpecialistReasoning)
from app.telemetry import EvidenceSource, EvidenceWindow


def analyze_change(incident: IncidentInput, question: str = "Assess recent changes",
                   prior_findings: list[AgentFinding] | None = None, *,
                   evidence_source: EvidenceSource | None = None,
                   evidence_window: EvidenceWindow | None = None,
                   execution_id: str = "offline") -> ChangeAnalysis:
    request = ChangeInvestigationInput(incident=incident, question=question,
                                      prior_findings=prior_findings or [])
    incident = request.incident
    candidates = retrieve_changes(incident)
    query_results = [query_evidence(evidence_source, source, incident, execution_id, evidence_window)
                     for source in ("changes", "deployments")]
    query_results = [result for result in query_results if result is not None]
    telemetry_refs = [ref for result in query_results for ref in result_refs(result)]
    candidates.extend(telemetry_refs)
    telemetry_context = [{"source": result.query.source, "status": result.status,
        "reason": result.reason, "missing_evidence": result.missing_evidence,
        "observations": compact_telemetry_records(result.records)}
        for result in query_results]
    reasoning = invoke_structured(
        "Analyze only the supplied change records and incident evidence. Assess temporal and technical relevance without asserting causality from proximity. Compare alternatives, cite only supplied references, and state evidence gaps.",
        f"Question: {request.question[:300]}\nIncident: {compact_incident(incident)}\nPrior findings: {compact_findings(prior_findings or [])}\nCandidate changes: {compact_evidence_refs(candidates)}\nTelemetry query results: {telemetry_context}",
        SpecialistReasoning)
    allowed = {r.ref for r in candidates}
    hypotheses = [h.model_copy(update={"supporting_refs": [x for x in h.supporting_refs if x in allowed],
                                       "contradicting_refs": [x for x in h.contradicting_refs if x in allowed]})
                  for h in reasoning.hypotheses]
    return ChangeAnalysis(summary=reasoning.summary,
        observed_facts=[r.excerpt for r in candidates], hypotheses=hypotheses,
        evidence_refs=candidates, uncertainty=reasoning.contradictions,
        missing_evidence=reasoning.missing_evidence + [gap for result in query_results
            for gap in result.missing_evidence], follow_up=reasoning.follow_up,
        evidence_queries=[EvidenceQueryState(source=result.query.source,
            status="retrieved" if result.status == "available" else result.status,
            record_count=len(result.records), missing_evidence=result.missing_evidence,
            reason=result.reason) for result in query_results],
        candidate_changes=[r.excerpt for r in candidates],
        )
