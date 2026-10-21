"""Log evidence retrieval is deterministic; interpretation is LLM-driven."""
from app.incident_tools import retrieve_logs
from app.agents.context import compact_findings, compact_telemetry_records, compact_evidence_refs, compact_incident
from app.evidence_tools import query_evidence, result_refs
from app.llm import invoke_structured
from app.models import (AgentFinding, EvidenceQueryState, IncidentInput, LogAnalysis,
                        LogInvestigationInput, SpecialistReasoning)
from app.telemetry import EvidenceSource, EvidenceWindow


def investigate_logs(incident: IncidentInput, question: str = "Investigate supplied logs",
                     prior_findings: list[AgentFinding] | None = None, *,
                     evidence_source: EvidenceSource | None = None,
                     evidence_window: EvidenceWindow | None = None,
                     execution_id: str = "offline") -> LogAnalysis:
    request = LogInvestigationInput(incident=incident, question=question,
                                    prior_findings=prior_findings or [])
    incident = request.incident
    records = retrieve_logs(incident, question)
    query_result = query_evidence(evidence_source, "logs", incident, execution_id, evidence_window)
    telemetry_refs = result_refs(query_result)
    records.extend(telemetry_refs)
    telemetry_context = ({"status": query_result.status, "reason": query_result.reason,
        "missing_evidence": query_result.missing_evidence,
        "observations": compact_telemetry_records(query_result.records)}
        if query_result else None)
    reasoning = invoke_structured(
        "You investigate supplied log records. Distinguish observed facts from hypotheses. Cite only the provided refs; do not invent timestamps, queries, records, or external access. Consider whether coverage is sufficient and what evidence would change the conclusion.",
        f"Question: {request.question[:300]}\nIncident: {compact_incident(incident)}\nPrior findings: {compact_findings(prior_findings or [])}\nRecords: {compact_evidence_refs(records)}\nTelemetry query: {telemetry_context}",
        SpecialistReasoning)
    allowed = {r.ref for r in records}
    hypotheses = [h.model_copy(update={"supporting_refs": [x for x in h.supporting_refs if x in allowed],
                                       "contradicting_refs": [x for x in h.contradicting_refs if x in allowed]})
                  for h in reasoning.hypotheses]
    return LogAnalysis(summary=reasoning.summary, observed_facts=[r.excerpt for r in records],
        hypotheses=hypotheses, evidence_refs=records, uncertainty=reasoning.contradictions,
        missing_evidence=reasoning.missing_evidence + (query_result.missing_evidence if query_result else []),
        evidence_queries=([EvidenceQueryState(source=query_result.query.source,
            status="retrieved" if query_result.status == "available" else query_result.status,
            record_count=len(query_result.records),
            missing_evidence=query_result.missing_evidence, reason=query_result.reason)]
            if query_result else []),
        follow_up=reasoning.follow_up,
        timestamps=[r.observed_at.isoformat() for r in records if r.observed_at])
