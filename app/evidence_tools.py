"""Adapters shared by specialist agents and triage evidence requests."""
from __future__ import annotations

from app.models import AgentFinding, EvidenceQueryState, EvidenceRef, IncidentInput
from app.telemetry import EvidenceQuery, EvidenceQueryResult, EvidenceSource, EvidenceWindow


def query_evidence(source: EvidenceSource | None, kind: str, incident: IncidentInput,
                   execution_id: str, window: EvidenceWindow | None) -> EvidenceQueryResult | None:
    if source is None:
        return None
    if window is None:
        raise ValueError("A timezone-aware incident evidence window is required")
    return source.query(EvidenceQuery(execution_id=execution_id,
        incident_id=incident.incident_id, service=incident.service,
        source=kind, window=window))


def result_refs(result: EvidenceQueryResult | None) -> list[EvidenceRef]:
    if result is None:
        return []
    return [EvidenceRef(ref=f"telemetry:{record.source}:{record.record_id}",
        source=record.source, excerpt=(record.message + ("; " if record.message else "") +
            ", ".join(f"{key}={str(value).lower() if isinstance(value, bool) else value}"
                      for key, value in record.values.items())) or record.message,
        observed_at=record.observed_at, execution_id=record.execution_id,
        source_id=record.source_id, incident_id=record.incident_id) for record in result.records]


def request_result_finding(result: EvidenceQueryResult) -> AgentFinding:
    source = result.query.source
    agent = ("logs" if source == "logs" else "changes" if source in {"changes", "deployments"}
             else "metrics")
    refs = result_refs(result)
    facts = [f"{ref.observed_at.isoformat()} {ref.source_id}: {ref.excerpt}" for ref in refs]
    if result.status == "available":
        summary = f"Retrieved {len(result.records)} {source} observation(s) from the requested incident window."
    else:
        summary = result.reason or f"The {source} query returned {result.status} evidence."
    return AgentFinding(agent=agent, summary=summary, observed_facts=facts,
        evidence_refs=refs, missing_evidence=list(result.missing_evidence),
        evidence_queries=[EvidenceQueryState(source=source,
            status="retrieved" if result.status == "available" else result.status,
            record_count=len(result.records), missing_evidence=result.missing_evidence,
            reason=result.reason)],
        reasoning_status=("retrieved" if result.status == "available" else result.status))
