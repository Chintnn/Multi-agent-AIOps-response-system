"""LLM-driven incident interpretation and next-investigation planning."""
from app.llm import invoke_structured
from app.agents.context import compact_findings, compact_incident
from app.models import (AgentFinding, IncidentInput, TRIAGE_ACTION_VALUES,
                        TriageDecision, TriageInput)


AlertTriageResult = TriageDecision


def investigate_alert(incident: IncidentInput, findings: list[AgentFinding] | None = None,
                     history: list[str] | None = None, outstanding: list[str] | None = None) -> TriageDecision:
    request = TriageInput(incident=incident, prior_findings=findings or [],
        investigation_history=history or [], outstanding_questions=outstanding or [])
    context = request.model_dump(mode="json")
    context["incident"] = compact_incident(incident)
    specialist_findings = [finding for finding in (findings or []) if finding.agent != "triage"]
    prior_triage = next((finding for finding in reversed(findings or [])
                         if finding.agent == "triage"), None)
    context["prior_findings"] = compact_findings(specialist_findings)
    context["investigation_history"] = request.investigation_history[-6:]
    context["outstanding_questions"] = [item[:140] for item in request.outstanding_questions[:8]]
    source_status = {name: {"source": name, "status": "not_requested", "record_count": 0}
        for name in ("logs", "metrics", "traffic", "database_health", "changes", "deployments")}
    context["evidence_source_status"] = {
        **source_status,
        **{query.source: query.model_dump(mode="json")
        for finding in specialist_findings for query in finding.evidence_queries
        }
    }
    context["prior_triage_assessment"] = ({
        "summary": prior_triage.summary[:280],
        "hypotheses": [{"statement": h.statement[:150], "rationale": h.rationale[:180]}
                       for h in prior_triage.hypotheses[:2]],
    } if prior_triage else None)
    specialists = {"logs", "metrics", "changes"}
    attempted = sorted({item.split(":", 1)[0] for item in request.investigation_history
                        if item.split(":", 1)[0] in specialists})
    unrun = sorted(specialists - set(attempted))
    route_context = ""
    if attempted:
        route_context = (f" Specialist attempts already recorded: {attempted}. "
                         f"Specialists not yet attempted: {unrun}. "
                         "Choose an unrun specialist unless new independent evidence justifies reviewing a previous one.")
    return invoke_structured(
        "You are the incident triage and planning agent. Assess only supplied facts. Preserve competing hypotheses; never infer causality from timing alone. Select the single most useful next agent based on all prior findings. Prefer an unrun specialist while investigation budget remains. Do not request the same specialist again unless another specialist has added new evidence since its previous run. Return assessment, hypotheses, evidence_gaps, next_agent, investigation_question, expected_information_gain, confidence, decision_rationale, and evidence_requests. Each evidence request must name one source from logs, metrics, traffic, database_health, changes, deployments and explain the specific gap it addresses; the workflow will query it over the active incident window. Request sources only when the evidence interface may collect the missing data; if no source is available, use more_information with an explicit gap. Reconcile prior evidence_source_status and evidence query findings: available/retrieved evidence is not missing, but do not call it analyzed until its specialist has interpreted it. Keep unresolved causal uncertainty separate from source availability. The next_agent value must be exactly one of these values, with identical spelling: " + ", ".join(TRIAGE_ACTION_VALUES) + ". Do not use synonyms, past tense, prose, or any other value. Confidence must be low, moderate, or high. Use remediation only when evidence is sufficient; otherwise investigate or escalate. Keep narrative fields concise, return no more than two competing hypotheses and five evidence gaps, and include empty lists where no entries apply. Confidence is qualitative, not a calibrated probability." + route_context,
        "Plan the next step and return the required structured decision. Context:\n" + str(context),
        TriageDecision)


def triage_finding(decision: TriageDecision) -> AgentFinding:
    return AgentFinding(agent="triage", summary=decision.assessment,
        hypotheses=decision.hypotheses, uncertainty=decision.evidence_gaps,
        missing_evidence=decision.evidence_gaps,
        follow_up=f"{decision.next_agent}: {decision.investigation_question}")
