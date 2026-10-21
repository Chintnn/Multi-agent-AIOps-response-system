"""Adaptive incident workflow with LangGraph transitions and an offline runner."""
from __future__ import annotations

import os
from pathlib import Path
from typing import TypedDict
from uuid import uuid4

from app.agents.alert_agent import investigate_alert, triage_finding
from app.agents.change_agent import analyze_change
from app.agents.log_agent import investigate_logs
from app.agents.metrics_agent import investigate_metrics
from app.agents.remediation_agent import execute_remediation, propose_remediation, verify_recovery
from app.evidence_tools import query_evidence, request_result_finding
from app.llm import (ProviderUnavailable, clear_last_call_metadata,
                     get_last_call_metadata)
from app.models import (AgentFinding, AgentRequest, ApprovalRecord, IncidentInput,
                        EvidenceQueryState, IncidentReport, IncidentState, TraceEvent, TriageDecision,
                        RemediationProposal, RecoveryResult, Hypothesis)
from app.incident_tools import retrieve_changes, retrieve_logs
from app.telemetry import EvidenceSource, EvidenceWindow

MAX_INVESTIGATIONS = 4
SPECIALISTS = {"logs", "metrics", "changes"}
EVIDENCE_SOURCES = ("logs", "metrics", "traffic", "database_health", "changes", "deployments")


class GraphState(TypedDict):
    incident: IncidentInput
    execution_id: str
    status: str
    current_plan: TriageDecision | None
    findings: list[AgentFinding]
    hypotheses: list[Hypothesis]
    investigation_history: list[str]
    evidence_at_last_invocation: dict[str, int]
    handoffs: list[AgentRequest]
    errors: list[str]
    outstanding_questions: list[str]
    budget: int
    remediation: RemediationProposal | None
    approval: ApprovalRecord | None
    simulated_execution: dict | None
    recovery: RecoveryResult | None
    trace: list[TraceEvent]
    report: IncidentReport | None
    post_action_metrics: dict[str, float] | None
    evidence_source: EvidenceSource | None
    evidence_window: EvidenceWindow | None
    evidence_requests_attempted: bool
    evidence_source_status: dict[str, EvidenceQueryState]


_EVIDENCE_GAP_ALIASES = {
    "logs": ("logs", "log records", "error logs", "timestamped logs"),
    "metrics": ("metrics", "metric", "latency", "cpu", "pool utilization"),
    "traffic": ("traffic", "request volume", "request count", "request history"),
    "database_health": ("database health", "db health", "health checks", "database connections"),
    "deployments": ("deployment", "deployments", "deployment history", "deployment timestamp"),
    "changes": ("recent changes", "code change", "code changes", "change list",
                "configuration change"),
}


def _source_in_gap(gap: str) -> str | None:
    normalized = " ".join(gap.casefold().replace("_", " ").replace("-", " ").split())
    if any(term in normalized for term in ("cause", "causal", "causality", "correlat", "bottleneck", "root cause", "post action")):
        return None
    for source, aliases in _EVIDENCE_GAP_ALIASES.items():
        if any(alias in normalized for alias in aliases):
            return source
    return None


def _reconcile_evidence_gaps(gaps: list[str], statuses: dict[str, EvidenceQueryState]) -> list[str]:
    """Update source-availability gaps without treating fetched evidence as analyzed."""
    reconciled: list[str] = []
    for gap in gaps:
        source = _source_in_gap(gap)
        state = statuses.get(source) if source else None
        if state is None:
            reconciled.append(gap)
        elif state.status == "analyzed":
            continue
        elif state.status == "retrieved":
            reconciled.append(f"{source} evidence was retrieved; specialist analysis is pending.")
        elif state.status == "pending":
            reconciled.append(f"{source} evidence request is pending.")
        elif state.status == "unavailable":
            reconciled.append(f"{source} evidence source is unavailable: {state.reason or 'no provider configured'}.")
        elif state.status == "insufficient":
            reconciled.append(f"{source} source returned insufficient evidence: {state.reason or 'no matching observations'}.")
        else:
            reconciled.append(f"{source} evidence has not been requested yet.")
    return list(dict.fromkeys(reconciled))


def _event(state: dict, kind: str, agent: str | None = None, **details) -> list[TraceEvent]:
    return list(state.get("trace", [])) + [TraceEvent(execution_id=state["execution_id"],
        event_type=kind, agent=agent, details=details)]


def triage_node(state: GraphState) -> dict:
    if state["budget"] <= 0:
        return {"status": "unresolved", "errors": state["errors"] + ["Investigation budget exhausted"],
                "trace": _event(state, "budget_exhausted", "triage")}
    try:
        clear_last_call_metadata()
        decision = investigate_alert(state["incident"], state["findings"],
            state["investigation_history"], state["outstanding_questions"])
        # Revalidate even if an adapter or test double bypassed normal Pydantic parsing.
        decision_payload = decision.model_dump(mode="json", exclude={"next_agent"})
        raw_action = decision.next_agent
        decision_payload["next_agent"] = getattr(raw_action, "value", raw_action)
        decision = TriageDecision.model_validate(decision_payload)
        call_metadata = get_last_call_metadata()
        retry_trace = ([TraceEvent(execution_id=state["execution_id"],
            event_type="provider_retry", agent="triage",
            details={"operation": "triage_decision", "attempts": call_metadata["retry_attempts"]})]
            if call_metadata and call_metadata.get("retry_attempts") else [])
        recovery_trace = retry_trace + (_event(state, "structured_output_recovery", "triage",
            operation="triage_decision", **call_metadata)
            if call_metadata and call_metadata.get("recovery_attempted") else [])
        prior_calls = sum(x.startswith(decision.next_agent + ":")
                          for x in state["investigation_history"])
        other_evidence_count = sum(f.agent in SPECIALISTS and f.agent != decision.next_agent
                                   for f in state["findings"])
        previous_snapshot = state["evidence_at_last_invocation"].get(decision.next_agent, 0)
        if decision.next_agent in SPECIALISTS and prior_calls and (
                prior_calls >= 2 or other_evidence_count <= previous_snapshot):
            return {"current_plan": decision, "status": "unresolved",
                "errors": state["errors"] + [f"Triage requested repeated investigation without new evidence: {decision.next_agent}"],
                "trace": _event(state, "route_rejected", "triage", route=decision.next_agent,
                                reason="no new independent evidence or repeat limit reached")}
        if decision.next_agent == "remediation" and len([f for f in state["findings"] if f.agent in SPECIALISTS]) < 2:
            return {"current_plan": decision, "status": "unresolved",
                "errors": state["errors"] + ["Remediation rejected: fewer than two specialist findings"],
                "trace": _event(state, "route_rejected", "triage", route="remediation",
                                reason="insufficient independent specialist findings")}
        valid_refs = {r.ref for r in retrieve_logs(state["incident"])}
        valid_refs |= {r.ref for r in retrieve_changes(state["incident"])}
        valid_refs |= {f"metrics:{name}" for name in state["incident"].metrics}
        valid_refs |= {ref.ref for finding in state["findings"] for ref in finding.evidence_refs}
        sanitized_hypotheses = [h.model_copy(update={
            "supporting_refs": [r for r in h.supporting_refs if r in valid_refs],
            "contradicting_refs": [r for r in h.contradicting_refs if r in valid_refs]})
            for h in decision.hypotheses]
        reported_gaps = list(decision.evidence_gaps)
        query_gaps = ([gap for finding in state["findings"] if finding.agent in {"logs", "metrics", "changes"}
                       for gap in finding.missing_evidence] if state.get("evidence_requests_attempted") else [])
        reconciled_gaps = _reconcile_evidence_gaps(reported_gaps + query_gaps,
                                                    state["evidence_source_status"])
        decision = decision.model_copy(update={"hypotheses": sanitized_hypotheses,
                                                "evidence_gaps": reconciled_gaps})
        preserved = {h.statement.casefold(): h for h in state["hypotheses"]}
        preserved.update({h.statement.casefold(): h for h in decision.hypotheses})
        accumulated_hypotheses = list(preserved.values())
        finding = triage_finding(decision)
        lifecycle = ("awaiting_information" if decision.next_agent == "more_information"
                     else "unresolved" if decision.next_agent == "escalate" else "investigating")
        outstanding = reconciled_gaps
        return {"current_plan": decision,
            "findings": state["findings"] + [finding],
            "hypotheses": accumulated_hypotheses,
            "outstanding_questions": outstanding,
            "status": lifecycle,
            "trace": recovery_trace + _event(state, "routing_decision", "triage", next_agent=decision.next_agent,
                            question=decision.investigation_question,
                            rationale=decision.decision_rationale,
                            confidence=decision.confidence,
                            evidence_gaps=reported_gaps,
                            reconciled_evidence_gaps=outstanding,
                            evidence_source_status={name: value.model_dump(mode="json")
                                for name, value in state["evidence_source_status"].items()},
                            evidence_requests=[request.model_dump(mode="json") for request in decision.evidence_requests],
                            hypotheses=[h.model_dump(mode="json") for h in decision.hypotheses]) +
                ([TraceEvent(execution_id=state["execution_id"], event_type="evidence_reconciliation",
                    agent="triage", details={"finding_ids": [f.finding_id for f in state["findings"]],
                    "hypotheses": [h.model_dump(mode="json") for h in decision.hypotheses],
                    "reported_evidence_gaps": reported_gaps,
                    "evidence_gaps": outstanding,
                    "evidence_source_status": {name: value.model_dump(mode="json")
                        for name, value in state["evidence_source_status"].items()}})] if state["findings"] else [])}
    except Exception as exc:
        if not isinstance(exc, ProviderUnavailable):
            label = "agent_failure"
        elif exc.category in {"local_validation", "malformed_json", "empty_response"}:
            label = "response_validation_failure"
        else:
            label = "provider_unavailable"
        reason = str(exc) if isinstance(exc, ProviderUnavailable) else type(exc).__name__
        message = f"Triage {label}: {reason}"
        details = {"error": message, "execution_id": state["execution_id"],
            "operation": "triage_decision"}
        if isinstance(exc, ProviderUnavailable):
            details.update({"provider_category": exc.category, "status_code": exc.status_code,
                "provider_code": exc.provider_code, "retryable": exc.retryable,
                "initial_provider_code": exc.initial_provider_code,
                "initial_status_code": exc.initial_status_code,
                "provider_operation": exc.operation,
                "recovery_attempted": exc.recovery_attempted,
                "response_mode": exc.response_mode,
                "retry_attempts": exc.retry_diagnostics,
                "retry_exhausted": exc.retry_exhausted})
        return {"status": "unresolved" if isinstance(exc, ProviderUnavailable) else "failed",
                "errors": state["errors"] + [message],
                "trace": _event(state, label, "triage", **details)}


def _specialist_node(state: GraphState, agent: str) -> dict:
    plan = state.get("current_plan")
    if plan is None:
        return {"status": "failed", "errors": state["errors"] + ["Investigation has no validated triage plan"]}
    refs = sorted({ref.ref for f in state["findings"] for ref in f.evidence_refs})
    req = AgentRequest(execution_id=state["execution_id"], sender="triage",
        recipient=agent, question=plan.investigation_question, evidence_refs=refs,
        shared_finding_ids=[f.finding_id for f in state["findings"]],
        expected_outcome=plan.expected_information_gain)
    trace = _event(state, "agent_invoked", agent, question=req.question, handoff=req.model_dump(mode="json"))
    try:
        clear_last_call_metadata()
        evidence_kwargs = ({"evidence_source": state["evidence_source"],
            "evidence_window": state["evidence_window"],
            "execution_id": state["execution_id"]} if state.get("evidence_source") is not None else {})
        if agent == "logs":
            finding = investigate_logs(state["incident"], req.question, state["findings"], **evidence_kwargs)
        elif agent == "metrics":
            finding = investigate_metrics(state["incident"], req.question, state["findings"], **evidence_kwargs)
        else:
            finding = analyze_change(state["incident"], req.question, state["findings"], **evidence_kwargs)
        source_status = dict(state["evidence_source_status"])
        analyzed_queries = []
        for query in finding.evidence_queries:
            observed_status = "analyzed" if query.status == "retrieved" else query.status
            normalized = query.model_copy(update={"status": observed_status})
            analyzed_queries.append(normalized)
            source_status[query.source] = normalized
        finding = finding.model_copy(update={"evidence_queries": analyzed_queries})
        call_metadata = get_last_call_metadata()
        retry_trace = ([TraceEvent(execution_id=state["execution_id"],
            event_type="provider_retry", agent=agent,
            details={"operation": f"{agent}_investigation",
                     "attempts": call_metadata["retry_attempts"]})]
            if call_metadata and call_metadata.get("retry_attempts") else [])
        history = state["investigation_history"] + [agent + ":" + finding.finding_id]
        snapshots = dict(state["evidence_at_last_invocation"])
        snapshots[agent] = sum(f.agent in SPECIALISTS and f.agent != agent for f in state["findings"])
        return {"findings": state["findings"] + [finding],
            "evidence_source_status": source_status,
            "investigation_history": history, "handoffs": state["handoffs"] + [req],
            "evidence_at_last_invocation": snapshots,
            "budget": state["budget"] - 1, "status": "investigating",
            "trace": trace + retry_trace + [TraceEvent(execution_id=state["execution_id"], event_type="agent_result",
                agent=agent, details={"finding_id": finding.finding_id,
                    "summary": finding.summary, "evidence_refs": [r.ref for r in finding.evidence_refs],
                    "tool_evidence": [r.model_dump(mode="json") for r in finding.evidence_refs],
                    "missing_evidence": finding.missing_evidence,
                    "finding": finding.model_dump(mode="json")})] +
                ([TraceEvent(execution_id=state["execution_id"],
                    event_type="evidence_source_status", agent=agent,
                    details={"sources": [query.model_dump(mode="json") for query in analyzed_queries]})]
                    if analyzed_queries else [])}
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ProviderUnavailable) else type(exc).__name__
        exhausted = isinstance(exc, ProviderUnavailable) and exc.retry_exhausted
        label = "provider_unavailable" if isinstance(exc, ProviderUnavailable) and exhausted else "agent_failure"
        message = f"{agent} provider unavailable: {reason}" if label == "provider_unavailable" else f"{agent} agent failed: {reason}"
        details = {"error": message, "execution_id": state["execution_id"],
            "agent": agent, "operation": f"{agent}_investigation"}
        if isinstance(exc, ProviderUnavailable):
            details.update({"provider_category": exc.category, "status_code": exc.status_code,
                "provider_code": exc.provider_code, "retryable": exc.retryable,
                "initial_provider_code": exc.initial_provider_code,
                "initial_status_code": exc.initial_status_code,
                "provider_operation": exc.operation,
                "recovery_attempted": exc.recovery_attempted,
                "response_mode": exc.response_mode,
                "retry_attempts": exc.retry_diagnostics,
                "retry_exhausted": exc.retry_exhausted})
        snapshots = dict(state["evidence_at_last_invocation"])
        snapshots[agent] = sum(f.agent in SPECIALISTS and f.agent != agent for f in state["findings"])
        return {"errors": state["errors"] + [message],
            "investigation_history": state["investigation_history"] + [agent + ":failed"],
            "evidence_at_last_invocation": snapshots,
            "handoffs": state["handoffs"] + [req], "budget": state["budget"] - 1,
            "status": "unresolved" if exhausted else "investigating",
            "trace": trace + [TraceEvent(execution_id=state["execution_id"],
                event_type=label, agent=agent, details=details)]}


def logs_node(state: GraphState) -> dict: return _specialist_node(state, "logs")
def metrics_node(state: GraphState) -> dict: return _specialist_node(state, "metrics")
def changes_node(state: GraphState) -> dict: return _specialist_node(state, "changes")


def evidence_request_node(state: GraphState) -> dict:
    """Execute one bounded batch of triage-requested, typed evidence queries."""
    plan = state.get("current_plan")
    source = state.get("evidence_source")
    if plan is None:
        return {"evidence_requests_attempted": True, "status": "investigating"}
    findings = list(state["findings"])
    trace = list(state["trace"])
    source_status = dict(state["evidence_source_status"])
    for request in plan.evidence_requests[:6]:
        pending = EvidenceQueryState(source=request.source, status="pending")
        source_status[request.source] = pending
        trace.append(TraceEvent(execution_id=state["execution_id"],
            event_type="evidence_source_status", agent="triage",
            details={"source": request.source, "status": "pending", "reason": request.reason}))
        try:
            if source is None:
                raise LookupError("no_source")
            window = state.get("evidence_window")
            if window is None:
                raise LookupError("no_window")
            result = query_evidence(source, request.source, state["incident"],
                                    state["execution_id"], window)
            if result is None:
                raise ValueError("No evidence source is configured")
            findings.append(request_result_finding(result))
            retrieved_state = EvidenceQueryState(source=request.source,
                status="retrieved" if result.status == "available" else result.status,
                record_count=len(result.records), missing_evidence=result.missing_evidence,
                reason=result.reason)
            source_status[request.source] = retrieved_state
            trace.append(TraceEvent(execution_id=state["execution_id"],
                event_type="evidence_source_status", agent="triage",
                details=retrieved_state.model_dump(mode="json")))
            trace.append(TraceEvent(execution_id=state["execution_id"],
                event_type="evidence_query_result", agent="triage",
                details={"source": request.source, "reason": request.reason,
                    "status": result.status, "record_count": len(result.records),
                    "missing_evidence": result.missing_evidence,
                    "records": [record.model_dump(mode="json") for record in result.records]}))
        except Exception as exc:
            reason = ("No evidence source is configured" if isinstance(exc, LookupError) and str(exc) == "no_source"
                      else "No incident time window is available" if isinstance(exc, LookupError)
                      else f"Evidence provider query failed ({type(exc).__name__})")
            missing = f"{request.source} evidence request unavailable: {reason}"
            findings.append(AgentFinding(agent=("logs" if request.source == "logs" else
                "changes" if request.source in {"changes", "deployments"} else "metrics"),
                summary=missing, missing_evidence=[missing], reasoning_status="unavailable"))
            unavailable_state = EvidenceQueryState(source=request.source,
                status="unavailable", missing_evidence=[missing], reason=reason)
            source_status[request.source] = unavailable_state
            trace.append(TraceEvent(execution_id=state["execution_id"],
                event_type="evidence_source_status", agent="triage",
                details=unavailable_state.model_dump(mode="json")))
            trace.append(TraceEvent(execution_id=state["execution_id"],
                event_type="evidence_query_result", agent="triage",
                details={"source": request.source, "reason": request.reason,
                    "status": "unavailable", "record_count": 0, "missing_evidence": [missing]}))
    if len(plan.evidence_requests) > 6:
        trace.append(TraceEvent(execution_id=state["execution_id"],
            event_type="evidence_query_limit", agent="triage",
            details={"requested": len(plan.evidence_requests), "executed": 6}))
    return {"findings": findings, "evidence_source_status": source_status,
            "evidence_requests_attempted": True,
            "status": "investigating", "trace": trace}


def remediation_node(state: GraphState) -> dict:
    try:
        proposal = propose_remediation(state["incident"], state["findings"], state["outstanding_questions"])
        status = "awaiting_approval" if proposal.approval_status == "awaiting_approval" else "remediating"
        execution = None
        recovery = None
        trace = _event(state, "remediation_proposed", "remediation", proposal=proposal.model_dump(mode="json"))
        if proposal.approval_status == "not_required" or state.get("approval") is not None:
            execution = execute_remediation(proposal, state.get("approval"))
            trace = trace + [TraceEvent(execution_id=state["execution_id"], event_type="simulated_execution",
                agent="remediation", details=execution)]
            if execution["executed"]:
                recovery = verify_recovery(state["incident"], state.get("post_action_metrics") or {})
                trace = trace + [TraceEvent(execution_id=state["execution_id"], event_type="recovery_verification",
                    agent="remediation", details=recovery.model_dump(mode="json"))]
                status = "recovered" if recovery.outcome == "recovered" else "unresolved"
            else:
                status = "awaiting_approval"
        return {"remediation": proposal, "simulated_execution": execution,
                "recovery": recovery, "status": status, "trace": trace}
    except Exception as exc:
        message = f"Remediation withheld: {type(exc).__name__}"
        return {"status": "unresolved", "errors": state["errors"] + [message],
            "trace": _event(state, "remediation_withheld", "remediation", reason=str(exc))}


def final_node(state: GraphState) -> dict:
    plan = state.get("current_plan")
    status = state["status"]
    provider_failure = next((event for event in reversed(state["trace"])
        if event.event_type == "provider_unavailable"), None)
    if provider_failure is not None:
        operation = provider_failure.details.get("operation", "an LLM operation")
        if plan is None:
            root_cause_assessment = ("No LLM triage assessment was available because the provider failed "
                f"during {provider_failure.agent or 'triage'} ({operation}).")
        else:
            root_cause_assessment = (f"Investigation stopped because the LLM provider was unavailable "
                f"during {provider_failure.agent or 'triage'} ({operation}); last validated triage "
                f"assessment: {plan.assessment}")
    else:
        root_cause_assessment = plan.assessment if plan else "No LLM triage assessment was available."
    questions = list(state["outstanding_questions"])
    next_steps = []
    if status == "awaiting_approval":
        next_steps.append("Obtain an authorized approval for the specific proposal before simulated execution.")
    if state.get("recovery") and state["recovery"].outcome == "insufficient_evidence":
        questions.extend(state["recovery"].missing_metrics)
        next_steps.append("Supply all required post-action metrics before declaring recovery.")
    elif status == "unresolved":
        next_steps.append("Review outstanding evidence and continue investigation or escalate to an operator.")
    report = IncidentReport(incident_id=state["incident"].incident_id,
        execution_id=state["execution_id"], service=state["incident"].service,
        summary=state["incident"].summary, severity=state["incident"].severity,
        status=status, findings=state["findings"], hypotheses=state["hypotheses"],
        root_cause_assessment=root_cause_assessment,
        investigations=state["investigation_history"], errors=state["errors"],
        remediation=state.get("remediation"), simulated_execution=state.get("simulated_execution"),
        recovery=state.get("recovery"), outstanding_questions=questions,
        next_steps=next_steps, trace_reference=None,
        metadata={"simulated_actions_only": True,
            "confidence": plan.confidence if plan else "unavailable",
            "evidence_sources": {name: value.model_dump(mode="json")
                for name, value in state["evidence_source_status"].items()}})
    return {"report": report, "trace": _event(state, "final_report", None,
        status=status, report=report.model_dump(mode="json"))}


def route_after_triage(state: dict) -> str:
    plan = state.get("current_plan")
    if (plan is not None and plan.evidence_requests
            and not state.get("evidence_requests_attempted")):
        return "evidence"
    if state["status"] != "investigating" or state.get("current_plan") is None:
        return "final"
    choice = state["current_plan"].next_agent
    return choice if choice in SPECIALISTS | {"remediation"} else "final"


def route_after_specialist(state: dict) -> str:
    return "triage" if state["status"] == "investigating" and state["budget"] > 0 else "final"


def build_graph():
    """Compile LangGraph transitions. Raises a clear error when it is not installed."""
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:
        raise RuntimeError("LangGraph is not installed; install requirements.txt") from exc
    graph = StateGraph(GraphState)
    for name, fn in (("triage", triage_node), ("evidence", evidence_request_node),
                     ("logs", logs_node), ("metrics", metrics_node),
                     ("changes", changes_node), ("remediation", remediation_node), ("final", final_node)):
        graph.add_node(name, fn)
    graph.add_edge(START, "triage")
    graph.add_conditional_edges("triage", route_after_triage,
        {"logs": "logs", "metrics": "metrics", "changes": "changes", "evidence": "evidence",
         "remediation": "remediation", "final": "final"})
    graph.add_edge("evidence", "triage")
    for name in SPECIALISTS:
        graph.add_conditional_edges(name, route_after_specialist, {"triage": "triage", "final": "final"})
    graph.add_edge("remediation", "final")
    graph.add_edge("final", END)
    return graph.compile()


def _run_without_langgraph(state: dict) -> dict:
    """Same validated transitions for minimal test environments lacking LangGraph."""
    while state["status"] in {"received", "investigating"}:
        patch = triage_node(state)
        state.update(patch)
        target = route_after_triage(state)
        if target == "final":
            break
        patch = (logs_node if target == "logs" else metrics_node if target == "metrics"
                 else changes_node if target == "changes" else evidence_request_node
                 if target == "evidence" else remediation_node)(state)
        state.update(patch)
        if target == "remediation" or state["status"] != "investigating":
            break
    state.update(final_node(state))
    return state


def _persist_trace(state: dict) -> str | None:
    trace_dir = Path(os.getenv("AIOPS_TRACE_DIR", "traces"))
    path = trace_dir / f"{state['execution_id']}.jsonl"
    try:
        trace_dir.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for event in state["trace"]:
                handle.write(event.model_dump_json() + "\n")
        return str(path)
    except OSError as exc:
        state["errors"].append(f"Trace persistence failed: {type(exc).__name__}")
        state["trace"] = _event(state, "trace_write_failure", details={"error": type(exc).__name__})
        return None


def run_incident(incident: IncidentInput, *, execution_id: str | None = None,
                 approval: ApprovalRecord | None = None,
                 post_action_metrics: dict[str, float] | None = None,
                 evidence_source: EvidenceSource | None = None,
                 evidence_window: EvidenceWindow | None = None) -> IncidentState:
    if evidence_source is not None and evidence_window is None:
        raise ValueError("evidence_window is required when an evidence_source is configured")
    eid = execution_id or str(uuid4())
    initial_evidence_status = {name: EvidenceQueryState(source=name, status="not_requested")
                               for name in EVIDENCE_SOURCES}
    initial = {"incident": incident, "execution_id": eid, "status": "investigating",
        "current_plan": None, "findings": [], "hypotheses": [], "investigation_history": [],
        "evidence_at_last_invocation": {},
        "handoffs": [], "errors": [], "outstanding_questions": [],
        "budget": MAX_INVESTIGATIONS, "remediation": None, "approval": approval,
        "simulated_execution": None, "recovery": None,
        "evidence_source": evidence_source, "evidence_window": evidence_window,
        "evidence_requests_attempted": False,
        "evidence_source_status": initial_evidence_status,
        "trace": [TraceEvent(execution_id=eid, event_type="execution_started",
                             details={"incident_id": incident.incident_id}),
                  TraceEvent(execution_id=eid, event_type="input_validated",
                    details={"service": incident.service, "summary": incident.summary,
                        "severity": incident.severity, "symptoms": incident.symptoms,
                        "metric_names": sorted(incident.metrics),
                        "log_records": len(incident.logs),
                        "recent_change_records": len(incident.recent_changes)}),
                  TraceEvent(execution_id=eid, event_type="evidence_source_status",
                    agent="triage", details={"sources": {name: value.model_dump(mode="json")
                        for name, value in initial_evidence_status.items()}})],
        "report": None, "post_action_metrics": post_action_metrics}
    try:
        result = build_graph().invoke(initial)
    except RuntimeError as exc:
        if "LangGraph is not installed" not in str(exc):
            raise
        result = _run_without_langgraph(initial)
    trace_ref = _persist_trace(result)
    report = result.get("report")
    if report:
        report.trace_reference = trace_ref
        report.errors = list(result["errors"])
        if trace_ref is None:
            report.next_steps.append("Trace persistence failed; capture the execution log before relying on this run as an audit artifact.")
        result["report"] = report
    normalized = {key: result.get(key) for key in IncidentState.model_fields}
    return IncidentState.model_validate(normalized)
