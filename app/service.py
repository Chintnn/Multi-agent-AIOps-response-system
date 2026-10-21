"""Thread-safe in-process service boundary used by the API and CLI adapters.

The registry is deliberately process-local. ``ExecutionRepository`` documents the
minimal persistence boundary a later database implementation can replace.
"""
from __future__ import annotations

from threading import RLock
from uuid import uuid4

from app.agents.remediation_agent import execute_remediation, verify_recovery
from app.models import ApprovalRecord, IncidentInput, IncidentState, TraceEvent
from app.orchestrator import _persist_trace, run_incident
from app.telemetry import EvidenceWindow, InMemoryTelemetryStore


class ExecutionRepository:
    """Small repository contract for the current process-local implementation."""
    def __init__(self):
        self.lock = RLock()
        self.states: dict[str, IncidentState] = {}
        self.evidence: dict[str, tuple[InMemoryTelemetryStore, EvidenceWindow]] = {}


_REPOSITORY = ExecutionRepository()
_EXECUTIONS = _REPOSITORY.states  # Backward-compatible internal alias.


def submit_incident(incident: IncidentInput, *, execution_id: str | None = None,
                    evidence_source: InMemoryTelemetryStore | None = None,
                    evidence_window: EvidenceWindow | None = None) -> str:
    """Validate and register an incident, optionally with its generated evidence."""
    incident = IncidentInput.model_validate(incident)
    execution_id = execution_id or str(uuid4())
    with _REPOSITORY.lock:
        if execution_id in _EXECUTIONS:
            raise ValueError("Execution ID already exists")
        _EXECUTIONS[execution_id] = IncidentState(incident=incident, execution_id=execution_id)
        if evidence_source is not None and evidence_window is not None:
            _REPOSITORY.evidence[execution_id] = (evidence_source, evidence_window)
    return execution_id


def get_evidence_context(execution_id: str):
    with _REPOSITORY.lock:
        _require_execution(execution_id)
        return _REPOSITORY.evidence.get(execution_id)


def execution_count() -> int:
    with _REPOSITORY.lock:
        return len(_EXECUTIONS)


def start_investigation(execution_id: str, *, post_action_metrics: dict[str, float] | None = None) -> IncidentState:
    with _REPOSITORY.lock:
        initial = _require_execution(execution_id)
        if initial.status != "received":
            raise ValueError("Investigation has already been started")
        initial.status = "investigating"
        context = _REPOSITORY.evidence.get(execution_id)
    kwargs = {}
    if context:
        kwargs = {"evidence_source": context[0], "evidence_window": context[1]}
    try:
        result = run_incident(initial.incident, execution_id=execution_id,
                              post_action_metrics=post_action_metrics, **kwargs)
    except Exception as exc:
        with _REPOSITORY.lock:
            initial.status = "failed"
            initial.errors.append(f"Investigation execution failed: {type(exc).__name__}")
            _EXECUTIONS[execution_id] = initial
        raise
    with _REPOSITORY.lock:
        _EXECUTIONS[execution_id] = result
    return result


def record_approval(execution_id: str, approved_by: str, decision: str,
                    post_action_metrics: dict[str, float] | None = None,
                    *, proposal_id: str | None = None) -> IncidentState:
    with _REPOSITORY.lock:
        state = _require_execution(execution_id)
        proposal = state.remediation
        if proposal is None or state.status != "awaiting_approval":
            raise ValueError("Execution has no pending remediation approval")
        if proposal_id is not None and proposal_id != proposal.proposal_id:
            raise ValueError("Proposal ID does not match the pending remediation")
        approval = ApprovalRecord(proposal_id=proposal.proposal_id, approved_by=approved_by,
                                  decision=decision)
        state.approval = approval
        state.trace.append(TraceEvent(execution_id=execution_id, event_type="approval_recorded",
            agent="remediation", details={"proposal_id": proposal.proposal_id,
                "decision": decision, "approved_by": approved_by}))
        if decision == "rejected":
            proposal = proposal.model_copy(update={"approval_status": "rejected"})
            state.remediation = proposal
            state.status = "unresolved"
            state.errors.append("Remediation approval was rejected")
        else:
            proposal = proposal.model_copy(update={"approval_status": "approved"})
            state.remediation = proposal
            result = execute_remediation(proposal, approval)
            state.simulated_execution = result
            state.trace.append(TraceEvent(execution_id=execution_id,
                event_type="simulated_execution", agent="remediation", details=result))
            if result["executed"]:
                recovery = verify_recovery(state.incident, post_action_metrics or {})
                state.recovery = recovery
                state.trace.append(TraceEvent(execution_id=execution_id,
                    event_type="recovery_verification", agent="remediation",
                    details=recovery.model_dump(mode="json")))
                state.status = "recovered" if recovery.outcome == "recovered" else "unresolved"
        if state.report:
            state.report.status = state.status
            state.report.remediation = proposal
            state.report.simulated_execution = state.simulated_execution
            state.report.recovery = state.recovery
            state.report.errors = state.errors
            state.report.next_steps = (["Supply all required post-action metrics before declaring recovery."]
                if state.recovery and state.recovery.outcome == "insufficient_evidence" else [])
            state.report.trace_reference = _persist_trace({"execution_id": execution_id,
                "trace": state.trace, "errors": state.errors})
            state.report.errors = list(state.errors)
            if state.report.trace_reference is None:
                state.report.next_steps.append("Trace persistence failed; capture the execution log before relying on this run as an audit artifact.")
        _EXECUTIONS[execution_id] = state
        return state


def get_execution_status(execution_id: str) -> dict:
    with _REPOSITORY.lock:
        state = _require_execution(execution_id)
        return {"execution_id": execution_id, "incident_id": state.incident.incident_id,
                "status": state.status, "budget_remaining": state.budget,
                "errors": state.errors}


def get_incident_report(execution_id: str):
    with _REPOSITORY.lock:
        return _require_execution(execution_id).report


def get_execution_trace(execution_id: str) -> list[dict]:
    with _REPOSITORY.lock:
        state = _require_execution(execution_id)
        return [event.model_dump(mode="json") for event in state.trace]


def get_remediation_state(execution_id: str) -> dict:
    with _REPOSITORY.lock:
        state = _require_execution(execution_id)
        return {"proposal": state.remediation, "approval": state.approval,
                "execution": state.simulated_execution, "recovery": state.recovery}


def _require_execution(execution_id: str) -> IncidentState:
    state = _EXECUTIONS.get(execution_id)
    if state is None:
        raise KeyError("Unknown execution_id")
    return state
