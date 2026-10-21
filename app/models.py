"""Validated contracts shared by the service, agents, and workflow."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IncidentInput(Contract):
    incident_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    summary: str = Field(min_length=5)
    severity: Literal["low", "medium", "high", "critical"]
    symptoms: list[str] = Field(min_length=1)
    metrics: dict[str, float] = Field(default_factory=dict)
    logs: list[str] = Field(default_factory=list)
    recent_changes: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None


class EvidenceRef(Contract):
    ref: str
    source: str
    excerpt: str
    observed_at: datetime | None = None
    execution_id: str | None = None
    source_id: str | None = None
    incident_id: str | None = None


class EvidenceRequest(Contract):
    source: Literal["logs", "metrics", "traffic", "database_health", "changes", "deployments"]
    reason: str


class TriageAction(str, Enum):
    logs = "logs"
    metrics = "metrics"
    changes = "changes"
    remediation = "remediation"
    more_information = "more_information"
    escalate = "escalate"


TRIAGE_ACTION_VALUES = tuple(action.value for action in TriageAction)


class EvidenceQueryState(Contract):
    source: Literal["logs", "metrics", "traffic", "database_health", "changes", "deployments"]
    status: Literal["not_requested", "pending", "unavailable", "insufficient", "retrieved", "analyzed"]
    record_count: int = Field(default=0, ge=0)
    missing_evidence: list[str] = Field(default_factory=list)
    reason: str | None = None


class EvidenceFinding(Contract):
    source: str
    observation: str
    evidence: list[str] = Field(default_factory=list)
    suggested_next_step: str | None = None


class Hypothesis(Contract):
    statement: str
    rationale: str
    supporting_refs: list[str] = Field(default_factory=list)
    contradicting_refs: list[str] = Field(default_factory=list)
    uncertainty: str


class TriageDecision(Contract):
    assessment: str
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    next_agent: TriageAction
    investigation_question: str
    expected_information_gain: str
    confidence: Literal["low", "moderate", "high"]
    decision_rationale: str
    evidence_requests: list[EvidenceRequest] = Field(default_factory=list)


class AgentFinding(Contract):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    agent: Literal["triage", "logs", "metrics", "changes", "remediation"]
    summary: str
    observed_facts: list[str] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    evidence_queries: list[EvidenceQueryState] = Field(default_factory=list)
    follow_up: str | None = None
    reasoning_status: Literal["complete", "retrieved", "insufficient", "unavailable", "failed"] = "complete"


class TriageInput(Contract):
    incident: IncidentInput
    prior_findings: list[AgentFinding] = Field(default_factory=list)
    investigation_history: list[str] = Field(default_factory=list)
    outstanding_questions: list[str] = Field(default_factory=list)


class SpecialistReasoning(Contract):
    summary: str
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    follow_up: str | None = None
    contradictions: list[str] = Field(default_factory=list)


class LogAnalysis(AgentFinding):
    agent: Literal["logs"] = "logs"
    timestamps: list[str] = Field(default_factory=list)


class MetricsAnalysis(AgentFinding):
    agent: Literal["metrics"] = "metrics"
    metric_values: dict[str, float] = Field(default_factory=dict)
    calculated_values: dict[str, float] = Field(default_factory=dict)
    abnormal_metrics: list[str] = Field(default_factory=list)
    missing_metrics: list[str] = Field(default_factory=list)


class ChangeAnalysis(AgentFinding):
    agent: Literal["changes"] = "changes"
    candidate_changes: list[str] = Field(default_factory=list)


class RemediationReasoning(Contract):
    recommend_action: Literal["restart_service", "scale_up_db_pool", "clear_cache", "rollback_deployment", "investigate_more", "escalate"]
    rationale: str
    expected_benefit: str
    prerequisites: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class AgentRequest(Contract):
    execution_id: str
    sender: str
    recipient: str
    question: str
    evidence_refs: list[str] = Field(default_factory=list)
    shared_finding_ids: list[str] = Field(default_factory=list)
    expected_outcome: str


class LogInvestigationInput(Contract):
    incident: IncidentInput
    question: str = Field(min_length=1)
    prior_findings: list[AgentFinding] = Field(default_factory=list)


class MetricsInvestigationInput(Contract):
    incident: IncidentInput
    question: str = Field(min_length=1)
    prior_findings: list[AgentFinding] = Field(default_factory=list)


class ChangeInvestigationInput(Contract):
    incident: IncidentInput
    question: str = Field(min_length=1)
    prior_findings: list[AgentFinding] = Field(default_factory=list)


class RemediationInput(Contract):
    incident: IncidentInput
    findings: list[AgentFinding] = Field(min_length=2)
    unresolved_questions: list[str] = Field(default_factory=list)


class TraceEvent(Contract):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    execution_id: str
    event_type: str
    agent: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ApprovalRecord(Contract):
    model_config = ConfigDict(extra="forbid", frozen=True)
    proposal_id: str
    approved_by: str = Field(min_length=1)
    decision: Literal["approved", "rejected"]
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RemediationProposal(Contract):
    model_config = ConfigDict(extra="forbid", frozen=True)
    proposal_id: str = Field(default_factory=lambda: str(uuid4()))
    action: Literal["restart_service", "scale_up_db_pool", "clear_cache", "rollback_deployment"]
    risk_level: Literal["low", "medium", "high"]
    rationale: str
    expected_benefit: str
    prerequisites: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    approval_status: Literal["not_required", "awaiting_approval", "approved", "rejected"]


class RecoveryResult(Contract):
    outcome: Literal["recovered", "not_recovered", "insufficient_evidence"]
    missing_metrics: list[str] = Field(default_factory=list)
    still_elevated: list[str] = Field(default_factory=list)
    checked_metrics: dict[str, float] = Field(default_factory=dict)
    explanation: str


class IncidentReport(Contract):
    incident_id: str
    execution_id: str
    service: str
    summary: str
    severity: str
    status: Literal["received", "investigating", "awaiting_information", "awaiting_approval", "remediating", "recovered", "unresolved", "failed"]
    findings: list[AgentFinding] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    root_cause_assessment: str
    investigations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    remediation: RemediationProposal | None = None
    simulated_execution: dict[str, Any] | None = None
    recovery: RecoveryResult | None = None
    outstanding_questions: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    trace_reference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentState(Contract):
    incident: IncidentInput
    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    status: Literal["received", "investigating", "awaiting_information", "awaiting_approval", "remediating", "recovered", "unresolved", "failed"] = "received"
    current_plan: TriageDecision | None = None
    findings: list[AgentFinding] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    investigation_history: list[str] = Field(default_factory=list)
    handoffs: list[AgentRequest] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    outstanding_questions: list[str] = Field(default_factory=list)
    budget: int = Field(default=4, ge=0)
    remediation: RemediationProposal | None = None
    approval: ApprovalRecord | None = None
    simulated_execution: dict[str, Any] | None = None
    recovery: RecoveryResult | None = None
    trace: list[TraceEvent] = Field(default_factory=list)
    report: IncidentReport | None = None


class IncidentSubmission(Contract):
    incident: IncidentInput


class IncidentReportEnvelope(Contract):
    report: IncidentReport
