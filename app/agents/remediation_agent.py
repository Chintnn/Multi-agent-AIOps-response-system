"""LLM recommendations with deterministic policy, approval, and verification."""
from app.incident_tools import METRIC_THRESHOLDS
from app.agents.context import compact_findings
from app.llm import invoke_structured
from app.models import (AgentFinding, ApprovalRecord, IncidentInput,
                        RemediationInput, RemediationProposal,
                        RemediationReasoning, RecoveryResult)

ACTION_RISK_LEVELS = {
    "restart_service": "medium", "scale_up_db_pool": "medium",
    "clear_cache": "low", "rollback_deployment": "high",
}
RISK_LEVELS_REQUIRING_APPROVAL = {"medium", "high"}
RECOVERY_THRESHOLDS = {name: threshold for name, (threshold, _) in METRIC_THRESHOLDS.items()}


def recommend_remediation(incident: IncidentInput, findings: list[AgentFinding],
                          unresolved: list[str] | None = None) -> RemediationReasoning:
    request = RemediationInput(incident=incident, findings=findings,
                               unresolved_questions=unresolved or [])
    incident, findings, unresolved = request.incident, request.findings, request.unresolved_questions
    usable = [f for f in findings if f.agent != "triage" and f.reasoning_status == "complete"]
    if len(usable) < 2 or not any(f.evidence_refs for f in usable) or unresolved:
        raise ValueError("Insufficient or conflicting evidence; remediation requires human review or more investigation")
    refs = {r.ref for finding in usable for r in finding.evidence_refs}
    result = invoke_structured(
        "You recommend a simulated remediation. Use only supplied findings and evidence references. If evidence is weak or contradictory, choose investigate_more or escalate. Never claim approval, execution, or recovery. Compare benefits, prerequisites, risks, alternatives. Cite only supplied refs.",
        f"Incident: {incident.model_dump(mode='json')}\nFindings: {compact_findings(usable)}\nUnresolved questions: {unresolved}",
        RemediationReasoning)
    if not set(result.evidence_refs).issubset(refs):
        raise ValueError("Remediation reasoning cited unknown evidence references")
    if result.recommend_action in {"investigate_more", "escalate"}:
        raise ValueError(result.rationale)
    return result


def propose_remediation(incident: IncidentInput, findings: list[AgentFinding],
                        unresolved: list[str] | None = None) -> RemediationProposal:
    reasoning = recommend_remediation(incident, findings, unresolved)
    action = reasoning.recommend_action
    risk = ACTION_RISK_LEVELS[action]
    return RemediationProposal(action=action, risk_level=risk,
        rationale=reasoning.rationale, expected_benefit=reasoning.expected_benefit,
        prerequisites=reasoning.prerequisites, alternatives=reasoning.alternatives,
        evidence_refs=reasoning.evidence_refs,
        approval_status="awaiting_approval" if risk in RISK_LEVELS_REQUIRING_APPROVAL else "not_required")


def execute_remediation(proposal: RemediationProposal,
                        approval: ApprovalRecord | None = None) -> dict:
    """Simulate an action only after independently checking policy and approval identity."""
    if not isinstance(proposal, RemediationProposal):
        return {"executed": False, "reason": "Invalid proposal schema"}
    expected_risk = ACTION_RISK_LEVELS.get(proposal.action)
    if expected_risk is None or proposal.risk_level != expected_risk:
        return {"executed": False, "reason": "Action or risk classification failed policy validation"}
    if expected_risk in RISK_LEVELS_REQUIRING_APPROVAL:
        if (not isinstance(approval, ApprovalRecord) or approval.decision != "approved"
                or approval.proposal_id != proposal.proposal_id
                or not approval.approved_by.strip()):
            return {"executed": False, "reason": "Matching explicit approval is required"}
    return {"executed": True, "simulated": True,
            "reason": f"Action {proposal.action} simulated; this does not establish recovery."}


def verify_recovery(incident: IncidentInput, post_action_metrics: dict[str, float]) -> RecoveryResult:
    del incident  # The verification contract is based only on explicitly post-action measurements.
    missing = [name for name in RECOVERY_THRESHOLDS if name not in post_action_metrics]
    elevated = [f"{name}={post_action_metrics[name]:g} (threshold {limit:g})"
                for name, limit in RECOVERY_THRESHOLDS.items()
                if name in post_action_metrics and post_action_metrics[name] >= limit]
    if missing:
        return RecoveryResult(outcome="insufficient_evidence", missing_metrics=missing,
            still_elevated=elevated, checked_metrics=post_action_metrics,
            explanation="Recovery cannot be established because required post-action metrics are missing.")
    if elevated:
        return RecoveryResult(outcome="not_recovered", still_elevated=elevated,
            checked_metrics=post_action_metrics,
            explanation="One or more required post-action metrics remain above threshold.")
    return RecoveryResult(outcome="recovered", checked_metrics=post_action_metrics,
        explanation="All required post-action metrics are below configured thresholds.")
