"""
Remediation & Verification Agent

Owner: Member 3

Responsibility:
- Evaluates safe remediation options based on findings from other agents.
- States risks and expected effects of each option.
- Requires human approval before executing risky actions.
- Checks simulated post-action metrics to verify recovery.
"""

from app.models import EvidenceFinding, IncidentInput

# Risk classification for known remediation actions.
# Anything not in this map defaults to "high" risk (safe default).
ACTION_RISK_LEVELS = {
    "restart_service": "medium",
    "scale_up_db_pool": "medium",
    "clear_cache": "low",
    "rollback_deployment": "high",
}

# Risk levels that require explicit human approval before execution.
RISK_LEVELS_REQUIRING_APPROVAL = {"medium", "high"}

# Same thresholds used by inspect_metrics in incident_tools.py, reused here
# so "recovered" means "back under the same bar that flagged the incident."
RECOVERY_THRESHOLDS = {
    "p95_latency_ms": 1000.0,
    "http_5xx_rate_percent": 5.0,
    "cpu_percent": 90.0,
    "db_connection_pool_percent": 85.0,
}


def _choose_action(findings: list[EvidenceFinding]) -> str:
    """
    Pick a remediation action based on combined evidence from other agents.
    Simple keyword-based heuristic, consistent with the rest of the codebase.
    """
    combined_text = " ".join(
        f"{f.observation} {' '.join(f.evidence)}" for f in findings
    ).lower()

    if "deploy" in combined_text or "rollout" in combined_text:
        return "rollback_deployment"
    if "connection pool" in combined_text or "db" in combined_text:
        return "scale_up_db_pool"
    if "cpu" in combined_text:
        return "restart_service"

    return "clear_cache"


def propose_remediation(findings: list[EvidenceFinding]) -> dict:
    """
    Propose a safe remediation action based on combined agent findings.

    Returns:
        dict with keys: action, risk_level, requires_approval, rationale
    """
    action = _choose_action(findings)
    risk_level = ACTION_RISK_LEVELS.get(action, "high")
    requires_approval = risk_level in RISK_LEVELS_REQUIRING_APPROVAL

    rationale = (
        f"Selected '{action}' based on combined evidence from "
        f"{len(findings)} finding(s). Risk level: {risk_level}."
    )

    return {
        "action": action,
        "risk_level": risk_level,
        "requires_approval": requires_approval,
        "rationale": rationale,
    }


def execute_remediation(proposal: dict, approved: bool = False) -> dict:
    """
    Attempt to execute a remediation proposal, enforcing the approval gate.

    Args:
        proposal: output of propose_remediation().
        approved: whether a human has explicitly approved this action.

    Returns:
        dict with keys: executed (bool), reason (str)
    """
    if proposal["requires_approval"] and not approved:
        return {
            "executed": False,
            "reason": f"Action '{proposal['action']}' requires human approval "
                      f"(risk level: {proposal['risk_level']}) but was not approved.",
        }

    return {
        "executed": True,
        "reason": f"Action '{proposal['action']}' executed (simulated).",
    }


def verify_recovery(incident: IncidentInput, post_action_metrics: dict) -> dict:
    """
    Check simulated post-action metrics to determine if recovery occurred.

    Compares post_action_metrics against the same thresholds used to flag
    the original incident (see inspect_metrics in incident_tools.py).

    Args:
        incident: the original IncidentInput being resolved.
        post_action_metrics: simulated metrics captured after remediation.

    Returns:
        dict with keys:
            recovered (bool): True if no metric is still crossing its threshold.
            still_elevated (list[str]): descriptions of metrics still crossing thresholds.
            next_step (str): what to do next.
    """
    still_elevated = []

    for metric, threshold in RECOVERY_THRESHOLDS.items():
        value = post_action_metrics.get(metric)
        if value is not None and value >= threshold:
            still_elevated.append(
                f"{metric} is still elevated: {value:g} (threshold {threshold:g})"
            )

    recovered = len(still_elevated) == 0

    if recovered:
        next_step = "Incident appears resolved. Close out and document the remediation."
    else:
        next_step = (
            "Recovery incomplete. Escalate to a human operator or attempt an "
            "alternative remediation action."
        )

    return {
        "recovered": recovered,
        "still_elevated": still_elevated,
        "next_step": next_step,
    }