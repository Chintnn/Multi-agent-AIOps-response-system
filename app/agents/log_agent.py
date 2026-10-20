"""Log Investigation Agent – investigates error patterns, timeouts, and exceptions."""

from app.incident_tools import inspect_logs
from app.llm import ask_llm, llm_available
from app.models import EvidenceFinding, IncidentInput


def investigate_logs(incident: IncidentInput) -> EvidenceFinding:
    """
    Investigate logs for the given incident.

    1. Run deterministic tool to extract evidence.
    2. Optionally ask the LLM to refine observation, hypotheses and next step.
    3. Fall back to rule-based logic when the LLM is unavailable.
    """
    finding = inspect_logs(incident)
    evidence_text = "\n".join(finding.evidence) if finding.evidence else "(no matching log lines)"

    # --- LLM path ---
    if llm_available() and finding.evidence:
        system = (
            "You are the Log Investigation Agent in a multi-agent AIOps system. "
            "Given log evidence from a software incident, produce a concise investigation result. "
            "Reply in exactly this format (no extra text):\n"
            "OBSERVATION: <1-3 sentences>\n"
            "HYPOTHESES: <comma-separated short hypotheses>\n"
            "NEXT_STEP: <one clear recommended next investigation step>"
        )
        user = (
            f"Service: {incident.service}\n"
            f"Summary: {incident.summary}\n"
            f"Severity: {incident.severity}\n"
            f"Log evidence:\n{evidence_text}"
        )
        llm_reply = ask_llm(system, user)
        if llm_reply:
            observation, next_step = _parse_llm_reply(llm_reply, finding)
            return EvidenceFinding(
                source="log_agent",
                observation=observation,
                evidence=finding.evidence,
                suggested_next_step=next_step,
            )

    # --- Deterministic fallback (always available) ---
    return _deterministic_log_finding(finding)


def _parse_llm_reply(reply: str, base: EvidenceFinding) -> tuple[str, str]:
    observation = base.observation
    next_step = base.suggested_next_step or "Correlate with metrics and recent changes."

    for line in reply.splitlines():
        line = line.strip()
        if line.upper().startswith("OBSERVATION:"):
            observation = line.split(":", 1)[1].strip()
        elif line.upper().startswith("NEXT_STEP:"):
            next_step = line.split(":", 1)[1].strip()
        elif line.upper().startswith("HYPOTHESES:"):
            hyps = line.split(":", 1)[1].strip()
            if hyps:
                observation = f"{observation} Possible causes: {hyps}."

    return observation, next_step


def _deterministic_log_finding(finding: EvidenceFinding) -> EvidenceFinding:
    hypotheses: list[str] = []
    evidence_text = " ".join(finding.evidence).lower()

    if not finding.evidence:
        observation = (
            "No error-related log lines found in the supplied sample. "
            "Evidence is currently insufficient to support a log-based root cause."
        )
        next_step = "Request a wider log time window or additional log sources."
    else:
        if "timeout" in evidence_text or "database connection" in evidence_text:
            hypotheses.append("Database connection acquisition failures / pool pressure")
        if "failed to create order" in evidence_text:
            hypotheses.append("Order creation failing due to downstream DB issues")
        if "exception" in evidence_text:
            hypotheses.append("Unhandled exception path contributing to errors")

        observation = finding.observation
        if hypotheses:
            observation += f" Possible causes: {'; '.join(hypotheses)}."
        else:
            observation += " Error signals present but no strong pattern matched yet."

        next_step = (
            finding.suggested_next_step
            or "Correlate these log findings with metrics and recent deployment timeline."
        )

    return EvidenceFinding(
        source="log_agent",
        observation=observation,
        evidence=finding.evidence,
        suggested_next_step=next_step,
    )
