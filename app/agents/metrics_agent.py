"""Metrics Investigation Agent – interprets latency, error rate, CPU, and DB pool signals."""

from app.incident_tools import inspect_metrics
from app.llm import ask_llm, llm_available
from app.models import EvidenceFinding, IncidentInput


def investigate_metrics(incident: IncidentInput) -> EvidenceFinding:
    """
    Investigate metrics for the given incident.

    1. Run deterministic tool to extract evidence.
    2. Optionally ask the LLM to refine observation, hypotheses and next step.
    3. Fall back to rule-based logic when the LLM is unavailable.
    """
    finding = inspect_metrics(incident)
    evidence_text = "\n".join(finding.evidence) if finding.evidence else "(no metrics crossed thresholds)"

    # --- LLM path ---
    if llm_available() and finding.evidence:
        system = (
            "You are the Metrics Investigation Agent in a multi-agent AIOps system. "
            "Given metric evidence from a software incident, produce a concise investigation result. "
            "Reply in exactly this format (no extra text):\n"
            "OBSERVATION: <1-3 sentences>\n"
            "HYPOTHESES: <comma-separated short hypotheses>\n"
            "NEXT_STEP: <one clear recommended next investigation step>"
        )
        user = (
            f"Service: {incident.service}\n"
            f"Summary: {incident.summary}\n"
            f"Severity: {incident.severity}\n"
            f"Metric evidence:\n{evidence_text}\n"
            f"Raw metrics: {incident.metrics}"
        )
        llm_reply = ask_llm(system, user)
        if llm_reply:
            observation, next_step = _parse_llm_reply(llm_reply, finding)
            return EvidenceFinding(
                source="metrics_agent",
                observation=observation,
                evidence=finding.evidence,
                suggested_next_step=next_step,
            )

    # --- Deterministic fallback ---
    return _deterministic_metrics_finding(finding)


def _parse_llm_reply(reply: str, base: EvidenceFinding) -> tuple[str, str]:
    observation = base.observation
    next_step = base.suggested_next_step or "Cross-check with logs and recent changes."

    for line in reply.splitlines():
        line = line.strip()
        if line.upper().startswith("OBSERVATION:"):
            observation = line.split(":", 1)[1].strip()
        elif line.upper().startswith("NEXT_STEP:"):
            next_step = line.split(":", 1)[1].strip()
        elif line.upper().startswith("HYPOTHESES:"):
            hyps = line.split(":", 1)[1].strip()
            if hyps:
                observation = f"{observation} Supporting signals: {hyps}."

    return observation, next_step


def _deterministic_metrics_finding(finding: EvidenceFinding) -> EvidenceFinding:
    hypotheses: list[str] = []
    evidence_text = " ".join(finding.evidence).lower()
    has_pool = "database connection pool" in evidence_text
    has_latency = "latency" in evidence_text
    has_5xx = "5xx" in evidence_text
    has_cpu = "cpu" in evidence_text

    if not finding.evidence:
        observation = (
            "No supplied metric crossed the starter thresholds. "
            "Either the service is healthy on these signals or key metrics are missing."
        )
        next_step = "Verify whether required metrics are present and thresholds are appropriate."
    else:
        if has_pool:
            hypotheses.append("Database connection pool near exhaustion")
        if has_latency:
            hypotheses.append("Elevated p95 latency indicating slow downstream calls")
        if has_5xx:
            hypotheses.append("High HTTP 5xx rate – service is returning errors")
        if has_cpu:
            hypotheses.append("High CPU usage on the service")

        observation = finding.observation
        if hypotheses:
            observation += f" Supporting signals: {'; '.join(hypotheses)}."

        if has_pool and not has_latency and not has_5xx:
            observation += " Note: pool pressure is high but latency/5xx are not elevated in the current sample."
        elif (has_latency or has_5xx) and not has_pool:
            observation += " Note: error/latency signals present without clear pool exhaustion."

        next_step = (
            finding.suggested_next_step
            or "Cross-check with logs and recent changes; investigate if signals conflict."
        )

    return EvidenceFinding(
        source="metrics_agent",
        observation=observation,
        evidence=finding.evidence,
        suggested_next_step=next_step,
    )
