"""Log Investigation Agent – investigates error patterns, timeouts, and exceptions."""

from app.incident_tools import inspect_logs
from app.models import EvidenceFinding, IncidentInput


def investigate_logs(incident: IncidentInput) -> EvidenceFinding:
    """
    Investigate logs for the given incident.

    Currently uses the deterministic tool and adds simple rule-based
    hypotheses. Later this will call an LLM for deeper reasoning.
    """
    finding = inspect_logs(incident)

    # Build a simple hypothesis from the evidence
    hypotheses: list[str] = []
    evidence_text = " ".join(finding.evidence).lower()

    if "timeout" in evidence_text or "database connection" in evidence_text:
        hypotheses.append("Database connection acquisition failures / pool pressure")
    if "failed to create order" in evidence_text:
        hypotheses.append("Order creation failing due to downstream DB issues")
    if not finding.evidence:
        hypotheses.append("No clear error signals in the supplied log window")

    observation = finding.observation
    if hypotheses:
        observation += f" Possible causes: {'; '.join(hypotheses)}."

    return EvidenceFinding(
        source="log_agent",
        observation=observation,
        evidence=finding.evidence,
        suggested_next_step=(
            finding.suggested_next_step
            or "Correlate with metrics and recent deployment timeline."
        ),
    )
