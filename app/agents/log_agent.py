"""Log Investigation Agent – investigates error patterns, timeouts, and exceptions."""

from app.incident_tools import inspect_logs
from app.models import EvidenceFinding, IncidentInput


def investigate_logs(incident: IncidentInput) -> EvidenceFinding:
    """
    Run log investigation for the given incident.

    Currently wraps the deterministic log inspection tool.
    Later this will call the LLM with the relevant log evidence.
    """
    finding = inspect_logs(incident)

    return EvidenceFinding(
        source="log_agent",
        observation=finding.observation,
        evidence=finding.evidence,
        suggested_next_step=finding.suggested_next_step,
    )
