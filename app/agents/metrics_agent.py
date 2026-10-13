"""Metrics Investigation Agent – interprets latency, error rate, CPU, and DB pool signals."""

from app.incident_tools import inspect_metrics
from app.models import EvidenceFinding, IncidentInput


def investigate_metrics(incident: IncidentInput) -> EvidenceFinding:
    """
    Run metrics investigation for the given incident.

    Currently wraps the deterministic metrics inspection tool.
    Later this will call the LLM to interpret trends and contradictions.
    """
    finding = inspect_metrics(incident)

    return EvidenceFinding(
        source="metrics_agent",
        observation=finding.observation,
        evidence=finding.evidence,
        suggested_next_step=finding.suggested_next_step,
    )
