"""Metrics Investigation Agent – interprets latency, error rate, CPU, and DB pool signals."""

from app.incident_tools import inspect_metrics
from app.models import EvidenceFinding, IncidentInput


def investigate_metrics(incident: IncidentInput) -> EvidenceFinding:
    """
    Investigate metrics for the given incident.

    Currently uses the deterministic tool and adds simple rule-based
    hypotheses. Later this will call an LLM to interpret trends and
    contradictions.
    """
    finding = inspect_metrics(incident)

    hypotheses: list[str] = []
    evidence_text = " ".join(finding.evidence).lower()

    if "database connection pool" in evidence_text:
        hypotheses.append("Database connection pool near exhaustion")
    if "latency" in evidence_text:
        hypotheses.append("Elevated p95 latency indicating slow downstream calls")
    if "5xx" in evidence_text:
        hypotheses.append("High HTTP 5xx rate – service is returning errors")
    if "cpu" in evidence_text:
        hypotheses.append("High CPU usage on the service")
    if not finding.evidence:
        hypotheses.append("No metric crossed the configured thresholds")

    observation = finding.observation
    if hypotheses:
        observation += f" Supporting signals: {'; '.join(hypotheses)}."

    return EvidenceFinding(
        source="metrics_agent",
        observation=observation,
        evidence=finding.evidence,
        suggested_next_step=(
            finding.suggested_next_step
            or "Cross-check with logs and recent changes."
        ),
    )
