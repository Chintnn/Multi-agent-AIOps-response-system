"""
Change Analysis Agent

Owner: Member 3

Responsibility:
- Inspects an incident's recent_changes for signals of a change-related cause.
- Does NOT assume the latest deployment caused the incident by default;
  flags it as a hypothesis to correlate with logs/metrics, not a conclusion.
"""

from app.models import EvidenceFinding, IncidentInput


def analyze_change(incident: IncidentInput) -> EvidenceFinding:
    """
    Inspect recent_changes for deployment/config changes that could plausibly
    relate to the incident. Simple keyword-based baseline, consistent with
    inspect_logs / inspect_metrics in incident_tools.py.
    """
    change_keywords = ("deploy", "config", "rollout", "release", "migration")

    matches = [
        change
        for change in incident.recent_changes
        if any(term in change.lower() for term in change_keywords)
    ]

    if matches:
        observation = (
            f"Found {len(matches)} recent change(s) that may be related to the incident."
        )
        next_step = (
            "Correlate the timing and nature of these changes with log and metric "
            "evidence before concluding they caused the incident."
        )
    else:
        observation = "No recent changes were found that obviously relate to this incident."
        next_step = "Treat change history as unlikely cause; focus on logs and metrics."

    return EvidenceFinding(
        source="change_agent",
        observation=observation,
        evidence=matches,
        suggested_next_step=next_step,
    )