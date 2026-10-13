"""
Change Analysis Agent

Owner: Member 3

Responsibility:
- Takes deployment/config change history and the incident timestamp.
- Checks whether any change occurred near the incident window.
- Returns evidence for or against a change-related root cause.
- Does NOT assume the latest deployment caused the incident by default;
  must check timing and correlate with other evidence.
"""

from app.models import AgentFinding  # TODO: confirm this model exists / adjust import


def analyze_change(incident_id: str, deployment_history: list) -> AgentFinding:
    """
    Analyze deployment/change history against the incident.

    Args:
        incident_id: ID of the incident being investigated.
        deployment_history: List of recent deployments/config changes.

    Returns:
        AgentFinding: structured evidence, hypotheses, and recommended next step.
    """
    # TODO: implement timing comparison logic
    # TODO: call LLM (Groq/Llama) with incident + deployment context
    # TODO: validate output against shared schema
    raise NotImplementedError("Change Analysis Agent not yet implemented")