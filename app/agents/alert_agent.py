
import os

from dotenv import load_dotenv
from langchain_groq import ChatGroq
from pydantic import BaseModel, Field

from app.models import IncidentInput

load_dotenv()


class AlertTriageResult(BaseModel):
    """Structured assessment produced by the Alert Agent."""

    priority: str = Field(
        description="Incident priority: low, medium, high, or critical"
    )
    assessment: str = Field(
        description="Brief explanation of the incident based on supplied evidence"
    )
    suspected_causes: list[str] = Field(
        description="Possible causes; do not present hypotheses as proven facts"
    )
    next_investigation: str = Field(
        description="Which investigation should happen next: logs, metrics, changes, or more_information"
    )
    missing_information: list[str] = Field(
        description="Important information that is missing, if any"
    )


def create_alert_agent():
    """Create the LLM-backed triage agent."""

    if not os.getenv("GROQ_API_KEY"):
        raise RuntimeError(
            "GROQ_API_KEY is missing. Add it to your .env file."
        )

    llm = ChatGroq(
        model="openai/gpt-oss-120b",
        temperature=0,
    )

    return llm.with_structured_output(AlertTriageResult)


def investigate_alert(incident: IncidentInput) -> AlertTriageResult:
    """Assess an incident and recommend the next investigation."""

    agent = create_alert_agent()

    prompt = f"""
You are the Alert and Triage Agent in a multi-agent AIOps system.

Assess the incident below using only the supplied information.

Rules:
- Choose a sensible priority based on the symptoms and severity.
- Separate possible causes from confirmed facts.
- Recommend one next investigation: logs, metrics, changes, or more_information.
- Request missing information when the evidence is insufficient.
- Never recommend executing commands or changing production systems.
- Return the requested structured result.

Incident data:
{incident.model_dump_json(indent=2)}
"""

    return agent.invoke(prompt)
