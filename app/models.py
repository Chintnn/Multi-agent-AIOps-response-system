from typing import Any
from pydantic import BaseModel, Field


class IncidentInput(BaseModel):
    """Validated information describing one software incident."""

    incident_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    summary: str = Field(min_length=5)
    severity: str = Field(pattern=r"^(low|medium|high|critical)$")
    symptoms: list[str] = Field(min_length=1)
    metrics: dict[str, float] = Field(default_factory=dict)
    logs: list[str] = Field(default_factory=list)
    recent_changes: list[str] = Field(default_factory=list)


class EvidenceFinding(BaseModel):
    """A finding from one investigation tool or agent."""

    source: str
    observation: str
    evidence: list[str] = Field(default_factory=list)
    suggested_next_step: str | None = None


class IncidentReport(BaseModel):
    """Structured output that can later be returned by the orchestrator."""

    incident_id: str
    service: str
    severity: str
    findings: list[EvidenceFinding]
    preliminary_assessment: str
    requires_human_approval: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
