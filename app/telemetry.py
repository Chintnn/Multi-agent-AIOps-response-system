"""Typed, time-bounded interfaces for incident evidence sources."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator


EvidenceSourceName = Literal[
    "logs", "metrics", "traffic", "database_health", "changes", "deployments"
]


class EvidenceWindow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def valid_window(self):
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("Evidence window timestamps must include a timezone")
        if self.start > self.end:
            raise ValueError("Evidence window start must be before its end")
        return self


class EvidenceQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    execution_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    source: EvidenceSourceName
    window: EvidenceWindow


class TelemetryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    record_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    source: EvidenceSourceName
    source_id: str = Field(min_length=1)
    observed_at: datetime
    kind: str = Field(min_length=1)
    message: str = ""
    values: dict[str, str | float | int | bool | None] = Field(default_factory=dict)

    @model_validator(mode="after")
    def observed_time_has_timezone(self):
        if self.observed_at.tzinfo is None:
            raise ValueError("Telemetry observation timestamps must include a timezone")
        return self


class EvidenceQueryResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    query: EvidenceQuery
    status: Literal["available", "insufficient", "unavailable"]
    records: list[TelemetryRecord] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    reason: str | None = None


class EvidenceSource(Protocol):
    def query(self, request: EvidenceQuery) -> EvidenceQueryResult: ...


class InMemoryTelemetryStore:
    """Run-scoped evidence store used by the repeatable local demo and tests."""

    def __init__(self, records: list[TelemetryRecord] | None = None,
                 unavailable_sources: set[EvidenceSourceName] | None = None):
        self.records = list(records or [])
        self.unavailable_sources = set(unavailable_sources or set())

    def add(self, record: TelemetryRecord) -> None:
        self.records.append(TelemetryRecord.model_validate(record))

    def query(self, request: EvidenceQuery) -> EvidenceQueryResult:
        request = EvidenceQuery.model_validate(request)
        if request.source in self.unavailable_sources:
            return EvidenceQueryResult(query=request, status="unavailable",
                missing_evidence=[f"{request.source} source is unavailable"],
                reason=f"No configured provider for {request.source}")
        records = [record for record in self.records
            if record.execution_id == request.execution_id
            and record.incident_id == request.incident_id
            and record.service == request.service
            and record.source == request.source
            and request.window.start <= record.observed_at <= request.window.end]
        records.sort(key=lambda record: (record.observed_at, record.record_id))
        if not records:
            return EvidenceQueryResult(query=request, status="insufficient",
                missing_evidence=[f"No {request.source} observations in the requested window"],
                reason="The source responded but had no matching observations")
        return EvidenceQueryResult(query=request, status="available", records=records)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
