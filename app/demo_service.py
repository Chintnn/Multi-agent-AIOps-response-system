"""In-process checkout simulator that emits queryable, timestamped telemetry."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.models import IncidentInput
from app.telemetry import (EvidenceWindow, InMemoryTelemetryStore,
                           TelemetryRecord, utc_now)


class FaultScenario(str, Enum):
    baseline = "baseline"
    database_connection_pressure = "database_connection_pressure"
    high_latency = "high_latency"
    elevated_5xx = "elevated_5xx"
    faulty_deployment = "faulty_deployment"


class CheckoutOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    request_id: str
    observed_at: datetime
    status_code: int = Field(ge=100, le=599)
    latency_ms: float = Field(ge=0)
    database_connected: bool


class DemoRun(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    execution_id: str
    incident: IncidentInput
    window: EvidenceWindow
    outcomes: list[CheckoutOutcome]
    telemetry: InMemoryTelemetryStore
    scenario: FaultScenario


class CheckoutDemoService:
    """Deterministic request handler; outcomes and logs are generated per request."""

    def __init__(self, *, scenario: FaultScenario, incident_id: str,
                 execution_id: str | None = None, started_at: datetime | None = None):
        self.scenario = FaultScenario(scenario)
        self.incident_id = incident_id
        self.execution_id = execution_id or str(uuid4())
        self.started_at = started_at or utc_now()
        if self.started_at.tzinfo is None:
            raise ValueError("started_at must include a timezone")
        self.store = InMemoryTelemetryStore()
        self.outcomes: list[CheckoutOutcome] = []
        self._record_number = 0
        self.base_pool_size = 20
        self.pool_size = 2 if self.scenario == FaultScenario.faulty_deployment else self.base_pool_size
        if self.scenario == FaultScenario.faulty_deployment:
            self._add_record("deployments", self.started_at - timedelta(seconds=1),
                "configuration_deployment",
                "Checkout 2.4.1 reduced db_pool_max from 20 to 2",
                {"version": "2.4.1", "parameter": "db_pool_max",
                 "previous_value": 20, "new_value": 2})

    def handle_checkout(self, request_id: str, observed_at: datetime | None = None) -> CheckoutOutcome:
        observed_at = observed_at or self.started_at + timedelta(seconds=len(self.outcomes))
        if observed_at.tzinfo is None:
            raise ValueError("observed_at must include a timezone")
        if self.scenario in {FaultScenario.database_connection_pressure, FaultScenario.faulty_deployment}:
            active = self.pool_size
            pool_percent = 100.0
            connected = False
            latency, status = 1800.0, 503
        elif self.scenario == FaultScenario.high_latency:
            active = max(1, int(self.pool_size * .6))
            pool_percent = active / self.pool_size * 100
            connected = True
            latency, status = 2500.0, 200
        elif self.scenario == FaultScenario.elevated_5xx:
            active = max(1, int(self.pool_size * .3))
            pool_percent = active / self.pool_size * 100
            connected = True
            latency, status = 350.0, 500
        else:
            active = max(1, int(self.pool_size * .2))
            pool_percent = active / self.pool_size * 100
            connected = True
            latency, status = 180.0, 200
        outcome = CheckoutOutcome(request_id=request_id, observed_at=observed_at,
            status_code=status, latency_ms=latency, database_connected=connected)
        self.outcomes.append(outcome)
        level = "ERROR" if status >= 500 or not connected else "INFO"
        message = (f"{observed_at.isoformat()} {level} checkout request_id={request_id} "
            f"status={status} latency_ms={latency:g} "
            + ("database connection acquisition timed out" if not connected else "request completed"))
        self._add_record("logs", observed_at, "application_log", message,
            {"level": level, "request_id": request_id, "status_code": status})
        self._add_record("traffic", observed_at, "http_request", message,
            {"request_id": request_id, "status_code": status, "latency_ms": latency})
        cpu = 72.0 if self.scenario in {FaultScenario.database_connection_pressure,
                                        FaultScenario.faulty_deployment} else 48.0
        self._add_record("metrics", observed_at, "service_metrics", "Checkout request metrics",
            {"cpu_percent": cpu, "db_connection_pool_percent": pool_percent})
        self._add_record("database_health", observed_at, "database_health_check",
            "Database connection pool is saturated" if not connected else "Database is accepting connections",
            {"healthy": connected, "active_connections": active,
             "max_connections": self.pool_size, "db_connection_pool_percent": pool_percent})
        return outcome

    def run_requests(self, count: int) -> list[CheckoutOutcome]:
        if count < 1 or count > 500:
            raise ValueError("Request count must be between 1 and 500")
        return [self.handle_checkout(f"req-{i + 1:04d}", self.started_at + timedelta(seconds=i))
                for i in range(count)]

    def finish(self, summary: str | None = None) -> DemoRun:
        if not self.outcomes:
            raise ValueError("Run at least one checkout request before creating an incident")
        start = self.started_at - timedelta(seconds=1)
        end = max(outcome.observed_at for outcome in self.outcomes)
        scenario_text = {
            FaultScenario.baseline: "Checkout requests completed under baseline configuration",
            FaultScenario.database_connection_pressure: "Checkout requests failed to acquire database connections",
            FaultScenario.high_latency: "Checkout requests experienced high latency",
            FaultScenario.elevated_5xx: "Checkout requests returned elevated server errors",
            FaultScenario.faulty_deployment: "Checkout requests failed after a faulty pool configuration deployment",
        }[self.scenario]
        incident = IncidentInput(incident_id=self.incident_id, service="checkout-api",
            summary=summary or scenario_text, severity="high" if self.scenario != FaultScenario.baseline else "low",
            symptoms=[scenario_text], metrics={}, logs=[], recent_changes=[])
        return DemoRun(execution_id=self.execution_id, incident=incident,
            window=EvidenceWindow(start=start, end=end), outcomes=list(self.outcomes),
            telemetry=self.store, scenario=self.scenario)

    def _add_record(self, source: str, at: datetime, kind: str, message: str,
                    values: dict) -> None:
        self._record_number += 1
        source_id = f"checkout-api/{source}"
        self.store.add(TelemetryRecord(record_id=f"obs-{self._record_number:05d}",
            execution_id=self.execution_id, incident_id=self.incident_id,
            service="checkout-api", source=source, source_id=source_id,
            observed_at=at, kind=kind, message=message, values=values))


def simulate_checkout(scenario: FaultScenario | str, requests: int = 12, *,
                      started_at: datetime | None = None,
                      execution_id: str | None = None,
                      incident_id: str | None = None) -> DemoRun:
    execution_id = execution_id or str(uuid4())
    simulator = CheckoutDemoService(scenario=FaultScenario(scenario),
        incident_id=incident_id or f"INC-{execution_id[:8]}",
        execution_id=execution_id, started_at=started_at)
    simulator.run_requests(requests)
    return simulator.finish()
