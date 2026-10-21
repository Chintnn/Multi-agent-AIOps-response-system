"""HTTP adapter for the local AIOps simulation and investigation service."""
from __future__ import annotations

import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import RLock
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from app import service
from app.demo_service import FaultScenario, simulate_checkout
from app.llm import llm_available
from app.models import (ApprovalRecord, IncidentReport, RecoveryResult,
                        RemediationProposal)
from app.telemetry import (EvidenceQuery, EvidenceQueryResult, EvidenceWindow)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IncidentCreate(StrictModel):
    scenario: FaultScenario
    requests: int = Field(default=12, ge=1, le=500)


class IncidentCreated(StrictModel):
    execution_id: str
    incident_id: str
    service: str
    scenario: FaultScenario
    request_count: int
    status_codes: dict[str, int]
    mean_latency_ms: float
    telemetry_record_count: int
    evidence_window: EvidenceWindow


class HealthResponse(StrictModel):
    status: Literal["ok"]
    llm_configured: bool
    storage: Literal["in_memory"]
    simulated_telemetry: bool
    approvals_enabled: bool


class ScenarioItem(StrictModel):
    id: FaultScenario
    label: str


class ScenariosResponse(StrictModel):
    scenarios: list[ScenarioItem]


class StatusResponse(StrictModel):
    execution_id: str
    incident_id: str
    status: str
    budget_remaining: int
    errors: list[str]
    phase: Literal["created", "queued", "running", "completed", "failed"]
    worker_error: str | None = None


class TraceResponse(StrictModel):
    execution_id: str
    events: list[dict[str, Any]]


class EvidenceResponse(StrictModel):
    execution_id: str
    window: EvidenceWindow | None = None
    results: list[EvidenceQueryResult]
    reason: str | None = None


class RemediationResponse(StrictModel):
    proposal: RemediationProposal | None = None
    approval: ApprovalRecord | None = None
    execution: dict[str, Any] | None = None
    recovery: RecoveryResult | None = None


class ApprovalResponse(StrictModel):
    execution_id: str
    status: str
    remediation: RemediationProposal


class InvestigationAccepted(StrictModel):
    execution_id: str
    phase: Literal["queued"]
    status_url: str


class ApprovalRequest(StrictModel):
    proposal_id: str = Field(min_length=1)
    approved_by: str = Field(min_length=1, max_length=120)
    decision: Literal["approved", "rejected"]
    post_action_metrics: dict[str, float] = Field(default_factory=dict)


class Job:
    def __init__(self):
        self.phase = "queued"
        self.error: str | None = None


app = FastAPI(title="Multi-Agent AIOps Incident Response API", version="1.0.0",
              description="Simulated checkout telemetry and LLM-driven incident investigation.")
origins = [item.strip() for item in os.getenv("AIOPS_FRONTEND_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if item.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type", "Authorization"])
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="aiops-investigation")
_job_lock = RLock()
_jobs: dict[str, Job] = {}
_MAX_REGISTERED_RUNS = 128
_FRONTEND = Path(__file__).resolve().parent.parent / "frontend"


def _run_in_background(execution_id: str) -> None:
    with _job_lock:
        _jobs[execution_id].phase = "running"
    try:
        result = service.start_investigation(execution_id)
        with _job_lock:
            _jobs[execution_id].phase = "failed" if result.status == "failed" else "completed"
            _jobs[execution_id].error = None
    except Exception as exc:
        # Keep provider text and prompts out of the API response; record only a safe class.
        with _job_lock:
            _jobs[execution_id].phase = "failed"
            _jobs[execution_id].error = type(exc).__name__


def _known_status(execution_id: str) -> dict[str, Any]:
    try:
        payload = service.get_execution_status(execution_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown execution ID") from None
    with _job_lock:
        job = _jobs.get(execution_id)
        phase = job.phase if job else ("created" if payload["status"] == "received" else "completed")
        error = job.error if job else None
    payload.update(phase=phase, worker_error=error)
    return payload


@app.get("/api/health", response_model=HealthResponse)
def health() -> dict[str, Any]:
    return {"status": "ok", "llm_configured": llm_available(),
            "storage": "in_memory", "simulated_telemetry": True,
            "approvals_enabled": len(os.getenv("AIOPS_APPROVAL_TOKEN", "")) >= 32}


@app.get("/api/scenarios", response_model=ScenariosResponse)
def scenarios() -> dict[str, Any]:
    return {"scenarios": [{"id": scenario.value, "label": scenario.value.replace("_", " ").title()}
                           for scenario in FaultScenario]}


@app.post("/api/incidents", response_model=IncidentCreated, status_code=status.HTTP_201_CREATED)
def create_incident(request: IncidentCreate) -> IncidentCreated:
    with _job_lock:
        if service.execution_count() >= _MAX_REGISTERED_RUNS:
            raise HTTPException(status_code=429, detail="In-memory run capacity reached; restart the local service to clear completed runs")
        demo = simulate_checkout(request.scenario, request.requests)
        try:
            service.submit_incident(demo.incident, execution_id=demo.execution_id,
                                    evidence_source=demo.telemetry, evidence_window=demo.window)
        except ValueError:
            raise HTTPException(status_code=409, detail="Could not register generated execution") from None
    codes = {str(code): sum(outcome.status_code == code for outcome in demo.outcomes)
             for code in sorted({outcome.status_code for outcome in demo.outcomes})}
    return IncidentCreated(execution_id=demo.execution_id, incident_id=demo.incident.incident_id,
        service=demo.incident.service, scenario=demo.scenario, request_count=len(demo.outcomes),
        status_codes=codes,
        mean_latency_ms=round(sum(row.latency_ms for row in demo.outcomes) / len(demo.outcomes), 2),
        telemetry_record_count=len(demo.telemetry.records), evidence_window=demo.window)


@app.post("/api/incidents/{execution_id}/investigation", response_model=InvestigationAccepted,
          status_code=status.HTTP_202_ACCEPTED)
def start_investigation(execution_id: str) -> InvestigationAccepted:
    try:
        service.get_execution_status(execution_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown execution ID") from None
    with _job_lock:
        if execution_id in _jobs:
            raise HTTPException(status_code=409, detail="Investigation has already been queued")
        if service.get_execution_status(execution_id)["status"] != "received":
            raise HTTPException(status_code=409, detail="Investigation cannot be started in its current state")
        if sum(job.phase in {"queued", "running"} for job in _jobs.values()) >= 16:
            raise HTTPException(status_code=429, detail="Investigation worker capacity reached")
        _jobs[execution_id] = Job()
        _executor.submit(_run_in_background, execution_id)
    return InvestigationAccepted(execution_id=execution_id, phase="queued",
                                 status_url=f"/api/incidents/{execution_id}/status")


@app.get("/api/incidents/{execution_id}/status", response_model=StatusResponse)
def get_status(execution_id: str) -> dict[str, Any]:
    return _known_status(execution_id)


@app.get("/api/incidents/{execution_id}/report", response_model=IncidentReport)
def get_report(execution_id: str) -> IncidentReport:
    _known_status(execution_id)
    with _job_lock:
        phase = _jobs.get(execution_id).phase if execution_id in _jobs else "created"
    if phase in {"queued", "running", "created"}:
        raise HTTPException(status_code=409, detail="Investigation report is not ready")
    report = service.get_incident_report(execution_id)
    if report is None:
        raise HTTPException(status_code=409, detail="Investigation did not produce a report")
    return report.model_dump(mode="json")


@app.get("/api/incidents/{execution_id}/trace", response_model=TraceResponse)
def get_trace(execution_id: str) -> dict[str, Any]:
    _known_status(execution_id)
    return {"execution_id": execution_id, "events": service.get_execution_trace(execution_id)}


@app.get("/api/incidents/{execution_id}/evidence", response_model=EvidenceResponse)
def get_evidence(execution_id: str, source: str | None = None) -> dict[str, Any]:
    try:
        state = service.get_execution_status(execution_id)
        context = service.get_evidence_context(execution_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown execution ID") from None
    if context is None:
        return {"execution_id": execution_id, "results": [], "reason": "No telemetry source was registered"}
    store, window = context
    available = ["logs", "metrics", "traffic", "database_health", "changes", "deployments"]
    selected = [source] if source else available
    if any(name not in available for name in selected):
        raise HTTPException(status_code=422, detail="Unsupported evidence source")
    results = []
    for name in selected:
        query = EvidenceQuery(execution_id=execution_id, incident_id=state["incident_id"],
            service="checkout-api", source=name, window=window)
        result = store.query(query)
        results.append(result.model_dump(mode="json"))
    return {"execution_id": execution_id, "window": window.model_dump(mode="json"), "results": results}


@app.get("/api/incidents/{execution_id}/remediation", response_model=RemediationResponse)
def get_remediation(execution_id: str) -> dict[str, Any]:
    _known_status(execution_id)
    result = service.get_remediation_state(execution_id)
    return {key: value.model_dump(mode="json") if hasattr(value, "model_dump") else value
            for key, value in result.items()}


@app.post("/api/incidents/{execution_id}/approval", response_model=ApprovalResponse)
def submit_approval(execution_id: str, request: ApprovalRequest,
                    authorization: str | None = Header(default=None)) -> dict[str, Any]:
    configured_token = os.getenv("AIOPS_APPROVAL_TOKEN", "")
    if not configured_token:
        raise HTTPException(status_code=403, detail="Approval actions are disabled for this deployment")
    if len(configured_token) < 32:
        raise HTTPException(status_code=503, detail="Approval authentication is not safely configured")
    expected = f"Bearer {configured_token}"
    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Valid operator authorization is required",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        state = service.record_approval(execution_id, request.approved_by, request.decision,
            request.post_action_metrics, proposal_id=request.proposal_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown execution ID") from None
    except ValueError as exc:
        code = 409 if "Proposal ID" in str(exc) or "pending remediation" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from None
    return {"execution_id": execution_id, "status": state.status,
            "remediation": service.get_remediation_state(execution_id)["proposal"].model_dump(mode="json")}


if _FRONTEND.is_dir():
    @app.get("/", include_in_schema=False)
    def frontend_index():
        return FileResponse(_FRONTEND / "index.html")

    from fastapi.staticfiles import StaticFiles
    app.mount("/static", StaticFiles(directory=_FRONTEND), name="static")
