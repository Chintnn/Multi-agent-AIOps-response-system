from __future__ import annotations

import time

from fastapi.testclient import TestClient

from app import api, service
from app.models import IncidentReport, IncidentState, RemediationProposal, TraceEvent


def setup_function():
    with service._REPOSITORY.lock:
        service._EXECUTIONS.clear()
        service._REPOSITORY.evidence.clear()
    with api._job_lock:
        api._jobs.clear()


def test_health_and_scenario_listing(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "server-only-test-secret")
    monkeypatch.delenv("AIOPS_APPROVAL_TOKEN", raising=False)
    client = TestClient(api.app)
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["storage"] == "in_memory"
    assert "llm_configured" in health.json()
    assert health.json()["approvals_enabled"] is False
    assert "server-only-test-secret" not in health.text
    assert "GROQ_API_KEY" not in health.text
    assert len(client.get("/api/scenarios").json()["scenarios"]) == 5
    assert client.get("/openapi.json").status_code == 200


def test_frontend_assets_are_served_by_fastapi():
    client = TestClient(api.app)
    index = client.get("/")
    assert index.status_code == 200
    assert "SignalOps" in index.text
    assert '/static/app.js' in index.text
    assert "approval-form" not in index.text
    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "/approval" not in script.text
    assert "GROQ_API_KEY" not in script.text
    assert client.get("/static/styles.css").status_code == 200
    assert "GROQ_API_KEY" not in index.text


def test_render_blueprint_uses_port_health_check_and_existing_fastapi_entrypoint():
    from pathlib import Path

    blueprint = Path("render.yaml").read_text(encoding="utf-8")
    assert "pip install -r requirements.txt" in blueprint
    assert "uvicorn app.api:app --host 0.0.0.0 --port $PORT" in blueprint
    assert "healthCheckPath: /api/health" in blueprint


def test_gitignore_excludes_local_secrets_runtime_and_generated_files():
    from pathlib import Path

    ignored = Path(".gitignore").read_text(encoding="utf-8")
    for pattern in (".env", ".env.*", ".venv/", "__pycache__/", ".pytest_cache/",
                    "traces/", "node_modules/", "*.sqlite3"):
        assert pattern in ignored
    assert "!.env.example" in ignored


def test_incident_creation_validation_and_real_evidence_query():
    client = TestClient(api.app)
    response = client.post("/api/incidents", json={"scenario": "faulty_deployment", "requests": 3})
    assert response.status_code == 201
    created = response.json()
    assert created["request_count"] == 3
    assert created["telemetry_record_count"] == 13  # deployment plus four observations per request
    evidence = client.get(f"/api/incidents/{created['execution_id']}/evidence")
    assert evidence.status_code == 200
    by_source = {row["query"]["source"]: row for row in evidence.json()["results"]}
    assert len(by_source["logs"]["records"]) == 3
    assert by_source["logs"]["records"][0]["source_id"] == "checkout-api/logs"
    assert by_source["deployments"]["status"] == "available"
    assert by_source["changes"]["status"] == "insufficient"
    assert client.post("/api/incidents", json={"scenario": "fake", "requests": 3}).status_code == 422
    assert client.post("/api/incidents", json={"scenario": "baseline", "requests": 501}).status_code == 422


def test_unknown_execution_and_invalid_evidence_source():
    client = TestClient(api.app)
    assert client.get("/api/incidents/unknown/status").status_code == 404
    created = client.post("/api/incidents", json={"scenario": "baseline"}).json()
    assert client.get(f"/api/incidents/{created['execution_id']}/evidence?source=secrets").status_code == 422
    assert client.get("/api/incidents/unknown/report").status_code == 404


def test_background_investigation_status_report_and_trace(monkeypatch):
    client = TestClient(api.app)

    def fake_run(incident, *, execution_id, **kwargs):
        state = IncidentState(incident=incident, execution_id=execution_id,
            status="awaiting_information", outstanding_questions=["Need a request ID"])
        state.trace.append(TraceEvent(execution_id=execution_id, event_type="routing_decision",
            agent="triage", details={"next_agent": "more_information"}))
        state.report = IncidentReport(incident_id=incident.incident_id, execution_id=execution_id,
            service=incident.service, summary=incident.summary, severity=incident.severity,
            status="awaiting_information", findings=[], hypotheses=[],
            root_cause_assessment="Evidence is insufficient.", investigations=[], errors=[],
            outstanding_questions=["Need a request ID"])
        return state

    monkeypatch.setattr(service, "run_incident", fake_run)
    created = client.post("/api/incidents", json={"scenario": "high_latency", "requests": 4}).json()
    accepted = client.post(f"/api/incidents/{created['execution_id']}/investigation")
    assert accepted.status_code == 202
    assert accepted.json()["phase"] == "queued"
    deadline = time.time() + 3
    while time.time() < deadline:
        current = client.get(f"/api/incidents/{created['execution_id']}/status").json()
        if current["phase"] in {"completed", "failed"}:
            break
        time.sleep(.01)
    assert current["phase"] == "completed"
    assert current["status"] == "awaiting_information"
    assert client.get(f"/api/incidents/{created['execution_id']}/report").json()["status"] == "awaiting_information"
    trace = client.get(f"/api/incidents/{created['execution_id']}/trace").json()["events"]
    assert trace[0]["details"]["next_agent"] == "more_information"
    assert client.post(f"/api/incidents/{created['execution_id']}/investigation").status_code == 409


def test_provider_failure_is_reported_without_raw_exception(monkeypatch):
    client = TestClient(api.app)
    def broken_run(*args, **kwargs):
        raise RuntimeError("private prompt and API key must not escape")
    monkeypatch.setattr(service, "run_incident", broken_run)
    created = client.post("/api/incidents", json={"scenario": "baseline"}).json()
    client.post(f"/api/incidents/{created['execution_id']}/investigation")
    deadline = time.time() + 3
    while time.time() < deadline:
        result = client.get(f"/api/incidents/{created['execution_id']}/status").json()
        if result["phase"] == "failed":
            break
        time.sleep(.01)
    assert result["phase"] == "failed"
    assert result["status"] == "failed"
    assert "private prompt" not in str(result)
    assert result["errors"] == ["Investigation execution failed: RuntimeError"]
    assert client.get(f"/api/incidents/{created['execution_id']}/report").status_code == 409


def test_mismatched_proposal_id_cannot_authorize_remediation(monkeypatch):
    token = "t" * 40
    monkeypatch.setenv("AIOPS_APPROVAL_TOKEN", token)
    client = TestClient(api.app)
    created = client.post("/api/incidents", json={"scenario": "baseline"}).json()
    execution_id = created["execution_id"]
    state = service._EXECUTIONS[execution_id]
    state.status = "awaiting_approval"
    state.remediation = RemediationProposal(action="scale_up_db_pool", risk_level="medium",
        rationale="Evidence supports the action", expected_benefit="Reduce saturation",
        approval_status="awaiting_approval")
    state.report = IncidentReport(incident_id=state.incident.incident_id, execution_id=execution_id,
        service=state.incident.service, summary=state.incident.summary, severity=state.incident.severity,
        status="awaiting_approval", findings=[], hypotheses=[], root_cause_assessment="Supported",
        investigations=[], errors=[])
    body = {"proposal_id": "wrong-proposal", "approved_by": "Reviewer", "decision": "approved",
            "post_action_metrics": {}}
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(f"/api/incidents/{execution_id}/approval", json=body, headers=headers)
    assert response.status_code == 409
    assert state.approval is None
    assert state.simulated_execution is None
    body["proposal_id"] = state.remediation.proposal_id
    assert client.post(f"/api/incidents/{execution_id}/approval", json=body, headers=headers).status_code == 200
    assert state.simulated_execution["executed"] is True
    assert state.recovery.outcome == "insufficient_evidence"


def test_rejecting_proposal_records_decision_without_execution(monkeypatch):
    token = "r" * 40
    monkeypatch.setenv("AIOPS_APPROVAL_TOKEN", token)
    client = TestClient(api.app)
    created = client.post("/api/incidents", json={"scenario": "baseline"}).json()
    execution_id = created["execution_id"]
    state = service._EXECUTIONS[execution_id]
    state.status = "awaiting_approval"
    state.remediation = RemediationProposal(action="rollback_deployment", risk_level="high",
        rationale="Evidence supports rollback", expected_benefit="Restore configuration",
        approval_status="awaiting_approval")
    proposal_id = state.remediation.proposal_id
    response = client.post(f"/api/incidents/{execution_id}/approval", json={
        "proposal_id": proposal_id, "approved_by": "Reviewer", "decision": "rejected"},
        headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["status"] == "unresolved"
    assert state.simulated_execution is None


def test_public_approval_is_disabled_and_authenticated_endpoint_rejects_bad_tokens(monkeypatch):
    client = TestClient(api.app)
    created = client.post("/api/incidents", json={"scenario": "baseline"}).json()
    execution_id = created["execution_id"]
    state = service._EXECUTIONS[execution_id]
    state.status = "awaiting_approval"
    state.remediation = RemediationProposal(action="scale_up_db_pool", risk_level="medium",
        rationale="Supported by evidence", expected_benefit="Reduce pressure",
        approval_status="awaiting_approval")
    body = {"proposal_id": state.remediation.proposal_id, "approved_by": "Public visitor",
            "decision": "approved"}

    monkeypatch.delenv("AIOPS_APPROVAL_TOKEN", raising=False)
    disabled = client.post(f"/api/incidents/{execution_id}/approval", json=body)
    assert disabled.status_code == 403
    assert state.approval is None and state.simulated_execution is None

    token = "s" * 40
    monkeypatch.setenv("AIOPS_APPROVAL_TOKEN", token)
    monkeypatch.setenv("AIOPS_APPROVAL_TOKEN", "too-short")
    weak_config = client.post(f"/api/incidents/{execution_id}/approval", json=body)
    assert weak_config.status_code == 503
    assert state.approval is None and state.simulated_execution is None

    monkeypatch.setenv("AIOPS_APPROVAL_TOKEN", token)
    unauthorized = client.post(f"/api/incidents/{execution_id}/approval", json=body,
        headers={"Authorization": "Bearer wrong-token"})
    assert unauthorized.status_code == 401
    assert state.approval is None and state.simulated_execution is None
    assert client.get("/api/health").json()["approvals_enabled"] is True

    authorized = client.post(f"/api/incidents/{execution_id}/approval", json=body,
        headers={"Authorization": f"Bearer {token}"})
    assert authorized.status_code == 200
    assert token not in authorized.text
    assert state.approval is not None
    assert state.simulated_execution["simulated"] is True
