from datetime import datetime, timedelta, timezone

import pytest

from app.demo_service import FaultScenario, simulate_checkout
from app.models import EvidenceRequest, Hypothesis, IncidentInput, LogAnalysis, SpecialistReasoning, TriageDecision
from app.orchestrator import run_incident
from app.telemetry import EvidenceQuery, EvidenceWindow, InMemoryTelemetryStore, TelemetryRecord


START = datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(("scenario", "status", "latency"), [
    (FaultScenario.baseline, 200, 180.0),
    (FaultScenario.database_connection_pressure, 503, 1800.0),
    (FaultScenario.high_latency, 200, 2500.0),
    (FaultScenario.elevated_5xx, 500, 350.0),
    (FaultScenario.faulty_deployment, 503, 1800.0),
])
def test_scenarios_generate_request_outcomes_and_timestamped_telemetry(scenario, status, latency):
    run = simulate_checkout(scenario, requests=3, started_at=START,
                            execution_id="exec-demo", incident_id="INC-demo")

    assert [row.status_code for row in run.outcomes] == [status] * 3
    assert [row.latency_ms for row in run.outcomes] == [latency] * 3
    assert len(run.telemetry.records) == (13 if scenario == FaultScenario.faulty_deployment else 12)
    assert all(row.execution_id == run.execution_id for row in run.telemetry.records)
    logs = [row for row in run.telemetry.records if row.source == "logs"]
    assert len(logs) == 3
    assert all(row.observed_at.tzinfo is not None and "request_id=req-" in row.message for row in logs)
    if scenario == FaultScenario.faulty_deployment:
        deployment = next(row for row in run.telemetry.records if row.source == "deployments")
        assert deployment.values["previous_value"] == 20
        assert deployment.values["new_value"] == 2


def test_typed_queries_filter_by_window_incident_and_execution():
    run = simulate_checkout(FaultScenario.high_latency, requests=3, started_at=START,
                            execution_id="exec-window", incident_id="INC-window")
    window = EvidenceWindow(start=START + timedelta(seconds=1), end=START + timedelta(seconds=2))
    result = run.telemetry.query(EvidenceQuery(execution_id="exec-window",
        incident_id="INC-window", service="checkout-api", source="traffic", window=window))

    assert result.status == "available"
    assert [record.values["request_id"] for record in result.records] == ["req-0002", "req-0003"]
    assert all(record.observed_at in (window.start, window.end) for record in result.records)
    wrong_execution = run.telemetry.query(EvidenceQuery(execution_id="other",
        incident_id="INC-window", service="checkout-api", source="traffic", window=window))
    assert wrong_execution.status == "insufficient"
    assert wrong_execution.records == []


def test_evidence_windows_reject_naive_or_reversed_times():
    with pytest.raises(ValueError, match="timezone"):
        EvidenceWindow(start=datetime(2026, 1, 2), end=datetime(2026, 1, 3))
    with pytest.raises(ValueError, match="before its end"):
        EvidenceWindow(start=START + timedelta(seconds=2), end=START)


def test_unavailable_and_empty_sources_are_distinguished():
    run = simulate_checkout(FaultScenario.baseline, requests=1, started_at=START,
                            execution_id="exec-source", incident_id="INC-source")
    query = EvidenceQuery(execution_id=run.execution_id, incident_id=run.incident.incident_id,
        service="checkout-api", source="database_health", window=run.window)
    unavailable = InMemoryTelemetryStore(run.telemetry.records,
        unavailable_sources={"database_health"}).query(query)
    assert unavailable.status == "unavailable"
    empty_query = query.model_copy(update={"source": "deployments"})
    empty = run.telemetry.query(empty_query)
    assert empty.status == "insufficient"


def test_metrics_agent_uses_telemetry_and_preserves_provenance(monkeypatch, tmp_path):
    from app.agents.metrics_agent import investigate_metrics

    run = simulate_checkout(FaultScenario.elevated_5xx, requests=4, started_at=START,
                            execution_id="exec-agent", incident_id="INC-agent")
    captured = {}
    monkeypatch.setattr("app.agents.metrics_agent.invoke_structured", lambda system, prompt, schema:
        (captured.update(prompt=prompt) or SpecialistReasoning(summary="Observed elevated errors.")))

    finding = investigate_metrics(run.incident, "Check live demo telemetry", evidence_source=run.telemetry,
        evidence_window=run.window, execution_id=run.execution_id)

    assert finding.metric_values["http_5xx_rate_percent"] == 100.0
    assert finding.metric_values["p95_latency_ms"] == 350.0
    assert any(ref.execution_id == run.execution_id and ref.source_id == "checkout-api/traffic"
               for ref in finding.evidence_refs)
    assert "Telemetry query results" in captured["prompt"]


def test_high_latency_metrics_report_structured_values_without_claiming_cause(monkeypatch):
    from app.agents.metrics_agent import investigate_metrics

    run = simulate_checkout(FaultScenario.high_latency, requests=10, started_at=START,
        execution_id="exec-high-latency", incident_id="INC-high-latency")
    captured = {}
    monkeypatch.setattr("app.agents.metrics_agent.invoke_structured", lambda system, prompt, schema:
        (captured.update(prompt=prompt) or SpecialistReasoning(
            summary="Latency is elevated while supplied infrastructure health readings are normal.")))

    finding = investigate_metrics(run.incident, "Interpret the ten generated request observations.",
        evidence_source=run.telemetry, evidence_window=run.window, execution_id=run.execution_id)

    assert finding.metric_values == {"p95_latency_ms": 2500.0,
        "http_5xx_rate_percent": 0.0, "cpu_percent": 48.0,
        "db_connection_pool_percent": 60.0}
    assert finding.calculated_values == {"p95_latency_ms": 2500.0,
        "http_5xx_rate_percent": 0.0}
    assert finding.abnormal_metrics == ["p95_latency_ms"]
    assert any("10 request outcome(s)" in fact for fact in finding.observed_facts)
    assert any("latency_ms=2500" in fact and "10 of 10" in fact for fact in finding.observed_facts)
    assert any("cpu_percent=48%" in fact for fact in finding.observed_facts)
    assert any("db_connection_pool_percent=60%" in fact for fact in finding.observed_facts)
    assert any("healthy=true (10/10)" in fact for fact in finding.observed_facts)
    assert any("active_connections=12" in fact for fact in finding.observed_facts)
    assert any("max_connections=20" in fact for fact in finding.observed_facts)
    assert any(ref.source == "metrics" and "cpu_percent=48.0" in ref.excerpt
               for ref in finding.evidence_refs)
    assert any(ref.source == "database_health" and "healthy=true" in ref.excerpt
               and "active_connections=12" in ref.excerpt for ref in finding.evidence_refs)
    assert any("do not establish its cause" in item for item in finding.uncertainty)
    assert "'healthy': True" in captured["prompt"]


def test_retrieved_evidence_is_not_reported_missing_and_requires_specialist_analysis(monkeypatch, tmp_path):
    run = simulate_checkout(FaultScenario.high_latency, requests=2, started_at=START,
        execution_id="exec-reconcile", incident_id="INC-reconcile")
    decisions = iter([
        TriageDecision(assessment="Request logs to inspect the generated latency records.", next_agent="logs",
            investigation_question="Review application request logs.", expected_information_gain="Interpret log outcomes.",
            confidence="moderate", decision_rationale="Logs can provide the requested timestamps.",
            evidence_gaps=["timestamped error logs"],
            evidence_requests=[EvidenceRequest(source="logs", reason="Retrieve time-windowed request logs.")]),
        TriageDecision(assessment="Retrieved logs should be interpreted by the log specialist.", next_agent="logs",
            investigation_question="Interpret the generated request logs.", expected_information_gain="Analyze log content.",
            confidence="moderate", decision_rationale="Retrieval has not yet been analyzed."),
        TriageDecision(assessment="Logs are available but the bottleneck remains unknown.", next_agent="more_information",
            investigation_question="A trace or dependency timing breakdown is needed.", expected_information_gain="Identify the latency bottleneck.",
            confidence="low", decision_rationale="The records do not identify a causal bottleneck.",
            evidence_gaps=["timestamped error logs", "Cause remains unknown without dependency tracing."]),
    ])
    triage_inputs = []
    def triage(incident, findings, history, outstanding):
        triage_inputs.append((findings, list(outstanding)))
        return next(decisions)
    monkeypatch.setattr("app.orchestrator.investigate_alert", triage)
    monkeypatch.setattr("app.agents.log_agent.invoke_structured", lambda *args:
        SpecialistReasoning(summary="The timestamped logs show successful HTTP 200 responses."))

    state = run_incident(run.incident, execution_id=run.execution_id,
        evidence_source=run.telemetry, evidence_window=run.window)

    states = state.report.metadata["evidence_sources"]
    assert state.status == "awaiting_information"
    assert states["logs"]["status"] == "analyzed"
    assert states["traffic"]["status"] == "not_requested"
    assert state.report.outstanding_questions == ["Cause remains unknown without dependency tracing."]
    initial_route = next(event for event in state.trace if event.event_type == "routing_decision")
    assert initial_route.details["evidence_gaps"] == ["timestamped error logs"]
    reconciliation = [event for event in state.trace if event.event_type == "evidence_reconciliation"][-1]
    assert reconciliation.details["reported_evidence_gaps"] == [
        "timestamped error logs", "Cause remains unknown without dependency tracing."]
    assert reconciliation.details["evidence_gaps"] == [
        "Cause remains unknown without dependency tracing."]
    assert any(query.status == "analyzed" for finding in state.findings
               for query in finding.evidence_queries if query.source == "logs")


def test_log_and_change_agents_query_telemetry_sources(monkeypatch):
    from app.agents.change_agent import analyze_change
    from app.agents.log_agent import investigate_logs

    run = simulate_checkout(FaultScenario.faulty_deployment, requests=2, started_at=START,
                            execution_id="exec-specialists", incident_id="INC-specialists")
    monkeypatch.setattr("app.agents.log_agent.invoke_structured", lambda *args:
        SpecialistReasoning(summary="Timestamped simulated errors found."))
    monkeypatch.setattr("app.agents.change_agent.invoke_structured", lambda *args:
        SpecialistReasoning(summary="Faulty pool configuration recorded."))

    logs = investigate_logs(run.incident, evidence_source=run.telemetry,
        evidence_window=run.window, execution_id=run.execution_id)
    changes = analyze_change(run.incident, evidence_source=run.telemetry,
        evidence_window=run.window, execution_id=run.execution_id)

    assert any(ref.source == "logs" and ref.execution_id == run.execution_id for ref in logs.evidence_refs)
    assert any(ref.source == "deployments" and ref.source_id == "checkout-api/deployments"
               for ref in changes.evidence_refs)
    assert any("reduced db_pool_max from 20 to 2" in change for change in changes.candidate_changes)


def test_triage_evidence_request_is_retrieved_and_handed_to_next_agent(monkeypatch, tmp_path):
    run = simulate_checkout(FaultScenario.high_latency, requests=2, started_at=START,
                            execution_id="exec-handoff", incident_id="INC-handoff")
    decisions = iter([
        TriageDecision(assessment="Need request history.", next_agent="more_information",
            investigation_question="Retrieve traffic history.", expected_information_gain="Request outcomes.",
            confidence="moderate", decision_rationale="Traffic is missing.",
            evidence_requests=[EvidenceRequest(source="traffic", reason="Compare response status and latency.")]),
        TriageDecision(assessment="Traffic evidence is available.", next_agent="logs",
            investigation_question="Review correlated application logs.", expected_information_gain="Correlate failures.",
            confidence="moderate", decision_rationale="Logs are the next source."),
        TriageDecision(assessment="Investigation is incomplete.", next_agent="more_information",
            investigation_question="Need another source.", expected_information_gain="Additional DB evidence.",
            confidence="moderate", decision_rationale="No DB health observations were requested.",
            evidence_gaps=["database health"]),
    ])
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *args: next(decisions))
    captured = {}
    def fake_logs(incident, question, prior, **kwargs):
        captured["prior"] = prior
        return LogAnalysis(summary="Logs reviewed.")
    monkeypatch.setattr("app.orchestrator.investigate_logs", fake_logs)

    state = run_incident(run.incident, execution_id=run.execution_id,
        evidence_source=run.telemetry, evidence_window=run.window)

    query_event = next(event for event in state.trace if event.event_type == "evidence_query_result")
    assert query_event.details["source"] == "traffic"
    assert query_event.details["status"] == "available"
    assert query_event.details["record_count"] == 2
    handoff = next(event.details["handoff"] for event in state.trace
                   if event.event_type == "agent_invoked" and event.agent == "logs")
    telemetry_finding = next(finding for finding in captured["prior"]
                             if any(ref.execution_id == run.execution_id for ref in finding.evidence_refs))
    assert telemetry_finding.finding_id in handoff["shared_finding_ids"]
    assert state.status == "awaiting_information"


def test_successful_evidence_retrieval_is_pending_until_specialist_analysis(monkeypatch, tmp_path):
    run = simulate_checkout(FaultScenario.high_latency, requests=2, started_at=START,
        execution_id="exec-evidence-state", incident_id="INC-evidence-state")
    decisions = iter([
        TriageDecision(assessment="Retrieve logs for specialist review.", next_agent="logs",
            investigation_question="Review generated request logs.", expected_information_gain="Interpret request evidence.",
            confidence="moderate", decision_rationale="The logs can answer the current question.",
            evidence_gaps=["timestamped error logs"],
            evidence_requests=[EvidenceRequest(source="logs", reason="Retrieve the request log records.")]),
        TriageDecision(assessment="Logs are retrieved but still need interpretation.", next_agent="logs",
            investigation_question="Interpret request log evidence.", expected_information_gain="Analyze request results.",
            confidence="moderate", decision_rationale="Retrieval alone is not analysis."),
        TriageDecision(assessment="The logs are analyzed; a causal bottleneck remains unknown.",
            next_agent="more_information", investigation_question="Obtain dependency timing traces.",
            expected_information_gain="Identify the latency bottleneck.", confidence="low",
            decision_rationale="The available logs do not establish causation.",
            evidence_gaps=["timestamped error logs", "Cause remains unknown without dependency tracing."]),
    ])
    seen = []
    def triage(incident, findings, history, outstanding):
        seen.append(findings)
        return next(decisions)
    monkeypatch.setattr("app.orchestrator.investigate_alert", triage)
    monkeypatch.setattr("app.agents.log_agent.invoke_structured", lambda *args:
        SpecialistReasoning(summary="The request logs contain timestamped HTTP outcomes."))

    state = run_incident(run.incident, execution_id=run.execution_id,
        evidence_source=run.telemetry, evidence_window=run.window)

    statuses = state.report.metadata["evidence_sources"]
    assert statuses["logs"]["status"] == "analyzed"
    assert statuses["logs"]["record_count"] == 2
    assert statuses["traffic"]["status"] == "not_requested"
    assert state.report.outstanding_questions == ["Cause remains unknown without dependency tracing."]
    assert next(f for f in seen[1] if f.evidence_queries).evidence_queries[0].status == "retrieved"
    assert any(event.event_type == "evidence_source_status" and event.details.get("status") == "pending"
               for event in state.trace)
    assert any(event.event_type == "evidence_source_status" and event.details.get("status") == "retrieved"
               for event in state.trace)
    assert any(event.event_type == "evidence_reconciliation" and
               event.details["reported_evidence_gaps"] != event.details["evidence_gaps"]
               for event in state.trace)


def test_unavailable_requested_source_becomes_explicit_finding(monkeypatch, tmp_path):
    run = simulate_checkout(FaultScenario.baseline, requests=1, started_at=START,
                            execution_id="exec-missing", incident_id="INC-missing")
    run.telemetry.unavailable_sources.add("traffic")
    decisions = iter([
        TriageDecision(assessment="Need traffic data.", next_agent="more_information",
            investigation_question="Retrieve traffic.", expected_information_gain="Requests.",
            confidence="low", decision_rationale="No traffic currently supplied.",
            evidence_requests=[EvidenceRequest(source="traffic", reason="Estimate request rate.")]),
        TriageDecision(assessment="Traffic provider is unavailable.", next_agent="more_information",
            investigation_question="Request traffic source access.", expected_information_gain="Restore source.",
            confidence="low", decision_rationale="Query failed explicitly."),
    ])
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *args: next(decisions))

    state = run_incident(run.incident, execution_id=run.execution_id,
        evidence_source=run.telemetry, evidence_window=run.window)

    result = next(event.details for event in state.trace if event.event_type == "evidence_query_result")
    assert result["status"] == "unavailable"
    finding = next(finding for finding in state.findings if finding.reasoning_status == "unavailable")
    assert "traffic source is unavailable" in finding.missing_evidence[0]
    assert state.report.metadata["evidence_sources"]["traffic"]["status"] == "unavailable"
    assert state.status == "awaiting_information"


def test_empty_requested_source_is_insufficient_not_unavailable(monkeypatch, tmp_path):
    run = simulate_checkout(FaultScenario.baseline, requests=1, started_at=START,
        execution_id="exec-empty-deployments", incident_id="INC-empty-deployments")
    decisions = iter([
        TriageDecision(assessment="Check for a recent deployment.", next_agent="more_information",
            investigation_question="Query deployment history.", expected_information_gain="Find a deployment record.",
            confidence="low", decision_rationale="No deployment data has been queried.",
            evidence_requests=[EvidenceRequest(source="deployments", reason="Look for a deployment in-window.")]),
        TriageDecision(assessment="The source returned no deployment observations.", next_agent="more_information",
            investigation_question="Request deployment history from an operator.", expected_information_gain="Resolve the change gap.",
            confidence="low", decision_rationale="The configured source returned an empty window.",
            evidence_gaps=["deployment timestamps"]),
    ])
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *args: next(decisions))

    state = run_incident(run.incident, execution_id=run.execution_id,
        evidence_source=run.telemetry, evidence_window=run.window)

    source_state = state.report.metadata["evidence_sources"]["deployments"]
    assert source_state["status"] == "insufficient"
    assert source_state["record_count"] == 0
    assert source_state["reason"] == "The source responded but had no matching observations"
    assert "deployments source returned insufficient evidence" in state.report.outstanding_questions[0]
    assert source_state["status"] != "unavailable"


def test_requested_evidence_without_provider_is_reported_unavailable(monkeypatch, tmp_path):
    from app.sample_data import sample_incident

    decisions = iter([
        TriageDecision(assessment="Need DB health.", next_agent="more_information",
            investigation_question="Retrieve database health.", expected_information_gain="DB state.",
            confidence="low", decision_rationale="No DB health supplied.",
            evidence_requests=[EvidenceRequest(source="database_health", reason="Check active connections.")]),
        TriageDecision(assessment="DB-health source is unavailable.", next_agent="more_information",
            investigation_question="Configure the DB-health source.", expected_information_gain="DB state.",
            confidence="low", decision_rationale="No provider is configured."),
    ])
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *args: next(decisions))

    state = run_incident(sample_incident())

    result = next(event.details for event in state.trace if event.event_type == "evidence_query_result")
    assert result["status"] == "unavailable"
    assert result["missing_evidence"] == ["database_health evidence request unavailable: No evidence source is configured"]
    assert state.status == "awaiting_information"
