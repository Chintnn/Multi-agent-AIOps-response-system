from app.models import (AgentFinding, ChangeAnalysis, EvidenceRef, Hypothesis,
                        LogAnalysis, MetricsAnalysis, RemediationProposal,
                        TriageDecision)
from app.orchestrator import run_incident
from app.llm import ProviderUnavailable
from app.sample_data import sample_incident


def _plan(agent, question="Inspect evidence"):
    return TriageDecision(assessment="Database pressure is a hypothesis, not a confirmed cause.",
        hypotheses=[Hypothesis(statement="Pool pressure", rationale="Timeouts and elevated pool metric align.", uncertainty="No tracing data")],
        evidence_gaps=[], next_agent=agent, investigation_question=question,
        expected_information_gain="Distinguish possible causes", confidence="moderate",
        decision_rationale=f"{agent} can provide useful evidence now.")


def _evidence(agent, ref, excerpt):
    return EvidenceRef(ref=ref, source="test.fixture", excerpt=excerpt)


def test_complete_workflow_adaptively_uses_all_five_roles(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    choices = iter(["logs", "metrics", "changes", "remediation"])
    observed_context_sizes = []
    def triage(incident, findings, history, outstanding):
        observed_context_sizes.append((len(findings), list(history)))
        return _plan(next(choices))
    monkeypatch.setattr("app.orchestrator.investigate_alert", triage)
    monkeypatch.setattr("app.orchestrator.investigate_logs", lambda *a: LogAnalysis(
        summary="DB acquisition timeouts observed", observed_facts=["ERROR timeout"],
        evidence_refs=[_evidence("logs", "logs:0", "ERROR timeout")]))
    monkeypatch.setattr("app.orchestrator.investigate_metrics", lambda *a: MetricsAnalysis(
        summary="Pool metric is elevated", observed_facts=["pool=96"], metric_values={"db_connection_pool_percent": 96},
        abnormal_metrics=["db_connection_pool_percent"], missing_metrics=[],
        evidence_refs=[_evidence("metrics", "metrics:db_connection_pool_percent", "pool=96")]))
    monkeypatch.setattr("app.orchestrator.analyze_change", lambda *a: ChangeAnalysis(
        summary="Deployment is temporally relevant but not causal proof", observed_facts=["deployed 12m before"],
        candidate_changes=["deployed"], evidence_refs=[_evidence("changes", "changes:0", "deployed")]))
    monkeypatch.setattr("app.orchestrator.propose_remediation", lambda *a: RemediationProposal(
        action="rollback_deployment", risk_level="high", rationale="Candidate only; human review required.",
        expected_benefit="Restore prior version", evidence_refs=["changes:0"], approval_status="awaiting_approval"))

    state = run_incident(sample_incident())
    assert [f.agent for f in state.findings if f.agent != "triage"] == ["logs", "metrics", "changes"]
    assert state.status == "awaiting_approval"
    assert state.remediation is not None and state.simulated_execution is None
    assert observed_context_sizes[0][0] == 0
    assert observed_context_sizes[-1][0] >= 5
    assert state.report is not None and state.report.status == "awaiting_approval"
    assert state.report.trace_reference
    lines = open(state.report.trace_reference, encoding="utf-8").read().splitlines()
    assert any('"event_type":"routing_decision"' in line for line in lines)
    assert any('"event_type":"agent_result"' in line for line in lines)


def test_provider_failure_is_reported_as_unresolved_not_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    def fail(*args):
        raise ProviderUnavailable("Groq BadRequestError HTTP 400 code=json_validate_failed",
            category="BadRequestError", status_code=400,
            provider_code="json_validate_failed", retryable=False)
    monkeypatch.setattr("app.orchestrator.investigate_alert", fail)
    state = run_incident(sample_incident())
    assert state.status == "unresolved"
    assert "json_validate_failed" in state.errors[0]
    assert state.findings == []
    assert state.report.root_cause_assessment.startswith("No LLM triage")
    failure = next(event for event in state.trace if event.event_type == "provider_unavailable")
    assert failure.execution_id == state.execution_id
    assert failure.agent == "triage"
    assert failure.details["operation"] == "triage_decision"
    assert failure.details["provider_operation"] == "chat.completions.create"
    assert failure.details["status_code"] == 400
    assert failure.details["retryable"] is False


def test_successful_provider_retry_is_a_trace_event(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *args: _plan("more_information"))
    monkeypatch.setattr("app.orchestrator.get_last_call_metadata", lambda: {
        "schema": "TriageDecision", "retry_attempts": [{"attempt": 1,
            "status_code": 429, "provider_code": "rate_limit_exceeded",
            "delay_seconds": 1.25, "delay_source": "retry_after"}],
        "retry_exhausted": False})

    state = run_incident(sample_incident())

    retry = next(event for event in state.trace if event.event_type == "provider_retry")
    assert retry.agent == "triage"
    assert retry.details["operation"] == "triage_decision"
    assert retry.details["attempts"][0]["delay_seconds"] == 1.25


def test_specialist_provider_failure_is_traced_with_execution_context(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    choices = iter(["metrics", "more_information"])
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *a: _plan(next(choices)))
    def fail(*args):
        raise ProviderUnavailable("Groq BadRequestError HTTP 400 code=json_validate_failed",
            category="BadRequestError", status_code=400,
            provider_code="json_validate_failed", retryable=False)
    monkeypatch.setattr("app.orchestrator.investigate_metrics", fail)

    state = run_incident(sample_incident())
    failure = next(event for event in state.trace if event.event_type == "agent_failure")
    assert state.status == "awaiting_information"
    assert failure.execution_id == state.execution_id
    assert failure.agent == "metrics"
    assert failure.details["operation"] == "metrics_investigation"
    assert failure.details["provider_operation"] == "chat.completions.create"
    assert failure.details["status_code"] == 400
    assert failure.details["retryable"] is False


def test_exhausted_provider_rate_limit_stops_without_retriage_or_remediation(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    triage_calls = []
    monkeypatch.setattr("app.orchestrator.investigate_alert",
        lambda *args: (triage_calls.append(args) or _plan("metrics")))
    def fail(*args):
        raise ProviderUnavailable("Groq RateLimitError HTTP 429", category="RateLimitError",
            status_code=429, provider_code="rate_limit_exceeded", retryable=True,
            retry_diagnostics=[{"attempt": 1, "status_code": 429,
                "provider_code": "rate_limit_exceeded", "delay_seconds": 2.0,
                "delay_source": "retry_after"}], retry_exhausted=True)
    monkeypatch.setattr("app.orchestrator.investigate_metrics", fail)
    remediation_calls = []
    monkeypatch.setattr("app.orchestrator.propose_remediation",
        lambda *args: remediation_calls.append(args))

    state = run_incident(sample_incident())

    assert state.status == "unresolved"
    assert len(triage_calls) == 1
    assert remediation_calls == []
    failure = next(event for event in state.trace if event.event_type == "provider_unavailable")
    assert failure.agent == "metrics"
    assert failure.details["retry_exhausted"] is True
    assert state.remediation is None


def test_triage_failure_keeps_prior_validated_findings(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    calls = 0
    def triage(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _plan("changes")
        raise ProviderUnavailable("Groq BadRequestError HTTP 400 code=json_validate_failed",
            category="BadRequestError", status_code=400,
            provider_code="json_validate_failed", retryable=False,
            response_mode="json_schema_strict")
    monkeypatch.setattr("app.orchestrator.investigate_alert", triage)
    monkeypatch.setattr("app.orchestrator.analyze_change", lambda *a: ChangeAnalysis(
        summary="Change timing is relevant but not proof of cause.", candidate_changes=["deploy"],
        evidence_refs=[_evidence("changes", "changes:0", "deployed 12m before alert")]))

    state = run_incident(sample_incident())

    assert state.status == "unresolved"
    assert any(f.agent == "changes" for f in state.findings)
    assert any(f.agent == "changes" for f in state.report.findings)
    assert state.report.root_cause_assessment.startswith("Investigation stopped because the LLM provider was unavailable")
    assert "last validated triage assessment" in state.report.root_cause_assessment
    assert any(event.event_type == "agent_result" and event.agent == "changes" for event in state.trace)
    failure = next(event for event in state.trace if event.event_type == "provider_unavailable")
    assert failure.details["response_mode"] == "json_schema_strict"
    assert failure.details["recovery_attempted"] is False


def test_invalid_next_action_is_rejected_before_any_route_or_remediation(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    invalid = _plan("more_information").model_copy(update={"next_agent": "rollback_deployment"})
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *args: invalid)
    remediation_calls = []
    monkeypatch.setattr("app.orchestrator.propose_remediation",
                        lambda *args: remediation_calls.append(args))

    state = run_incident(sample_incident())

    assert state.status == "failed"
    assert remediation_calls == []
    assert not any(event.event_type == "agent_invoked" for event in state.trace)
    failure = next(event for event in state.trace if event.event_type == "agent_failure")
    assert failure.agent == "triage"
    assert "ValidationError" in failure.details["error"]


def test_strict_schema_recovery_is_recorded_in_successful_trace(monkeypatch, tmp_path):
    import json
    import sys
    from types import SimpleNamespace

    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    monkeypatch.setenv("GROQ_API_KEY", "unit-test-secret")
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setenv("GROQ_MAX_RETRIES", "0")
    calls = []

    class BadRequestError(Exception):
        status_code = 400
        body = {"error": {"code": "json_validate_failed", "message": "next_agent enum rejected"}}

    decision = _plan("more_information", "Review available evidence")
    class FakeGroq:
        def __init__(self, **kwargs):
            pass
        @property
        def chat(self):
            def create(**kwargs):
                calls.append(kwargs)
                if len(calls) == 1:
                    raise BadRequestError()
                return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
                    content=json.dumps(decision.model_dump(mode="json"))))])
            return SimpleNamespace(completions=SimpleNamespace(create=create))

    monkeypatch.setitem(sys.modules, "groq", SimpleNamespace(Groq=FakeGroq))
    state = run_incident(sample_incident())

    recovery = next(event for event in state.trace if event.event_type == "structured_output_recovery")
    assert state.status == "awaiting_information"
    assert len(calls) == 2
    assert calls[0]["response_format"]["json_schema"]["strict"] is True
    assert calls[1]["response_format"] == {"type": "json_object"}
    assert recovery.agent == "triage"
    assert recovery.details["operation"] == "triage_decision"
    assert recovery.details["initial_provider_code"] == "json_validate_failed"
    assert recovery.details["initial_status_code"] == 400
    assert recovery.details["response_mode"] == "json_object_recovery"
    assert recovery.details["recovery_attempted"] is True
    assert not any(event.event_type == "remediation_proposed" for event in state.trace)


def test_failed_schema_recovery_is_visible_and_never_routes_to_remediation(monkeypatch, tmp_path):
    import sys
    from types import SimpleNamespace

    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    monkeypatch.setenv("GROQ_API_KEY", "unit-test-secret")
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setenv("GROQ_MAX_RETRIES", "0")
    calls = []

    class BadRequestError(Exception):
        status_code = 400
        body = {"error": {"code": "json_validate_failed", "message": "next_agent enum rejected"}}

    class RecoveryError(Exception):
        status_code = 400
        body = {"error": {"code": "invalid_request", "message": "Recovery request rejected"}}

    class FakeGroq:
        def __init__(self, **kwargs):
            pass
        @property
        def chat(self):
            def create(**kwargs):
                calls.append(kwargs)
                raise BadRequestError() if len(calls) == 1 else RecoveryError()
            return SimpleNamespace(completions=SimpleNamespace(create=create))

    monkeypatch.setitem(sys.modules, "groq", SimpleNamespace(Groq=FakeGroq))
    state = run_incident(sample_incident())

    assert state.status == "unresolved"
    assert len(calls) == 2
    assert state.report.status == "unresolved"
    failure = next(event for event in state.trace if event.event_type == "provider_unavailable")
    assert failure.agent == "triage"
    assert failure.details["provider_code"] == "invalid_request"
    assert failure.details["initial_provider_code"] == "json_validate_failed"
    assert failure.details["initial_status_code"] == 400
    assert failure.details["recovery_attempted"] is True
    assert failure.details["response_mode"] == "json_object_recovery"
    assert not any(event.event_type == "remediation_proposed" for event in state.trace)


def test_inconclusive_plan_stops_and_retains_question(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    decision = _plan("more_information", "Provide a wider incident time window")
    decision.evidence_gaps = ["onset timestamp", "post-action metrics"]
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *a: decision)
    state = run_incident(sample_incident())
    assert state.status == "awaiting_information"
    assert state.report.outstanding_questions == decision.evidence_gaps


def test_service_approval_and_post_action_metrics_complete_simulated_lifecycle(monkeypatch, tmp_path):
    from app.service import submit_incident, start_investigation, record_approval
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    choices = iter(["logs", "metrics", "remediation"])
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *a: _plan(next(choices)))
    monkeypatch.setattr("app.orchestrator.investigate_logs", lambda *a: LogAnalysis(
        summary="timeout observed", evidence_refs=[_evidence("logs", "logs:0", "timeout")]))
    monkeypatch.setattr("app.orchestrator.investigate_metrics", lambda *a: MetricsAnalysis(
        summary="pool elevated", metric_values={"db_connection_pool_percent": 96},
        abnormal_metrics=["db_connection_pool_percent"], evidence_refs=[_evidence("metrics", "metrics:db_connection_pool_percent", "96")]))
    monkeypatch.setattr("app.orchestrator.propose_remediation", lambda *a: RemediationProposal(
        action="rollback_deployment", risk_level="high", rationale="reviewed proposal",
        expected_benefit="restore previous version", approval_status="awaiting_approval"))
    execution_id = submit_incident(sample_incident())
    pending = start_investigation(execution_id)
    assert pending.status == "awaiting_approval"
    healthy = {"p95_latency_ms": 300.0, "http_5xx_rate_percent": 0.5,
        "cpu_percent": 40.0, "db_connection_pool_percent": 50.0}
    done = record_approval(execution_id, "operator-1", "approved", healthy)
    assert done.status == "recovered"
    assert done.simulated_execution["simulated"] is True
    assert done.recovery.outcome == "recovered"
    assert done.report.status == "recovered"


def test_triage_can_request_revision_after_new_independent_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    choices = iter(["logs", "metrics", "logs", "more_information"])
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *a: _plan(next(choices)))
    log_calls = []
    def revise(*args):
        log_calls.append(args[1])
        return LogAnalysis(summary=f"log review {len(log_calls)}", observed_facts=["timeout"],
            evidence_refs=[_evidence("logs", f"logs:{len(log_calls)}", "timeout")])
    monkeypatch.setattr("app.orchestrator.investigate_logs", revise)
    monkeypatch.setattr("app.orchestrator.investigate_metrics", lambda *a: MetricsAnalysis(
        summary="pool anomaly", metric_values={"db_connection_pool_percent": 96},
        abnormal_metrics=["db_connection_pool_percent"], evidence_refs=[_evidence("metrics", "metrics:db", "96")]))
    state = run_incident(sample_incident())
    assert len(log_calls) == 2
    assert len([x for x in state.investigation_history if x.startswith("logs:")]) == 2
    assert state.status == "awaiting_information"


def test_reconciliation_preserves_competing_hypotheses(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    h1 = Hypothesis(statement="Pool overload caused the failures", rationale="Timeout log appears related.",
        supporting_refs=["logs:0"], uncertainty="No comparison metrics yet")
    h2 = Hypothesis(statement="Pool overload is unlikely to be causal", rationale="Latency stayed normal in another interval.",
        contradicting_refs=["metrics:p95_latency_ms"], uncertainty="Time window is incomplete")
    plans = iter([_plan("logs"), _plan("metrics"), _plan("more_information")])
    first = next(plans).model_copy(update={"hypotheses": [h1]})
    second = next(plans).model_copy(update={"hypotheses": [h2]})
    third = next(plans).model_copy(update={"hypotheses": [h2], "evidence_gaps": ["aligned time window"]})
    decisions = iter([first, second, third])
    monkeypatch.setattr("app.orchestrator.investigate_alert", lambda *a: next(decisions))
    monkeypatch.setattr("app.orchestrator.investigate_logs", lambda *a: LogAnalysis(
        summary="timeout", evidence_refs=[_evidence("logs", "logs:0", "timeout")]))
    monkeypatch.setattr("app.orchestrator.investigate_metrics", lambda *a: MetricsAnalysis(
        summary="metric snapshot", metric_values={"p95_latency_ms": 200},
        evidence_refs=[_evidence("metrics", "metrics:p95_latency_ms", "200ms")]))
    state = run_incident(sample_incident())
    assert {h.statement for h in state.hypotheses} == {
        "Pool overload caused the failures", "Pool overload is unlikely to be causal"}
    assert any(event.event_type == "evidence_reconciliation" for event in state.trace)
