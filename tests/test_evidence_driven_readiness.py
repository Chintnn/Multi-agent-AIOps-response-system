"""Deterministic evidence scenarios through the real workflow and agent boundaries."""
from app.models import (
    ApprovalRecord,
    Hypothesis,
    IncidentInput,
    RemediationReasoning,
    SpecialistReasoning,
    TriageDecision,
)
from app.orchestrator import run_incident
from app.service import record_approval, start_investigation, submit_incident


def _incident(strong: bool) -> IncidentInput:
    if strong:
        return IncidentInput(
            incident_id="INC-STRONG-1", service="checkout-api",
            summary="Checkout DB calls time out after connection pool config change",
            severity="high",
            symptoms=["DB acquisition timeouts", "checkout requests fail"],
            metrics={"p95_latency_ms": 2400, "http_5xx_rate_percent": 12,
                     "cpu_percent": 55, "db_connection_pool_percent": 97},
            logs=["2026-10-21T13:00:00Z ERROR database connection acquisition timed out",
                  "2026-10-21T13:01:00Z ERROR order failed due to DB timeout"],
            recent_changes=["2026-10-21T12:50:00Z checkout-api 2.4.1 changed db_pool_max from 100 to 20"],
        )
    return IncidentInput(
        incident_id="INC-WEAK-1", service="checkout-api",
        summary="Some checkout requests seem slower",
        severity="medium", symptoms=["intermittent slowness"],
        metrics={}, logs=["checkout request delayed"], recent_changes=[],
    )


def _install_scenario_provider_mocks(monkeypatch, strong: bool):
    triage_prompts = []

    def triage_provider(system, prompt, schema):
        triage_prompts.append(prompt)
        call_number = len(triage_prompts)
        if call_number == 1:
            target, gaps = "metrics", []
        elif not strong:
            target, gaps = "more_information", [
                "time-correlated DB metrics", "timestamped error logs", "reliable change record"]
        elif call_number == 2:
            target, gaps = "changes", []
        elif call_number == 3:
            target, gaps = "logs", []
        else:
            # Only the strong fixture supplies this complete, cross-source evidence.
            assert "db_connection_pool_percent': 97.0" in prompt
            assert "logs:0" in prompt and "changes:0" in prompt
            target, gaps = "remediation", []
        return TriageDecision(
            assessment="Evidence supports pool exhaustion after a specific configuration change." if target == "remediation"
                       else "Available evidence is insufficient to identify a cause." if target == "more_information"
                       else "Gather the next relevant evidence source.",
            hypotheses=[Hypothesis(statement="Reduced DB pool capacity caused connection timeouts",
                rationale="The supplied metrics, errors, and change record align." if strong else "Evidence is incomplete.",
                uncertainty="moderate")],
            evidence_gaps=gaps, next_agent=target,
            investigation_question="Assess the supplied incident evidence.",
            expected_information_gain="Correlate independent evidence sources.",
            confidence="high" if target == "remediation" else "moderate",
            decision_rationale="The supplied evidence supports this next step.",
        )

    def specialist_provider(system, prompt, schema):
        return SpecialistReasoning(
            summary="The evidence is consistent with the supplied measurements and records.",
            hypotheses=[Hypothesis(statement="DB pool pressure", rationale="Supplied evidence aligns.", uncertainty="moderate")],
        )

    monkeypatch.setattr("app.agents.alert_agent.invoke_structured", triage_provider)
    monkeypatch.setattr("app.agents.metrics_agent.invoke_structured", specialist_provider)
    monkeypatch.setattr("app.agents.change_agent.invoke_structured", specialist_provider)
    monkeypatch.setattr("app.agents.log_agent.invoke_structured", specialist_provider)
    monkeypatch.setattr("app.agents.remediation_agent.invoke_structured", lambda *args: RemediationReasoning(
        recommend_action="scale_up_db_pool",
        rationale="The pool is saturated and independent log evidence reports acquisition timeouts.",
        expected_benefit="Reduce connection acquisition waits.", prerequisites=["operator approval"],
        alternatives=["inspect DB wait events"],
        evidence_refs=["metrics:db_connection_pool_percent", "logs:0", "changes:0"],
    ))
    return triage_prompts


def test_strong_evidence_can_reach_approval_gated_remediation(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    prompts = _install_scenario_provider_mocks(monkeypatch, strong=True)

    state = run_incident(_incident(strong=True))

    assert [finding.agent for finding in state.findings if finding.agent != "triage"] == [
        "metrics", "changes", "logs"]
    assert state.status == "awaiting_approval"
    assert state.remediation.action == "scale_up_db_pool"
    assert state.remediation.risk_level == "medium"
    assert state.remediation.approval_status == "awaiting_approval"
    assert state.simulated_execution is None
    assert "db_connection_pool_percent': 97.0" in prompts[-1]
    assert "logs:0" in prompts[-1] and "changes:0" in prompts[-1]


def test_insufficient_evidence_requests_more_information(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    _install_scenario_provider_mocks(monkeypatch, strong=False)

    state = run_incident(_incident(strong=False))

    assert state.status == "awaiting_information"
    assert [finding.agent for finding in state.findings if finding.agent != "triage"] == ["metrics"]
    assert state.remediation is None
    assert state.report.outstanding_questions == [
        "time-correlated DB metrics", "logs evidence has not been requested yet.",
        "reliable change record"]


def test_rejected_approval_does_not_execute_simulated_action(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOPS_TRACE_DIR", str(tmp_path))
    _install_scenario_provider_mocks(monkeypatch, strong=True)
    execution_id = submit_incident(_incident(strong=True))
    pending = start_investigation(execution_id)

    assert pending.status == "awaiting_approval"
    rejected = record_approval(execution_id, "operator-1", "rejected")

    assert rejected.status == "unresolved"
    assert rejected.remediation.approval_status == "rejected"
    assert rejected.simulated_execution is None
