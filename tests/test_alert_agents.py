from app.agents.alert_agent import investigate_alert
from app.models import AgentFinding, Hypothesis, MetricsAnalysis, TriageDecision
from app.sample_data import sample_incident


def test_triage_uses_prior_findings_and_validates_output(monkeypatch):
    captured = {}
    def fake(system, prompt, schema):
        captured["system"] = system
        captured["prompt"] = prompt
        return TriageDecision(assessment="Pool pressure is plausible, not proven.",
            hypotheses=[Hypothesis(statement="Pool exhaustion", rationale="Errors and pool metric align.", uncertainty="No change correlation yet")],
            evidence_gaps=["deployment event timestamp"], next_agent="changes",
            investigation_question="Compare change timing with onset.",
            expected_information_gain="Temporal and technical correlation", confidence="moderate",
            decision_rationale="Change evidence can distinguish a deployment hypothesis.")
    monkeypatch.setattr("app.agents.alert_agent.invoke_structured", fake)
    result = investigate_alert(sample_incident(), [], ["logs:done"], ["timestamp"])
    assert result.next_agent == "changes"
    assert "investigation_history" in captured["prompt"]
    assert "Prefer an unrun specialist" in captured["system"]
    assert "Specialist attempts already recorded: ['logs']" in captured["system"]
    assert "Specialists not yet attempted: ['changes', 'metrics']" in captured["system"]


def test_triage_compacts_prior_context_without_dropping_specialist_metrics(monkeypatch):
    captured = {}
    monkeypatch.setattr("app.agents.alert_agent.invoke_structured",
        lambda system, prompt, schema: (captured.update(prompt=prompt) or TriageDecision(
            assessment="Continue gathering evidence.", hypotheses=[], evidence_gaps=[],
            next_agent="changes", investigation_question="Review deployment changes.",
            expected_information_gain="Compare versions.", confidence="moderate",
            decision_rationale="Change evidence is still missing.")))
    old_triage = AgentFinding(agent="triage", summary="T" * 600)
    metrics = MetricsAnalysis(agent="metrics", summary="Pool utilization is high.",
        metric_values={"db_connection_pool_percent": 96},
        abnormal_metrics=["db_connection_pool_percent"])

    investigate_alert(sample_incident(), [old_triage, metrics], ["metrics:complete"], [])

    assert "prior_triage_assessment" in captured["prompt"]
    assert "metric_values" in captured["prompt"]
    assert "T" * 300 not in captured["prompt"]
