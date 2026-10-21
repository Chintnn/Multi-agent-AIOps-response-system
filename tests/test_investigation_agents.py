from app.agents.change_agent import analyze_change
from app.agents.log_agent import investigate_logs
from app.agents.metrics_agent import investigate_metrics
from app.llm import ProviderUnavailable
from app.models import Hypothesis, SpecialistReasoning
from app.sample_data import sample_incident


def _reasoning(**updates):
    values = dict(summary="Evidence is consistent with downstream database pressure, but not conclusive.",
        hypotheses=[Hypothesis(statement="Database pressure", rationale="Observed timeout and pool saturation.",
            supporting_refs=["logs:0", "metrics:db_connection_pool_percent"], uncertainty="No tracing data")],
        missing_evidence=["distributed trace"], follow_up="Inspect DB connection wait events.", contradictions=[])
    values.update(updates)
    return SpecialistReasoning(**values)


def test_log_agent_uses_question_and_actual_records(monkeypatch):
    captured = {}
    def fake(system, prompt, schema):
        captured["prompt"] = prompt
        return _reasoning()
    monkeypatch.setattr("app.agents.log_agent.invoke_structured", fake)
    result = investigate_logs(sample_incident(), "Find recurring database timeouts")
    assert result.agent == "logs"
    assert result.evidence_refs[0].ref == "logs:0"
    assert "Find recurring" in captured["prompt"]
    assert result.observed_facts[0] == sample_incident().logs[0]


def test_metrics_agent_marks_missing_metrics_and_uses_real_values(monkeypatch):
    monkeypatch.setattr("app.agents.metrics_agent.invoke_structured", lambda *args: _reasoning())
    result = investigate_metrics(sample_incident().model_copy(update={"metrics": {"cpu_percent": 30.0}}))
    assert result.metric_values == {"cpu_percent": 30.0}
    assert "p95_latency_ms" in result.missing_metrics
    assert "cpu_percent" not in result.abnormal_metrics


def test_change_agent_cites_supplied_change_only(monkeypatch):
    monkeypatch.setattr("app.agents.change_agent.invoke_structured", lambda *args: _reasoning())
    result = analyze_change(sample_incident(), "Assess deployment relevance")
    assert result.agent == "changes"
    assert result.candidate_changes == sample_incident().recent_changes
    assert result.evidence_refs[0].ref == "changes:0"


def test_provider_failure_is_not_reported_as_success(monkeypatch):
    def fail(*args):
        raise ProviderUnavailable("offline")
    monkeypatch.setattr("app.agents.log_agent.invoke_structured", fail)
    import pytest
    with pytest.raises(ProviderUnavailable):
        investigate_logs(sample_incident())


def test_unknown_metric_is_preserved_without_inventing_a_threshold(monkeypatch):
    monkeypatch.setattr("app.agents.metrics_agent.invoke_structured", lambda *args: _reasoning())
    incident = sample_incident().model_copy(update={"metrics": {"queue_depth": 17.0}})
    result = investigate_metrics(incident)
    assert result.metric_values == {"queue_depth": 17.0}
    assert "no configured threshold" in result.evidence_refs[0].excerpt
