"""Tests for Log and Metrics investigation agents."""

from app.agents.log_agent import investigate_logs
from app.agents.metrics_agent import investigate_metrics
from app.sample_data import sample_incident


def test_log_agent_finds_database_timeouts():
    finding = investigate_logs(sample_incident())
    assert finding.source == "log_agent"
    assert any("database connection" in e.lower() for e in finding.evidence)
    assert "timeout" in finding.observation.lower() or "database" in finding.observation.lower()


def test_log_agent_handles_empty_logs():
    incident = sample_incident().model_copy(update={"logs": []})
    finding = investigate_logs(incident)
    assert finding.source == "log_agent"
    assert finding.evidence == []
    assert "no" in finding.observation.lower()


def test_metrics_agent_flags_latency_and_pool():
    finding = investigate_metrics(sample_incident())
    assert finding.source == "metrics_agent"
    joined = " ".join(finding.evidence).lower()
    assert "latency" in joined
    assert "database connection pool" in joined
    assert "5xx" in joined


def test_metrics_agent_handles_empty_metrics():
    incident = sample_incident().model_copy(update={"metrics": {}})
    finding = investigate_metrics(incident)
    assert finding.source == "metrics_agent"
    assert finding.evidence == []
    assert "no" in finding.observation.lower() or "threshold" in finding.observation.lower()


def test_agents_suggest_next_step():
    log_finding = investigate_logs(sample_incident())
    metrics_finding = investigate_metrics(sample_incident())
    assert log_finding.suggested_next_step
    assert metrics_finding.suggested_next_step
