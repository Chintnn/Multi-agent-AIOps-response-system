from app.incident_tools import inspect_logs, inspect_metrics
from app.sample_data import sample_incident


def test_log_inspection_finds_database_timeout():
    finding = inspect_logs(sample_incident())
    assert finding.source == "log_inspection_tool"
    assert any("database connection" in item.lower() for item in finding.evidence)


def test_metrics_flag_latency_errors_and_database_pool():
    finding = inspect_metrics(sample_incident())
    joined = " ".join(finding.evidence).lower()
    assert "latency" in joined
    assert "5xx" in joined
    assert "database connection pool" in joined


def test_empty_logs_are_handled():
    incident = sample_incident().model_copy(update={"logs": []})
    finding = inspect_logs(incident)
    assert finding.evidence == []
    assert "no obvious" in finding.observation.lower()
