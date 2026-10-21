import pytest

from app.incident_tools import inspect_logs, inspect_metric_values, inspect_metrics, retrieve_changes
from app.models import IncidentInput
from app.sample_data import sample_incident


def test_log_retrieval_preserves_actual_records_and_refs():
    incident = sample_incident()
    finding = inspect_logs(incident)
    assert finding.source == "log_inspection_tool"
    assert len(finding.evidence) == 2
    assert finding.evidence[0] == incident.logs[0]


def test_metrics_are_compared_deterministically_and_missing_is_explicit():
    result = inspect_metric_values(sample_incident())
    assert set(result["abnormal"]) == {"p95_latency_ms", "http_5xx_rate_percent", "db_connection_pool_percent"}
    assert result["missing"] == []
    partial = inspect_metrics(sample_incident().model_copy(update={"metrics": {"cpu_percent": 30.0}}))
    assert "Missing metrics" in " ".join(partial.evidence)


def test_change_retrieval_does_not_keyword_filter_or_invent():
    incident = sample_incident()
    records = retrieve_changes(incident)
    assert [record.excerpt for record in records] == incident.recent_changes


def test_invalid_incident_is_rejected():
    with pytest.raises(Exception):
        IncidentInput(incident_id="", service="", summary="bad", severity="urgent", symptoms=[])
