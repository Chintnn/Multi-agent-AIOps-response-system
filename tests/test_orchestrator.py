
from unittest.mock import patch

from app.agents.alert_agent import AlertTriageResult
from app.models import EvidenceFinding
from app.orchestrator import run_incident
from app.sample_data import sample_incident


def fake_triage(incident):
    return AlertTriageResult(
        priority="high",
        assessment="Latency and errors suggest a database-related incident.",
        suspected_causes=["Database connection pool pressure"],
        next_investigation="logs",
        missing_information=[],
    )


def test_orchestrator_routes_to_logs_and_metrics():
    with patch(
        "app.orchestrator.investigate_alert",
        side_effect=fake_triage,
    ):
        result = run_incident(sample_incident())

    assert result["triage"] is not None
    assert {"logs", "metrics"}.issubset(
        set(result["completed_investigations"])
    )
    assert len(result["findings"]) == 2
    assert result["steps"] == 2
    assert result["status"] == "investigating"


def test_orchestrator_stops_when_triage_fails():
    with patch(
        "app.orchestrator.investigate_alert",
        side_effect=RuntimeError("simulated triage failure"),
    ):
        result = run_incident(sample_incident())

    assert result["status"] == "needs_more_information"
    assert result["findings"] == []
    assert any("Alert triage failed" in error for error in result["errors"])


def test_orchestrator_collects_expected_finding_types():
    with patch(
        "app.orchestrator.investigate_alert",
        side_effect=fake_triage,
    ):
        result = run_incident(sample_incident())

    sources = {finding.source for finding in result["findings"]}
    assert sources == {"log_agent", "metrics_agent"}
    assert all(
        isinstance(finding, EvidenceFinding)
        for finding in result["findings"]
    )
