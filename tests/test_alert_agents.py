
from app.agents.alert_agent import investigate_alert
from app.sample_data import sample_incident


def test_alert_agent_returns_valid_triage():
    result = investigate_alert(sample_incident())

    assert result.priority in {"low", "medium", "high", "critical"}
    assert result.assessment.strip()
    assert isinstance(result.suspected_causes, list)
    assert result.next_investigation in {
        "logs", "metrics", "changes", "more_information"
    }
