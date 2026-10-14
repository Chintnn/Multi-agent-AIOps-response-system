"""
Tests for Change Analysis Agent and Remediation & Verification Agent.

Currently placeholders — real tests added as agents are implemented.
"""

import pytest

from app.agents.change_agent import analyze_change
from app.models import IncidentInput


def _base_incident(**overrides) -> IncidentInput:
    defaults = dict(
        incident_id="INC-1001",
        service="checkout-api",
        summary="Checkout requests are slow and some are failing",
        severity="high",
        symptoms=["p95 latency is above the normal range"],
        metrics={},
        logs=[],
        recent_changes=[],
    )
    defaults.update(overrides)
    return IncidentInput(**defaults)


def test_detects_relevant_change():
    incident = _base_incident(
        recent_changes=["checkout-api version 2.4.1 deployed 12 minutes before alert"]
    )
    result = analyze_change(incident)
    assert result.source == "change_agent"
    assert len(result.evidence) == 1
    assert "deployed" in result.evidence[0].lower()
    assert "correlate" in result.suggested_next_step.lower()


def test_no_relevant_change_found():
    incident = _base_incident(
        recent_changes=["Updated internal documentation for on-call runbook"]
    )
    result = analyze_change(incident)
    assert result.evidence == []
    assert "unlikely" in result.suggested_next_step.lower()


def test_empty_recent_changes():
    incident = _base_incident(recent_changes=[])
    result = analyze_change(incident)
    assert result.evidence == []
    assert result.source == "change_agent"


@pytest.mark.skip(reason="Remediation Agent not yet implemented")
def test_remediation_requires_approval_for_risky_action():
    pass


@pytest.mark.skip(reason="Verification logic not yet implemented")
def test_verify_recovery_detects_failed_recovery():
    pass