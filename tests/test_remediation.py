"""
Tests for Change Analysis Agent and Remediation & Verification Agent.

Currently placeholders — real tests added as agents are implemented.
"""

import pytest

from app.agents.change_agent import analyze_change
from app.agents.remediation_agent import propose_remediation, execute_remediation
from app.models import IncidentInput, EvidenceFinding


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


def _finding(observation: str, evidence: list[str] | None = None) -> EvidenceFinding:
    return EvidenceFinding(
        source="test_source",
        observation=observation,
        evidence=evidence or [],
        suggested_next_step="n/a",
    )


# --- Change Analysis Agent tests ---

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


# --- Remediation Agent tests ---

def test_proposes_rollback_for_deployment_related_evidence():
    findings = [_finding("Deployment occurred near incident time", ["deployed v2.4.1"])]
    proposal = propose_remediation(findings)
    assert proposal["action"] == "rollback_deployment"
    assert proposal["risk_level"] == "high"
    assert proposal["requires_approval"] is True


def test_proposes_low_risk_action_for_unrelated_evidence():
    findings = [_finding("Nothing unusual found")]
    proposal = propose_remediation(findings)
    assert proposal["action"] == "clear_cache"
    assert proposal["risk_level"] == "low"
    assert proposal["requires_approval"] is False


def test_high_risk_action_blocked_without_approval():
    findings = [_finding("Deployment occurred near incident time", ["deployed v2.4.1"])]
    proposal = propose_remediation(findings)
    result = execute_remediation(proposal, approved=False)
    assert result["executed"] is False
    assert "requires human approval" in result["reason"]


def test_high_risk_action_allowed_with_approval():
    findings = [_finding("Deployment occurred near incident time", ["deployed v2.4.1"])]
    proposal = propose_remediation(findings)
    result = execute_remediation(proposal, approved=True)
    assert result["executed"] is True


def test_low_risk_action_does_not_need_approval():
    findings = [_finding("Nothing unusual found")]
    proposal = propose_remediation(findings)
    result = execute_remediation(proposal, approved=False)
    assert result["executed"] is True


# --- Verification tests (commit 4) ---

@pytest.mark.skip(reason="Verification logic not yet implemented")
def test_verify_recovery_detects_failed_recovery():
    pass