import pytest

from app.agents.remediation_agent import (
    execute_remediation, propose_remediation, verify_recovery,
)
from app.models import (AgentFinding, ApprovalRecord, EvidenceRef, IncidentInput,
                        RemediationReasoning)
from app.sample_data import sample_incident


def _findings():
    return [
        AgentFinding(agent="logs", summary="Database acquisition timed out.",
            evidence_refs=[EvidenceRef(ref="logs:0", source="incident.logs", excerpt="db timeout")]),
        AgentFinding(agent="metrics", summary="Pool pressure is elevated.",
            evidence_refs=[EvidenceRef(ref="metrics:db_connection_pool_percent", source="incident.metrics", excerpt="pool=96")]),
    ]


def test_remediation_uses_llm_rationale_and_independent_policy(monkeypatch):
    monkeypatch.setattr("app.agents.remediation_agent.invoke_structured", lambda *args: RemediationReasoning(
        recommend_action="scale_up_db_pool", rationale="Pool pressure is supported by logs and metrics.",
        expected_benefit="Reduce connection acquisition waits.", prerequisites=["operator review"],
        alternatives=["inspect DB wait events"], evidence_refs=["logs:0", "metrics:db_connection_pool_percent"]))
    proposal = propose_remediation(sample_incident(), _findings())
    assert proposal.risk_level == "medium"
    assert proposal.approval_status == "awaiting_approval"
    assert not execute_remediation(proposal)["executed"]
    assert not execute_remediation(proposal, True)["executed"]  # bool is not an approval record
    approval = ApprovalRecord(proposal_id=proposal.proposal_id, approved_by="operator-1", decision="approved")
    result = execute_remediation(proposal, approval)
    assert result["executed"] and result["simulated"]


def test_insufficient_evidence_prevents_remediation(monkeypatch):
    with pytest.raises(ValueError):
        propose_remediation(sample_incident(), _findings()[:1])


def test_approval_must_match_exact_proposal():
    from app.models import RemediationProposal
    proposal = RemediationProposal(action="rollback_deployment", risk_level="high",
        rationale="reviewed", expected_benefit="revert bad release", approval_status="awaiting_approval")
    wrong = ApprovalRecord(proposal_id="different", approved_by="operator", decision="approved")
    assert not execute_remediation(proposal, wrong)["executed"]


def test_invalid_action_fails_policy_validation():
    from app.models import RemediationProposal
    forged = RemediationProposal.model_construct(action="delete_database", risk_level="low",
        proposal_id="proposal-1", rationale="bad", expected_benefit="bad",
        prerequisites=[], alternatives=[], evidence_refs=[], approval_status="not_required")
    result = execute_remediation(forged)
    assert result["executed"] is False
    assert "policy validation" in result["reason"]


def test_recovery_requires_complete_post_action_metrics():
    result = verify_recovery(sample_incident(), {})
    assert result.outcome == "insufficient_evidence"
    partial = verify_recovery(sample_incident(), {"p95_latency_ms": 200.0})
    assert partial.outcome == "insufficient_evidence"
    assert "db_connection_pool_percent" in partial.missing_metrics


def test_recovery_distinguishes_healthy_from_elevated():
    healthy = {"p95_latency_ms": 300.0, "http_5xx_rate_percent": 0.5,
        "cpu_percent": 40.0, "db_connection_pool_percent": 50.0}
    assert verify_recovery(sample_incident(), healthy).outcome == "recovered"
    elevated = dict(healthy, p95_latency_ms=2200.0)
    assert verify_recovery(sample_incident(), elevated).outcome == "not_recovered"
