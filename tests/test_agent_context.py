from datetime import datetime, timezone, timedelta
import json

from app.agents.context import compact_findings, compact_telemetry_records
from app.models import EvidenceRef, Hypothesis, MetricsAnalysis
from app.telemetry import TelemetryRecord


def test_compact_context_preserves_key_evidence_and_bounds_text():
    finding = MetricsAnalysis(
        summary="S" * 600,
        observed_facts=["F" * 200],
        hypotheses=[Hypothesis(statement="connection pool", rationale="R" * 300,
            supporting_refs=["metrics:db_pool"], contradicting_refs=["metrics:db_pool_normal"], uncertainty="U" * 200),
            Hypothesis(statement="pool is normal", rationale="A later sample contradicts this.",
            supporting_refs=["metrics:db_pool_normal"], contradicting_refs=["metrics:db_pool"], uncertainty="Conflicting samples")],
        evidence_refs=[EvidenceRef(ref="metrics:db_pool", source="telemetry", excerpt="E" * 300,
            observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc), execution_id="exec-1",
            source_id="checkout/metrics", incident_id="inc-1")],
        metric_values={"db_connection_pool_percent": 96},
        abnormal_metrics=["db_connection_pool_percent"], missing_metrics=[],
    )

    result = compact_findings([finding])[0]

    assert len(result["summary"]) == 280
    assert len(result["observed_facts"][0]) == 140
    assert result["evidence_refs"][0]["ref"] == "metrics:db_pool"
    assert result["evidence_refs"][0]["execution_id"] == "exec-1"
    assert result["evidence_refs"][0]["incident_id"] == "inc-1"
    assert result["evidence_refs"][0]["source_id"] == "checkout/metrics"
    assert result["metric_values"] == {"db_connection_pool_percent": 96}
    assert result["hypotheses"][0]["supporting_refs"] == ["metrics:db_pool"]
    assert result["hypotheses"][0]["contradicting_refs"] == ["metrics:db_pool_normal"]
    assert result["hypotheses"][1]["statement"] == "pool is normal"

    bounded = compact_findings([finding.model_copy(update={
        "observed_facts": ["F" * 1000] * 30}) for _ in range(12)])
    assert len(bounded) == 6
    assert len(json.dumps(bounded)) < 20_000


def test_compact_telemetry_is_bounded_and_preserves_provenance_and_contradictions():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    records = [TelemetryRecord(record_id=f"r{i}", execution_id="exec-7",
        incident_id="inc-7", service="checkout", source="metrics",
        source_id="checkout/metrics", observed_at=start + timedelta(seconds=i),
        kind="sample", message="pool observation",
        values={"pool_percent": value, "healthy": healthy})
        for i, (value, healthy) in enumerate([(35, True), (42, True), (96, False), (38, True), (97, False), (40, True), (41, True), (39, True), (98, False), (36, True)])]

    compact = compact_telemetry_records(records, limit=5)

    assert compact["record_count"] == 10
    assert len(compact["samples"]) <= 5
    assert compact["value_summary"]["pool_percent"] == {"min": 35.0, "max": 98.0, "count": 10}
    assert compact["value_summary"]["healthy"]["distinct_values"] == ["false", "true"]
    assert {sample["execution_id"] for sample in compact["samples"]} == {"exec-7"}
    assert {sample["incident_id"] for sample in compact["samples"]} == {"inc-7"}
    assert {sample["source_id"] for sample in compact["samples"]} == {"checkout/metrics"}
    assert all(len(sample["message"]) <= 180 for sample in compact["samples"])
    assert len(json.dumps(compact)) < 5_000
