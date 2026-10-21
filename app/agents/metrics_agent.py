"""Numeric checks are deterministic; anomaly interpretation uses the LLM."""
from math import ceil

from app.incident_tools import METRIC_THRESHOLDS, inspect_metric_values
from app.agents.context import compact_findings, compact_telemetry_records, compact_evidence_refs, compact_incident
from app.evidence_tools import query_evidence, result_refs
from app.llm import invoke_structured
from app.models import (AgentFinding, EvidenceQueryState, EvidenceRef, IncidentInput, MetricsAnalysis,
                        MetricsInvestigationInput, SpecialistReasoning)
from app.telemetry import EvidenceSource, EvidenceWindow


def investigate_metrics(incident: IncidentInput, question: str = "Investigate supplied metrics",
                        prior_findings: list[AgentFinding] | None = None, *,
                        evidence_source: EvidenceSource | None = None,
                        evidence_window: EvidenceWindow | None = None,
                        execution_id: str = "offline") -> MetricsAnalysis:
    request = MetricsInvestigationInput(incident=incident, question=question,
                                       prior_findings=prior_findings or [])
    incident = request.incident
    telemetry_results = [query_evidence(evidence_source, source, incident,
        execution_id, evidence_window) for source in ("metrics", "traffic", "database_health")]
    telemetry_results = [result for result in telemetry_results if result is not None]
    telemetry_records = [record for result in telemetry_results for record in result.records]
    traffic = [record for record in telemetry_records if record.source == "traffic"]
    derived: dict[str, float] = {}
    latencies = sorted(float(record.values["latency_ms"]) for record in traffic
                       if isinstance(record.values.get("latency_ms"), (int, float)))
    statuses = [int(record.values["status_code"]) for record in traffic
                if isinstance(record.values.get("status_code"), (int, float))]
    if latencies:
        derived["p95_latency_ms"] = latencies[max(0, ceil(.95 * len(latencies)) - 1)]
    if statuses:
        derived["http_5xx_rate_percent"] = 100 * sum(status >= 500 for status in statuses) / len(statuses)
    metric_records = [record for record in telemetry_records
                      if record.source in {"metrics", "database_health"}]
    for name in ("cpu_percent", "db_connection_pool_percent"):
        values = [float(record.values[name]) for record in metric_records
                  if isinstance(record.values.get(name), (int, float))]
        if values:
            derived[name] = values[-1]
    result = inspect_metric_values(incident, derived)
    refs = [EvidenceRef(ref=f"metrics:{name}", source="incident.metrics",
             excerpt=(f"{name}={value:g}; threshold={METRIC_THRESHOLDS[name][0]:g} {METRIC_THRESHOLDS[name][1]}"
                      if name in METRIC_THRESHOLDS else f"{name}={value:g}; no configured threshold"),
             observed_at=incident.observed_at)
            for name, value in incident.metrics.items()]
    telemetry_refs = [ref for telemetry_result in telemetry_results
                      for ref in result_refs(telemetry_result)]
    refs.extend(telemetry_refs)
    missing = result["missing"]
    missing_sources = [gap for telemetry_result in telemetry_results
                       for gap in telemetry_result.missing_evidence]
    telemetry_context = [{"source": telemetry_result.query.source,
        "status": telemetry_result.status, "reason": telemetry_result.reason,
        "missing_evidence": telemetry_result.missing_evidence,
        "observations": compact_telemetry_records(telemetry_result.records)}
        for telemetry_result in telemetry_results]
    reasoning = invoke_structured(
        "You interpret supplied metric values and deterministic threshold results. Do not invent measurements. Distinguish abnormal, normal, and missing metrics. Explain support or contradiction relative to prior findings and state uncertainty. Cite only supplied metric refs.",
        f"Question: {request.question[:300]}\nIncident: {compact_incident(incident)}\nPrior findings: {compact_findings(prior_findings or [])}\nValues and checks: {result}\nTelemetry query results: {telemetry_context}\nEvidence refs: {compact_evidence_refs(refs)}",
        SpecialistReasoning)
    allowed = {r.ref for r in refs}
    hypotheses = [h.model_copy(update={"supporting_refs": [x for x in h.supporting_refs if x in allowed],
                                       "contradicting_refs": [x for x in h.contradicting_refs if x in allowed]})
                  for h in reasoning.hypotheses]
    observed_facts = [f"Calculated {name}={value:g} from {len(traffic)} traffic observation(s)."
        if name in {"p95_latency_ms", "http_5xx_rate_percent"} else f"Observed {name}={value:g}."
        for name, value in result["values"].items()]
    if traffic:
        observed_facts.append(f"Observed {len(traffic)} request outcome(s).")
        if latencies:
            counts = {value: latencies.count(value) for value in sorted(set(latencies))}
            if len(counts) == 1:
                value = next(iter(counts))
                observed_facts.append(f"Observed latency_ms={value:g} for {len(latencies)} of {len(traffic)} request(s).")
            else:
                observed_facts.append(f"Observed request latency range {min(latencies):g}–{max(latencies):g} ms across {len(latencies)} requests.")
        if statuses:
            status_counts = {code: statuses.count(code) for code in sorted(set(statuses))}
            observed_facts.append("Observed HTTP status counts: " + ", ".join(
                f"{code}={count}" for code, count in status_counts.items()) + ".")
    direct_metrics = [record for record in telemetry_records if record.source == "metrics"]
    for name in ("cpu_percent", "db_connection_pool_percent"):
        values = [record.values[name] for record in direct_metrics
                  if isinstance(record.values.get(name), (int, float))]
        if values:
            observed_facts.append(f"Observed {name}={values[-1]:g}% in {len(values)} metric observation(s).")
    health_records = [record for record in telemetry_records if record.source == "database_health"]
    if health_records:
        health_values = [record.values.get("healthy") for record in health_records
                         if isinstance(record.values.get("healthy"), bool)]
        if health_values:
            counts = {value: health_values.count(value) for value in sorted(set(health_values))}
            observed_facts.append("Database health observations report " + ", ".join(
                f"healthy={str(value).lower()} ({count}/{len(health_records)})"
                for value, count in counts.items()) + ".")
        for key in ("active_connections", "max_connections"):
            values = [record.values[key] for record in health_records
                      if isinstance(record.values.get(key), (int, float))]
            if values:
                distinct = sorted(set(values))
                shown = ", ".join(f"{value:g}" for value in distinct)
                observed_facts.append(f"Database health observations report {key}={shown}.")
    uncertainty = list(reasoning.contradictions)
    if "p95_latency_ms" in result["abnormal"]:
        uncertainty.append("The observed metrics show elevated latency but do not establish its cause.")
    return MetricsAnalysis(summary=reasoning.summary,
        observed_facts=observed_facts,
        hypotheses=hypotheses, evidence_refs=refs,
        uncertainty=uncertainty,
        missing_evidence=reasoning.missing_evidence + [f"Missing metric: {m}" for m in missing] + missing_sources,
        evidence_queries=[EvidenceQueryState(source=telemetry_result.query.source,
            status="retrieved" if telemetry_result.status == "available" else telemetry_result.status,
            record_count=len(telemetry_result.records),
            missing_evidence=telemetry_result.missing_evidence, reason=telemetry_result.reason)
            for telemetry_result in telemetry_results],
        follow_up=reasoning.follow_up, metric_values=result["values"],
        calculated_values={name: result["values"][name]
            for name in ("p95_latency_ms", "http_5xx_rate_percent")
            if name in result["values"]},
        abnormal_metrics=list(result["abnormal"]), missing_metrics=missing)
