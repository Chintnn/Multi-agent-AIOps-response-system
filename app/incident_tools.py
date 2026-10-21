"""Deterministic, provenance-preserving tools over evidence supplied by callers."""
from __future__ import annotations

import re

from app.models import EvidenceFinding, EvidenceRef, IncidentInput

METRIC_THRESHOLDS: dict[str, tuple[float, str]] = {
    "p95_latency_ms": (1000.0, "ms"),
    "http_5xx_rate_percent": (5.0, "%"),
    "cpu_percent": (90.0, "%"),
    "db_connection_pool_percent": (85.0, "%"),
}


def retrieve_logs(incident: IncidentInput, question: str = "") -> list[EvidenceRef]:
    """Return actual supplied log lines, preserving stable per-run references."""
    # Do not filter away evidence based on an LLM-generated query. Return the
    # supplied incident window and let structured reasoning assess relevance.
    return [EvidenceRef(ref=f"logs:{i}", source="incident.logs", excerpt=line,
                        observed_at=_timestamp(line))
            for i, line in enumerate(incident.logs)]


def retrieve_changes(incident: IncidentInput) -> list[EvidenceRef]:
    return [EvidenceRef(ref=f"changes:{i}", source="incident.recent_changes", excerpt=change,
                        observed_at=_timestamp(change))
            for i, change in enumerate(incident.recent_changes)]


def inspect_metric_values(incident: IncidentInput,
                          additional_values: dict[str, float] | None = None) -> dict:
    actual = dict(incident.metrics)
    actual.update(additional_values or {})
    abnormal = {name: {"value": value, "threshold": METRIC_THRESHOLDS[name][0],
                       "unit": METRIC_THRESHOLDS[name][1]}
                for name, value in actual.items()
                if name in METRIC_THRESHOLDS and value >= METRIC_THRESHOLDS[name][0]}
    missing = [name for name in METRIC_THRESHOLDS if name not in actual]
    return {"values": actual, "abnormal": abnormal, "missing": missing,
            "thresholds": {k: {"value": v[0], "unit": v[1]} for k, v in METRIC_THRESHOLDS.items()}}


def inspect_logs(incident: IncidentInput) -> EvidenceFinding:
    refs = retrieve_logs(incident)
    matches = [ref.excerpt for ref in refs
               if any(term in ref.excerpt.lower() for term in ("error", "timeout", "failed", "exception"))]
    return EvidenceFinding(source="log_inspection_tool",
        observation=f"Found {len(matches)} log line(s) containing error-related signals." if matches else "No obvious error-related log lines were found in the supplied sample.",
        evidence=matches,
        suggested_next_step="Correlate log records with metrics and recent changes." if matches else "Request a wider time window or additional log sources.")


def inspect_metrics(incident: IncidentInput) -> EvidenceFinding:
    result = inspect_metric_values(incident)
    evidence = [f"{name}={data['value']:g}{data['unit']} (threshold {data['threshold']:g}{data['unit']})"
                for name, data in result["abnormal"].items()]
    if result["missing"]:
        evidence.append("Missing metrics: " + ", ".join(result["missing"]))
    return EvidenceFinding(source="metrics_inspection_tool",
        observation=f"{len(result['abnormal'])} supplied metric(s) crossed configured thresholds; {len(result['missing'])} metric(s) are missing.",
        evidence=evidence,
        suggested_next_step="Correlate anomalies with logs and changes." if result["abnormal"] else "Request missing measurements before concluding the service is healthy.")


def _timestamp(text: str):
    match = re.search(r"\b(20\d\d-\d\d-\d\d[T ]\d\d:\d\d(?::\d\d)?Z?)\b", text)
    return match.group(1) if match else None
