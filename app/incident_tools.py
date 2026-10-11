from app.models import EvidenceFinding, IncidentInput


def inspect_logs(incident: IncidentInput) -> EvidenceFinding:
    """Simple baseline log search; deterministic and easy to test."""
    matches = [
        line for line in incident.logs
        if any(term in line.lower() for term in ("error", "timeout", "failed", "exception"))
    ]
    if matches:
        observation = f"Found {len(matches)} log line(s) containing error-related signals."
        next_step = "Compare database pool metrics with the deployment timeline."
    else:
        observation = "No obvious error-related log lines were found in the supplied sample."
        next_step = "Collect a wider time window of logs."
    return EvidenceFinding(
        source="log_inspection_tool",
        observation=observation,
        evidence=matches,
        suggested_next_step=next_step,
    )


def inspect_metrics(incident: IncidentInput) -> EvidenceFinding:
    """Flag metric values that cross simple starter thresholds."""
    thresholds = {
        "p95_latency_ms": (1000.0, "p95 latency is elevated"),
        "http_5xx_rate_percent": (5.0, "HTTP 5xx error rate is elevated"),
        "cpu_percent": (90.0, "CPU usage is high"),
        "db_connection_pool_percent": (85.0, "Database connection pool is near exhaustion"),
    }
    evidence: list[str] = []
    for metric, (threshold, description) in thresholds.items():
        value = incident.metrics.get(metric)
        if value is not None and value >= threshold:
            evidence.append(f"{description}: {value:g} (threshold {threshold:g})")

    if evidence:
        observation = f"{len(evidence)} metric signal(s) crossed the starter thresholds."
        next_step = "Correlate the elevated metrics with logs and recent changes."
    else:
        observation = "No supplied metric crossed the starter thresholds."
        next_step = "Check whether metrics are missing or thresholds need adjustment."

    return EvidenceFinding(
        source="metrics_inspection_tool",
        observation=observation,
        evidence=evidence,
        suggested_next_step=next_step,
    )
