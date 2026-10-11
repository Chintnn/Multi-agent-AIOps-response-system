from app.models import IncidentInput


def sample_incident() -> IncidentInput:
    """Return a repeatable simulated checkout incident for development and tests."""
    return IncidentInput(
        incident_id="INC-1001",
        service="checkout-api",
        summary="Checkout requests are slow and some are failing",
        severity="high",
        symptoms=[
            "p95 latency is above the normal range",
            "HTTP 500 errors increased after a deployment",
        ],
        metrics={
            "p95_latency_ms": 2400.0,
            "http_5xx_rate_percent": 12.5,
            "cpu_percent": 68.0,
            "db_connection_pool_percent": 96.0,
        },
        logs=[
            "ERROR checkout: database connection acquisition timed out",
            "WARN checkout: request exceeded 2000ms",
            "ERROR checkout: failed to create order due to DB timeout",
        ],
        recent_changes=[
            "checkout-api version 2.4.1 deployed 12 minutes before alert",
        ],
    )
