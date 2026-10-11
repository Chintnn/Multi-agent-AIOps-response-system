from app.incident_tools import inspect_logs, inspect_metrics
from app.models import IncidentReport
from app.sample_data import sample_incident


def main() -> None:
    incident = sample_incident()
    log_finding = inspect_logs(incident)
    metrics_finding = inspect_metrics(incident)

    report = IncidentReport(
        incident_id=incident.incident_id,
        service=incident.service,
        severity=incident.severity,
        findings=[log_finding, metrics_finding],
        preliminary_assessment=(
            "The supplied evidence suggests database connection-pool pressure. "
            "A recent deployment is temporally related, but correlation alone "
            "does not prove it caused the incident."
        ),
        requires_human_approval=True,
        metadata={"mode": "simulated", "remediation_executed": False},
    )

    print("=== AIOps Starter Incident Report ===")
    print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
