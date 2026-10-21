"""CLI for generating checkout faults and optionally investigating their telemetry."""
from __future__ import annotations

import argparse
import json

from app.demo_service import FaultScenario, simulate_checkout
from app.orchestrator import run_incident


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate checkout requests and inspect generated evidence")
    parser.add_argument("--scenario", choices=[item.value for item in FaultScenario],
                        default=FaultScenario.database_connection_pressure.value)
    parser.add_argument("--requests", type=int, default=12)
    parser.add_argument("--investigate", action="store_true",
                        help="run the adaptive LLM investigation (requires GROQ_API_KEY)")
    args = parser.parse_args()
    demo = simulate_checkout(args.scenario, args.requests)
    print(json.dumps({"execution_id": demo.execution_id,
        "incident_id": demo.incident.incident_id, "scenario": demo.scenario.value,
        "requests": len(demo.outcomes),
        "status_codes": {str(status): sum(row.status_code == status for row in demo.outcomes)
                         for status in sorted({row.status_code for row in demo.outcomes})},
        "mean_latency_ms": round(sum(row.latency_ms for row in demo.outcomes) / len(demo.outcomes), 2),
        "telemetry_records": len(demo.telemetry.records)}, indent=2))
    if not args.investigate:
        print("Simulation complete. Add --investigate to run the LLM-driven workflow.")
        return
    state = run_incident(demo.incident, execution_id=demo.execution_id,
        evidence_source=demo.telemetry, evidence_window=demo.window)
    print(json.dumps({"status": state.status,
        "route": [event.details.get("next_agent") for event in state.trace
                  if event.event_type == "routing_decision"],
        "investigations": state.investigation_history,
        "evidence_queries": [{"source": event.details.get("source"),
            "status": event.details.get("status"),
            "records": event.details.get("record_count"),
            "missing": event.details.get("missing_evidence")}
            for event in state.trace if event.event_type == "evidence_query_result"],
        "errors": state.errors,
        "trace": state.report.trace_reference if state.report else None}, indent=2))


if __name__ == "__main__":
    main()
