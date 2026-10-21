"""CLI entry point: run the same adaptive workflow exposed by the service."""
import json

from app.orchestrator import run_incident
from app.sample_data import sample_incident


def main() -> None:
    state = run_incident(sample_incident())
    if state.report is None:
        raise RuntimeError("Incident workflow ended without a report")
    # Escape non-ASCII text so the CLI remains printable on Windows consoles
    # using legacy code pages such as CP1252.
    print(json.dumps(state.report.model_dump(mode="json"), indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
