
from typing import Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from app.agents.alert_agent import (
    AlertTriageResult,
    investigate_alert,
)
from app.agents.log_agent import investigate_logs
from app.agents.metrics_agent import investigate_metrics
from app.models import EvidenceFinding, IncidentInput


MAX_INVESTIGATIONS = 3


class IncidentState(TypedDict):
    """Shared state passed between nodes in the incident workflow."""

    incident: IncidentInput
    triage: AlertTriageResult | None
    findings: list[EvidenceFinding]
    completed_investigations: list[str]
    next_investigation: str
    steps: int
    status: Literal[
        "investigating",
        "completed",
        "needs_more_information",
    ]
    errors: list[str]


def triage_node(state: IncidentState) -> dict:
    """Assess the incident and select the next investigation."""
    try:
        result = investigate_alert(state["incident"])
        return {
            "triage": result,
            "next_investigation": result.next_investigation,
            "status": "investigating",
        }
    except Exception as exc:
        return {
            "errors": state["errors"] + [f"Alert triage failed: {exc}"],
            "status": "needs_more_information",
            "next_investigation": "stop",
        }


def log_node(state: IncidentState) -> dict:
    """Investigate log evidence."""
    finding = investigate_logs(state["incident"])
    return {
        "findings": state["findings"] + [finding],
        "completed_investigations": (
            state["completed_investigations"] + ["logs"]
        ),
        "steps": state["steps"] + 1,
    }


def metrics_node(state: IncidentState) -> dict:
    """Investigate metric evidence."""
    finding = investigate_metrics(state["incident"])
    return {
        "findings": state["findings"] + [finding],
        "completed_investigations": (
            state["completed_investigations"] + ["metrics"]
        ),
        "steps": state["steps"] + 1,
    }


def route_after_triage(
    state: IncidentState,
) -> Literal["logs", "metrics", "stop"]:
    """Choose an investigation using triage's recommendation."""
    requested = state["next_investigation"]
    completed = state["completed_investigations"]

    if state["status"] != "investigating":
        return "stop"

    if state["steps"] >= MAX_INVESTIGATIONS:
        return "stop"

    if requested in {"logs", "metrics"} and requested not in completed:
        return requested

    # If the requested investigation has already run, try the other one.
    for candidate in ("logs", "metrics"):
        if candidate not in completed:
            return candidate

    return "stop"


def route_after_investigation(
    state: IncidentState,
) -> Literal["triage", "stop"]:
    """Reassess evidence or stop when both investigations have run."""
    if state["steps"] >= MAX_INVESTIGATIONS:
        return "stop"

    if {"logs", "metrics"}.issubset(
        set(state["completed_investigations"])
    ):
        return "stop"

    return "triage"


def build_graph():
    """Create and compile the LangGraph incident workflow."""
    builder = StateGraph(IncidentState)

    builder.add_node("triage", triage_node)
    builder.add_node("logs", log_node)
    builder.add_node("metrics", metrics_node)

    builder.add_edge(START, "triage")

    builder.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "logs": "logs",
            "metrics": "metrics",
            "stop": END,
        },
    )

    for node_name in ("logs", "metrics"):
        builder.add_conditional_edges(
            node_name,
            route_after_investigation,
            {
                "triage": "triage",
                "stop": END,
            },
        )

    return builder.compile()


def run_incident(incident: IncidentInput) -> IncidentState:
    """Run the workflow and return its final state."""
    graph = build_graph()

    initial_state: IncidentState = {
        "incident": incident,
        "triage": None,
        "findings": [],
        "completed_investigations": [],
        "next_investigation": "more_information",
        "steps": 0,
        "status": "investigating",
        "errors": [],
    }

    return graph.invoke(initial_state)
