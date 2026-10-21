"""Compact already-validated findings before handing them to another agent."""
from __future__ import annotations

from app.models import AgentFinding


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit - 1].rstrip() + "…"


def compact_evidence_refs(refs: list, limit: int = 8) -> list[dict]:
    selected = refs if len(refs) <= limit else refs[:limit - 1] + refs[-1:]
    return [{"ref": ref.ref, "source": ref.source,
        "observed_at": ref.observed_at.isoformat() if ref.observed_at else None,
        "execution_id": ref.execution_id, "incident_id": ref.incident_id,
        "source_id": ref.source_id, "excerpt": _clip(ref.excerpt, 180)}
        for ref in selected]


def compact_incident(incident) -> dict:
    """Bound user-provided lists without dropping distinct observations."""
    data = incident.model_dump(mode="json")
    data["summary"] = _clip(data["summary"], 500)
    data["symptoms"] = [_clip(value, 180) for value in data["symptoms"][:6]]
    data["logs"] = [_clip(value, 180) for value in data["logs"][:5]]
    data["recent_changes"] = [_clip(value, 180) for value in data["recent_changes"][:5]]
    return data


def compact_findings(findings: list[AgentFinding]) -> list[dict]:
    """Retain decision-relevant content while avoiding repeated full trace payloads."""
    compact: list[dict] = []
    for finding in findings[-6:]:
        refs = [{"ref": ref.ref, "source": ref.source,
                 "observed_at": ref.observed_at.isoformat() if ref.observed_at else None,
                 "execution_id": ref.execution_id, "incident_id": ref.incident_id,
                 "source_id": ref.source_id, "excerpt": _clip(ref.excerpt, 180)}
                for ref in finding.evidence_refs[:5]]
        item = {
            "finding_id": finding.finding_id,
            "agent": finding.agent,
            "summary": _clip(finding.summary, 280),
            "observed_facts": [_clip(value, 140) for value in finding.observed_facts[:4]],
            "hypotheses": [{
                "statement": _clip(h.statement, 150),
                "rationale": _clip(h.rationale, 180),
                "supporting_refs": h.supporting_refs[:6],
                "contradicting_refs": h.contradicting_refs[:6],
                "uncertainty": _clip(h.uncertainty, 100),
            } for h in finding.hypotheses[:2]],
            "evidence_refs": refs,
            "uncertainty": [_clip(value, 100) for value in finding.uncertainty[:3]],
            "missing_evidence": [_clip(value, 120) for value in finding.missing_evidence[:3]],
            "follow_up": _clip(finding.follow_up, 160) if finding.follow_up else None,
            "reasoning_status": finding.reasoning_status,
            "evidence_queries": [{"source": query.source, "status": query.status,
                "record_count": query.record_count,
                "missing_evidence": [_clip(value, 100) for value in query.missing_evidence[:2]],
                "reason": _clip(query.reason, 120) if query.reason else None}
                for query in finding.evidence_queries],
        }
        for name in ("metric_values", "calculated_values", "abnormal_metrics", "missing_metrics",
                     "candidate_changes", "timestamps"):
            value = getattr(finding, name, None)
            if value is not None:
                item[name] = (value if isinstance(value, dict) else
                              [_clip(entry, 160) if isinstance(entry, str) else entry
                               for entry in value[:5]])
        compact.append(item)
    return compact


def compact_telemetry_records(records: list, limit: int = 6) -> dict:
    """Compact model-facing telemetry while retaining provenance and contradictions."""
    if not records:
        return {"record_count": 0, "samples": [], "value_summary": {}}
    numeric: dict[str, list[tuple[float, object]]] = {}
    categories: dict[str, set[str]] = {}
    for record in records:
        for key, value in record.values.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                numeric.setdefault(key, []).append((float(value), record))
            elif value is not None:
                categories.setdefault(key, set()).add(str(value).lower() if isinstance(value, bool) else str(value))
    summary = {key: {"min": min(values, key=lambda pair: pair[0])[0],
                     "max": max(values, key=lambda pair: pair[0])[0],
                     "count": len(values)} for key, values in numeric.items()}
    summary.update({key: {"distinct_values": sorted(values)[:12],
                          "distinct_count": len(values)} for key, values in categories.items()})

    chosen = {0, len(records) - 1}
    for key in numeric:
        eligible = [i for i, record in enumerate(records)
                    if isinstance(record.values.get(key), (int, float))
                    and not isinstance(record.values.get(key), bool)]
        if eligible:
            low = min(eligible, key=lambda i: float(records[i].values[key]))
            high = max(eligible, key=lambda i: float(records[i].values[key]))
            if len(chosen) < limit or low in chosen:
                chosen.add(low)
            if len(chosen) < limit or high in chosen:
                chosen.add(high)
    # Distinct categorical states and message variants often carry contradictory evidence.
    signatures = set()
    for index, record in enumerate(records):
        signature = (tuple(sorted((k, str(v)) for k, v in record.values.items())), record.message[:120])
        if signature not in signatures and len(chosen) < limit:
            chosen.add(index)
            signatures.add(signature)
    indices = sorted(chosen)
    if len(indices) > limit:
        # Keep the endpoints plus selected distinct signatures/extrema up to the bound.
        indices = sorted(set([0, len(records) - 1] + indices))
        middle = [i for i in indices if i not in {0, len(records) - 1}]
        indices = sorted({0, len(records) - 1, *middle[:max(0, limit - 2)]})
    samples = [{"record_id": r.record_id, "execution_id": r.execution_id,
        "incident_id": r.incident_id, "service": r.service, "source": r.source,
        "source_id": r.source_id, "observed_at": r.observed_at.isoformat(),
        "kind": r.kind, "message": _clip(r.message, 180), "values": r.values}
        for r in (records[i] for i in indices)]
    return {"record_count": len(records), "sample_count": len(samples),
            "value_summary": summary, "samples": samples}
