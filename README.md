# Multi-Agent AIOps Incident Response System

This Python service investigates an incident using five coordinated roles: alert triage, log investigation, metrics investigation, change analysis, and remediation/recovery. Triage and specialist interpretation use structured Groq LLM responses; tools retrieve only evidence supplied in the incident and calculate numeric threshold results deterministically. The workflow may choose different investigations based on the incident and accumulated findings. Actions are simulated only.

The repository includes an in-process checkout simulator and run-scoped telemetry store for repeatable local investigations. It does not connect to production logs, metrics, deployment systems, or execute infrastructure changes. A successful simulated action is not evidence of recovery; recovery requires all configured post-action metrics.

## Requirements and setup

Python 3.10 or newer is recommended. From PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `GROQ_API_KEY` in `.env` to enable LLM planning and interpretation. The application does not silently substitute deterministic decisions when the provider is unavailable; it returns an unresolved/failed report with the affected agent recorded. Never commit `.env`.

Configuration:

| Variable | Default | Purpose |
|---|---|---|
| `GROQ_API_KEY` | unset | Groq credential; required for agent reasoning |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Single configured model used by all roles |
| `GROQ_TEMPERATURE` | `0` | Provider sampling temperature |
| `GROQ_TIMEOUT_SECONDS` | `20` | Per-request timeout |
| `GROQ_RETRY_MAX_ATTEMPTS` | `2` | Maximum provider attempts, including the first request |
| `GROQ_RETRY_WAIT_BUDGET_SECONDS` | `25` | Maximum cumulative retry delay; honors `Retry-After` when it fits |
| `GROQ_RETRY_BASE_DELAY_SECONDS` | `0.5` | Base for bounded exponential jitter without provider guidance |
| `GROQ_MAX_COMPLETION_TOKENS` | `1000` | Maximum generated tokens per structured response |
| `AIOPS_TRACE_DIR` | `traces` | JSONL execution trace location |
| `AIOPS_APPROVAL_TOKEN` | unset | Optional operator-only bearer token (at least 32 characters); unset disables API approval actions |

## Run and test

```powershell
python -m app.main
python -m pytest
```

The CLI runs `run_incident` with a synthetic checkout incident and prints the validated final report. Each workflow writes a JSONL trace named by execution ID under `AIOPS_TRACE_DIR`. Traces may contain incident evidence; keep the directory access-controlled. Without a provider key, the run terminates explicitly as unresolved rather than claiming an LLM decision.

Tests mock the provider boundary and do not require a live Groq key. Optional live-provider checks are not part of the ordinary test suite.

## Checkout fault simulation and telemetry

The demo handles each checkout request in-process and emits its actual modeled HTTP status, latency, timestamped application log, traffic observation, service metrics, and database-health observation. The `faulty_deployment` scenario also emits a configuration deployment record for the pool-size change. Evidence is stored in memory for that execution; no production system is queried or changed.

Run any scenario without an API key to inspect its generated request outcomes:

```powershell
python -m app.demo --scenario baseline --requests 12
python -m app.demo --scenario database_connection_pressure --requests 12
python -m app.demo --scenario high_latency --requests 12
python -m app.demo --scenario elevated_5xx --requests 12
python -m app.demo --scenario faulty_deployment --requests 12
```

To run the generated incident through triage and the specialist agents, configure `GROQ_API_KEY` in `.env`, then add `--investigate`:

```powershell
python -m app.demo --scenario faulty_deployment --requests 12 --investigate
```

The investigation command passes the simulation's telemetry store, execution ID, and time window to the existing workflow. Metrics analysis derives latency and 5xx rate from generated request outcomes, reads pool and database health observations, and retains record timestamps and source IDs. Log and change investigations query the generated application-log and deployment records. References use `telemetry:<source>:<record_id>` and include the observation time, source ID, and execution ID. The existing incident-payload tools continue to work unchanged when no telemetry source is passed.

Evidence queries use validated `EvidenceQuery`/`EvidenceWindow` contracts. If triage requests a source, the workflow runs a bounded batch of up to six queries over the current incident window, hands returned records back to triage, and traces each result. Empty windows are marked insufficient; unconfigured providers and unavailable sources are marked unavailable with explicit missing evidence. The demo's provider is in-memory only and is discarded when the process exits.

## Agent and workflow boundaries

- **Alert triage:** interprets the incident plus accumulated findings and chooses one next agent, requests information, or escalates.
- **Log investigation:** analyzes incident payload records (`logs:N`) and, when configured, time-windowed telemetry log records.
- **Metrics investigation:** deterministic thresholds identify anomalies and missing values; the LLM interprets their relevance. Payload metric references use `metrics:NAME` IDs; telemetry references include source, record, timestamp, and execution identifiers.
- **Change analysis:** evaluates supplied change records and time-windowed deployment metadata without claiming causality from proximity alone.
- **Remediation/recovery:** an LLM may recommend among a fixed action set only after sufficient findings. Deterministic code assigns risk, validates the proposal and approval identity, and simulates actions. Required post-action metrics are checked separately.

LangGraph controls conditional transitions when installed. A small compatible runner uses the same transitions if LangGraph is unavailable, so missing dependencies do not make a false claim that a graph was executed. The graph enforces the LLM-selected destination against allowed agents, completed work, and the investigation budget.

## Python service interface

`app.service` exposes backend functions for a future HTTP adapter:

- `submit_incident(incident)` returns an execution ID.
- `start_investigation(execution_id)` runs the investigation.
- `get_execution_status(execution_id)` returns lifecycle status and remaining budget.
- `get_incident_report(execution_id)` returns the final report.
- `get_execution_trace(execution_id)` returns trace events.
- `get_remediation_state(execution_id)` returns proposal, approval, simulated execution, and recovery state.
- `record_approval(execution_id, approved_by, decision, post_action_metrics)` records a decision for the matching proposal and then simulates/checks it.

The service registry is process-local and is not durable across restarts. Approval actions are disabled unless the server has an `AIOPS_APPROVAL_TOKEN` of at least 32 characters. The API compares the bearer token on the server and never returns it. The public dashboard is read-only; it displays proposals and recovery results but offers no approval or rejection controls. `approved_by` remains a supplied label, not an independently verified user identity, so use the token only for a trusted operator in this simulation. Do not configure it for a public read-only demo.

## Local HTTP API and dashboard

Install dependencies from `requirements.txt`, configure `.env` as needed, then start the API and dashboard from the repository root:

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.api:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/` for the responsive dashboard. API documentation is at `http://127.0.0.1:8000/docs`; the health endpoint is `GET /api/health`. The dependency-free HTML/CSS/JavaScript frontend uses only these HTTP endpoints and is served by FastAPI from `frontend/`.

The dashboard lets you choose all five scenarios, generate 1–500 actual simulated checkout outcomes, start the adaptive investigation, poll worker and workflow status, and inspect the report, trace, time-windowed evidence, and any approval-gated simulated proposal/recovery result. A local run does not require a Groq key to generate telemetry. LLM investigation does require `GROQ_API_KEY`; without it, the workflow preserves a failed/unresolved outcome rather than inventing an agent decision.

The API exposes:

- `GET /api/health` and `GET /api/scenarios`
- `POST /api/incidents` to generate and register simulated requests and telemetry
- `POST /api/incidents/{execution_id}/investigation` to queue an investigation (`202 Accepted`)
- `GET /api/incidents/{execution_id}/status`, `/report`, `/trace`, `/evidence`, and `/remediation`
- `POST /api/incidents/{execution_id}/approval` with `proposal_id`, `approved_by`, `decision`, and optional `post_action_metrics`; it returns 403 when disabled, and otherwise requires `Authorization: Bearer <AIOPS_APPROVAL_TOKEN>`

Investigation work runs in a bounded in-process thread pool. Execution, job, and telemetry state are held in memory and disappear when the process restarts; this is a local demo, not durable storage. `app.service.ExecutionRepository` is the boundary for a later persistent implementation. Configure allowed browser origins with comma-separated `AIOPS_FRONTEND_ORIGINS`; the default allows the two loopback origins on port 8000.

To drive the API without the dashboard, in another PowerShell window:

```powershell
$incident = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/incidents -ContentType 'application/json' -Body '{"scenario":"faulty_deployment","requests":12}'
$id = $incident.execution_id
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/incidents/$id/investigation"
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/incidents/$id/status"
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/incidents/$id/trace"
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/incidents/$id/evidence"
```

An approval body must repeat the exact proposal ID returned by `/remediation`. Medium/high risk simulated execution is impossible without that matching explicit decision and operator bearer credential. The shared token is not per-user identity, and the public UI has no approval controls. No UI or API path connects to production infrastructure.

## Render preparation

The root `render.yaml` defines one Python web service and uses the existing FastAPI application (`app.api:app`). It installs `requirements.txt`, binds Uvicorn to `0.0.0.0` on Render's assigned `$PORT`, and checks `/api/health`. FastAPI serves `frontend/index.html` at `/` and the checked-in assets at `/static/`; there is no separate frontend build step. Render's Blueprint and web-service settings support these build/start commands and health-check configuration ([Blueprint reference](https://render.com/docs/blueprint-spec), [web services](https://render.com/docs/web-services)).

To deploy later, push the reviewed project to the intended Git branch, create a Render Blueprint from that repository, review `render.yaml`, and apply it. Add `GROQ_API_KEY` as a secret environment variable in Render; it is read by server-side Python only. Do not put it in frontend files, build arguments, or public API responses. Leave `AIOPS_APPROVAL_TOKEN` unset for the public demo. Render writes traces under `/tmp/aiops-traces`; that directory and all incident/job/telemetry state are ephemeral and are not a persistence layer. Confirm the deployed service reports healthy at `/api/health`; no deployment URL is assumed here.

LLM execution depends on the configured Groq model, account quota, and provider availability. Calls have bounded retries, but rate limits can still stop an investigation with an unresolved report. The application does not promise reliable or unlimited live inference. Public exposure should also add request rate limits and durable audit/storage controls before use beyond a small demonstration.

## Input and output

Inputs use `IncidentInput` from `app.models` (incident ID, service, summary, severity, symptoms, optional metrics/logs/recent changes and observed time). `IncidentReport` is the stable final response model. Example synthetic input is in `app/sample_data.py`; exact outputs depend on the configured model and the evidence it receives. They are recorded in the JSONL trace and CLI report rather than presented here as a fabricated run.

## Safety and known limits

- No agent has a production action tool. All execution results are explicitly marked simulated.
- Medium and high risk actions require an `ApprovalRecord` bound to the proposal ID; action and risk are independently checked against policy.
- Recovery has three outcomes: recovered, not recovered, and insufficient evidence. Missing any required metric prevents a recovered status.
- Agent/provider failures and unsupported routes are preserved in the report and trace. The workflow does not claim deterministic fallback reasoning was an LLM decision.
- Production telemetry adapters, persistent service storage, per-user approval identity, public request rate limits, and production monitoring remain future work. The local simulator is not a substitute for production data sources.
