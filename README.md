# Multi-Agent AIOps Incident Response System

Starter foundation for a CA3 multi-agent project. This first milestone uses deterministic simulated incident data. AI agents and LangGraph orchestration will be added in the next milestone.

## Requirements
- Python 3.10+
- Git

## Setup (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use Command Prompt instead:
```bat
.venv\Scripts\activate.bat
```

## Run the first incident investigation
```powershell
python -m app.main
```

## Run tests
```powershell
python -m pytest
```

## What this milestone does
- Defines a validated incident input model.
- Loads a realistic simulated checkout incident.
- Runs small, deterministic log and metrics inspection tools.
- Produces a structured evidence summary.
- Tests expected behaviour.

No production services are touched and no remediation commands are executed.

## Next milestone
Add the model provider, individual specialist agents, and a LangGraph orchestrator that can choose which investigation to run next based on evidence.
