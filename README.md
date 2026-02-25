# AI SOC Automation Platform

Production-style SOC automation stack using FastAPI, Redis orchestration, Docker sandbox execution, Ollama (Mistral 7B), and a React analyst UI.

## Architecture

- **Ingestion**: two analyst-selectable modes are supported in UI: `manual` input and `automatic` malicious-IP collection from global feeds (`/ingestion/automatic`).
- **Training assist**: optional curated dataset quick-load chips are provided for SOC learning scenarios.
- **Threat intel enrichment**: Backend enriches IOC with VirusTotal + AbuseIPDB APIs (authenticated via `VT_API_KEY` and `ABUSEIPDB_API_KEY`).
- **Detection & ATT&CK mapping**: IOC/context pattern mapping and risk scoring.
- **Model correctness checks**: confidence/severity consistency + command safety checks returned in `model_validation`.
- **CVSS-like risk scoring**: `RiskScoreEngine` produces `risk_score` (0-10), severity, confidence, and factor breakdown.
- **LLM explainability**: Ollama Mistral 7B generates reasoning and mitigation rationale.
- **Mitigation generation**: Structured playbook + commands.
- **Security controls**: Command whitelist + unsafe command rejection.
- **Execution isolation**: Approved commands run in hardened Docker sandbox and fully audit logged.
- **Orchestration**: Redis stores incident state and audit timeline.

## Backend Modules

Located in `backend/app`:

1. `detector.py`
2. `redis_client.py`
3. `llm_engine.py`
4. `mitigation_generator.py`
5. `command_verifier.py`
6. `atave_validator.py`
7. `sandbox_executor.py`
8. `audit_logger.py`
9. `pipeline_orchestrator.py`
10. `main_api.py`

## Frontend Modules

Located in `frontend/src/components`:

1. `AnalystDashboard.jsx`
2. `IncidentPanel.jsx`
3. `ExplainabilityPanel.jsx`
4. `MitigationPanel.jsx`
5. `RiskScoreChart.jsx`
6. `AuditLogsViewer.jsx`

## Installation

### Prerequisites
- Docker + Docker Compose
- At least 8GB RAM for local LLM runtime

### 1) Clone and configure env

```bash
cp .env.example .env 2>/dev/null || true
```

Create `.env` with:

```bash
VT_API_KEY=<your_virustotal_api_key>
ABUSEIPDB_API_KEY=<your_abuseipdb_api_key>
JWT_SECRET=<strong_secret>
SOC_USER=socadmin
SOC_PASS=socpass
```

### 2) Pull/start stack

```bash
docker compose up --build -d
```

### 3) Pull Ollama model

```bash
docker compose exec ollama ollama pull mistral:7b
```

## Run Instructions

- API docs: `http://localhost:8000/docs`
- UI: `http://localhost:5173`

### Typical workflow

1. Click **Authenticate** in UI (uses default SOC credentials).
2. Submit IOC + telemetry context in **Incident Ingestion** panel.
3. Review:
   - LLM reasoning
   - MITRE ATT&CK mapping
   - Confidence and severity chart
   - mitigation commands and command safety verdicts
   - full audit logs (including sandbox isolation metadata)

## Redis Setup

Redis is used only for orchestration/state:
- Incident object cache: `incident:<id>`
- Audit timeline list: `audit:<id>`

## Docker Sandbox Setup

Sandbox executor runs:
- image: `alpine:3.20`
- `--network none`
- `--cap-drop ALL`
- CPU/memory limits

This guarantees mitigation commands are isolated and logged.

## Local Development

Backend only:
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main_api:app --reload
```

Frontend only:
```bash
cd frontend
npm install
npm run dev
```


## Data Ingestion (Manual + Automatic)

The platform supports two primary ingestion modes:

- `manual`: analyst-entered IOC and context from the dashboard.
- `automatic`: pulls suspicious/corrupted IP indicators from global reputation feeds (`blocklist.de`, abuse.ch Feodo tracker) with resilient fallback values.

Real log ingestion is also available through:
- `GET /ingestion/logs/samples` (Sysmon/Suricata/Wazuh sample payloads)
- `POST /ingestion/logs/parse` (normalizes raw log to source + indicator + message)

For learning workflows, curated dataset examples from `backend/app/data/sample_incidents.json` can be auto-filled in manual mode.

`/incidents/process` accepts:

```json
{
  "source": "suricata",
  "indicator": "10.10.4.13",
  "context": {"message": "Repeated failed SSH attempts"},
  "execute_mitigation": false,
  "ingestion_mode": "automatic",
  "dataset_name": null
}
```
