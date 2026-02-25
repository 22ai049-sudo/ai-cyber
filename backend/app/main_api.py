import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .atave_validator import AtaveValidator
from .audit_logger import AuditLogger
from .command_verifier import CommandVerifier
from .detector import Detector
from .llm_engine import LLMEngine
from .data_ingestion import DataIngestionService
from .mitigation_generator import MitigationGenerator
from .pipeline_orchestrator import PipelineOrchestrator
from .redis_client import RedisClient
from .risk_score_engine import RiskScoreEngine
from .sandbox_executor import SandboxExecutor

JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
ADMIN_USER = os.getenv("SOC_USER", "socadmin")
ADMIN_PASS = os.getenv("SOC_PASS", "socpass")


class LoginRequest(BaseModel):
    username: str
    password: str


class IncidentRequest(BaseModel):
    source: str = Field(default="siem")
    indicator: str
    context: Dict[str, Any] = Field(default_factory=dict)
    execute_mitigation: bool = False
    ingestion_mode: str = Field(default="manual")
    dataset_name: str | None = None


class ParseLogRequest(BaseModel):
    source: str
    raw_log: str


redis_client = RedisClient(os.getenv("REDIS_URL", "redis://redis:6379/0"))
audit_logger = AuditLogger(redis_client)
ingestion_service = DataIngestionService()

orchestrator = PipelineOrchestrator(
    detector=Detector(os.getenv("VT_API_KEY"), os.getenv("ABUSEIPDB_API_KEY")),
    validator=AtaveValidator(),
    risk_engine=RiskScoreEngine(),
    llm_engine=LLMEngine(os.getenv("OLLAMA_URL", "http://ollama:11434")),
    mitigation_generator=MitigationGenerator(),
    command_verifier=CommandVerifier(),
    sandbox_executor=SandboxExecutor(),
    audit_logger=audit_logger,
)

app = FastAPI(title="AI SOC Automation Platform")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer()


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def auth(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return str(payload["sub"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}") from exc


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "redis": redis_client.healthcheck()}


@app.post("/auth/login")
def login(req: LoginRequest) -> Dict[str, str]:
    if req.username != ADMIN_USER or req.password != ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_token(req.username)}


@app.post("/incidents/process")
def process_incident(req: IncidentRequest, _user: str = Depends(auth)) -> Dict[str, Any]:
    if req.ingestion_mode not in {"manual", "automatic", "dataset", "live"}:
        raise HTTPException(status_code=422, detail="Unsupported ingestion_mode")
    if not req.indicator.strip():
        raise HTTPException(status_code=422, detail="indicator is required")

    result = orchestrator.process(req.source, req.indicator, req.context, req.execute_mitigation, req.ingestion_mode, req.dataset_name)
    redis_client.set_json(f"incident:{result['incident_id']}", result, ttl_seconds=86400)
    return result


@app.get("/incidents/{incident_id}/audit")
def get_audit(incident_id: str, _user: str = Depends(auth)) -> Dict[str, Any]:
    return {"incident_id": incident_id, "logs": redis_client.get_audit(incident_id)}


@app.get("/ingestion/samples")
def ingestion_samples(_user: str = Depends(auth)) -> Dict[str, Any]:
    return {"samples": ingestion_service.dataset_samples()}


@app.get("/ingestion/live")
def ingestion_live(_user: str = Depends(auth)) -> Dict[str, Any]:
    return ingestion_service.live_metrics()


@app.get("/ingestion/automatic")
def ingestion_automatic(_user: str = Depends(auth)) -> Dict[str, Any]:
    return ingestion_service.automatic_ip_feed()


@app.get("/ingestion/logs/samples")
def ingestion_log_samples(_user: str = Depends(auth)) -> Dict[str, Any]:
    return {"samples": ingestion_service.sample_logs()}


@app.post("/ingestion/logs/parse")
def ingestion_log_parse(req: ParseLogRequest, _user: str = Depends(auth)) -> Dict[str, Any]:
    return ingestion_service.parse_security_log(req.source, req.raw_log)
