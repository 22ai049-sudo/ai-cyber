from datetime import datetime, timezone
from typing import Any, Dict

from .redis_client import RedisClient


class AuditLogger:
    def __init__(self, redis_client: RedisClient) -> None:
        self.redis_client = redis_client

    def log(self, incident_id: str, action: str, details: Dict[str, Any]) -> Dict[str, Any]:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident_id,
            "action": action,
            "details": details,
        }
        self.redis_client.append_audit(incident_id, record)
        return record
