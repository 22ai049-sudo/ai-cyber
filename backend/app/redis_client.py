import json
from typing import Any, Dict, List, Optional

import redis


class RedisClient:
    """Redis-only orchestration and ephemeral state helper."""

    def __init__(self, url: str = "redis://redis:6379/0") -> None:
        self._client = redis.Redis.from_url(url, decode_responses=True)

    def healthcheck(self) -> bool:
        return bool(self._client.ping())

    def set_json(self, key: str, value: Dict[str, Any], ttl_seconds: int = 3600) -> None:
        self._client.setex(key, ttl_seconds, json.dumps(value))

    def get_json(self, key: str) -> Optional[Dict[str, Any]]:
        raw = self._client.get(key)
        return json.loads(raw) if raw else None

    def push_queue(self, queue: str, value: Dict[str, Any]) -> None:
        self._client.lpush(queue, json.dumps(value))

    def pop_queue(self, queue: str, timeout: int = 1) -> Optional[Dict[str, Any]]:
        item = self._client.brpop(queue, timeout=timeout)
        if not item:
            return None
        _, raw = item
        return json.loads(raw)

    def append_audit(self, incident_id: str, record: Dict[str, Any]) -> None:
        self._client.lpush(f"audit:{incident_id}", json.dumps(record))

    def get_audit(self, incident_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        raw_entries = self._client.lrange(f"audit:{incident_id}", 0, limit - 1)
        return [json.loads(entry) for entry in raw_entries]
