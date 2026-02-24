from typing import Any, Dict, Optional

import requests


class Detector:
    def __init__(self, virus_total_api_key: Optional[str] = None) -> None:
        self.virus_total_api_key = virus_total_api_key

    def ingest_event(self, source: str, indicator: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source": source,
            "indicator": indicator,
            "context": context,
        }

    def enrich_with_virustotal(self, indicator: str) -> Dict[str, Any]:
        if not self.virus_total_api_key:
            return {"enabled": False, "message": "VirusTotal API key not configured.", "malicious": 0}

        headers = {"x-apikey": self.virus_total_api_key}
        # URL endpoint for domain/hash/file can be adapted via indicator type in production.
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "enabled": True,
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "reputation": data.get("reputation", 0),
            }
        except requests.RequestException as exc:
            return {"enabled": True, "error": str(exc), "malicious": 0}
