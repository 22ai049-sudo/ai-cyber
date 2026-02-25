import ipaddress
import re
from typing import Any, Dict, Optional

import requests


class Detector:
    def __init__(self, virus_total_api_key: Optional[str] = None, abuse_ipdb_api_key: Optional[str] = None) -> None:
        self.virus_total_api_key = virus_total_api_key
        self.abuse_ipdb_api_key = abuse_ipdb_api_key

    def ingest_event(
        self,
        source: str,
        indicator: str,
        context: Dict[str, Any],
        ingestion_mode: str = "manual",
        dataset_name: str | None = None,
    ) -> Dict[str, Any]:
        return {
            "source": source,
            "indicator": indicator,
            "context": context,
            "ingestion_mode": ingestion_mode,
            "dataset_name": dataset_name,
        }

    def enrich_with_virustotal(self, indicator: str) -> Dict[str, Any]:
        if not self.virus_total_api_key:
            return {"enabled": False, "message": "VirusTotal API key not configured.", "malicious": 0}

        headers = {"x-apikey": self.virus_total_api_key}
        indicator_type = self._indicator_type(indicator)
        endpoint = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
        }.get(indicator_type, "ip_addresses")
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}"
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
                "indicator_type": indicator_type,
            }
        except requests.RequestException as exc:
            return {"enabled": True, "error": str(exc), "malicious": 0}

    def enrich_with_abuseipdb(self, indicator: str) -> Dict[str, Any]:
        if not self.abuse_ipdb_api_key:
            return {"enabled": False, "message": "AbuseIPDB key not configured.", "abuse_confidence_score": 0}

        if self._indicator_type(indicator) != "ip":
            return {
                "enabled": True,
                "message": "AbuseIPDB supports only IP indicators.",
                "abuse_confidence_score": 0,
            }

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuse_ipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": indicator, "maxAgeInDays": 90},
                timeout=15,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            return {
                "enabled": True,
                "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0)),
                "total_reports": int(data.get("totalReports", 0)),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
            }
        except requests.RequestException as exc:
            return {"enabled": True, "error": str(exc), "abuse_confidence_score": 0}

    @staticmethod
    def _indicator_type(indicator: str) -> str:
        text = indicator.strip()
        try:
            ipaddress.ip_address(text)
            return "ip"
        except ValueError:
            pass

        if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", text):
            return "hash"
        if "." in text and " " not in text:
            return "domain"
        return "unknown"
