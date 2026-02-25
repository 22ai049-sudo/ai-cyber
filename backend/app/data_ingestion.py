from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from random import choice, randint, random
from typing import Any, Dict, List

import requests


class DataIngestionService:
    def __init__(self) -> None:
        self._dataset_path = Path(__file__).resolve().parent / "data" / "sample_incidents.json"
        self._threat_feed_sources = [
            {
                "name": "blocklist_de_all",
                "url": "https://lists.blocklist.de/lists/all.txt",
                "parser": self._parse_plain_ip_lines,
            },
            {
                "name": "feodotracker_ip",
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "parser": self._parse_feodotracker,
            },
        ]
        self._sample_logs = {
            "sysmon": "EventID=1 Image=powershell.exe CommandLine=powershell -enc SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoA.exe SourceIp=185.220.101.46",
            "suricata": "{""alert"":{""signature"":""ET TROJAN Suspicious DNS C2"",""severity"":1},""src_ip"":""45.9.148.114"",""dest_ip"":""10.10.4.23""}",
            "wazuh": "rule.id=5710 level=10 srcip=193.142.146.35 description='Multiple authentication failures from same source'",
        }

    def dataset_samples(self) -> List[Dict[str, Any]]:
        if not self._dataset_path.exists():
            return []
        with self._dataset_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def live_metrics(self) -> Dict[str, Any]:
        severities = ["low", "medium", "high", "critical"]
        sources = ["suricata", "sysmon", "crowdstrike", "azure-ad"]
        active_alerts = randint(8, 40)
        triage_backlog = randint(1, 22)
        severity_mix = {sev: randint(0, 10) for sev in severities}
        feed = [
            {
                "time": datetime.now(timezone.utc).isoformat(),
                "source": choice(sources),
                "severity": choice(severities),
                "indicator": choice(["10.0.10.44", "f4c3b00c...", "c2.bad-domain.io"]),
                "message": choice(
                    [
                        "Burst of failed SSH attempts from external host.",
                        "Potential credential stuffing from TOR exit node.",
                        "Encoded PowerShell command detected from user endpoint.",
                        "Suspicious DNS beaconing every 60 seconds.",
                    ]
                ),
                "confidence": round(0.58 + random() * 0.4, 2),
            }
            for _ in range(6)
        ]
        return {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "active_alerts": active_alerts,
            "triage_backlog": triage_backlog,
            "severity_mix": severity_mix,
            "feed": feed,
        }

    def automatic_ip_feed(self, limit: int = 20) -> Dict[str, Any]:
        """Collect potentially malicious IPs from public threat feeds with graceful fallback."""
        collected: List[Dict[str, str]] = []
        errors: List[str] = []

        for source in self._threat_feed_sources:
            try:
                response = requests.get(source["url"], timeout=12)
                response.raise_for_status()
                ips = source["parser"](response.text)
                for ip in ips[: max(5, limit // 2)]:
                    collected.append(
                        {
                            "indicator": ip,
                            "source": source["name"],
                            "reason": "listed as suspicious in public reputation feed",
                        }
                    )
            except requests.RequestException as exc:
                errors.append(f"{source['name']}: {exc}")

        if not collected:
            # Offline-safe fallback values keep UI functional.
            collected = [
                {"indicator": "185.220.101.46", "source": "fallback_tor_exit", "reason": "high-abuse relay pattern"},
                {"indicator": "45.9.148.114", "source": "fallback_c2_observed", "reason": "simulated C2 beacon source"},
                {"indicator": "193.142.146.35", "source": "fallback_bruteforce", "reason": "simulated brute-force host"},
            ]

        deduped = []
        seen = set()
        for item in collected:
            indicator = item["indicator"]
            if indicator in seen:
                continue
            seen.add(indicator)
            deduped.append(item)
            if len(deduped) >= limit:
                break

        return {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "mode": "automatic",
            "count": len(deduped),
            "indicators": deduped,
            "errors": errors,
        }

    def sample_logs(self) -> Dict[str, str]:
        return self._sample_logs

    def parse_security_log(self, source: str, raw: str) -> Dict[str, Any]:
        lowered = source.lower().strip()
        text = raw.strip()
        indicator = ""
        message = text

        if lowered == "sysmon":
            indicator = self._extract_token(text, "SourceIp=")
            message = "Sysmon process creation with suspicious encoded execution"
        elif lowered == "suricata":
            indicator = self._extract_json_like_value(text, '"src_ip":"')
            message = "Suricata IDS alert: suspicious network activity"
        elif lowered == "wazuh":
            indicator = self._extract_token(text, "srcip=")
            message = "Wazuh authentication anomaly detected"

        return {
            "source": lowered or "unknown",
            "indicator": indicator,
            "message": message,
            "raw": text,
            "parsed": bool(indicator),
        }

    @staticmethod
    def _parse_plain_ip_lines(payload: str) -> List[str]:
        return [line.strip() for line in payload.splitlines() if line.strip() and not line.startswith("#")]

    @staticmethod
    def _parse_feodotracker(payload: str) -> List[str]:
        ips = []
        for line in payload.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            ips.append(clean.split(",")[0].strip())
        return ips

    @staticmethod
    def _extract_token(payload: str, marker: str) -> str:
        if marker not in payload:
            return ""
        return payload.split(marker, 1)[1].split()[0].strip("'\" ,")

    @staticmethod
    def _extract_json_like_value(payload: str, marker: str) -> str:
        if marker not in payload:
            return ""
        return payload.split(marker, 1)[1].split('"', 1)[0].strip()
