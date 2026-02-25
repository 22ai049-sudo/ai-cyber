from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class AttackMapping:
    tactic: str
    technique_id: str
    technique_name: str


class AtaveValidator:
    """MITRE ATT&CK mapping + confidence/risk scoring validator."""

    IOC_MAP: Dict[str, AttackMapping] = {
        "powershell -enc": AttackMapping("Execution", "T1059.001", "PowerShell"),
        "mimikatz": AttackMapping("Credential Access", "T1003.001", "LSASS Memory"),
        "rundll32": AttackMapping("Defense Evasion", "T1218.011", "Rundll32"),
        "wmic process call create": AttackMapping("Execution", "T1047", "Windows Management Instrumentation"),
        "curl http": AttackMapping("Command and Control", "T1105", "Ingress Tool Transfer"),
    }

    def map_attack(self, signal_text: str) -> List[Dict[str, str]]:
        lowered = signal_text.lower()
        matches = []
        for ioc, mapping in self.IOC_MAP.items():
            if ioc in lowered:
                matches.append(
                    {
                        "ioc": ioc,
                        "tactic": mapping.tactic,
                        "technique_id": mapping.technique_id,
                        "technique_name": mapping.technique_name,
                    }
                )
        return matches

    def score(self, signal_text: str, vt_malicious_count: int) -> Dict[str, str | float]:
        mapping_count = len(self.map_attack(signal_text))
        confidence = min(0.95, 0.25 + mapping_count * 0.15 + min(vt_malicious_count, 20) * 0.02)

        if confidence >= 0.8:
            severity = "critical"
        elif confidence >= 0.6:
            severity = "high"
        elif confidence >= 0.4:
            severity = "medium"
        else:
            severity = "low"

        return {"confidence": round(confidence, 2), "severity": severity}

    def validate_model_output(
        self,
        confidence: float,
        severity: str,
        attack_matches: List[Dict[str, str]],
        command_validation: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        expected = self._severity_for_confidence(confidence)
        findings: List[str] = []
        checks = {
            "severity_consistency": expected == severity,
            "attack_mapping_present": len(attack_matches) > 0,
            "unsafe_commands_blocked": all(v.get("allowed") is False for v in command_validation if v.get("violations")),
        }

        if not checks["severity_consistency"]:
            findings.append(f"Severity '{severity}' does not match confidence band '{expected}'.")
        if not checks["attack_mapping_present"]:
            findings.append("No ATT&CK mapping found; review telemetry quality.")
        if not checks["unsafe_commands_blocked"]:
            findings.append("Unsafe command handling failed consistency check.")

        pass_count = sum(1 for value in checks.values() if value)
        score = round(pass_count / len(checks), 2)
        return {
            "score": score,
            "status": "pass" if score >= 0.67 else "review",
            "checks": checks,
            "findings": findings,
        }

    @staticmethod
    def _severity_for_confidence(confidence: float) -> str:
        if confidence >= 0.8:
            return "critical"
        if confidence >= 0.6:
            return "high"
        if confidence >= 0.4:
            return "medium"
        return "low"
