from typing import Dict, List


class MitigationGenerator:
    BASE_COMMANDS: Dict[str, List[str]] = {
        "Credential Access": [
            "echo 'Rotate privileged credentials immediately'",
            "ps aux | grep -i mimikatz",
        ],
        "Execution": [
            "ps aux | grep -Ei 'powershell|wmic|rundll32'",
            "netstat -plant",
        ],
        "Command and Control": [
            "ss -tupn",
            "iptables -S",
        ],
        "default": [
            "echo 'Collect triage evidence and isolate endpoint logically'",
            "sha256sum /var/log/syslog",
        ],
    }

    def generate(self, attack_matches: List[Dict[str, str]]) -> Dict[str, List[str]]:
        tactics = {m["tactic"] for m in attack_matches}
        commands: List[str] = []
        for tactic in tactics:
            commands.extend(self.BASE_COMMANDS.get(tactic, []))

        if not commands:
            commands.extend(self.BASE_COMMANDS["default"])

        return {
            "commands": list(dict.fromkeys(commands)),
            "playbook": [
                "Confirm scope using endpoint and SIEM telemetry",
                "Contain impacted hosts and block known-bad IOCs",
                "Eradicate persistence and rotate credentials",
                "Recover services and monitor for re-infection",
            ],
        }
