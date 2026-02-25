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

    SOAR_PLAYBOOKS: Dict[str, List[str]] = {
        "Credential Access": [
            "Disable suspected accounts and force MFA + password reset",
            "Trigger EDR memory scan and isolate impacted endpoints",
            "Open IAM review task and notify identity response channel",
        ],
        "Execution": [
            "Quarantine host via EDR network containment",
            "Collect volatile evidence (process tree, autoruns, connections)",
            "Create SIEM watchlist for related parent/child process behavior",
        ],
        "Command and Control": [
            "Push temporary egress block rules for IOC set",
            "Create DNS sinkhole entries for malicious domains",
            "Schedule 24-hour beaconing hunt across endpoints",
        ],
    }

    def generate(self, attack_matches: List[Dict[str, str]]) -> Dict[str, List[str]]:
        tactics = {m["tactic"] for m in attack_matches}
        commands: List[str] = []
        for tactic in tactics:
            commands.extend(self.BASE_COMMANDS.get(tactic, []))

        if not commands:
            commands.extend(self.BASE_COMMANDS["default"])

        soar_workflow: List[str] = []
        for tactic in tactics:
            soar_workflow.extend(self.SOAR_PLAYBOOKS.get(tactic, []))

        return {
            "commands": list(dict.fromkeys(commands)),
            "playbook": [
                "Confirm scope using endpoint and SIEM telemetry",
                "Contain impacted hosts and block known-bad IOCs",
                "Eradicate persistence and rotate credentials",
                "Recover services and monitor for re-infection",
            ],
            "soar_workflow": list(dict.fromkeys(soar_workflow)) or [
                "Open analyst triage task",
                "Collect baseline forensic artifacts",
                "Escalate to incident commander when confidence rises",
            ],
        }
