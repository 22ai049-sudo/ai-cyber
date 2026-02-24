import re
from typing import Dict, List


class CommandVerifier:
    WHITELIST_PREFIXES = (
        "echo",
        "ls",
        "cat",
        "grep",
        "awk",
        "sed",
        "ps",
        "netstat",
        "ss",
        "find",
        "sha256sum",
        "iptables -S",
    )

    UNSAFE_PATTERNS = [
        r"\brm\s+-rf\s+/",
        r"\bdd\s+if=",
        r"\bmkfs\b",
        r"\bshutdown\b",
        r"\breboot\b",
        r"\bnc\s+.*-e",
        r"\bcurl\s+.*\|\s*(sh|bash)",
        r"\bwget\s+.*\|\s*(sh|bash)",
        r"(;|&&)\s*(rm|mkfs|shutdown|reboot)",
    ]

    def validate(self, command: str) -> Dict[str, str | bool | List[str]]:
        trimmed = command.strip()
        if not any(trimmed.startswith(prefix) for prefix in self.WHITELIST_PREFIXES):
            return {
                "allowed": False,
                "reason": "Command rejected: not on whitelist.",
                "violations": ["whitelist_violation"],
            }

        hits = [p for p in self.UNSAFE_PATTERNS if re.search(p, trimmed, re.IGNORECASE)]
        if hits:
            return {
                "allowed": False,
                "reason": "Command rejected: unsafe pattern detected.",
                "violations": hits,
            }

        return {"allowed": True, "reason": "Command approved.", "violations": []}
