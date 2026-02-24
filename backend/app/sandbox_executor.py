import subprocess
from datetime import datetime, timezone
from typing import Dict


class SandboxExecutor:
    """Executes verified commands in Docker for isolation."""

    def run(self, command: str) -> Dict[str, str | int]:
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--memory",
            "128m",
            "--cpus",
            "0.5",
            "alpine:3.20",
            "sh",
            "-lc",
            command,
        ]
        started = datetime.now(timezone.utc).isoformat()
        proc = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=20)
        ended = datetime.now(timezone.utc).isoformat()
        return {
            "started_at": started,
            "ended_at": ended,
            "exit_code": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "sandbox": "docker",
            "isolation": "network=none,cap-drop=ALL",
        }
