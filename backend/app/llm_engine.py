from typing import Dict

import requests


class LLMEngine:
    def __init__(self, ollama_host: str = "http://ollama:11434", model: str = "mistral:7b") -> None:
        self.ollama_host = ollama_host
        self.model = model

    def explain_incident(self, incident_text: str, attack_summary: str) -> Dict[str, str]:
        prompt = f"""
You are an expert SOC copilot.
Provide concise JSON with keys: reasoning, mitigation_plan, confidence_rationale.
Incident: {incident_text}
MITRE mapping: {attack_summary}
""".strip()

        response = requests.post(
            f"{self.ollama_host}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False},
            timeout=45,
        )
        response.raise_for_status()
        text = response.json().get("response", "")
        return {"raw_reasoning": text}
