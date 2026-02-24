import uuid
from typing import Any, Dict

from .atave_validator import AtaveValidator
from .audit_logger import AuditLogger
from .command_verifier import CommandVerifier
from .detector import Detector
from .llm_engine import LLMEngine
from .mitigation_generator import MitigationGenerator
from .sandbox_executor import SandboxExecutor


class PipelineOrchestrator:
    def __init__(
        self,
        detector: Detector,
        validator: AtaveValidator,
        llm_engine: LLMEngine,
        mitigation_generator: MitigationGenerator,
        command_verifier: CommandVerifier,
        sandbox_executor: SandboxExecutor,
        audit_logger: AuditLogger,
    ) -> None:
        self.detector = detector
        self.validator = validator
        self.llm_engine = llm_engine
        self.mitigation_generator = mitigation_generator
        self.command_verifier = command_verifier
        self.sandbox_executor = sandbox_executor
        self.audit_logger = audit_logger

    def process(self, source: str, indicator: str, context: Dict[str, Any], execute: bool = False) -> Dict[str, Any]:
        incident_id = str(uuid.uuid4())
        event = self.detector.ingest_event(source, indicator, context)
        self.audit_logger.log(incident_id, "ingested", event)

        vt = self.detector.enrich_with_virustotal(indicator)
        self.audit_logger.log(incident_id, "virustotal_enrichment", vt)

        signal_text = f"{indicator} {context.get('message', '')}"
        attack = self.validator.map_attack(signal_text)
        scoring = self.validator.score(signal_text, vt.get("malicious", 0))
        self.audit_logger.log(incident_id, "attack_mapped", {"matches": attack, **scoring})

        mitigation = self.mitigation_generator.generate(attack)
        verification = [self.command_verifier.validate(cmd) for cmd in mitigation["commands"]]
        self.audit_logger.log(incident_id, "command_verified", {"verification": verification})

        safe_commands = [
            cmd for cmd, verdict in zip(mitigation["commands"], verification) if verdict["allowed"]
        ]

        execution = []
        if execute:
            for command in safe_commands[:3]:
                result = self.sandbox_executor.run(command)
                execution.append({"command": command, "result": result})
                self.audit_logger.log(incident_id, "sandbox_executed", {"command": command, **result})

        llm = self.llm_engine.explain_incident(str(event), str(attack))
        self.audit_logger.log(incident_id, "llm_explanation", llm)

        return {
            "incident_id": incident_id,
            "event": event,
            "virustotal": vt,
            "mitre_attack": attack,
            "confidence": scoring["confidence"],
            "severity": scoring["severity"],
            "mitigation": mitigation,
            "command_validation": verification,
            "sandbox_execution": execution,
            "reasoning": llm["raw_reasoning"],
        }
