from __future__ import annotations

from typing import Any, Dict, List


class RiskScoreEngine:
    """CVSS-like scoring model tailored for SOC incident prioritization."""

    SEVERITY_BANDS = [
        (9.0, "critical"),
        (7.0, "high"),
        (4.0, "medium"),
        (0.0, "low"),
    ]

    def score(
        self,
        *,
        attack_matches: List[Dict[str, str]],
        vt_malicious: int,
        vt_suspicious: int,
        abuse_confidence: int,
        ingestion_mode: str,
    ) -> Dict[str, Any]:
        exploitability = min(3.9, 1.2 + len(attack_matches) * 0.9)
        intel_impact = min(3.1, vt_malicious * 0.15 + vt_suspicious * 0.1 + abuse_confidence * 0.02)
        context_impact = 1.2 if ingestion_mode == "automatic" else 0.7
        score = round(min(10.0, exploitability + intel_impact + context_impact), 1)

        severity = "low"
        for threshold, label in self.SEVERITY_BANDS:
            if score >= threshold:
                severity = label
                break

        confidence = round(min(0.98, 0.35 + score * 0.06), 2)
        return {
            "cvss_like_score": score,
            "severity": severity,
            "confidence": confidence,
            "factors": {
                "exploitability": round(exploitability, 2),
                "intel_impact": round(intel_impact, 2),
                "context_impact": context_impact,
            },
        }
