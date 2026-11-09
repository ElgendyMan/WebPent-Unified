"""
VIP Smart Autonomous Bug Hunter — Smart Prioritizer.

Ranks findings by:
1. Vulnerability class severity (CVSS-aligned weights)
2. Detection confidence
3. Asset criticality context
4. Exploit complexity
5. Business impact indicators

Governance: Prioritizer REORDERS findings only — never removes or demotes
a finding to "not a vulnerability". All findings are preserved.
"""
from dataclasses import dataclass
from typing import Any

# Severity weights — loosely aligned with CVSS v3.1 qualitative ratings
CLASS_SEVERITY: dict[str, float] = {
    "multi_step_chain": 10.0,
    "privilege_escalation": 9.5,
    "sensitive_data_exposure": 9.0,
    "ssrf": 8.5,
    "sqli": 8.5,
    "broken_access_control": 8.0,
    "idor": 7.5,
    "tenant_isolation": 9.0,
    "business_logic": 7.0,
    "workflow_authz": 6.5,
}

EXPLOIT_COMPLEXITY_MULTIPLIER: dict[str, float] = {
    "low": 1.2,
    "medium": 1.0,
    "high": 0.8,
}

ASSET_CRITICALITY_MULTIPLIER: dict[str, float] = {
    "low": 0.7,
    "medium": 1.0,
    "high": 1.3,
    "critical": 1.5,
}


@dataclass
class PrioritizedFinding:
    finding_id: str
    priority_score: float
    priority_tier: str
    rank: int
    original: dict[str, Any]
    reasoning: str


class SmartPrioritizer:
    """
    Intelligently ranks findings.
    GOVERNANCE: Never removes findings. Only reorders and annotates.
    """

    def __init__(self):
        self.class_severity = dict(CLASS_SEVERITY)

    def _compute_score(
        self,
        finding: dict[str, Any],
        asset_context: dict[str, Any] | None = None,
    ) -> tuple:
        cls = finding.get("class", "unknown")
        confidence = float(finding.get("confidence", 0.5))
        exploit = str(finding.get("exploit_complexity", "medium")).lower()

        severity = self.class_severity.get(cls, 5.0)
        exploit_mult = EXPLOIT_COMPLEXITY_MULTIPLIER.get(exploit, 1.0)

        asset_mult = 1.0
        if asset_context:
            asset_crit = str(asset_context.get("asset_criticality", "medium")).lower()
            asset_mult = ASSET_CRITICALITY_MULTIPLIER.get(asset_crit, 1.0)
            if asset_context.get("has_pii"):
                asset_mult *= 1.15
            if asset_context.get("has_payment"):
                asset_mult *= 1.2

        score = severity * confidence * exploit_mult * asset_mult

        parts = [
            f"severity({cls})={severity:.1f}",
            f"confidence={confidence:.2f}",
            f"exploit={exploit}(x{exploit_mult})",
            f"asset_mult=x{asset_mult:.2f}",
        ]
        reasoning = " x ".join(parts) + f" = {score:.2f}"

        return round(score, 3), reasoning

    def _tier(self, score: float) -> str:
        if score >= 8.0:
            return "P0 — CRITICAL"
        elif score >= 6.0:
            return "P1 — HIGH"
        elif score >= 4.0:
            return "P2 — MEDIUM"
        else:
            return "P3 — LOW"

    def prioritize(
        self,
        findings: list[dict[str, Any]],
        asset_context: dict[str, Any] | None = None,
    ) -> list[PrioritizedFinding]:
        """
        Prioritize findings. Returns the SAME number of findings, reordered.
        GOVERNANCE: No finding is ever dropped.
        """
        scored = []
        for f in findings:
            score, reasoning = self._compute_score(f, asset_context)
            scored.append((f, score, reasoning))

        scored.sort(key=lambda x: x[1], reverse=True)

        result = []
        for rank, (finding, score, reasoning) in enumerate(scored, 1):
            result.append(PrioritizedFinding(
                finding_id=finding.get("finding_id", f"finding_{rank}"),
                priority_score=score,
                priority_tier=self._tier(score),
                rank=rank,
                original=finding,
                reasoning=reasoning,
            ))

        return result
