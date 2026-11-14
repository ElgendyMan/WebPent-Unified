"""
VIP Smart Autonomous Bug Hunter — Smart Reporter.

Generates predictive, actionable reports including:
- Summary statistics by severity tier
- Overall risk score (0-10)
- Predicted next likely vulnerability patterns
- Actionable remediation recommendations

Governance: Report is descriptive and advisory only.
Never hides, suppresses, or downplays findings.
"""
from collections import Counter
from typing import Any

CLASS_REMEDIATION: dict[str, list[str]] = {
    "idor": [
        "Implement proper object-level authorization checks",
        "Validate that the requesting user owns or has access to each object",
        "Use indirect references or verify ownership on every request",
    ],
    "broken_access_control": [
        "Enforce role-based access control (RBAC) on all endpoints",
        "Deny by default — allow only explicitly authorized roles",
        "Audit authorization logic centrally, not per-endpoint",
    ],
    "privilege_escalation": [
        "Implement strict role boundaries — no horizontal-to-vertical paths",
        "Require re-authentication for admin-level operations",
        "Audit all role changes and privilege grants",
    ],
    "tenant_isolation": [
        "Enforce tenant isolation at the data layer (row-level security)",
        "Validate tenant context on every request",
        "Use separate databases or schemas per tenant for critical data",
    ],
    "business_logic": [
        "Map and validate all business workflows",
        "Implement state machines to enforce correct ordering",
        "Validate preconditions and postconditions on every transition",
    ],
    "workflow_authz": [
        "Verify required role/permission at each workflow stage",
        "Implement separation of duties for critical workflows",
        "Audit all workflow state transitions",
    ],
    "sensitive_data_exposure": [
        "Classify data and apply least-privilege access",
        "Redact sensitive fields in API responses",
        "Encrypt sensitive data at rest and in transit",
    ],
    "multi_step_chain": [
        "Break the chain — fix the easiest-to-fix link first",
        "Apply defense in depth across all steps",
        "Implement monitoring for anomalous multi-step sequences",
    ],
    "ssrf": [
        "Block requests to internal/private IP ranges",
        "Use allowlists for permitted external hosts",
        "Disable unnecessary URL scheme handlers",
    ],
    "sqli": [
        "Use parameterized queries / prepared statements",
        "Apply input validation and sanitization",
        "Use ORM with proper query building",
    ],
}

# Pattern co-occurrence — which patterns tend to appear together
PATTERN_COOCCURRENCE: dict[str, list[str]] = {
    "idor": ["broken_access_control", "sensitive_data_exposure", "privilege_escalation"],
    "broken_access_control": ["idor", "privilege_escalation", "workflow_authz"],
    "tenant_isolation": ["idor", "broken_access_control", "sensitive_data_exposure"],
    "privilege_escalation": ["broken_access_control", "idor", "multi_step_chain"],
    "sensitive_data_exposure": ["idor", "broken_access_control", "ssrf"],
    "business_logic": ["workflow_authz", "privilege_escalation", "multi_step_chain"],
    "workflow_authz": ["business_logic", "broken_access_control", "privilege_escalation"],
    "multi_step_chain": ["privilege_escalation", "idor", "ssrf"],
    "ssrf": ["sensitive_data_exposure", "sqli", "multi_step_chain"],
    "sqli": ["ssrf", "sensitive_data_exposure", "broken_access_control"],
}


class SmartReporter:
    """
    Generates predictive, actionable reports.
    GOVERNANCE: All findings are reported — never suppressed or downplayed.
    """

    def __init__(self):
        self.class_remediation = dict(CLASS_REMEDIATION)
        self.pattern_cooccurrence = dict(PATTERN_COOCCURRENCE)

    def _compute_risk_score(self, findings: list[dict[str, Any]]) -> float:
        """Overall risk score 0-10 based on highest-severity findings."""
        tier_weights = {
            "P0 — CRITICAL": 10.0,
            "P1 — HIGH": 7.5,
            "P2 — MEDIUM": 5.0,
            "P3 — LOW": 2.5,
        }
        if not findings:
            return 0.0

        scores = []
        for f in findings:
            tier = f.get("priority_tier", "P2 — MEDIUM")
            conf = float(f.get("confidence", 0.5))
            scores.append(tier_weights.get(tier, 5.0) * conf)

        scores.sort(reverse=True)
        top_n = min(3, len(scores))
        top_weight = sum(scores[:top_n]) / top_n * 0.6 if top_n > 0 else 0
        rest_weight = sum(scores[top_n:]) / max(len(scores) - top_n, 1) * 0.4 if len(scores) > top_n else 0

        return round(min(top_weight + rest_weight, 10.0), 2)

    def _predict_next_patterns(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Predict which vulnerability patterns are likely next based on co-occurrence."""
        found_classes = {f.get("class") for f in findings}
        predictions = Counter()
        for cls in found_classes:
            for co in self.pattern_cooccurrence.get(cls, []):
                if co not in found_classes:
                    predictions[co] += 1

        total = predictions.total()
        if total == 0:
            return []

        return [
            {"pattern_type": p, "likelihood": round(c / total, 2),
             "reason": "Co-occurs with already-found patterns"}
            for p, c in predictions.most_common(5)
        ]

    def _get_recommendations(self, findings: list[dict[str, Any]]) -> list[str]:
        """Generate actionable remediation recommendations."""
        classes_found = {f.get("class") for f in findings}
        recs = []
        for cls in sorted(classes_found):
            class_recs = self.class_remediation.get(cls, [])
            for rec in class_recs:
                recs.append(f"[{cls.upper()}] {rec}")
        return recs

    def generate_summary(
        self,
        findings: list[dict[str, Any]],
        asset_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a comprehensive smart report."""
        total = len(findings)

        by_tier = Counter()
        by_class = Counter()
        for f in findings:
            by_tier[f.get("priority_tier", "UNRANKED")] += 1
            by_class[f.get("class", "unknown")] += 1

        risk_score = self._compute_risk_score(findings)
        predicted = self._predict_next_patterns(findings)
        recommendations = self._get_recommendations(findings)

        if risk_score >= 8.0:
            posture = "CRITICAL — Immediate remediation required"
        elif risk_score >= 6.0:
            posture = "HIGH — Prioritize remediation in next sprint"
        elif risk_score >= 4.0:
            posture = "MEDIUM — Plan remediation in normal cycle"
        else:
            posture = "LOW — Monitor and address as time permits"

        return {
            "total_findings": total,
            "by_tier": dict(by_tier),
            "by_class": dict(by_class),
            "risk_score": risk_score,
            "risk_posture": posture,
            "predicted_next_patterns": predicted,
            "recommendations": recommendations,
            "asset_context": asset_context or {},
            "report_note": "All findings included. No findings suppressed or downplayed.",
        }
