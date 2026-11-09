# src/webpent/causal_reasoning_v2/causal_adapter.py
"""CausalAdapter — Red-Team fix Phase 4.

Exact-format adapter between the causal engine and the real pipeline models.
Fixes the critical flaw that causal_contribution / extra fields were silently
ignored because they don't exist in the real schemas.

Guarantees:
  * Every emitted dict validates against the ACTUAL Finding / Hypothesis
    model field sets (fields are listed explicitly below, extracted from
    webpent.models.findings.Finding and webpent.models.hypothesis.Hypothesis).
  * Extra causal metadata is carried in fields that DO exist:
    - origin_detail  (causal label + sibling count)
    - hint_provenance  (pattern IDs, always a list of strings)
    - reasoning  (human-readable causal explanation — exists on Finding)
    - confidence_score / confidence  (adjusted priority)
  * Environment variable WEBPENT_CAUSAL_V2_DISABLED=1 -> all hooks return
    neutral empty results, identical to pre-causal behavior.
  * Fail-safe: every hook is wrapped; on ANY exception returns [] / None.
  * Documented hook points: three integration locations with exact expected
    signatures and return types.
"""
from __future__ import annotations

import os
import traceback
from typing import Any, Iterable, Mapping

# Exact field sets extracted from the real models (Phase 4: no invented fields).
HYPOTHESIS_FIELDS = frozenset({
    "id", "target_url", "statement", "vuln_class", "status", "confidence_score",
    "evidence_refs", "origin", "origin_detail", "estimated_cost",
    "parent_hypothesis_id", "deterministic_match", "request_method",
    "request_data", "target_param", "evidence_contract", "hint_provenance",
    "novelty_score", "created_at", "updated_at",
})
FINDING_FIELDS = frozenset({
    "id", "title", "severity", "description", "tool_name", "payload",
    "request_method", "request_data", "target_param", "url", "campaign_id",
    "route", "confidence", "evidence", "references", "cvss_score",
    "business_impact", "vuln_class", "confidence_level", "reasoning",
    "oob_token", "advisory_evidence",
})

_DISABLED = os.environ.get("WEBPENT_CAUSAL_V2_DISABLED", "").strip() in ("1", "true", "yes")


class CausalAdapter:
    """Converts causal engine outputs into exact pipeline-model shapes."""

    # Hypothesis.origin is a closed enum in the current project. Preserve
    # causal provenance in origin_detail/hint_provenance rather than emitting
    # an unsupported enum value that fails Hypothesis.model_validate().
    ORIGIN_TAG = "heuristic"

    def __init__(self, disabled: bool | None = None):
        self.disabled = _DISABLED if disabled is None else bool(disabled)
        self._failures: list[str] = []

    # ------------------------------------------------------------------
    # Hook 1 — engagement start: transfer insights -> Hypothesis-shaped dicts
    # Integration point: graph builder, after target recon, before planner.
    # Return: list[dict] — each validates against Hypothesis fields.
    # ------------------------------------------------------------------
    def engagement_start_hypotheses(
        self,
        *,
        target_url: str,
        transferred_insights: Iterable[Mapping[str, Any]] = (),
    ) -> list[dict[str, Any]]:
        if self.disabled:
            return []
        try:
            out: list[dict[str, Any]] = []
            for ins in transferred_insights:
                conf = float(ins.get("confidence", 0.5))
                h = {
                    "target_url": str(target_url)[:2000],
                    "statement": (
                        f"[causal-transfer] Past engagements confirm pattern "
                        f"'{ins.get('causal_label','?')}' (conf={conf:.2f}, "
                        f"n={ins.get('sample_size',0)}). Probe: "
                        f"{', '.join(list(ins.get('typical_segments', []))[:4])}."
                    )[:500],
                    "vuln_class": str(ins.get("vuln_class", "unknown"))[:60],
                    "status": "unexplored",
                    "confidence_score": round(min(1.0, max(0.0, conf)), 4),
                    "origin": self.ORIGIN_TAG,
                    "origin_detail": f"transferred|pattern={ins.get('pattern_id','?')}|n={ins.get('sample_size',0)}",
                    "estimated_cost": None,
                    "parent_hypothesis_id": None,
                    "deterministic_match": True,
                    "request_method": "GET",
                    "request_data": {},
                    "target_param": None,
                    "evidence_contract": None,
                    "hint_provenance": [f"causal_v2_transfer:{ins.get('pattern_id','?')}"],
                    "novelty_score": 0.9,
                }
                self._validate(h, HYPOTHESIS_FIELDS, "Hypothesis")
                out.append(h)
            return out
        except Exception:
            self._failures.append(f"start:{traceback.format_exc(limit=1)[:160]}")
            return []

    # ------------------------------------------------------------------
    # Hook 2 — finding confirmed: structural siblings -> Hypothesis-shaped dicts
    # Integration point: after a finding is promoted to confirmed, before
    # the next planner iteration.
    # ------------------------------------------------------------------
    def sibling_hypotheses(
        self,
        *,
        sibling_routes: Iterable[str],
        parent_finding: Mapping[str, Any],
        causal_label: str,
        confidence: float,
    ) -> list[dict[str, Any]]:
        if self.disabled:
            return []
        try:
            out: list[dict[str, Any]] = []
            pid = str(parent_finding.get("id", "?"))[:16]
            for route in list(sibling_routes)[:16]:
                h = {
                    "target_url": str(route)[:2000],
                    "statement": (
                        f"[causal-sibling] Shares flawed segment with finding {pid}… "
                        f"(root cause: {causal_label}, conf={confidence:.2f})."
                    )[:500],
                    "vuln_class": str(parent_finding.get("vuln_class", "unknown"))[:60],
                    "status": "unexplored",
                    "confidence_score": round(min(1.0, max(0.0, confidence * 0.9)), 4),
                    "origin": self.ORIGIN_TAG,
                    "origin_detail": f"sibling_of:{pid}|cause:{causal_label}",
                    "estimated_cost": None,
                    "parent_hypothesis_id": None,
                    "deterministic_match": True,
                    "request_method": str(parent_finding.get("request_method", "GET"))[:10].upper(),
                    "request_data": {},
                    "target_param": parent_finding.get("target_param"),
                    "evidence_contract": None,
                    "hint_provenance": [f"causal_v2_sibling:{pid}"],
                    "novelty_score": 0.95,
                }
                self._validate(h, HYPOTHESIS_FIELDS, "Hypothesis")
                out.append(h)
            return out
        except Exception:
            self._failures.append(f"sibling:{traceback.format_exc(limit=1)[:160]}")
            return []

    # ------------------------------------------------------------------
    # Hook 3 — report finalize: root-cause clusters -> report section dicts
    # Integration point: report builder, before final report serialization.
    # Return: list[dict] — plain dicts for the report (no schema constraint).
    # ------------------------------------------------------------------
    def report_clusters(
        self,
        clusters: Iterable[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        if self.disabled:
            return []
        try:
            out = []
            for c in clusters:
                out.append({
                    "cluster_id": str(c.get("cluster_id", "")),
                    "causal_label": str(c.get("causal_label", "")),
                    "shared_object": c.get("shared_object"),
                    "flawed_segment": list(c.get("flawed_segment", [])),
                    "member_finding_ids": list(c.get("member_finding_ids", [])),
                    "sibling_endpoints_to_probe_next": list(c.get("sibling_endpoint_ids", [])),
                    "confidence": float(c.get("confidence", 0.0)),
                    "remediation_hint": str(c.get("remediation_hint", "")),
                })
            return out
        except Exception:
            self._failures.append(f"report:{traceback.format_exc(limit=1)[:160]}")
            return []

    # ------------------------------------------------------------------
    def annotate_finding(self, finding: dict[str, Any], causal_reasoning: str) -> dict[str, Any]:
        """Add causal reasoning to a finding using the EXISTING 'reasoning' field.
        Never adds invented fields.  Returns a new dict (does not mutate input)."""
        if self.disabled:
            return dict(finding)
        try:
            out = {k: v for k, v in finding.items() if k in FINDING_FIELDS}
            existing = str(finding.get("reasoning", ""))
            out["reasoning"] = (existing + " | " if existing else "") + str(causal_reasoning)[:1000]
            # Only add origin if the Finding schema actually has it (it doesn't —
            # origin is a Hypothesis field).  Never invent fields.
            if "origin" in FINDING_FIELDS:
                out["origin"] = self.ORIGIN_TAG
            return out
        except Exception:
            return dict(finding)

    @staticmethod
    def _validate(d: dict[str, Any], allowed: frozenset[str], name: str) -> None:
        extra = set(d.keys()) - allowed
        if extra:
            raise ValueError(f"CausalAdapter emitted {name} dict with non-schema fields: {sorted(extra)}")

    @property
    def failures(self) -> tuple[str, ...]:
        return tuple(self._failures)


# Documented hook points (Phase 4 requirement: exact locations + signatures).
HOOK_POINTS = {
    "engagement_start": {
        "location": "graph builder, after target recon, before planner node",
        "method": "CausalAdapter.engagement_start_hypotheses(target_url=..., transferred_insights=[...])",
        "returns": "list[dict] validating against Hypothesis schema",
        "on_failure": "returns [] — pipeline continues unchanged",
    },
    "finding_confirmed": {
        "location": "after finding promoted to confirmed, before next planner iteration",
        "method": "CausalAdapter.sibling_hypotheses(sibling_routes=[...], parent_finding={...}, causal_label='...', confidence=...)",
        "returns": "list[dict] validating against Hypothesis schema",
        "on_failure": "returns [] — pipeline continues unchanged",
    },
    "report_finalize": {
        "location": "report builder, before final serialization",
        "method": "CausalAdapter.report_clusters(clusters=[...])",
        "returns": "list[dict] for report root-cause section",
        "on_failure": "returns [] — report unchanged",
    },
}


__all__ = ["CausalAdapter", "HYPOTHESIS_FIELDS", "FINDING_FIELDS", "HOOK_POINTS"]
