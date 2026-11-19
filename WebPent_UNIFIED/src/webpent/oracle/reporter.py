"""THE ORACLE — U-ORACLE-11, the Oracle Reporter (v88).

Renders the whole passive picture into a seven-section report the
operator can read, keep and forward. The reporter defensively
re-sanitizes every datum it prints (ORACLE-L-3/L-4), names the legal
basis of every source it used (ORACLE-L-5) and never invents a figure
the evidence does not carry (ORACLE-L-6/L-8).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.chain_composer import ChainProposal
from webpent.oracle.graph_builder import AttackGraph
from webpent.oracle.impact_maximizer import ImpactEstimate
from webpent.oracle.kill_chain import SimulationTrace
from webpent.oracle.models import (
    OracleLawError,
    redact_pii,
    sanitize_secret,
    strip_pii_keys,
)
from webpent.oracle.osint import OsintReport
from webpent.oracle.path_predictor import PathPrediction
from webpent.oracle.perspectives import PerspectiveView
from webpent.oracle.stack_inferrer import TechStackProfile

SECTION_KEYS = (
    "executive_summary",
    "scope_and_legal_basis",
    "evidence_inventory",
    "tech_stack",
    "attack_graph",
    "predicted_chains",
    "perspectives_and_impact",
)

SECTION_TITLES = {
    "executive_summary": "1. Executive Summary",
    "scope_and_legal_basis": "2. Scope and Legal Basis",
    "evidence_inventory": "3. Evidence Inventory",
    "tech_stack": "4. Technology Stack",
    "attack_graph": "5. Attack Graph",
    "predicted_chains": "6. Predicted Chains and Simulations",
    "perspectives_and_impact": "7. Perspectives, Impact and Validation",
}

SECRET_KEY_HINTS = (
    "secret", "token", "password", "api_key", "apikey", "credential",
)


def _sanitized(value: Any) -> Any:
    """Defensive pass: whatever reaches the report goes through the same
    secret and PII hygiene the gatherer already applied (ORACLE-L-3/L-4)."""
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            key_lower = str(key).lower()
            if isinstance(item, str) and any(
                hint in key_lower for hint in SECRET_KEY_HINTS
            ):
                cleaned[key] = sanitize_secret(item)
            else:
                cleaned[key] = _sanitized(item)
        return strip_pii_keys(cleaned)
    if isinstance(value, list):
        return [_sanitized(item) for item in value]
    if isinstance(value, str):
        return redact_pii(value)
    return value


@dataclass
class OracleReportDoc:
    target_id: str
    generated_at: str
    sections: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "generated_at": self.generated_at,
            "sections": self.sections,
        }


class OracleReporter:
    def __init__(self, sources_path: Path) -> None:
        path = Path(sources_path)
        # a missing sources file is a configuration law breach, not an
        # accident to surface as FileNotFoundError (ORACLE-L-5)
        if not path.is_file():
            raise OracleLawError(
                f"osint sources file not found: {path}"
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        sources = data.get("sources")
        if not sources or not isinstance(sources, list):
            raise OracleLawError(
                "osint_sources.yaml missing a non-empty 'sources' list"
            )
        self._legal_basis = {
            s["source_id"]: s.get("legal_basis", "")
            for s in sources if isinstance(s, dict) and "source_id" in s
        }

    # -- section builders ---------------------------------------------------------

    def _executive_summary(
        self, report: OsintReport, graph: AttackGraph,
        estimates: list[ImpactEstimate],
    ) -> dict[str, Any]:
        top = estimates[0] if estimates else None
        return {
            "target": report.target_id,
            "sources_used": list(report.sources_used),
            "findings": len(report.findings),
            "graph_nodes": len(graph.nodes),
            "graph_edges": len(graph.edges),
            "top_impact": (
                {
                    "proposal": top.proposal_id,
                    "impact_category": top.impact_category,
                    "adjusted_payout": round(top.adjusted_payout, 3),
                } if top else None
            ),
            "mode": "passive-only, advisory (ORACLE-L-1/L-10)",
        }

    def _scope_and_legal_basis(self, report: OsintReport) -> dict[str, Any]:
        return {
            "target": report.target_id,
            "sources": [
                {
                    "source_id": source_id,
                    "legal_basis": self._legal_basis.get(source_id, ""),
                }
                for source_id in sorted(report.sources_used)
            ],
            "zero_touch": (
                "no request was issued to the target or its subdomains "
                "during this assessment (ORACLE-L-2)"
            ),
        }

    def _evidence_inventory(self, report: OsintReport) -> dict[str, Any]:
        by_category: dict[str, int] = {}
        by_source: dict[str, int] = {}
        for finding in report.findings:
            by_category[finding.category] = by_category.get(
                finding.category, 0
            ) + 1
            by_source[finding.source] = by_source.get(finding.source, 0) + 1
        samples = [
            {
                "source": f.source,
                "category": f.category,
                "confidence": round(f.confidence, 3),
                "evidence_hash": f.evidence_hash[:12],
                "data": _sanitized(dict(f.raw_data)),
            }
            for f in report.findings[:25]
        ]
        return {
            "by_category": by_category,
            "by_source": by_source,
            "coverage": dict(report.coverage),
            "samples": samples,
        }

    def _tech_stack(
        self, profile: TechStackProfile | None
    ) -> dict[str, Any]:
        if profile is None:
            return {"components": [], "cves": {}}
        return {
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "confidence": round(c.confidence, 3),
                }
                for c in profile.components
            ],
            "cves": {
                name: [
                    {"cve": c.cve, "severity": c.severity,
                     "summary": c.summary}
                    for c in cves
                ]
                for name, cves in profile.cves.items()
            },
        }

    def _attack_graph(self, graph: AttackGraph) -> dict[str, Any]:
        return {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "dot": graph.export_dot(),
        }

    def _predicted_chains(
        self,
        predictions: list[PathPrediction],
        proposals: list[ChainProposal],
        traces: list[SimulationTrace],
    ) -> dict[str, Any]:
        return {
            "predicted_paths": [p.to_dict() for p in predictions],
            "chain_proposals": [p.to_dict() for p in proposals],
            "simulations": [t.to_dict() for t in traces],
        }

    def _perspectives_and_impact(
        self,
        views: list[PerspectiveView],
        estimates: list[ImpactEstimate],
        validator_claim: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "perspectives": [v.to_dict() for v in views],
            "impact_estimates": [e.to_dict() for e in estimates],
            "validation": (
                validator_claim
                if validator_claim is not None
                else {
                    "status": "insufficient outcomes",
                    "note": "no accuracy claim without evidence (ORACLE-L-8)",
                }
            ),
        }

    # -- public surface ------------------------------------------------------------

    def build(
        self,
        report: OsintReport,
        graph: AttackGraph,
        stack_profile: TechStackProfile | None = None,
        predictions: list[PathPrediction] | None = None,
        proposals: list[ChainProposal] | None = None,
        traces: list[SimulationTrace] | None = None,
        views: list[PerspectiveView] | None = None,
        estimates: list[ImpactEstimate] | None = None,
        validator_claim: dict[str, Any] | None = None,
    ) -> OracleReportDoc:
        doc = OracleReportDoc(
            target_id=report.target_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            sections={
                "executive_summary": self._executive_summary(
                    report, graph, estimates or []
                ),
                "scope_and_legal_basis": self._scope_and_legal_basis(report),
                "evidence_inventory": self._evidence_inventory(report),
                "tech_stack": self._tech_stack(stack_profile),
                "attack_graph": self._attack_graph(graph),
                "predicted_chains": self._predicted_chains(
                    predictions or [], proposals or [], traces or []
                ),
                "perspectives_and_impact": self._perspectives_and_impact(
                    views or [], estimates or [], validator_claim
                ),
            },
        )
        missing = set(SECTION_KEYS) - set(doc.sections)
        if missing:
            raise OracleLawError(
                f"report is incomplete: {sorted(missing)} missing"
            )
        return doc

    def to_markdown(self, doc: OracleReportDoc) -> str:
        lines = [
            f"# ORACLE Report — {doc.target_id}",
            f"generated {doc.generated_at} | passive-only, advisory",
            "",
        ]
        for key in SECTION_KEYS:
            lines.append(f"## {SECTION_TITLES[key]}")
            lines.append("```json")
            lines.append(
                json.dumps(doc.sections[key], indent=2, sort_keys=True,
                           default=str)
            )
            lines.append("```")
            lines.append("")
        return "\n".join(lines)

    def to_json(self, doc: OracleReportDoc) -> str:
        return json.dumps(doc.to_dict(), indent=2, sort_keys=True,
                          default=str)

    def to_pdf(self, doc: OracleReportDoc, path: Path) -> Path:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
        )

        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        styles = getSampleStyleSheet()
        story: list[Any] = [
            Paragraph(f"ORACLE Report — {doc.target_id}",
                      styles["Title"]),
            Paragraph(
                f"generated {doc.generated_at} | passive-only, advisory",
                styles["Normal"],
            ),
            Spacer(1, 12),
        ]
        for key in SECTION_KEYS:
            story.append(Paragraph(SECTION_TITLES[key], styles["Heading2"]))
            body = json.dumps(doc.sections[key], indent=1, sort_keys=True,
                              default=str)[:4000]
            story.append(Paragraph(body.replace("\n", "<br/>"),
                                   styles["Code"]))
            story.append(Spacer(1, 10))
        SimpleDocTemplate(str(output), pagesize=A4).build(story)
        return output


__all__ = ["OracleReportDoc", "OracleReporter", "SECTION_KEYS"]
