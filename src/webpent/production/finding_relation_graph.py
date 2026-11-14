# src/webpent/production/finding_relation_graph.py
"""webpent.production.finding_relation_graph — Track 12, item 4.

Roadmap contract (المسار 12، البند 4 — رسم علاقات النتائج):

    عرض روابط الأدلة والأصول والأثر التجاري في graph تفاعلي، دون
    تحويله إلى تعليمات استغلال آلية.

    ("Visualize the links between evidence, assets, and business impact
    in an interactive graph — WITHOUT turning it into automated
    exploitation instructions.")

Design
------
``build_finding_graph`` turns a findings list into a deterministic,
REDACTION-FIRST relationship graph:

* **Node kinds** — ``asset`` (normalized origin, from the finding URL),
  ``finding`` (class + severity + id), ``evidence`` (the evidence HASH
  only — never the payload), ``impact`` (business-impact tag when the
  finding carries one).
* **Edge relations** — ``asset -> finding`` (targets), ``finding ->
  evidence`` (evidences), ``finding -> impact`` (impacts), and
  ``finding -> finding`` (related_to, when the reporter annotated a
  relation in evidence).
* **Redaction-first (the notifications contract, reused):** labels carry
  identifiers only. The request payload, reasoning, and evidence bodies
  NEVER enter the graph — the graph is a map of relations, and the
  report remains the only evidence surface.
* **Guardrail by construction:** nodes and edges carry references and
  classifications; there is no field that could hold an attack payload,
  and the exporters serialize exactly the model below — the graph
  cannot become exploitation instructions because it never receives
  them.
* **Interactive, dependency-free:** ``render_html`` produces one
  self-contained HTML file (inline CSS + vanilla-JS SVG, pan/drag +
  severity colors, read-only) with zero network dependencies, so it is
  safe to open offline and safe to attach to a report.

Deterministic: identical findings produce byte-identical output
(sorted nodes/edges, stable ids) — diff-friendly for reviews.
"""

from __future__ import annotations

import hashlib
import html
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "FindingGraph",
    "GraphNode",
    "GraphEdge",
    "build_finding_graph",
    "graph_to_dot",
    "graph_to_json",
    "render_html",
]

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}


@dataclass
class GraphNode:
    """One graph node (identifier-level data only — redaction-first)."""

    id: str
    kind: str  # asset | finding | evidence | impact
    label: str
    severity: str = "info"
    finding_class: str = ""
    ref: str = ""  # reference for humans (finding id / evidence hash)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """One directed edge (source id -> target id)."""

    source: str
    target: str
    relation: str  # targets | evidences | impacts | related_to
    note: str = ""


@dataclass
class FindingGraph:
    """Deterministic relation graph over findings (sorted, stable ids)."""

    engagement_id: str = ""
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        kinds: dict[str, int] = {}
        for node in self.nodes:
            kinds[node.kind] = kinds.get(node.kind, 0) + 1
        relations: dict[str, int] = {}
        for edge in self.edges:
            relations[edge.relation] = relations.get(edge.relation, 0) + 1
        return {
            "engagement_id": self.engagement_id,
            "nodes_total": len(self.nodes),
            "edges_total": len(self.edges),
            "nodes_by_kind": kinds,
            "edges_by_relation": relations,
        }


def _origin(url: str) -> str:
    """Normalize a URL to its origin (asset-level node identity)."""
    try:
        parts = urlsplit(str(url or "").strip())
        host = (parts.hostname or "").lower()
        if not host:
            return "unknown-origin"
        scheme = (parts.scheme or "https").lower()
        port = parts.port
        return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"
    except ValueError:
        return "unknown-origin"


def _node_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
    return f"{kind}-{digest}"


def _finding_payload(finding: Any) -> dict[str, Any] | None:
    """Extract identifier-level fields from a Finding (or mapping)."""
    if isinstance(finding, dict):
        return finding
    evidence = getattr(finding, "evidence", None)
    return {
        "id": str(getattr(finding, "id", "") or ""),
        "title": str(getattr(finding, "title", "") or ""),
        "severity": str(getattr(finding, "severity", "") or "info").lower(),
        "vuln_class": str(getattr(finding, "vuln_class", "") or ""),
        "url": str(getattr(finding, "url", "") or ""),
        "thread_id": str(getattr(finding, "thread_id", "") or ""),
        "evidence": evidence if isinstance(evidence, dict) else {},
    }


def build_finding_graph(
    findings: list[Any],
    *,
    engagement_id: str = "",
) -> FindingGraph:
    """Build the deterministic relation graph (pure, redaction-first)."""
    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str, str], GraphEdge] = {}

    for raw in findings:
        data = _finding_payload(raw)
        if not data or not data.get("id"):
            continue
        fid = _node_id("finding", str(data["id"]))
        severity = data.get("severity") if data.get("severity") in SEVERITY_COLORS else "info"
        nodes[fid] = GraphNode(
            id=fid,
            kind="finding",
            label=f"{data.get('vuln_class') or 'finding'}: {data.get('title') or data['id']}"[:160],
            severity=severity,
            finding_class=str(data.get("vuln_class") or ""),
            ref=str(data["id"]),
        )
        # asset node
        origin = _origin(str(data.get("url") or ""))
        aid = _node_id("asset", origin)
        if aid not in nodes:
            nodes[aid] = GraphNode(
                id=aid, kind="asset", label=origin, ref=origin, meta={"origin": origin}
            )
        edges.setdefault(
            (aid, fid, "targets"), GraphEdge(aid, fid, "targets")
        )
        # evidence node: HASH ONLY — the payload never enters the graph
        evidence = data.get("evidence") or {}
        ev_hash = str(evidence.get("evidence_hash") or "")
        if ev_hash:
            eid = _node_id("evidence", ev_hash)
            if eid not in nodes:
                nodes[eid] = GraphNode(
                    id=eid,
                    kind="evidence",
                    label=f"evidence {ev_hash[:16]}…",
                    ref=ev_hash,
                    meta={"redacted": True},
                )
            edges.setdefault(
                (fid, eid, "evidences"), GraphEdge(fid, eid, "evidences")
            )
        # impact node (business-impact tag when the reporter supplied one)
        impact = str(evidence.get("business_impact") or "").strip()
        if impact:
            iid = _node_id("impact", impact)
            if iid not in nodes:
                nodes[iid] = GraphNode(id=iid, kind="impact", label=impact[:160], ref=impact)
            edges.setdefault(
                (fid, iid, "impacts"), GraphEdge(fid, iid, "impacts")
            )
        # explicit cross-finding relation (reporter-annotated, never inferred)
        related = evidence.get("related_findings")
        if isinstance(related, list):
            for other in related:
                other_id = str(other or "").strip()
                if not other_id:
                    continue
                oid = _node_id("finding", other_id)
                nodes.setdefault(
                    oid,
                    GraphNode(
                        id=oid,
                        kind="finding",
                        label=f"finding {other_id}",
                        ref=other_id,
                        meta={"placeholder": True},
                    ),
                )
                edges.setdefault(
                    (fid, oid, "related_to"),
                    GraphEdge(fid, oid, "related_to", note="reporter-annotated"),
                )

    order = {"asset": 0, "finding": 1, "evidence": 2, "impact": 3}
    sorted_nodes = sorted(
        nodes.values(), key=lambda n: (order.get(n.kind, 9), n.id)
    )
    sorted_edges = sorted(edges.values(), key=lambda e: (e.relation, e.source, e.target))
    return FindingGraph(
        engagement_id=engagement_id,
        nodes=sorted_nodes,
        edges=sorted_edges,
    )


def graph_to_json(graph: FindingGraph) -> str:
    """Stable JSON serialization (sorted keys, redaction-first model)."""
    return json.dumps(
        {
            "engagement_id": graph.engagement_id,
            "nodes": [
                {
                    "id": n.id,
                    "kind": n.kind,
                    "label": n.label,
                    "severity": n.severity,
                    "class": n.finding_class,
                    "ref": n.ref,
                    "meta": n.meta,
                }
                for n in graph.nodes
            ],
            "edges": [
                {"source": e.source, "target": e.target, "relation": e.relation, "note": e.note}
                for e in graph.edges
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def graph_to_dot(graph: FindingGraph) -> str:
    """Graphviz DOT export (presentation attributes only)."""
    lines = ["digraph webpent_findings {", '  rankdir=LR;', '  node [fontname="Helvetica"];']
    for node in graph.nodes:
        shape = {"asset": "box", "finding": "ellipse", "evidence": "note", "impact": "tab"}.get(
            node.kind, "circle"
        )
        color = SEVERITY_COLORS.get(node.severity, "#6b7280")
        label = node.label.replace('"', "'")
        lines.append(
            f'  "{node.id}" [label="{label}", shape={shape}, color="{color}"];'
        )
    for edge in graph.edges:
        lines.append(
            f'  "{edge.source}" -> "{edge.target}" [label="{edge.relation}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_html(graph: FindingGraph) -> str:
    """Self-contained read-only interactive HTML (inline SVG + vanilla JS).

    Interactivity: click a node to highlight its neighborhood; drag to
    pan. No network calls, no external assets, no scripts beyond the
    inlined viewer — safe offline.
    """
    positions = _radial_positions(graph)
    svg_parts: list[str] = []
    for edge in graph.edges:
        a = positions.get(edge.source)
        b = positions.get(edge.target)
        if not a or not b:
            continue
        svg_parts.append(
            f'<line class="edge rel-{html.escape(edge.relation)}" '
            f'x1="{a[0]:.1f}" y1="{a[1]:.1f}" x2="{b[0]:.1f}" y2="{b[1]:.1f}" '
            f'data-a="{html.escape(edge.source)}" data-b="{html.escape(edge.target)}"/>'
        )
    for node in graph.nodes:
        x, y = positions.get(node.id, (0.0, 0.0))
        color = SEVERITY_COLORS.get(node.severity, "#6b7280")
        shape = {"asset": "rect", "finding": "circle", "evidence": "rect", "impact": "rect"}.get(
            node.kind, "circle"
        )
        label = html.escape(node.label, quote=True)
        if shape == "circle":
            body = (
                f'<circle class="node" data-id="{html.escape(node.id)}" '
                f'cx="{x:.1f}" cy="{y:.1f}" r="9" fill="{color}"/>'
            )
        else:
            body = (
                f'<rect class="node" data-id="{html.escape(node.id)}" '
                f'x="{x - 14:.1f}" y="{y - 8:.1f}" width="28" height="16" rx="3" '
                f'fill="{color}"/>'
            )
        svg_parts.append(body)
        svg_parts.append(
            f'<text class="label" x="{x + 14:.1f}" y="{y + 4:.1f}" '
            f'data-node="{html.escape(node.id)}">{label}</text>'
        )
    svg = "\n".join(svg_parts)
    # Script-context-safe JSON embedding: escape <, >, & so a hostile
    # label can never close the script tag or inject markup (the SVG
    # labels are separately html-escaped at render time).
    meta = {
        n.id: {"label": n.label, "kind": n.kind, "severity": n.severity, "ref": n.ref}
        for n in graph.nodes
    }
    payload = json.dumps(meta, ensure_ascii=False)
    payload = (
        payload.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
        "<title>webpent — finding relation graph</title>\n<style>\n"
        "body{font-family:Helvetica,Arial,sans-serif;margin:0;"
        "background:#0f172a;color:#e2e8f0}\n"
        "#wrap{width:100vw;height:100vh;overflow:hidden;cursor:grab}\n"
        "svg{width:100%;height:100%}\n"
        ".edge{stroke:#475569;stroke-width:1.4;opacity:.7}\n"
        ".edge.hot{stroke:#38bdf8;stroke-width:2.2;opacity:1}\n"
        ".edge.dim{opacity:.12}\n"
        ".node{stroke:#0f172a;stroke-width:1.5}\n"
        ".node.hot{stroke:#f8fafc;stroke-width:2.5}\n"
        ".label{font-size:11px;fill:#94a3b8;pointer-events:none}\n"
        "#hud{position:fixed;top:10px;left:10px;background:#1e293bcc;"
        "padding:10px 14px;border-radius:8px;max-width:420px;"
        "font-size:12px;line-height:1.5}\n"
        "#hud b{color:#f8fafc}\n"
        "</style></head><body>\n"
        "<div id=\"hud\"><b>webpent finding-relation graph</b><br>"
        "Read-only map of assets, findings, evidence hashes, and impact tags. "
        "Click a node to highlight its relations — evidence payloads are "
        "never included (report is the evidence surface).</div>\n"
        f"<div id=\"wrap\"><svg viewBox=\"-60 -60 720 520\">{svg}</svg></div>\n"
        "<script>\n"
        f"const META = {payload};\n"
        "const svg=document.querySelector('svg');let pan=null;\n"
        "svg.addEventListener('mousedown',e=>{pan={x:e.clientX,y:e.clientY,"
        "vb:svg.getAttribute('viewBox').split(' ').map(Number)};});\n"
        "window.addEventListener('mouseup',()=>pan=null);\n"
        "window.addEventListener('mousemove',e=>{if(!pan)return;const vb=pan.vb;"
        "svg.setAttribute('viewBox',(vb[0]-(e.clientX-pan.x))+' '+"
        "(vb[1]-(e.clientY-pan.y))+' '+vb[2]+' '+vb[3]);});\n"
        "svg.addEventListener('click',e=>{const t=e.target.closest('.node');"
        "document.querySelectorAll('.hot').forEach(x=>x.classList.remove('hot'));"
        "document.querySelectorAll('.edge').forEach(x=>{x.classList.remove('hot');x.classList.remove('dim')});"
        "if(!t)return;t.classList.add('hot');"
        "document.querySelectorAll('.edge').forEach(x=>{"
        "if(x.dataset.a===t.dataset.id||x.dataset.b===t.dataset.id){x.classList.add('hot');"
        "const other=x.dataset.a===t.dataset.id?x.dataset.b:x.dataset.a;"
        "document.querySelector('.node[data-id=\"'+other+'\"]').classList.add('hot');}"
        "else{x.classList.add('dim')}});"
        "const m=META[t.dataset.id]||{};"
        "const hud=document.getElementById('hud');"
        "hud.innerHTML='<b>'+(m.kind||'?')+'</b> — '+((m.label||'').replace(/</g,'&lt;'))"
        "+'<br>severity: '+(m.severity||'info')+(m.ref?'<br>ref: '+m.ref:'');"
        "});\n"
        "</script></body></html>\n"
    )


def _radial_positions(graph: FindingGraph) -> dict[str, tuple[float, float]]:
    """Deterministic layout: assets on the left ring, findings center,
    evidence/impact on the right (stable order = stable positions)."""
    positions: dict[str, tuple[float, float]] = {}
    assets = [n for n in graph.nodes if n.kind == "asset"]
    findings = [n for n in graph.nodes if n.kind == "finding"]
    others = [n for n in graph.nodes if n.kind in ("evidence", "impact")]
    import math

    for index, node in enumerate(assets):
        angle = 2 * math.pi * index / max(1, len(assets))
        positions[node.id] = (60 + 40 * math.cos(angle), 200 + 160 * math.sin(angle))
    for index, node in enumerate(findings):
        angle = 2 * math.pi * index / max(1, len(findings))
        positions[node.id] = (300 + 90 * math.cos(angle), 200 + 130 * math.sin(angle))
    for index, node in enumerate(others):
        angle = 2 * math.pi * index / max(1, len(others))
        positions[node.id] = (560 + 40 * math.cos(angle), 200 + 150 * math.sin(angle))
    return positions
