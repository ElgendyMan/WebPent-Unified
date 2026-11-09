# src/webpent/jsintel/api_surface_shadow.py
"""webpent.jsintel.api_surface_shadow — ق8 unified JS pass (FEATURE_PROPOSALS ق8).

Proposal contract (ق8، WebPent_FEATURE_PROPOSALS.md):

    ذكاء JS أعمق: ``js_discovery`` و``javascript_intelligence`` و
    ``sourcemap_analysis`` (legacy قوي: استخراج secrets/maps) + esprima
    مثبتة الآن — مسار واحد: من كل bundle → endpoints/keys/routes →
    فرضيات مباشرة (API surface shadow).

    ("Deeper JS intelligence: js_discovery, javascript_intelligence and
    sourcemap_analysis (strong legacy: secrets/maps extraction) plus
    esprima now installed — ONE pass: from every bundle → endpoints/
    keys/routes → direct hypotheses (API surface shadow).")

What this module adds (new file — the engines it composes are frozen
and imported, never edited):

1. **One pass** over every in-scope bundle:
   ``shared.javascript_intelligence.analyze_javascript_source`` (the
   strongest engine: routes, secret candidates, auth hints, sinks,
   source-map references) runs per bundle; source-map agent output
   (parsed maps, disclosures, API-looking original sources) merges
   into the same surface.
2. **Shadow diff**: endpoints that exist ONLY in JS (absent from the
   crawl's documented endpoint set) are the shadow API surface —
   the highest-value hunting ground and the exact thing the proposal
   names.
3. **Direct hypotheses**: every shadow endpoint, secret candidate,
   auth hint and map disclosure becomes a typed, bounded, deterministic
   hypothesis with a stable id — guidance for the hunt, never a
   finding (``advisory_only``/``does_not_confirm`` pinned; secret
   values stay redacted by the engine and are never copied here).

Postures inherited unchanged:

* **In-scope only.** ``analyze_javascript_source`` already rejects
  out-of-scope assets and redacts URLs outside the target origin; the
  shadow diff compares REDACTED paths against REDACTED known endpoints.
* **Fail-soft.** A bundle that cannot be analyzed degrades to a
  coverage gap entry; the pass never raises.
* **Bounded.** Per-pass budgets (bundles, endpoints, secrets, hints,
  hypotheses) so a bundle storm cannot flood downstream stages.
* **No network.** Bundle text arrives pre-fetched (by js_discovery or
  the operator); this module performs zero requests.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

from webpent.shared.javascript_intelligence import analyze_javascript_source

logger = logging.getLogger(__name__)

__all__ = [
    "ShadowHypothesis",
    "ApiSurfaceShadow",
    "build_api_surface_shadow",
    "shadow_from_crawl_surfaces",
    "shadow_hypothesis_to_state_hypothesis",
]

# Per-pass budgets (documented, deterministic).
_MAX_BUNDLES = 50
_MAX_MAX_BYTES = 400_000  # matches the engine's hard cap; smaller wins
_MAX_ENDPOINTS = 400
_MAX_SECRETS = 60
_MAX_HINTS = 60
_MAX_HYPOTHESES = 60

# Priority weights per hypothesis kind (deterministic; documented in
# the proposal spirit: shadow endpoints > map disclosure > secret
# candidate > auth hint).
_PRIORITY_WEIGHTS: dict[str, float] = {
    "undocumented_api_endpoint": 0.60,
    "source_map_disclosure": 0.50,
    "hardcoded_secret_candidate": 0.45,
    "js_auth_hint": 0.30,
}

_KNOWN_KINDS = frozenset(_PRIORITY_WEIGHTS)


def _redact_path(url: str, target_url: str) -> str | None:
    """Keep only the PATH (+query-less) of same-origin URLs.

    The engine already redacts asset URLs it emits; this guard applies
    the same stance to the shadow diff itself so a foreign-origin route
    can never enter the shadow set.
    """
    raw = str(url or "").strip()
    if not raw:
        return None
    target = urlparse(target_url)
    lowered = raw.lower()
    if lowered.startswith(("http://", "https://")):
        parsed = urlparse(raw)
    else:
        # Relative reference — resolve against the in-scope origin.
        path_part = raw if raw.startswith("/") else "/" + raw
        parsed = urlparse(f"https://{target.netloc}{path_part}")
    if parsed.scheme not in {"http", "https"}:
        return None
    if parsed.netloc and parsed.netloc != target.netloc:
        return None
    path = parsed.path or "/"
    return path if len(path) <= 1200 else None


def _shadow_hypothesis_id(kind: str, subject: str) -> str:
    basis = f"{kind}|{subject}"
    return "jsshadow-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class ShadowHypothesis:
    """One direct hypothesis from the JS surface — advisory guidance."""

    hypothesis_id: str
    kind: str
    subject: str  # redacted path / secret kind / hint identifier
    title: str
    rationale: str
    source_asset: str  # redacted asset URL from the engine
    priority: float
    line: int | None = None
    hypothesis_kind_override: str = ""
    advisory_only: bool = True
    does_not_confirm: bool = True

    @property
    def hypothesis_kind(self) -> str:
        return self.hypothesis_kind_override or self.kind

    def as_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "hypothesis_kind": self.hypothesis_kind,
            "subject": self.subject,
            "title": self.title,
            "rationale": self.rationale,
            "source_asset": self.source_asset,
            "priority": round(self.priority, 4),
            "line": self.line,
            "advisory_only": True,
            "does_not_confirm": True,
        }


@dataclass
class ApiSurfaceShadow:
    """The combined JS surface: endpoints, keys, routes, hypotheses.

    ``endpoints`` are redacted same-origin paths discovered from JS
    (routes + source-map API paths); ``shadow_endpoints`` is the subset
    NOT present in the caller's documented endpoint set; ``secret_
    candidates`` carry only the engine's redacted shape (kind /
    confidence / evidence_ref — never a value).
    """

    endpoints: list[dict[str, Any]] = field(default_factory=list)
    shadow_endpoints: list[str] = field(default_factory=list)
    secret_candidates: list[dict[str, Any]] = field(default_factory=list)
    auth_hints: list[dict[str, Any]] = field(default_factory=list)
    source_map_disclosures: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[ShadowHypothesis] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "endpoints": list(self.endpoints),
            "shadow_endpoints": list(self.shadow_endpoints),
            "secret_candidates": list(self.secret_candidates),
            "auth_hints": list(self.auth_hints),
            "source_map_disclosures": list(self.source_map_disclosures),
            "hypotheses": [h.as_dict() for h in self.hypotheses],
            "coverage_gaps": list(self.coverage_gaps),
            "stats": dict(self.stats),
            "advisory_only": True,
            "does_not_confirm": True,
            "redaction": "source_content_and_secret_values_omitted",
        }

    def __bool__(self) -> bool:
        return bool(
            self.endpoints
            or self.secret_candidates
            or self.auth_hints
            or self.source_map_disclosures
            or self.hypotheses
        )


def _endpoint_from_route(route: Any, target_url: str) -> dict[str, Any] | None:
    path = _redact_path(str(getattr(route, "route", "") or ""), target_url)
    if not path:
        return None
    return {
        "path": path,
        "method_hint": str(getattr(route, "method_hint", "UNKNOWN") or "UNKNOWN"),
        "discovery_kind": str(getattr(route, "discovery_kind", "unknown") or "unknown"),
        "source_asset": str(getattr(route, "source_asset", "") or ""),
        "line": getattr(route, "line", None),
        "evidence_ref": str(getattr(route, "evidence_ref", "") or ""),
    }


def _hypothesis_for_endpoint(
    entry: dict[str, Any], *, in_shadow: bool
) -> ShadowHypothesis | None:
    if not in_shadow:
        return None
    path = entry["path"]
    kind = "undocumented_api_endpoint"
    return ShadowHypothesis(
        hypothesis_id=_shadow_hypothesis_id(kind, path),
        kind=kind,
        subject=path,
        title=f"Undocumented API endpoint referenced only in JS: {path}",
        rationale=(
            "Route string present in an in-scope JavaScript bundle but "
            "absent from the documented crawl endpoint set — probe for "
            "missing authorization (BAC) and unlisted parameter "
            "handling before assuming it is internal-only."
        ),
        source_asset=str(entry.get("source_asset") or ""),
        priority=_PRIORITY_WEIGHTS[kind],
        line=entry.get("line"),
    )


def _hypothesis_for_secret(candidate: Any, source_asset: str) -> ShadowHypothesis | None:
    kind = "hardcoded_secret_candidate"
    secret_kind = str(getattr(candidate, "kind", "") or "unknown")
    evidence_ref = str(getattr(candidate, "evidence_ref", "") or "")
    if not secret_kind:
        return None
    return ShadowHypothesis(
        hypothesis_id=_shadow_hypothesis_id(kind, f"{secret_kind}|{evidence_ref}"),
        kind=kind,
        subject=secret_kind,
        title=f"Hardcoded secret candidate in JS: {secret_kind}",
        rationale=(
            "Secret-shaped literal detected in an in-scope bundle "
            "(value redacted by the engine); validate with a safe, "
            "read-only check before reporting — hardcoded keys in "
            "client bundles are a recurring bounty family."
        ),
        source_asset=source_asset,
        priority=_PRIORITY_WEIGHTS[kind],
        line=getattr(candidate, "line", None),
    )


def _hypothesis_for_hint(hint: Any, source_asset: str) -> ShadowHypothesis | None:
    kind = "js_auth_hint"
    hint_text = str(getattr(hint, "hint", "") or "")
    identifier = str(getattr(hint, "identifier", "") or "")
    if not hint_text:
        return None
    return ShadowHypothesis(
        hypothesis_id=_shadow_hypothesis_id(kind, f"{hint_text}|{identifier}"),
        kind=kind,
        subject=identifier or hint_text,
        title=f"JS authorization hint: {hint_text} ({identifier})",
        rationale=(
            "Authorization-shaped marker in an in-scope bundle — feed "
            "the identity/session paths (ق7) and the authorization "
            "matrix with live multi-role sessions instead of "
            "assumptions."
        ),
        source_asset=source_asset,
        priority=_PRIORITY_WEIGHTS[kind],
        line=getattr(hint, "line", None),
    )


def _hypothesis_for_map_disclosure(disclosure: dict[str, Any]) -> ShadowHypothesis | None:
    kind = "source_map_disclosure"
    path = str(disclosure.get("map_path") or "")
    if not path:
        return None
    return ShadowHypothesis(
        hypothesis_id=_shadow_hypothesis_id(kind, path),
        kind=kind,
        subject=path,
        title=f"Source map published for production bundle: {path}",
        rationale=(
            "A sourceMappingURL-resolvable map is served for a "
            "production bundle; original sources enlarge the attack "
            "surface (internal route names, code comments, secret "
            "shapes) — request map removal or restrict access."
        ),
        source_asset=str(disclosure.get("bundle_asset") or ""),
        priority=_PRIORITY_WEIGHTS[kind],
        line=None,
    )


def build_api_surface_shadow(
    *,
    bundles: Iterable[Mapping[str, Any]],
    target_url: str,
    known_endpoints: Iterable[str] | None = None,
    sourcemap_api_paths: Iterable[str] | None = None,
    sourcemap_findings: Iterable[Any] | None = None,
) -> ApiSurfaceShadow:
    """One pass: bundles → endpoints/keys/routes → direct hypotheses.

    Args:
        bundles: mappings with ``asset_url`` + ``source`` (and optional
            ``content_type`` / ``status_code`` / ``source_map_content``)
            — the exact shapes ``analyze_javascript_source`` accepts.
        target_url: the in-scope origin; everything is redacted against it.
        known_endpoints: redacted paths the crawl already documented;
            JS-only paths become ``shadow_endpoints``.
        sourcemap_api_paths: API-looking original sources from the
            source-map agent (already same-origin filtered there).
        sourcemap_findings: ``sourcemap_analysis.secrets`` findings —
            used only for counts here (their scan already ran there).
    """
    shadow = ApiSurfaceShadow()
    known = set()
    for raw in known_endpoints or ():
        path = _redact_path(str(raw), target_url)
        if path:
            known.add(path)

    endpoints_by_path: dict[str, dict[str, Any]] = {}
    secrets: list[dict[str, Any]] = []
    hints: list[dict[str, Any]] = []
    disclosures: list[dict[str, Any]] = []
    gaps: list[str] = []
    bundles_seen = 0

    for bundle in bundles:
        if bundles_seen >= _MAX_BUNDLES:
            gaps.append("bundle_budget_exceeded")
            break
        if not isinstance(bundle, Mapping):
            continue
        asset_url = str(bundle.get("asset_url") or "")
        source = bundle.get("source")
        if not asset_url or not isinstance(source, str) or not source:
            continue
        bundles_seen += 1
        try:
            intelligence = analyze_javascript_source(
                asset_url=asset_url,
                source=source,
                target_url=target_url,
                content_type=str(bundle.get("content_type") or "application/javascript"),
                status_code=int(bundle.get("status_code") or 200),
                source_map_content=bundle.get("source_map_content"),
                max_bytes=min(_MAX_MAX_BYTES, int(bundle.get("max_bytes") or _MAX_MAX_BYTES)),
            )
        except Exception as exc:  # noqa: BLE001 — per-bundle fail-soft
            logger.debug("shadow bundle skip %s: %s", asset_url, exc)
            gaps.append(f"bundle_analysis_failed:{asset_url[:120]}")
            continue

        for route in intelligence.routes:
            entry = _endpoint_from_route(route, target_url)
            if entry is None:
                continue
            # One entry per PATH: the engine can discover the same path
            # twice (fetch-call with a method hint AND a bare route
            # literal with UNKNOWN); the specific method hint wins.
            path = entry["path"]
            existing = endpoints_by_path.get(path)
            if existing is None:
                endpoints_by_path[path] = entry
            elif existing["method_hint"] == "UNKNOWN" and entry["method_hint"] != "UNKNOWN":
                endpoints_by_path[path] = entry

        source_asset_redacted = ""
        for asset in intelligence.assets:
            source_asset_redacted = str(getattr(asset, "asset_url", "") or "")
            map_url = getattr(asset, "source_map_url", None)
            if map_url:
                disclosures.append(
                    {
                        "bundle_asset": source_asset_redacted,
                        "map_path": _redact_path(str(map_url), target_url) or str(map_url)[:200],
                        "original_sources": [
                            str(s) for s in getattr(asset, "source_map_sources", [])[:50]
                        ],
                    }
                )

        for candidate in intelligence.secret_candidates[:_MAX_SECRETS]:
            if len(secrets) >= _MAX_SECRETS:
                break
            secrets.append(
                {
                    "kind": str(getattr(candidate, "kind", "unknown")),
                    "confidence": str(getattr(candidate, "confidence", "low")),
                    "validation_status": str(
                        getattr(candidate, "validation_status", "advisory")
                    ),
                    "source_asset": source_asset_redacted,
                    "line": getattr(candidate, "line", None),
                    "evidence_ref": str(getattr(candidate, "evidence_ref", "") or ""),
                    "value": "[REDACTED]",
                }
            )

        for hint in intelligence.auth_hints[:_MAX_HINTS]:
            if len(hints) >= _MAX_HINTS:
                break
            hints.append(
                {
                    "hint": str(getattr(hint, "hint", "")),
                    "identifier": str(getattr(hint, "identifier", "")),
                    "source_asset": source_asset_redacted,
                    "line": getattr(hint, "line", None),
                    "evidence_ref": str(getattr(hint, "evidence_ref", "") or ""),
                }
            )

        for gap in intelligence.coverage_gaps:
            if gap and gap not in gaps:
                gaps.append(gap)

    # Source-map agent outputs merge into the same surface.
    for raw_path in sourcemap_api_paths or ():
        path = _redact_path(str(raw_path), target_url)
        if not path:
            continue
        if path not in endpoints_by_path:
            endpoints_by_path[path] = {
                "path": path,
                "method_hint": "UNKNOWN",
                "discovery_kind": "source_map_original",
                "source_asset": "sourcemap_agent",
                "line": None,
                "evidence_ref": "sourcemap:original_source",
            }

    endpoints = list(endpoints_by_path.values())[:_MAX_ENDPOINTS]
    shadow.endpoints = endpoints
    shadow.secret_candidates = secrets
    shadow.auth_hints = hints
    shadow.source_map_disclosures = disclosures[:_MAX_SECRETS]
    shadow.coverage_gaps = gaps[:200]

    shadow.shadow_endpoints = sorted(
        {e["path"] for e in endpoints if e["path"] not in known}
    )[:_MAX_ENDPOINTS]

    hypotheses: list[ShadowHypothesis] = []
    for entry in endpoints:
        hypothesis = _hypothesis_for_endpoint(
            entry, in_shadow=entry["path"] not in known
        )
        if hypothesis is not None:
            hypotheses.append(hypothesis)
    for secret in secrets:
        hypothesis = _hypothesis_for_secret(
            SimpleNamespace(kind=secret["kind"], line=secret["line"], evidence_ref=secret["evidence_ref"]),
            source_asset=secret["source_asset"],
        )
        if hypothesis is not None:
            hypotheses.append(hypothesis)
    for hint in hints:
        hypothesis = _hypothesis_for_hint(
            SimpleNamespace(hint=hint["hint"], identifier=hint["identifier"], line=hint["line"]),
            source_asset=hint["source_asset"],
        )
        if hypothesis is not None:
            hypotheses.append(hypothesis)
    for disclosure in shadow.source_map_disclosures:
        hypothesis = _hypothesis_for_map_disclosure(disclosure)
        if hypothesis is not None:
            hypotheses.append(hypothesis)

    # dedupe by id, priority-desc, bounded
    seen_ids: set[str] = set()
    deduped: list[ShadowHypothesis] = []
    for hypothesis in sorted(
        hypotheses, key=lambda h: (-h.priority, h.hypothesis_id)
    ):
        if hypothesis.hypothesis_id in seen_ids:
            continue
        seen_ids.add(hypothesis.hypothesis_id)
        deduped.append(hypothesis)
    shadow.hypotheses = deduped[:_MAX_HYPOTHESES]

    shadow.stats = {
        "bundles_seen": bundles_seen,
        "endpoints": len(endpoints),
        "shadow_endpoints": len(shadow.shadow_endpoints),
        "known_endpoints": len(known),
        "secret_candidates": len(secrets),
        "auth_hints": len(hints),
        "map_disclosures": len(shadow.source_map_disclosures),
        "sourcemap_findings": len(list(sourcemap_findings or ())),
        "hypotheses": len(shadow.hypotheses),
    }
    if not bundles_seen:
        shadow.coverage_gaps.append("no_bundles")
    return shadow


def shadow_from_crawl_surfaces(
    *,
    surfaces_by_url: Mapping[str, Iterable[Any]],
    target_url: str,
    known_endpoints: Iterable[str] | None = None,
) -> ApiSurfaceShadow:
    """Adapter for ``agents.js_discovery``'s output shape.

    ``js_discovery_node`` produces ``{bundle_url: [surfaces]}``; this
    adapter converts that into the bundle mappings
    :func:`build_api_surface_shadow` consumes (source text is re-joined
    from surfaces when the crawl kept it; otherwise route strings only).
    Kept deliberately thin: js_discovery output without retained text
    yields route-only shadow entries.
    """
    bundles: list[dict[str, Any]] = []
    for asset_url, surfaces in (surfaces_by_url or {}).items():
        if not isinstance(asset_url, str) or not asset_url:
            continue
        route_lines: list[str] = []
        for surface in surfaces or ():
            raw = getattr(surface, "raw", None) or (
                surface.get("raw") if isinstance(surface, Mapping) else None
            )
            if isinstance(raw, str) and raw:
                route_lines.append(raw)
        if route_lines:
            # The engine's route-literal pattern only fires on QUOTED
            # strings, so re-emit each raw path quoted.
            bundles.append(
                {
                    "asset_url": asset_url,
                    "source": "\n".join(f'"{raw}"' for raw in route_lines),
                    "content_type": "application/javascript",
                    "status_code": 200,
                }
            )
    return build_api_surface_shadow(
        bundles=bundles,
        target_url=target_url,
        known_endpoints=known_endpoints,
    )


def shadow_hypothesis_to_state_hypothesis(
    shadow: ShadowHypothesis,
    *,
    target_url: str,
) -> "Hypothesis":
    """Convert one shadow hypothesis into a state ``Hypothesis``.

    M3 ق8 wiring helper (UM-DR-16). Advisory-pinned by construction:
    ``origin=RAG_INFORMED`` with ``hint_provenance=["api_surface_shadow:<id>"]``
    and an ``evidence_contract`` carrying the shadow kind/weights plus the
    undocumented-endpoint NEGATIVE CONTROL (a randomized non-existent path
    must reproduce the same baseline status — a hypothesis whose control
    fires is refuted, never confirmed).
    """
    from webpent.models.hypothesis import Hypothesis, HypothesisOrigin, HypothesisStatus

    provenance = f"api_surface_shadow:{shadow.hypothesis_id}"
    statement = f"{shadow.title}: {shadow.rationale}"[:500]
    negative_control = ""
    expected_behavior = ""
    preconditions: list[str] = []
    if shadow.kind == "undocumented_api_endpoint":
        expected_behavior = (
            f"the JS-referenced path {shadow.subject} responds differently from "
            "the site's not-found baseline (documented-but-uncrawled endpoint)"
        )
        negative_control = (
            "the same request against a randomized non-existent path "
            "(fixed random token in the same directory) must return the "
            "same baseline status/size — if the control matches the probe, "
            "the endpoint is refuted"
        )
        preconditions = [f"bundle {shadow.source_asset} references {shadow.subject}"]
    elif shadow.kind == "source_map_disclosure":
        expected_behavior = (
            f"the source map for {shadow.source_asset} exposes original "
            "sources revealing additional API surface"
        )
        negative_control = (
            "a content-type/route probe of a bundle WITHOUT a source-map "
            "annotation must not yield original sources"
        )
        preconditions = [f"{shadow.source_asset} ships a .map annotation"]
    elif shadow.kind == "hardcoded_secret_candidate":
        expected_behavior = (
            "the candidate string authenticates or authorizes against its "
            "referenced service when used as the corresponding credential kind"
        )
        negative_control = (
            "a deliberately corrupted variant of the candidate (one flipped "
            "character) must be REJECTED the same way an arbitrary string is"
        )
    evidence_contract = {
        "hypothesis_kind": shadow.kind,
        "advisory_only": True,
        "does_not_confirm": True,
        "kind_weight": shadow.weight if hasattr(shadow, "weight") else None,
        "source_asset": shadow.source_asset,
        "line": shadow.line,
    }
    if shadow.hypothesis_kind_override:
        evidence_contract["hypothesis_kind_override"] = shadow.hypothesis_kind_override
    return Hypothesis(
        target_url=target_url,
        statement=statement,
        status=HypothesisStatus.UNEXPLORED,
        origin=HypothesisOrigin.RAG_INFORMED,
        origin_detail=provenance,
        hint_provenance=[provenance],
        estimated_cost=1.0,
        expected_behavior=expected_behavior,
        negative_control=negative_control,
        preconditions=preconditions,
        evidence_contract=evidence_contract,
    )
