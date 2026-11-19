# src/webpent/shared/cve_advisory.py
"""webpent.shared.cve_advisory — ق6 CVE/KEV/EPSS advisory engine (FEATURE_PROPOSALS ق6).

Proposal contract (ق6، WebPent_FEATURE_PROPOSALS.md):

    محرك استشاري CVE/KEV: البذور موجودة (``shared/epss.py`` + أسماء
    متغيرات CVE_FEED_CATALOG_PATH/KEV_CATALOG_PATH). اجمع epss + feed
    محلي + مطابقة تقنيات في مرحلة target_understanding لتوجيه
    الفرضيات.

    ("CVE/KEV advisory engine: the seeds exist (shared/epss.py plus
    the CVE_FEED_CATALOG_PATH/KEV_CATALOG_PATH settings names). Combine
    EPSS + a local feed + tech matching in the target-understanding
    stage to steer hypotheses.")

This module is the COMBINED engine the proposal asks for. The three
half-pieces already existed and were frozen at their unit boundaries
(``shared/tech_stack_cve.py`` for fingerprint+correlate,
``shared/kev.py`` for KEV ids, ``shared/epss.py`` for EPSS scores);
what was missing is the one pass that chains them into hypothesis
guidance for the target-understanding stage. It therefore lives in a
NEW module (the frozen files are imported, never edited) and keeps
every inherited posture:

* **No network, ever.** All three inputs (CVE feed, KEV ids, EPSS
  catalog) are operator-injected — campaign state first, then the
  local JSON file named by the settings attribute. Mirrors
  ``epss.load_epss_catalog`` exactly.
* **Advisory only.** Output is hypothesis GUIDANCE for the operator's
  triage queue. The schema carries no verdict field; nothing here
  creates, upgrades, or confirms a finding. ``advisory_only`` /
  ``does_not_confirm`` are pinned on every emitted object.
* **Aggregates only.** Emitted titles/rationales contain product
  names, versions, CVE ids and scores — never URLs, hosts, cookies,
  tokens or any other target-identifying data.
* **Fail-soft everywhere.** An empty/missing/unreadable catalog
  degrades to the pre-engine behavior (empty advisory with coverage
  gaps recorded, not an exception).

The wiring point for the stage is :func:`advisory_for_target_state` —
a defensive, read-only adapter that extracts tech evidence from a
PentestState-like object (``shared/tech_stack_cve``'s exact input
kinds) and returns the advisory. Because ``agents/target_understanding/
agent.py`` sits behind the frozen-module gate, the call is documented
here instead of patched in there; any orchestrator that already holds
the stage's outputs can adopt it with one import.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from webpent.shared.epss import (
    build_epss_index,
    enrich_correlations_with_epss,
    epss_aware_sort_key,
    load_epss_catalog,
)
from webpent.shared.tech_stack_cve import (
    CveCorrelation,
    CveFeedEntry,
    correlate_cves,
    fingerprint_tech_stack,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AdvisoryHypothesis",
    "CveAdvisory",
    "load_cve_feed",
    "load_kev_ids",
    "build_cve_advisory",
    "advisory_for_target_state",
    "advisory_hypothesis_to_state_hypothesis",
]

# Cap the emitted guidance so a noisy catalog cannot flood the stage.
_MAX_HYPOTHESES = 25
_MAX_CORRELATIONS = 100

# Severity -> advisory weight (documented, deterministic; KEV and EPSS
# dominate because exploitation-in-the-wild beats a cvss label).
_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 0.20,
    "high": 0.12,
    "medium": 0.05,
    "low": 0.0,
}

# version_match -> advisory weight. A version-bounded match is the
# strongest N-day signal; product-wide and unknown matches rank lower
# but still surface (advisory, flagged).
_VERSION_MATCH_WEIGHT: dict[str, float] = {
    "matched": 0.15,
    "product_wide": 0.05,
    "unknown": 0.03,
}


@dataclass(frozen=True)
class AdvisoryHypothesis:
    """One advisory hypothesis — steering for the triage queue, never a finding.

    ``guidance_id`` is a deterministic digest of the inputs that
    produced the hypothesis (cve_id + product + detected version), so
    the same exposure observed twice yields the same id and downstream
    consumers can dedupe.
    """

    guidance_id: str
    cve_id: str
    product: str
    detected_version: str | None
    title: str
    rationale: str
    priority: float
    hypothesis_kind: str = "n_day_exposure"
    kev: bool = False
    epss: float | None = None
    severity: str | None = None
    advisory_only: bool = True
    does_not_confirm: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "guidance_id": self.guidance_id,
            "hypothesis_kind": self.hypothesis_kind,
            "cve_id": self.cve_id,
            "product": self.product,
            "detected_version": self.detected_version,
            "title": self.title,
            "rationale": self.rationale,
            "priority": round(self.priority, 4),
            "kev": self.kev,
            "epss": (round(self.epss, 6) if self.epss is not None else None),
            "severity": self.severity,
            "advisory_only": True,
            "does_not_confirm": True,
        }


@dataclass
class CveAdvisory:
    """The combined advisory bundle for one stage invocation.

    ``correlations`` are the EPSS-enriched, KEV-first sorted
    ``CveCorrelation.as_dict()`` payloads (bounded); ``hypotheses`` are
    the derived guidance entries (bounded, priority-descending);
    ``coverage_gaps`` records which input layer was absent so the
    operator can tell "no exposure" from "no catalog".
    """

    correlations: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[AdvisoryHypothesis] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "correlations": self.correlations,
            "hypotheses": [h.as_dict() for h in self.hypotheses],
            "coverage_gaps": list(self.coverage_gaps),
            "stats": dict(self.stats),
            "advisory_only": True,
            "does_not_confirm": True,
            "source": "operator-injected-catalogs",
        }

    def __bool__(self) -> bool:  # empty advisory is falsy — fail-soft callers
        return bool(self.correlations or self.hypotheses)


def load_cve_feed(
    state_value: Any, *, settings_attr: str = "cve_feed_catalog_path"
) -> list[CveFeedEntry]:
    """Resolve the CVE feed: campaign state first, then operator file.

    Mirrors ``epss.load_epss_catalog``: a non-empty list in
    ``state_value`` wins; otherwise the JSON file named by the settings
    attribute is loaded. Entries are normalised into
    :class:`CveFeedEntry` (same liberal mapping shape
    ``tech_stack_cve.correlate_cves`` accepts). Fail-soft to [].
    """
    entries: list[Any] = []
    if isinstance(state_value, list) and state_value:
        entries = list(state_value)
    else:
        path_value = ""
        try:
            from webpent.config.settings import get_settings

            path_value = str(getattr(get_settings(), settings_attr, "") or "")
        except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
            path_value = ""
        if path_value:
            try:
                data = json.loads(Path(path_value).read_text(encoding="utf-8"))
                entries = data if isinstance(data, list) else []
            except (OSError, ValueError):
                logger.debug("cve feed unreadable at %s — treating as empty", path_value)
                entries = []
    feed: list[CveFeedEntry] = []
    for entry in entries:
        if isinstance(entry, CveFeedEntry):
            feed.append(entry)
            continue
        if isinstance(entry, Mapping):
            try:
                feed.append(
                    CveFeedEntry(
                        cve_id=str(entry["cve_id"]),
                        product=str(entry["product"]),
                        version_lte=(
                            str(entry["version_lte"])
                            if entry.get("version_lte") is not None
                            else None
                        ),
                        severity=(
                            str(entry["severity"])
                            if entry.get("severity") is not None
                            else None
                        ),
                        kev=bool(entry.get("kev", False)),
                        source=str(entry.get("source", "injected_catalog")),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
    return feed


def load_kev_ids(
    state_value: Any, *, settings_attr: str = "kev_catalog_path"
) -> set[str]:
    """Resolve KEV ids: campaign state first, then operator file.

    Accepts bare CVE strings or objects with a ``cve_id`` field (the
    reporter's KEV catalog shape, per the settings field description).
    Returns the case-normalized UPPER id set. Fail-soft to an empty set.
    """
    entries: list[Any] = []
    if isinstance(state_value, list) and state_value:
        entries = list(state_value)
    else:
        path_value = ""
        try:
            from webpent.config.settings import get_settings

            path_value = str(getattr(get_settings(), settings_attr, "") or "")
        except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
            path_value = ""
        if path_value:
            try:
                data = json.loads(Path(path_value).read_text(encoding="utf-8"))
                entries = data if isinstance(data, list) else []
            except (OSError, ValueError):
                logger.debug("kev catalog unreadable at %s — treating as empty", path_value)
                entries = []
    ids: set[str] = set()
    for entry in entries:
        raw = entry
        if isinstance(raw, Mapping):
            raw = raw.get("cve_id") or raw.get("id") or raw.get("cve")
        text = str(raw or "").strip().upper()
        if text.startswith("CVE-"):
            ids.add(text)
    return ids


def _guidance_id(cve_id: str, product: str, detected_version: str | None) -> str:
    basis = f"{cve_id}|{product}|{detected_version or ''}"
    return "cveadv-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _priority_for(correlation: CveCorrelation) -> float:
    """Deterministic composite advisory priority in [0, 1].

    KEV flag (+0.35) and the EPSS probability (×0.25) dominate; severity
    and version-match quality contribute bounded boosts; fingerprint
    confidence scales the whole. With no KEV/EPSS/severity data the
    score reduces to the fingerprint confidence × the version-match
    weight — exactly the pre-engine ranking inputs.
    """
    score = _SEVERITY_WEIGHT.get(
        str(getattr(correlation, "severity", None) or "").lower(), 0.0
    )
    score += _VERSION_MATCH_WEIGHT.get(
        str(getattr(correlation, "version_match", "") or ""), 0.03
    )
    if bool(getattr(correlation, "kev", False)):
        score += 0.35
    epss = getattr(correlation, "epss", None)
    if epss is not None:
        score += 0.25 * float(epss)
    confidence = float(getattr(correlation, "fingerprint_confidence", 0.0) or 0.0)
    priority = score * min(1.0, max(0.0, confidence)) + 0.05 * min(1.0, max(0.0, confidence))
    return min(1.0, max(0.0, priority))


def _hypothesis_from(correlation: CveCorrelation) -> AdvisoryHypothesis:
    product = str(getattr(correlation, "product", "") or "")
    cve_id = str(getattr(correlation, "cve_id", "") or "")
    version = getattr(correlation, "detected_version", None)
    epss = getattr(correlation, "epss", None)
    kev = bool(getattr(correlation, "kev", False))
    severity = getattr(correlation, "severity", None)
    version_match = str(getattr(correlation, "version_match", "") or "")

    title = f"N-day exposure advisory: {cve_id} on {product}"
    if version:
        title += f" {version}"

    factors: list[str] = []
    if kev:
        factors.append("listed in KEV (known exploited)")
    if epss is not None:
        factors.append(f"EPSS {epss:.2f}")
    if severity:
        factors.append(f"severity {severity}")
    if version_match == "matched":
        factors.append(f"detected {version} within vulnerable bound")
    elif version_match == "product_wide":
        factors.append("product-wide advisory (no version bound in feed)")
    else:
        factors.append("version comparison inconclusive — verify manually")
    rationale = "; ".join(factors) + ". Advisory guidance only — verify before any report."

    return AdvisoryHypothesis(
        guidance_id=_guidance_id(cve_id, product, version),
        cve_id=cve_id,
        product=product,
        detected_version=version,
        title=title,
        rationale=rationale,
        priority=_priority_for(correlation),
        kev=kev,
        epss=epss,
        severity=severity,
    )


def build_cve_advisory(
    *,
    headers: Mapping[str, Any] | None = None,
    body: str | None = None,
    set_cookie_headers: Iterable[str] | None = None,
    cve_feed: Iterable[Any] | None = None,
    epss_records: Iterable[Any] | None = None,
    kev_ids: Iterable[str] | None = None,
    cve_feed_state: Any = None,
    epss_state: Any = None,
    kev_state: Any = None,
) -> CveAdvisory:
    """One combined pass: tech evidence → correlations → KEV/EPSS enrichment → guidance.

    Pure and offline. Catalog arguments win over settings-file loads;
    a catalog argument that is ``None`` (not passed / empty state)
    triggers the corresponding operator-file load so a caller holding
    only tech evidence still gets catalog-driven guidance.
    ``set_cookie_headers`` are raw ``Set-Cookie`` header VALUES (only
    their NAME prefix is ever fingerprinted — value redaction is
    inherited from ``tech_stack_cve``).
    """
    components = fingerprint_tech_stack(
        headers=dict(headers or {}),
        body=body or "",
        set_cookie_headers=[str(v) for v in (set_cookie_headers or [])],
    )

    feed = list(cve_feed) if cve_feed is not None else load_cve_feed(cve_feed_state)
    epss_list = list(epss_records) if epss_records is not None else load_epss_catalog(
        epss_state
    )
    # load_kev_ids normalizes case AND accepts the same bare-string /
    # mapping shapes the settings-file catalog carries, so explicit
    # caller-provided ids go through the same normalizer.
    kev_set = load_kev_ids(list(kev_ids)) if kev_ids is not None else load_kev_ids(
        kev_state
    )

    advisory = CveAdvisory()
    if not components:
        advisory.coverage_gaps.append("no_tech_evidence")
    if not feed:
        advisory.coverage_gaps.append("no_cve_feed")
    if not epss_list:
        advisory.coverage_gaps.append("no_epss_catalog")

    if components and feed:
        correlations = correlate_cves(components, feed)

        # KEV from the standalone catalog merges with feed-entry kev flags:
        # a correlation either carries the flag from its feed entry or is
        # flagged when its CVE id appears in the KEV catalog.
        if kev_set:
            for correlation in correlations:
                if not correlation.kev and str(correlation.cve_id).upper() in kev_set:
                    correlation.kev = True

        epss_index = build_epss_index(epss_list)
        correlations = enrich_correlations_with_epss(correlations, epss_index)
        correlations.sort(key=epss_aware_sort_key)

        advisory.correlations = [
            c.as_dict() for c in correlations[:_MAX_CORRELATIONS]
        ]
        advisory.hypotheses = [
            _hypothesis_from(c) for c in correlations[:_MAX_HYPOTHESES]
        ]
        advisory.hypotheses.sort(key=lambda h: (-h.priority, h.cve_id, h.guidance_id))

    advisory.stats = {
        "components_fingerprinted": len(components),
        "feed_entries": len(feed),
        "correlations": len(advisory.correlations),
        "hypotheses": len(advisory.hypotheses),
        "kev_flagged": sum(1 for c in advisory.correlations if c.get("kev")),
        "epss_enriched": sum(1 for c in advisory.correlations if c.get("epss") is not None),
    }
    return advisory


def advisory_for_target_state(state_like: Any) -> CveAdvisory:
    """Defensive adapter: extract tech evidence from a stage-like state.

    Reads ONLY aggregate request-evidence kinds the target-understanding
    stage already holds (response headers / body snippet / cookie
    NAMES) — never cookies' values, tokens, or raw object identifiers.
    Every read is defensive: a state lacking any field simply narrows
    the evidence. Campaign-state catalogs (``cve_feed`` / ``epss`` /
    ``kev`` keys) are honored before the operator files.

    Accepts BOTH attribute-style stage objects AND plain dict states
    (the LangGraph state the frozen ``target_understanding_node`` holds
    is a TypedDict — UM-DR-16): dict keys are read with ``.get`` under
    the SAME names, plus the ``crawled_data`` sub-keys the crawler
    actually records.
    """
    mapping: Mapping[str, Any] | None = None
    crawled: Mapping[str, Any] = {}
    if isinstance(state_like, Mapping):
        mapping = state_like
        raw_crawled = state_like.get("crawled_data")
        if isinstance(raw_crawled, Mapping):
            crawled = raw_crawled

    def _first(*names: str) -> Any:
        for source in (mapping, crawled):
            if source is None:
                continue
            for name in names:
                candidate = source.get(name)
                if candidate:
                    return candidate
        return None

    if mapping is not None:
        headers = _first("response_headers", "last_response_headers", "http_headers")
        headers = dict(headers) if isinstance(headers, Mapping) else {}
        body = _first("response_body", "last_response_body", "page_body")
        body = body if isinstance(body, str) else None
        set_cookie_values = _first("set_cookie_headers", "response_set_cookie")
        set_cookie_values = (
            [str(v) for v in set_cookie_values]
            if isinstance(set_cookie_values, (list, tuple))
            else []
        )
        if not set_cookie_values:
            set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
            if isinstance(set_cookie, str):
                set_cookie_values = [set_cookie]
            elif isinstance(set_cookie, (list, tuple)):
                set_cookie_values = [str(v) for v in set_cookie]
        cve_feed_state = _first("cve_feed")
        epss_state = _first("epss_catalog", "epss")
        kev_state = _first("kev_catalog", "kev")
        return build_cve_advisory(
            headers=headers,
            body=body,
            set_cookie_headers=set_cookie_values,
            cve_feed_state=cve_feed_state,
            epss_state=epss_state,
            kev_state=kev_state,
        )

    headers: dict[str, Any] = {}
    body: str | None = None
    set_cookie_values: list[str] = []

    for attr in ("response_headers", "last_response_headers", "http_headers"):
        candidate = getattr(state_like, attr, None)
        if isinstance(candidate, Mapping):
            headers = dict(candidate)
            break

    for attr in ("response_body", "last_response_body", "page_body"):
        candidate = getattr(state_like, attr, None)
        if isinstance(candidate, str) and candidate:
            body = candidate
            break

    # Raw Set-Cookie header values — the fingerprint layer reads only
    # the NAME prefix and never retains the value (inherited stance).
    for attr in ("set_cookie_headers", "response_set_cookie"):
        candidate = getattr(state_like, attr, None)
        if isinstance(candidate, (list, tuple)) and candidate:
            set_cookie_values = [str(v) for v in candidate]
            break
    if not set_cookie_values:
        set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
        if isinstance(set_cookie, str):
            set_cookie_values = [set_cookie]
        elif isinstance(set_cookie, (list, tuple)):
            set_cookie_values = [str(v) for v in set_cookie]

    cve_feed_state = getattr(state_like, "cve_feed", None)
    epss_state = getattr(state_like, "epss_catalog", None)
    kev_state = getattr(state_like, "kev_catalog", None)

    return build_cve_advisory(
        headers=headers,
        body=body,
        set_cookie_headers=set_cookie_values,
        cve_feed_state=cve_feed_state,
        epss_state=epss_state,
        kev_state=kev_state,
    )


def advisory_hypothesis_to_state_hypothesis(
    advisory: AdvisoryHypothesis,
    *,
    target_url: str,
) -> "Hypothesis":
    """Convert one advisory guidance record into a state ``Hypothesis``.

    M3 ق6 wiring helper (UM-DR-16). The conversion is PROVENANCE-PRESERVING
    and ADVISORY-PINNED by construction:

    * ``origin=RAG_INFORMED`` with ``origin_detail="cve_advisory:<guidance_id>"``
      and ``hint_provenance=["cve_advisory:<guidance_id>"]`` — the advisory
      feed is advisory knowledge, never a deterministic validator;
    * ``evidence_contract`` carries the ``advisory_only``/``does_not_confirm``
      pins, the cve/kev/epss facts, and the n-day ``expected_behavior``;
    * ``preconditions`` names the version-detection precondition;
    * ``estimated_cost`` derives from the priority (bounded lookup, same
      convention as the deterministic kernel hypotheses);
    * ``status`` stays UNEXPLORED — nothing here confirms anything.
    """
    from webpent.models.hypothesis import Hypothesis, HypothesisOrigin, HypothesisStatus

    guidance = f"cve_advisory:{advisory.guidance_id}"
    statement = f"{advisory.title}: {advisory.rationale}"[:500]
    expected = (
        f"n-day exposure probe: {advisory.product}"
        + (f" {advisory.detected_version}" if advisory.detected_version else "")
        + " shows the affected behavior described by "
        + advisory.cve_id
    )
    return Hypothesis(
        target_url=target_url,
        statement=statement,
        status=HypothesisStatus.UNEXPLORED,
        origin=HypothesisOrigin.RAG_INFORMED,
        origin_detail=guidance,
        hint_provenance=[guidance],
        estimated_cost=1.0,
        expected_behavior=expected,
        preconditions=[
            f"{advisory.product} detected"
            + (f" at version {advisory.detected_version}" if advisory.detected_version else "")
        ],
        evidence_contract={
            "hypothesis_kind": advisory.hypothesis_kind,
            "advisory_only": True,
            "does_not_confirm": True,
            "cve_id": advisory.cve_id,
            "kev": advisory.kev,
            "epss": (round(advisory.epss, 6) if advisory.epss is not None else None),
            "severity": advisory.severity,
            "priority": round(advisory.priority, 4),
        },
    )
