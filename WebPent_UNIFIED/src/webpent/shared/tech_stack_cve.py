"""webpent.shared.tech_stack_cve — deterministic tech-stack fingerprinting
and CVE/version correlation.

Project Zero-tier item 7: "as soon as the tool identifies the tech
stack and its version, it should automatically cross-reference against
up-to-date CVE feeds — this is how N-day vulnerabilities get found
first."

This module is the deterministic half of that pipeline, mirroring
``waf_fingerprints.py``'s shape exactly (dataclass signatures + a pure
matching function returning ``(name, version_or_None, confidence,
matched_signals)``), and ``kev.py``'s "injected catalog" posture for
the feed itself:

  * ``fingerprint_tech_stack()`` is a pure function over response
    signals (headers, a bounded body sample, and already-redacted
    cookie NAMES) — no network calls, no LLM. It is designed to run
    against the SAME probe responses ``waf_detector`` already makes
    (see ``agents/waf_detector/agent.py``), so a single probe can feed
    both WAF and tech-stack fingerprinting.
  * ``correlate_cves()`` cross-references a fingerprint's
    ``(product, version)`` pairs against an **injected** CVE catalog
    (a list of ``CveFeedEntry``-shaped dicts) rather than calling out
    to a live feed itself. This mirrors ``kev.py``'s
    ``enrich_finding_with_kev(finding, kev_ids)`` — the actual HTTP
    fetch of a CVE feed (NVD, OSV, vendor advisories, ...) is an
    operator/ops concern (scheduled job populating
    ``state["cve_feed_catalog"]``), not something this deterministic,
    offline-safe, unit-testable module should own. This keeps the
    module runnable in CI/sandboxed environments with no egress, and
    keeps "stale feed" a visible, auditable input rather than a silent
    network dependency buried in a detector.
  * Version comparison is a narrow, dependency-free semver-like
    comparator (``_version_lte``) — intentionally conservative: if a
    version string can't be parsed, the entry is still surfaced but
    flagged ``version_match="unknown"`` rather than silently matched
    or silently dropped (the same "advisory, never proof" posture as
    ``kev.py``'s ``does_not_confirm`` flag).

Nothing here authorizes a Finding or performs a network request — a
tech-stack+CVE correlation is advisory evidence for a hypothesis
generator (or the human operator) to act on, exactly like
``kev_context`` is advisory-only on a Finding.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Fingerprinting signatures
# ---------------------------------------------------------------------------

# Each entry: (product name, header name (lowercase), pattern with an
# optional named group "version"). A match with a captured version is
# higher confidence than a bare product hit.
_VERSION_RE_FRAGMENT = r"(?P<version>\d+(?:\.\d+){0,3}[A-Za-z0-9.\-]*)"


@dataclass(frozen=True)
class _HeaderFingerprint:
    product: str
    header_name: str
    pattern: re.Pattern[str]


_HEADER_FINGERPRINTS: tuple[_HeaderFingerprint, ...] = (
    _HeaderFingerprint(
        "apache_httpd", "server",
        re.compile(rf"apache/{_VERSION_RE_FRAGMENT}", re.I),
    ),
    _HeaderFingerprint(
        "nginx", "server",
        re.compile(rf"nginx/{_VERSION_RE_FRAGMENT}", re.I),
    ),
    _HeaderFingerprint(
        "iis", "server",
        re.compile(rf"microsoft-iis/{_VERSION_RE_FRAGMENT}", re.I),
    ),
    _HeaderFingerprint(
        "php", "x-powered-by",
        re.compile(rf"php/{_VERSION_RE_FRAGMENT}", re.I),
    ),
    _HeaderFingerprint(
        "aspnet", "x-powered-by",
        re.compile(r"asp\.net", re.I),
    ),
    _HeaderFingerprint(
        "aspnet", "x-aspnet-version",
        re.compile(rf"{_VERSION_RE_FRAGMENT}", re.I),
    ),
    _HeaderFingerprint(
        "express", "x-powered-by",
        re.compile(r"express", re.I),
    ),
    _HeaderFingerprint(
        "varnish", "via",
        re.compile(rf"varnish(?:/{_VERSION_RE_FRAGMENT})?", re.I),
    ),
    _HeaderFingerprint(
        "openresty", "server",
        re.compile(rf"openresty/{_VERSION_RE_FRAGMENT}", re.I),
    ),
)

# Case-insensitive body substrings -> (product, optional version-capture
# regex applied to the FULL body if a version is wanted). Kept separate
# from headers because generator meta tags / footer strings are a
# materially weaker signal (easily stale, templated, or stripped) than
# a live Server header, so they carry lower base confidence below.
_BODY_FINGERPRINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "wordpress",
        re.compile(
            rf'<meta name="generator" content="wordpress\s*{_VERSION_RE_FRAGMENT}?"',
            re.I,
        ),
    ),
    (
        "drupal",
        re.compile(
            rf'<meta name="generator" content="drupal\s*{_VERSION_RE_FRAGMENT}?"',
            re.I,
        ),
    ),
    (
        "joomla",
        re.compile(
            rf'<meta name="generator" content="joomla!\s*{_VERSION_RE_FRAGMENT}?"',
            re.I,
        ),
    ),
)

# Cookie NAME prefixes (never values, matching waf_fingerprints.py's
# redaction stance) that identify a framework/product.
_COOKIE_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("laravel_session", "laravel"),
    ("phpsessid", "php"),
    ("jsessionid", "java_servlet"),
    ("asp.net_sessionid", "aspnet"),
    ("django_language", "django"),
    ("_wordpress_logged_in_", "wordpress"),
)


@dataclass
class TechStackComponent:
    """One identified product/version with its matching evidence."""

    product: str
    version: str | None = None
    confidence: float = 0.0
    signals: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "version": self.version,
            "confidence": round(self.confidence, 2),
            "signals": self.signals[:20],
        }


def _extract_cookie_names(set_cookie_headers: Sequence[str]) -> list[str]:
    names: list[str] = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip().lower()
        if name:
            names.append(name)
    return names


def fingerprint_tech_stack(
    *,
    headers: Mapping[str, str] | None = None,
    set_cookie_headers: Sequence[str] | None = None,
    body: str = "",
) -> list[TechStackComponent]:
    """Deterministically fingerprint products/versions from one response.

    Pure function, no network calls. Designed to run against the same
    probe response ``waf_detector`` already captures.

    Confidence model (mirrors ``waf_fingerprints.detect_waf_vendor``):
    a header match with a captured version is the strongest single
    signal (0.6, since a Server/X-Powered-By header is operator/stack
    controlled, not easily spoofed by content); a header match with no
    captured version is weaker (0.4); a body/meta-tag match is weaker
    still (0.3, templated content is more easily stale or stripped);
    a cookie-name match is weak alone (0.25) but compounds when it
    corroborates a header/body hit for the SAME product.

    Returns:
        A list of :class:`TechStackComponent`, one per distinct
        product identified, sorted by descending confidence.
    """
    lowered_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cookie_names = _extract_cookie_names(set_cookie_headers or [])
    body_sample = (body or "")[:50_000]

    components: dict[str, TechStackComponent] = {}

    def _get_or_create(product: str) -> TechStackComponent:
        if product not in components:
            components[product] = TechStackComponent(product=product)
        return components[product]

    for fp in _HEADER_FINGERPRINTS:
        value = lowered_headers.get(fp.header_name)
        if value is None:
            continue
        match = fp.pattern.search(value)
        if not match:
            continue
        comp = _get_or_create(fp.product)
        version = None
        try:
            version = match.group("version")
        except (IndexError, re.error):
            version = None
        if version:
            comp.confidence = max(comp.confidence, 0.6)
            if not comp.version:
                comp.version = version
            comp.signals.append(f"header:{fp.header_name}=>{fp.product}/{version}")
        else:
            comp.confidence = max(comp.confidence, 0.4)
            comp.signals.append(f"header:{fp.header_name}=>{fp.product}")

    for product, pattern in _BODY_FINGERPRINTS:
        match = pattern.search(body_sample)
        if not match:
            continue
        comp = _get_or_create(product)
        version = None
        try:
            version = match.group("version")
        except (IndexError, re.error):
            version = None
        if version and not comp.version:
            comp.version = version
        bump = 0.35 if version else 0.3
        comp.confidence = min(1.0, comp.confidence + bump) if comp.confidence else bump
        comp.signals.append(f"body_marker:{product}" + (f"/{version}" if version else ""))

    for prefix, product in _COOKIE_FINGERPRINTS:
        if any(name.startswith(prefix) for name in cookie_names):
            comp = _get_or_create(product)
            bump = 0.25
            comp.confidence = min(1.0, comp.confidence + bump) if comp.confidence else bump
            comp.signals.append(f"cookie_prefix:{prefix}")

    ordered = sorted(components.values(), key=lambda c: c.confidence, reverse=True)
    for comp in ordered:
        comp.confidence = min(1.0, comp.confidence)
    return ordered


# ---------------------------------------------------------------------------
# CVE feed correlation (offline, injected catalog — mirrors kev.py)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CveFeedEntry:
    """One entry from an injected CVE/vulnerability feed.

    Deliberately a flat, serialisable shape (not a heavier NVD/OSV
    schema) — ``source`` records provenance (e.g. ``"nvd"``, ``"osv"``,
    ``"vendor_advisory"``) so correlation results carry that through,
    but this module does not parse or validate feed-specific formats;
    a thin adapter upstream (outside this module, where live network
    access is appropriate) is responsible for normalising a real feed
    into this shape.
    """

    cve_id: str
    product: str
    version_lte: str | None = None
    """Vulnerable up to and including this version (inclusive upper
    bound). ``None`` means "all known versions of this product" —
    used sparingly, for a product-wide advisory with no version
    granularity in the feed."""
    severity: str | None = None
    kev: bool = False
    """True if this CVE is in a Known Exploited Vulnerabilities
    catalog — mirrors ``kev.py``'s KEV concept but as a feed-entry
    attribute rather than a separate lookup set, so ``kev.py`` and
    this module can share one injected catalog shape if desired."""
    source: str = "injected_catalog"


# Matches the dotted numeric CORE of a version string only (e.g. the
# "2.4.49" in "2.4.49rc1" or "2.4.49-beta2"), anchored so it cannot
# match in the middle of a pre-release/build suffix. Deliberately NOT
# a bare r"\d+" findall over the whole string — that earlier approach
# silently absorbed a trailing digit in a pre-release suffix (e.g.
# "rc1", "beta2", "p1") as an extra, spuriously-high version
# component, making "2.4.49rc1" compare as NEWER than "2.4.49" instead
# of older/equal (a pre-release of 2.4.49 is not a confirmed "past"
# 2.4.49 for vulnerability-matching purposes). The fix: capture only
# the leading run of ``\d+(\.\d+)*`` and ignore everything after it.
_VERSION_CORE_RE = re.compile(r"^\s*v?(\d+(?:\.\d+)*)")


def _version_key(version: str) -> tuple[int, ...] | None:
    """Parse the leading dotted-numeric core of a version string into
    a comparable tuple of ints, ignoring any pre-release/build suffix.

    Returns ``None`` if no leading numeric core can be found at all
    (so comparison can't be attempted). A pre-release/build suffix
    (``"-beta"``, ``"rc1"``, ``"p1"``, ``"+build5"``, ...) is dropped
    in its entirety, not scanned for further digits — "4.2.0-beta2"
    and "4.2.0rc1" both compare as exactly (4, 2, 0), the same as a
    bare "4.2.0". This is deliberately conservative: a caller that
    needs to distinguish a pre-release from its final release (e.g.
    to treat an RC as "not yet patched") must do so before calling
    this comparator — collapsing them here means we never silently
    treat a pre-release's suffix as if it were an additional,
    version-bumping component.
    """
    match = _VERSION_CORE_RE.match(version or "")
    if match is None:
        return None
    tokens = match.group(1).split(".")
    return tuple(int(t) for t in tokens)


def _version_lte(candidate: str, bound: str) -> bool | None:
    """Return True if ``candidate <= bound``, False if not, or None if
    either version string couldn't be parsed (comparison attempted but
    inconclusive — the caller must treat this as "unknown", never as
    a match).
    """
    candidate_key = _version_key(candidate)
    bound_key = _version_key(bound)
    if candidate_key is None or bound_key is None:
        return None
    # Pad the shorter tuple with zeros so (4, 2) vs (4, 2, 1) compares
    # as 4.2.0 vs 4.2.1, not lexicographically on differing lengths.
    length = max(len(candidate_key), len(bound_key))
    candidate_padded = candidate_key + (0,) * (length - len(candidate_key))
    bound_padded = bound_key + (0,) * (length - len(bound_key))
    return candidate_padded <= bound_padded


@dataclass
class CveCorrelation:
    """One tech-stack component matched against one feed entry."""

    product: str
    detected_version: str | None
    cve_id: str
    version_match: str
    """One of ``"matched"`` (version in range), ``"unknown"``
    (component or feed version unparseable — surfaced anyway, flagged
    advisory-only), or ``"product_wide"`` (feed entry has no version
    bound, applies to all versions of the product)."""
    severity: str | None
    kev: bool
    source: str
    fingerprint_confidence: float
    # RESIDUAL CLOSURE 2026-10-29 (Track 10.6/11.4): EPSS enrichment —
    # aggregate probability score from the operator-injected catalog
    # (shared/epss.py). None = not in catalog; advisory-only like the
    # rest of the correlation; NEVER a confirmation signal.
    epss: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "detected_version": self.detected_version,
            "cve_id": self.cve_id,
            "version_match": self.version_match,
            "severity": self.severity,
            "kev": self.kev,
            "epss": (round(self.epss, 6) if self.epss is not None else None),
            "source": self.source,
            "fingerprint_confidence": round(self.fingerprint_confidence, 2),
            "advisory_only": True,
            "does_not_confirm": True,
        }


def correlate_cves(
    components: Iterable[TechStackComponent],
    feed: Iterable[CveFeedEntry | Mapping[str, Any]],
) -> list[CveCorrelation]:
    """Cross-reference fingerprinted tech-stack components against an
    injected CVE feed.

    This is the N-day-discovery step: as soon as a product+version is
    fingerprinted, every feed entry for that product is checked
    immediately, rather than waiting for a human to notice the version
    string and look it up. Never performs a network request itself —
    ``feed`` is operator/ops-supplied (see module docstring).

    Args:
        components: Fingerprinted components, typically the output of
            :func:`fingerprint_tech_stack`.
        feed: An iterable of :class:`CveFeedEntry` or plain dicts with
            the same keys (``cve_id``, ``product``, ``version_lte``,
            ``severity``, ``kev``, ``source``).

    Returns:
        A list of :class:`CveCorrelation`, one per (component, feed
        entry) match on product name (case-insensitive), sorted with
        KEV-flagged entries first, then by fingerprint confidence
        descending.
    """
    normalised_feed: list[CveFeedEntry] = []
    for item in feed:
        if isinstance(item, CveFeedEntry):
            normalised_feed.append(item)
            continue
        if isinstance(item, Mapping):
            try:
                normalised_feed.append(
                    CveFeedEntry(
                        cve_id=str(item["cve_id"]),
                        product=str(item["product"]),
                        version_lte=(
                            str(item["version_lte"])
                            if item.get("version_lte") is not None
                            else None
                        ),
                        severity=(
                            str(item["severity"])
                            if item.get("severity") is not None
                            else None
                        ),
                        kev=bool(item.get("kev", False)),
                        source=str(item.get("source", "injected_catalog")),
                    )
                )
            except KeyError:
                continue

    by_product: dict[str, list[CveFeedEntry]] = {}
    for entry in normalised_feed:
        by_product.setdefault(entry.product.lower(), []).append(entry)

    results: list[CveCorrelation] = []
    for comp in components:
        candidates = by_product.get(comp.product.lower())
        if not candidates:
            continue
        for entry in candidates:
            if entry.version_lte is None:
                version_match = "product_wide"
            elif comp.version is None:
                version_match = "unknown"
            else:
                outcome = _version_lte(comp.version, entry.version_lte)
                if outcome is None:
                    version_match = "unknown"
                elif outcome:
                    version_match = "matched"
                else:
                    # Detected version is strictly newer than the
                    # vulnerable upper bound — not applicable.
                    continue
            results.append(
                CveCorrelation(
                    product=comp.product,
                    detected_version=comp.version,
                    cve_id=entry.cve_id,
                    version_match=version_match,
                    severity=entry.severity,
                    kev=entry.kev,
                    source=entry.source,
                    fingerprint_confidence=comp.confidence,
                )
            )

    results.sort(key=lambda r: (not r.kev, -(r.epss or 0.0), -r.fingerprint_confidence))
    return results


__all__ = [
    "CveCorrelation",
    "CveFeedEntry",
    "TechStackComponent",
    "correlate_cves",
    "fingerprint_tech_stack",
]
