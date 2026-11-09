"""webpent.shared.source_leak_discovery — advisory-only source-leak
candidate generation.

Ultimate plan 2026-10-27, proposal 5 (reconnaissance depth), phase 4:
"detect source-code leaks tied to the target (leaked secrets, exposed
source) — ADVISORY ONLY, no downloading or scanning of code without
explicit approval."

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!  THIS MODULE NEVER FETCHES, CLONES, OR SCANS ANY CODE. EVER.     !!
!!                                                                  !!
!!  It is a pure name-generator: given the target domain and the    !!
!!  crawled-data bundle the framework ALREADY captured, it emits    !!
!!  candidate public-repository / project names for a HUMAN         !!
!!  operator to check MANUALLY, with proper authorization, using    !!
!!  their own tooling. Every candidate it returns carries           !!
!!  ``fetches_code=False`` and an explicit advisory note. There is  !!
!!  no network code path in this module — no HTTP client, no        !!
!!  subprocess, no git — and none may ever be added here.           !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

What it generates (all bounded, all advisory):

  * ``domain_heuristic`` candidates — the org-shaped GitHub org
    guess (the second-level domain: ``example`` from
    ``example.com``), expanded with a small wordlist of common
    org-prefixed repository-name markers (``example-frontend``,
    ``example-backend``, ``example-api``, ...). This is the
    "known leak-wordlist markers" surface: the names a leak hunter
    would manually try first.
  * ``js_asset_hint`` candidates — repository-name guesses inferred
    from the crawled JavaScript asset paths (the upstream convention
    is ``crawled_data["javascript_urls"]``): a bundle named
    ``/static/js/app.js`` hints at an SPA, so ``example-frontend``
    and ``example-web`` become candidates; ``admin``/``dashboard``
    assets hint at console repos, ``api``/``graphql`` assets at
    service repos.

Bounds: at most 50 JS paths are inspected, candidate strings are
capped at 64 characters, and the result is capped at 25 candidates.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

_MAX_CANDIDATES = 25
"""Hard cap on returned candidates (plan-mandated)."""

_MAX_JS_PATHS = 50
"""At most this many crawled JS paths are inspected for hints."""

_MAX_CANDIDATE_CHARS = 64
"""Candidate strings are truncated to this length."""

# ---------------------------------------------------------------------------
# Wordlists (the "known leak-wordlist markers")
# ---------------------------------------------------------------------------

# Common org-prefixed repository-name markers a leak hunter manually
# tries first. Kept deliberately small and boring — this generates
# NAMES for manual verification, not a fuzzing dictionary.
_REPO_SUFFIX_WORDLIST: tuple[str, ...] = (
    "frontend",
    "backend",
    "api",
    "web",
    "admin",
    "mobile",
    "ios",
    "android",
    "internal",
    "devops",
    "platform",
    "dashboard",
)

# Crawled-asset marker -> candidate repo-name suffixes. The classic
# example from the plan: "/static/js/app.js" -> example-frontend,
# example-web.
_JS_MARKER_TO_SUFFIXES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (
        ("app", "main", "bundle", "chunk", "vendor", "index", "spa"),
        ("frontend", "web"),
    ),
    (("admin", "dashboard", "console"), ("admin", "dashboard")),
    (("api", "graphql"), ("api", "backend")),
)

_ADVISORY_NOTE = "advisory only — manual verification required"


def _bounded_candidate(value: str) -> str:
    return value[:_MAX_CANDIDATE_CHARS]


def _second_level_domain(target_domain: str) -> str:
    """Extract the org-shaped second-level domain (``example.com`` ->
    ``example``; ``www.example.com`` -> ``example``).

    Purely heuristic — multi-part public suffixes (``example.co.uk``)
    yield ``co``, which is harmlessly uninteresting as a repo-name
    hint; the operator adjusts by hand. That trade-off is documented
    rather than papered over with a public-suffix table (this module
    must stay stdlib-only and dependency-free).
    """
    raw = str(target_domain or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw or "/" in raw:
        try:
            raw = urlparse(raw).hostname or ""
        except ValueError:
            return ""
    raw = raw.removeprefix("www.")
    parts = [part for part in raw.split(".") if part]
    if len(parts) < 2:
        return parts[0] if parts else ""
    return parts[-2]


def _js_hint_paths(crawled_data: dict[str, Any]) -> list[str]:
    """Collect bounded JS asset paths from the injected crawled-data bundle.

    Accepts the upstream convention ``javascript_urls`` plus the
    ``js_files``/``assets`` aliases; full URLs and bare paths both
    work (only the path is used).
    """
    paths: list[str] = []
    for key in ("javascript_urls", "js_files", "assets"):
        raw = crawled_data.get(key)
        if not isinstance(raw, list):
            continue
        for item in raw:
            text = str(item).strip()
            if not text:
                continue
            if "://" in text:
                try:
                    text = urlparse(text).path or text
                except ValueError:
                    continue
            paths.append(text)
            if len(paths) >= _MAX_JS_PATHS:
                return paths
    return paths


def suggest_leak_candidates(
    target_domain: str,
    crawled_data: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Generate advisory source-leak candidate names for a human operator.

    PURE FUNCTION — see the loud module docstring: this function only
    GENERATES NAMES (org guesses + repo-name patterns inferred from
    crawled JS asset paths). It never fetches, clones, or scans any
    code, and every candidate carries ``fetches_code=False`` plus the
    advisory note. Checking the candidates against public repositories
    is the human operator's authorized, out-of-band job.

    Args:
        target_domain: The engagement's target domain (bare domain or
            URL; the second-level domain is extracted as the org
            guess).
        crawled_data: The already-captured crawl bundle. JS asset
            paths are read from ``javascript_urls`` (the crawler's
            convention) or the ``js_files``/``assets`` aliases.

    Returns:
        At most 25 candidate dicts:
        ``{"candidate": str, "source": "domain_heuristic" |
        "js_asset_hint", "note": "advisory only — manual verification
        required", "fetches_code": False}``.
    """
    bundle = crawled_data if isinstance(crawled_data, dict) else {}
    org = _second_level_domain(target_domain)
    if not org:
        logger.info("source-leak advisory: no usable org guess from %r", target_domain)
        return []

    candidates: list[dict[str, Any]] = []

    def _add(name: str, source: str) -> None:
        if len(candidates) >= _MAX_CANDIDATES:
            return
        candidate = _bounded_candidate(name)
        if not candidate:
            return
        # Dedupe on (candidate, source): the same name surfacing from
        # two different heuristics (domain wordlist AND a JS asset
        # hint) is corroborating evidence, not a duplicate — both
        # observations stay visible to the operator.
        if any(
            existing["candidate"] == candidate and existing["source"] == source
            for existing in candidates
        ):
            return
        candidates.append(
            {
                "candidate": candidate,
                "source": source,
                "note": _ADVISORY_NOTE,
                "fetches_code": False,
            }
        )

    # Domain heuristic: the org guess itself, then the org expanded
    # with the common repo-name markers.
    _add(org, "domain_heuristic")
    for suffix in _REPO_SUFFIX_WORDLIST:
        _add(f"{org}-{suffix}", "domain_heuristic")

    # JS asset hints: infer repo-name candidates from the crawled
    # asset paths (e.g. "/static/js/app.js" -> example-frontend).
    for path in _js_hint_paths(bundle):
        lowered = path.lower()
        # Tokens = path segments AND their dot-separated parts, so
        # "graphql.api.js" yields the "graphql"/"api" markers while
        # "app.js" still yields "app".
        tokens = [
            part
            for segment in lowered.split("/")
            if segment
            for part in segment.split(".")
            if part
        ]
        for markers, suffixes in _JS_MARKER_TO_SUFFIXES:
            if any(token in markers for token in tokens):
                for suffix in suffixes:
                    _add(f"{org}-{suffix}", "js_asset_hint")

    logger.info(
        "source-leak advisory: %d candidate name(s) generated for %r "
        "(names only — nothing fetched, cloned, or scanned)",
        len(candidates),
        target_domain,
    )
    return candidates


def source_leak_advisory_enabled() -> bool:
    """Return the ``enable_source_leak_advisory`` settings flag.

    This is the gate the orchestrating graph node consults before
    surfacing these advisory candidates. The generator itself stays
    flag-free and deterministic (pure over injected data) so it
    remains unit-testable regardless of settings — and regardless of
    this flag, the module still never fetches anything.
    """
    from webpent.config.settings import get_settings

    return bool(get_settings().enable_source_leak_advisory)


__all__ = ["source_leak_advisory_enabled", "suggest_leak_candidates"]
