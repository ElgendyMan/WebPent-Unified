# src/webpent/shared/cache_key_discovery.py
"""Cache-key discovery probe (PROPOSALS_ULTIMATE_V2 §6, 2026-10-30).

Param-Miner-style discovery of UNKEYED inputs a cache or CDN will still
store against the request's cache key: for each candidate header (and a
short candidate-param list) the probe sends a poisoned request carrying
a unique marker, then an UNPOISONED victim request, and reads the
differential strictly:

- the marker was DELIVERED to a request that carried no marker-bearing
  input (the victim or baseline served the poisoned entry), OR it is
  reflected AND the victim differs from the baseline -> ``candidate``:
  handed to the existing poisoning validator
  (agents/advanced_web_vulns) — discovery never alleges poisoning
  itself.
- marker reflected (probe echo) but the victim is byte-identical to
  the baseline -> ``refuted``: pure reflection with no cache storage
  is a client echo, not a poisoning primitive.
- victim differs from baseline but no reflection
  -> ``inconclusive``: the cache stores something unkeyed, but we did
  not see what — never a candidate on storage alone.
- neither, or a fetch that failed (None) -> ``neutral``/``inconclusive``:
  a missing baseline or victim can never produce a confident verdict.

Fail-closed: flag off, no endpoints, or more endpoints than the
per-campaign budget is a refusal — a silently truncated sweep would
look like "no unkeyed inputs found".
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

__all__ = [
    "CACHE_KEY_HEADER_CANDIDATES",
    "CACHE_KEY_PARAM_CANDIDATES",
    "CacheKeyCandidate",
    "CacheKeyDiscoveryError",
    "CacheKeyResult",
    "discover_cache_keys",
    "to_validator_inputs",
]

DEFAULT_MAX_ENDPOINTS = 15
MARKER_TEMPLATE = "webpent-ck-{marker}"
# Cache-buster param: the probe and its victim share ONE buster value so
# they land on the same cache key whichever inputs the cache keys, while
# the baseline fetches through a DIFFERENT buster value for a clean
# origin reference. Without a buster on the probe, any pre-existing
# cache entry would be served to the probe as a hit and storage would be
# unobservable (and every earlier candidate's probe would consume the
# cold key of a path-only cache).
BUST_PARAM = "webpent-ck-bust"

# Headers commonly keyed (or commonly reflected-but-unkeyed) by CDNs,
# caches and fronting proxies. Sorted, lowercase, deduplicated.
CACHE_KEY_HEADER_CANDIDATES: tuple[str, ...] = tuple(sorted({
    "x-forwarded-host",
    "x-forwarded-scheme",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-server",
    "x-host",
    "x-http-host-override",
    "x-original-url",
    "x-rewrite-url",
    "x-url",
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "cf-ipcountry",
    "true-client-ip",
    "forwarded",
    "x-proxy-host",
    "x-proxy-url",
    "x-abuse-ip",
    "x-cluster-client-ip",
    "x-client-ip",
    "x-remote-addr",
    "x-remote-ip",
    "x-hostname",
    "x-site-url",
    "x-original-host",
    "x-appengine-country",
    "x-forwarded",
    "client-ip",
    "cf-ray",
    "x-request-id",
    "x-trace-id",
    "x-correlation-id",
    "x-amz-cf-id",
    "x-cache",
    "x-runtime",
    "x-wap-profile",
    "device-stock-browser",
    "save-data",
    "x-frame-options",
}))

# Query params that caches occasionally key on even when the app ignores
# them (tracking-style params are classic CDN keying surprises).
CACHE_KEY_PARAM_CANDIDATES: tuple[str, ...] = tuple(sorted({
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "utm_term",
    "utm_id",
    "fbclid",
    "gclid",
    "msclkid",
    "ref",
    "referrer",
    "callback",
    "redirect",
    "next",
    "v",
}))


class CacheKeyDiscoveryError(ValueError):
    """Raised when the sweep cannot run fail-closed."""


@dataclass(frozen=True)
class CacheKeyCandidate:
    """One differential verdict for one candidate input."""

    kind: str  # "header" | "param"
    name: str
    marker: str
    reflected: bool
    stored: bool
    verdict: str  # candidate | refuted | inconclusive | neutral


@dataclass(frozen=True)
class CacheKeyResult:
    """The sweep's verdicts for one endpoint."""

    endpoint: str
    candidates: "tuple[CacheKeyCandidate, ...]"


def to_validator_inputs(
    results: "Sequence[CacheKeyResult]",
) -> "tuple[dict[str, str], ...]":
    """Project ``candidate``-verdict entries for the poisoning validator.

    The ONLY hand-off surface to agents/advanced_web_vulns: a candidate
    is an input to validation, never a finding — the validator re-probes
    with its own markers and owns the verdict. ``refuted`` /
    ``inconclusive`` / ``neutral`` entries are dropped here.
    """
    inputs: list[dict[str, str]] = []
    for result in results:
        for cand in result.candidates:
            if cand.verdict == "candidate":
                inputs.append(
                    {
                        "endpoint": result.endpoint,
                        "kind": cand.kind,
                        "name": cand.name,
                        "marker": cand.marker,
                    }
                )
    return tuple(inputs)


# fetcher(url, headers, params) -> (status_code, body_text) | None
Fetcher = Callable[[str, Mapping[str, str], Mapping[str, str]],
                   "tuple[int, str] | None"]


def _differential(
    baseline: "tuple[int, str] | None",
    probe: "tuple[int, str] | None",
    victim: "tuple[int, str] | None",
    marker: str,
) -> "tuple[bool, bool, str]":
    # A missing baseline or victim means the differential could not be
    # established: never a confident verdict on a failed fetch.
    if baseline is None or victim is None:
        return False, False, "inconclusive"
    reflected = any(
        marker in body[1] for body in (probe, victim, baseline) if body is not None
    )
    stored = victim != baseline
    # Strongest signal: the marker reached a request that carried no
    # marker-bearing input (victim/baseline share the probe's buster but
    # not its poison) — the poisoned entry was SERVED, not just stored.
    delivered = marker in victim[1] or marker in baseline[1]
    if delivered or (reflected and stored):
        verdict = "candidate"
    elif reflected:
        verdict = "refuted"  # probe echo with no storage: client echo
    elif stored:
        verdict = "inconclusive"  # storage without visible reflection
    else:
        verdict = "neutral"
    return reflected, stored, verdict


def discover_cache_keys(
    endpoints: Sequence[str],
    *,
    fetcher: Fetcher,
    enable_cache_key_discovery: bool,
    marker_prefix: str | None = None,
    max_endpoints: int = DEFAULT_MAX_ENDPOINTS,
) -> "tuple[CacheKeyResult, ...]":
    """Run the header/param sweep over ``endpoints``, strictly bounded.

    Raises (never silently truncates): flag off, no endpoints, or more
    endpoints than ``max_endpoints``. ``marker_prefix`` pins the marker
    base (testability); one unique marker value is minted per candidate.
    Per candidate the fetch order is probe (buster B1, poisoned) ->
    victim (same buster B1, clean) -> baseline (fresh buster B2): the
    probe/victim pair shares a cache key whichever inputs the cache
    keys, while the baseline always sees the origin.
    """
    if not enable_cache_key_discovery:
        raise CacheKeyDiscoveryError("cache_key_discovery_flag_off")
    endpoint_list = [str(e) for e in endpoints]
    if not endpoint_list:
        raise CacheKeyDiscoveryError("cache_key_discovery_requires_endpoints")
    if len(endpoint_list) > max_endpoints:
        raise CacheKeyDiscoveryError("cache_key_budget_exceeded")
    base = marker_prefix or f"webpent-{secrets.token_hex(8)}"

    results: list[CacheKeyResult] = []
    for endpoint in endpoint_list:
        candidates: list[CacheKeyCandidate] = []
        for kind, name in (
            [("header", h) for h in CACHE_KEY_HEADER_CANDIDATES]
            + [("param", p) for p in CACHE_KEY_PARAM_CANDIDATES]
        ):
            marker = MARKER_TEMPLATE.format(marker=f"{base}-{kind}-{name}")
            bust = f"{base}-{kind}-{name}"
            # Probe FIRST through a fresh buster: cold key, so the poisoned
            # response is the one the cache stores. The victim shares the
            # probe's buster (same cache key, no poison); the baseline
            # fetches through a different buster for a clean reference.
            if kind == "header":
                probe = fetcher(
                    endpoint, {name: marker}, {BUST_PARAM: bust}
                )
            else:
                probe = fetcher(
                    endpoint, {}, {name: marker, BUST_PARAM: bust}
                )
            victim = fetcher(endpoint, {}, {BUST_PARAM: bust})
            baseline = fetcher(endpoint, {}, {BUST_PARAM: f"{bust}-alt"})
            reflected, stored, verdict = _differential(
                baseline, probe, victim, marker
            )
            candidates.append(
                CacheKeyCandidate(
                    kind=kind,
                    name=name,
                    marker=marker,
                    reflected=reflected,
                    stored=stored,
                    verdict=verdict,
                )
            )
        results.append(
            CacheKeyResult(
                endpoint=endpoint,
                candidates=tuple(candidates),
            )
        )
    return tuple(results)
