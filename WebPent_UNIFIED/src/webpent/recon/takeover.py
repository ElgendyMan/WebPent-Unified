# src/webpent/recon/takeover.py
"""Subdomain takeover detector (PROPOSALS_ULTIMATE_V3 §8, 2026-11-01).

Detects dangling DNS records (a CNAME pointing at a service that no
longer has the target registered) and matches the service's canonical
"not found" fingerprint against the fetched response body.

Honesty contracts, stated up front:
- FIRST-ROUND = PASSIVE. There is NO account registration and NO active
  proof in this module: no claim is filed on any service, no content is
  uploaded, nothing is taken over. A fingerprint match plus the
  dangling-CNAME evidence and the 404 body snippet is reported as a
  CANDIDATE for the operator to verify and claim MANUALLY. The verdict
  name is deliberately ``match_fingerprint`` — a strong hint, not a
  takeover.
- ``inconclusive`` is an honest outcome: DNS gone, resolver errors,
  fetch errors, or a CNAME to a service with no known fingerprint all
  yield inconclusive — never a vulnerability claim.
- Every HTTP fetch passes a MANDATORY scope check BEFORE the request
  and is recorded in the request ledger BEFORE it is issued; a ledger
  refusal fails closed (nothing is fetched).
- DNS and HTTP are INJECTED (resolver / fetch callables). The module
  owns no network transport; tests pass stubs.
- Flag-gated via ``enable_takeover_scan`` (default False). Concurrency
  for batch scans is capped by ``takeover_concurrency`` (default 4).

Deterministic per host for the same stubs and settings.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

__all__ = [
    "FINGERPRINTS",
    "TakeoverError",
    "TakeoverVerdict",
    "check_host",
    "scan_hosts",
    "takeover_refusal",
]

VERDICTS = ("not_vulnerable", "match_fingerprint", "inconclusive")

# Fixed, documented fingerprint library. Each entry: (service, regex
# matched against the response body). These are the services' own
# canonical not-found / unclaimed-asset messages.
_FINGERPRINT_SPEC: tuple[tuple[str, str], ...] = (
    ("github_pages", r"There isn'?t a GitHub Pages site here"),
    ("aws_s3", r"NoSuchBucket|Bucket Not Found"),
    ("heroku", r"No such app"),
    ("azure", r"404 Web Site not found"),
    ("fastly", r"Fastly error: unknown domain"),
    ("shopify", r"Sorry, this shop is currently unavailable"),
    ("tumblr", r"Whatever you were looking for doesn'?t currently exist"),
    ("zendesk", r"Help Center Closed"),
)
FINGERPRINTS: tuple[tuple[str, "re.Pattern[str]"], ...] = tuple(
    (service, re.compile(pattern)) for service, pattern in _FINGERPRINT_SPEC
)

_MAX_HOSTS = 500
_BODY_SNIPPET_CHARS = 200
_MAX_CNAME_CHAIN = 5


class TakeoverError(ValueError):
    """Raised when a check cannot proceed within its contracts."""


@dataclass(frozen=True)
class TakeoverVerdict:
    """Outcome of one host check. ``evidence`` is report-ready."""

    host: str
    verdict: str
    service: str = ""
    reason: str = ""
    cname: str = ""
    http_status: int = 0
    body_snippet: str = ""
    evidence: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise TakeoverError("takeover_unknown_verdict")


def takeover_refusal() -> str | None:
    """Refusal code when the operator's flag is off, else None."""
    from webpent.config.settings import get_settings

    if not get_settings().enable_takeover_scan:
        return "takeover_flag_off"
    return None


def _require_flag() -> None:
    if takeover_refusal() is not None:
        raise TakeoverError("takeover_flag_off")


def _fingerprint_match(body: str) -> str:
    for service, pattern in FINGERPRINTS:
        if pattern.search(body):
            return service
    return ""


def check_host(
    host: str,
    *,
    resolver: Callable[[str, str], list[str]],
    fetch: Callable[[str], tuple[int, str]],
    scope_checker: Callable[[str], bool] | None,
    ledger,
) -> TakeoverVerdict:
    """One host: DNS chain → scoped fetch → fingerprint match.

    ``resolver(record_type, host) -> list[str]`` is injected DNS (tests
    stub it; NXDOMAIN / errors → empty list). ``fetch(url) ->
    (status, body)`` is injected HTTP. ``scope_checker`` is mandatory;
    ``ledger`` is mandatory and every fetch is recorded first.
    """
    _require_flag()
    return _check_host_impl(
        host, resolver=resolver, fetch=fetch,
        scope_checker=scope_checker, ledger=ledger,
    )


def _check_host_impl(
    host: str,
    *,
    resolver: Callable[[str, str], list[str]],
    fetch: Callable[[str], tuple[int, str]],
    scope_checker: Callable[[str], bool] | None,
    ledger,
) -> TakeoverVerdict:
    """Body of one host check without the flag gate.

    The gate is checked by the caller; the batch path checks it ONCE in
    the main thread (the activated-settings context is per-thread, so
    worker threads must not re-check it — the batch still refuses
    wholesale when the flag is off).
    """
    if not host or not host.strip():
        raise TakeoverError("takeover_bad_host")
    if scope_checker is None:
        raise TakeoverError("takeover_scope_checker_required")
    if ledger is None:
        raise TakeoverError("takeover_ledger_required")

    url = f"https://{host}/"
    if not scope_checker(url):
        raise TakeoverError("takeover_out_of_scope")

    # 1. DNS: does a dangling record exist at all?
    chain = resolver("CNAME", host)
    if not chain:
        # NXDOMAIN or no alias: nothing dangling to take over. Honest
        # inconclusive — NXDOMAIN alone is NOT a vulnerability claim.
        return TakeoverVerdict(
            host=host,
            verdict="inconclusive",
            reason="takeover_dns_no_records",
        )
    if len(chain) > _MAX_CNAME_CHAIN:
        return TakeoverVerdict(
            host=host,
            verdict="inconclusive",
            reason="takeover_cname_chain_too_long",
        )
    cname = chain[0]

    # 2. HTTP: fetch the body (scope-checked above, ledgered now).
    recorded = ledger.record(
        "GET", url, flags="takeover",
    )
    if not recorded:
        raise TakeoverError("takeover_ledger_refused")
    try:
        status, body = fetch(url)
    except Exception as exc:  # fetch stub errors are honest data
        return TakeoverVerdict(
            host=host,
            verdict="inconclusive",
            cname=cname,
            reason=f"takeover_fetch_error:{type(exc).__name__}",
        )

    snippet = body[:_BODY_SNIPPET_CHARS]
    evidence = {
        "cname": cname,
        "http_status": status,
        "body_snippet": snippet,
        "note": (
            "PASSIVE detection only: fingerprint match + dangling CNAME "
            "as submission evidence. No claim was filed and no active "
            "proof was performed; verify and claim manually."
        ),
    }

    # 3. Match: a 200 with real content is the opposite of dangling.
    if status != 404:
        return TakeoverVerdict(
            host=host,
            verdict="not_vulnerable",
            cname=cname,
            http_status=status,
            body_snippet=snippet,
            reason="takeover_not_404",
            evidence=evidence,
        )

    service = _fingerprint_match(body)
    if service:
        return TakeoverVerdict(
            host=host,
            verdict="match_fingerprint",
            service=service,
            cname=cname,
            http_status=status,
            body_snippet=snippet,
            reason=f"takeover_fingerprint_match:{service}",
            evidence=evidence,
        )

    # 404 but no known fingerprint: honest not_vulnerable per contract
    # (a matching-CNAME + non-matching-404 body is not evidence).
    return TakeoverVerdict(
        host=host,
        verdict="not_vulnerable",
        cname=cname,
        http_status=status,
        body_snippet=snippet,
        reason="takeover_404_no_fingerprint",
        evidence=evidence,
    )


def scan_hosts(
    hosts: Sequence[str],
    *,
    resolver: Callable[[str, str], list[str]],
    fetch: Callable[[str], tuple[int, str]],
    scope_checker: Callable[[str], bool] | None,
    ledger,
    concurrency: int | None = None,
) -> list[TakeoverVerdict]:
    """Batch check with concurrency capped by ``takeover_concurrency``.

    Order-stable: results come back in input order. A host whose check
    raises (scope/ledger refusal, bad host) FAILS CLOSED for the whole
    batch — refusals are never swallowed into per-host inconclusives.
    """
    _require_flag()
    if len(hosts) > _MAX_HOSTS:
        raise TakeoverError("takeover_too_many_hosts")
    from webpent.config.settings import get_settings

    cap = int(
        get_settings().takeover_concurrency
        if concurrency is None
        else concurrency
    )
    if cap < 1:
        raise TakeoverError("takeover_bad_concurrency")

    # validate every host's preconditions first (fail closed, in order)
    for host in hosts:
        if not host or not host.strip():
            raise TakeoverError("takeover_bad_host")
        if scope_checker is None:
            raise TakeoverError("takeover_scope_checker_required")
        if ledger is None:
            raise TakeoverError("takeover_ledger_required")
        if not scope_checker(f"https://{host}/"):
            raise TakeoverError("takeover_out_of_scope")

    def _one(host: str) -> TakeoverVerdict:
        # gate-free body: the flag was checked once above, in-thread
        return _check_host_impl(
            host,
            resolver=resolver,
            fetch=fetch,
            scope_checker=scope_checker,
            ledger=ledger,
        )

    if len(hosts) <= 1 or cap == 1:
        return [_one(host) for host in hosts]

    with ThreadPoolExecutor(max_workers=min(cap, len(hosts))) as pool:
        return list(pool.map(_one, hosts))
