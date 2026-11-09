# src/webpent/tools/recon/gau.py
"""webpent.tools.recon.gau

Wrapper around the ``gau`` CLI (getallurls — fetches known URLs for a
domain from the AlienVault OTX, Wayback Machine and Common Crawl
archives).

Context (Ultimate plan 2026-10-27, proposal 5 — reconnaissance depth,
phase 2): the current recon layer (katana, httpx, subfinder, ffuf,
arjun) covers the LIVE surface only. It has no mechanism for archive
discovery — endpoints that were removed from the site but still work
(and are therefore a classic source of forgotten vulnerabilities), or
historical URLs that reveal parameter names and routes never present
in today's crawl. gau fills exactly this gap, and this wrapper follows
the architectural pattern of ``tools/recon/arjun.py`` precisely:
subprocess via ``run_command`` (never raw subprocess), scope refusal
BEFORE spawning, a disabled-by-default settings flag, bounded output.

The wrapper executes::

    gau --providers <providers> --threads 5 <domain>

Design notes:

  * Scope refusal raises :class:`ToolExecutionError` (this wrapper is
    more strict than arjun's silent ``[]`` return because archive
    discovery is an explicit, flagged operator opt-in — a refusal
    should be loud, not silently indistinguishable from "no results").
  * The tool is disabled by default behind the
    ``enable_archive_discovery`` settings flag; when the flag is off,
    calling this wrapper raises :class:`ToolExecutionError` with an
    explicit message naming the flag.
  * The ``gau`` basename is not in ``tools/utils/subprocess.py``'s
    frozen executable manifest; operators must deliberately register
    it via the ``WEBPENT_ALLOWED_EXECUTABLES`` environment variable
    (the governance mechanism for adding executables — the manifest
    must never be widened implicitly by a tool wrapper).
  * gau writes URLs to stdout, one per line, unsorted; zero output is
    a NORMAL result (nothing archived for the domain), not an error.
  * A missing binary surfaces as :class:`ToolNotFoundError` from
    ``run_command`` and is deliberately let propagate so callers can
    distinguish "not installed" from "ran with no results".

Archive URLs are historical: any URL returned here MUST be
re-checked against the engagement scope allowlist by the CONSUMER
before it is ever requested (an archived endpoint may point at
infrastructure that has since moved outside the authorized scope) —
this wrapper only reports names, it never fetches them.

Registration note: ``@register_tool`` fires on IMPORT of this module.
``tools/registry.py``'s ``auto_discover()`` uses a hardcoded module
list that is hash-pinned by the frozen-modules gate, so adding gau to
that list is deliberately left to a future unfreeze-window change;
until then the graph node wiring imports this module explicitly.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from webpent.config.settings import get_settings
from webpent.shared.engagement_scope import is_engagement_target_host
from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.registry import register_tool
from webpent.tools.utils.subprocess import run_command

logger = logging.getLogger(__name__)

# gau supports exactly these three archive providers. Anything else in
# the --providers list is a caller bug — reject it before spawning a
# subprocess rather than letting gau choke on an unknown provider.
_VALID_PROVIDERS = frozenset({"wayback", "commoncrawl", "otx"})

# Bounds: gau can emit hundreds of thousands of lines for old domains;
# the wrapper caps what it will parse/return per invocation.
_MAX_URL_LENGTH = 2048
_DEFAULT_MAX_URLS = 500
_HARD_MAX_URLS = 10_000
_MIN_TIMEOUT = 1
_MAX_TIMEOUT = 900

# Executable name. There is deliberately no ``gau_path`` setting yet —
# when one is added, this constant becomes its default (and the
# command builder gains the parameter). Resolved statically (no
# getattr on settings) so the direct-I/O inventory records only the
# one sanctioned subprocess boundary call below.
_GAU_EXECUTABLE = "gau"


@register_tool(
    name="gau",
    category="recon",
    description=(
        "Archive URL discovery (AlienVault OTX / Wayback / Common Crawl) "
        "with gau — scope-gated, settings-flagged, bounded output"
    ),
)
def run_gau(
    target_domain: str,
    *,
    providers: str = "wayback,commoncrawl,otx",
    timeout: int = 120,
    max_urls: int = 500,
) -> dict:
    """Fetch archived URL names for ``target_domain`` via the gau CLI.

    The wrapper never fetches any of the returned URLs itself — it
    returns NAMES for the crawler/scope layers to re-adjudicate (see
    module docstring: archive data is historical and must be
    re-checked against the engagement scope before use).

    Args:
        target_domain: Bare domain (e.g. ``example.com``) — not a URL.
            Must be the engagement's own declared target host.
        providers: Comma-separated subset of ``wayback``,
            ``commoncrawl``, ``otx``.
        timeout: Wall-clock subprocess timeout in seconds (1..900).
        max_urls: Cap on unique URLs returned (1..10000); when more
            unique URLs exist, the result is truncated and flagged.

    Returns:
        ``{"urls": [str, ...], "count": int, "truncated": bool}`` —
        deduplicated http(s) URLs in encounter order. Empty output is
        a normal result: ``{"urls": [], "count": 0, "truncated":
        False}``.

    Raises:
        ValueError: If ``target_domain`` is not a bare domain, a
            provider is unknown, or ``timeout``/``max_urls`` are out
            of their bounded ranges (caller bugs — surface loudly).
        ToolExecutionError: If the domain is out of engagement scope,
            the ``enable_archive_discovery`` settings flag is off, or
            the gau process itself fails.
        ToolNotFoundError: If the gau binary is not on PATH (let
            propagate from run_command).
    """
    domain = str(target_domain or "").strip().lower()
    if not domain or "://" in domain or "/" in domain or " " in domain:
        raise ValueError(
            f"gau target_domain must be a bare domain (e.g. 'example.com'), "
            f"got {target_domain!r}"
        )

    if not is_engagement_target_host(domain):
        logger.warning(
            "gau: refusing out-of-scope target domain %s; no archive fetch performed",
            domain,
        )
        raise ToolExecutionError(
            cmd=["gau", domain],
            returncode=-1,
            stdout="",
            stderr="",
            message=(
                f"gau: refusing out-of-scope target domain {domain!r} — the "
                "domain is not in the engagement's declared target hosts; no "
                "archive fetch was performed"
            ),
        )

    settings = get_settings()
    if not settings.enable_archive_discovery:
        raise ToolExecutionError(
            cmd=["gau", domain],
            returncode=-1,
            stdout="",
            stderr="",
            message="archive discovery disabled by settings (enable_archive_discovery)",
        )

    requested = [item.strip().lower() for item in providers.split(",") if item.strip()]
    if not requested or any(item not in _VALID_PROVIDERS for item in requested):
        raise ValueError(
            f"gau providers must be a comma-separated subset of "
            f"{sorted(_VALID_PROVIDERS)}, got {providers!r}"
        )
    if timeout < _MIN_TIMEOUT or timeout > _MAX_TIMEOUT:
        raise ValueError(f"gau timeout must be between {_MIN_TIMEOUT} and {_MAX_TIMEOUT}")
    if max_urls < 1 or max_urls > _HARD_MAX_URLS:
        raise ValueError(f"gau max_urls must be between 1 and {_HARD_MAX_URLS}")

    cmd = _build_gau_command(
        _GAU_EXECUTABLE,
        domain,
        providers=",".join(requested),
        threads=5,
    )
    stdout = run_command(cmd, timeout=timeout)
    return _parse_gau_output(stdout, max_urls=max_urls)


def _build_gau_command(
    gau_path: str,
    domain: str,
    *,
    providers: str,
    threads: int,
) -> list[str]:
    """Assemble the bounded gau argument vector (pure, testable).

    Deliberately fixed-shape: providers are pre-validated by the
    caller, the thread count is pinned to a polite 5, and the domain
    is a pre-validated bare domain — no user-controlled flags beyond
    that ever reach the command line.
    """
    return [
        gau_path,
        "--providers",
        providers,
        "--threads",
        str(threads),
        domain,
    ]


def _parse_gau_output(stdout: object, *, max_urls: int = _DEFAULT_MAX_URLS) -> dict:
    """Parse gau's stdout into a bounded, deduplicated URL list.

    Pure function: filters to well-formed http(s) URLs (validated with
    ``urlparse`` — scheme http/https AND a non-empty network location),
    deduplicates preserving first-encounter order (gau's own ordering
    carries per-provider priority), and caps the result at
    ``max_urls`` with an explicit ``truncated`` flag.
    """
    if isinstance(stdout, bytes):
        text = stdout.decode("utf-8", errors="replace")
    elif isinstance(stdout, str):
        text = stdout
    else:
        text = ""

    seen: set[str] = set()
    urls: list[str] = []
    truncated = False
    for raw_line in text.splitlines():
        candidate = raw_line.strip()[:_MAX_URL_LENGTH]
        if not candidate.lower().startswith(("http://", "https://")):
            continue
        try:
            parts = urlparse(candidate)
        except ValueError:
            continue
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        if len(urls) < max_urls:
            urls.append(candidate)
        else:
            truncated = True
    return {"urls": urls, "count": len(urls), "truncated": truncated}


__all__ = ["run_gau"]
