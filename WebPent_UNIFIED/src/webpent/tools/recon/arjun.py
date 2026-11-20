# src/webpent/tools/recon/arjun.py
"""webpent.tools.recon.arjun

Wrapper around s0md3v's ``arjun`` CLI for in-scope hidden HTTP parameter
discovery (GET/POST/JSON/XML).

Context (VIP detection-depth initiative, 2026-10): the crawler's discovery
layer (``crawler/agent.py``, ``recon/autonomous_crawler.py``) recovers
*endpoints* (via katana + HTTP fallback) but has no dedicated mechanism for
recovering *hidden parameters* on an endpoint that is already known — a
``GET /api/users`` route with an undocumented ``debug=1`` or ``role=admin``
parameter is invisible to pure endpoint discovery. Arjun fills exactly this
gap: given a URL, it brute-forces parameter names from a wordlist and
differentially detects which ones change server behavior (body length,
status code, etc.), the same differential-signal philosophy already used
by the race-condition and causal-signal validators elsewhere in this
codebase.

The wrapper executes::

    arjun -u <url> -oJ <tmp_output_file> -q -t <threads> -T <timeout> \
          [-m <method>] [-w <wordlist>]

Design notes, verified empirically against a local test HTTP server before
writing this wrapper (not assumed from documentation):

  * Arjun's ``-oJ`` JSON output is only written to disk when at least one
    parameter is found. Zero findings means the output file simply does
    not exist — this is NOT an error condition and must not raise.
  * Arjun's process exit code is ``0`` in both the found and zero-findings
    cases, so (unlike ``ffuf``/``katana``) exit code cannot be used to
    detect "no results" — presence of the output file is the only
    reliable signal.
  * Progress/status output goes to stdout with ANSI color codes and is not
    structured; this wrapper never parses stdout for results, only the
    JSON output file.
  * The JSON shape is ``{"<url>": {"headers": {...}, "method": "GET",
    "params": ["debug", "user_id", "id"]}}`` — one entry per scanned URL
    (this wrapper always scans exactly one URL per call, so the dict has
    at most one key).

Like ``ffuf``, this wrapper requires the caller to supply an explicit
wordlist path when overriding Arjun's bundled default, respects the
engagement scope allowlist (refuses out-of-scope hosts before spawning
the subprocess), and is disabled by default behind a settings flag.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from webpent.config.settings import get_settings
from webpent.shared.engagement_scope import is_engagement_target_host
from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.registry import register_tool
from webpent.tools.utils.subprocess import run_command

logger = logging.getLogger(__name__)

# Arjun supports four request-body shapes. Anything else is a caller bug —
# reject it before spawning a subprocess rather than letting arjun choke
# on an unrecognised -m value.
_VALID_METHODS = frozenset({"GET", "POST", "JSON", "XML"})


@register_tool(
    name="arjun",
    category="recon",
    description="In-scope hidden HTTP parameter discovery (GET/POST/JSON/XML) with arjun",
)
def run_arjun(
    target_url: str,
    *,
    method: str = "GET",
    wordlist_path: str | None = None,
    threads: int = 5,
    chunk_size: int | None = None,
    stealth_mode: bool = False,
    extra_headers: dict[str, str] | None = None,
    session_cookies: dict[str, str] | None = None,
) -> list[str]:
    """Discover hidden parameters accepted by ``target_url`` and return their names.

    The wrapper never follows out-of-scope redirects implicitly (arjun's own
    ``--disable-redirects`` is always passed) and only runs against hosts
    already present in the engagement's target allowlist — mirroring the
    SSRF posture of ``run_katana``/``run_ffuf``. It is safe to expose behind
    a disabled-by-default settings flag.

    Args:
        target_url: Absolute URL to probe. Query string, if any, is left
            untouched — arjun fuzzes additional parameter names, it does
            not replace existing ones.
        method: One of ``GET``, ``POST``, ``JSON``, ``XML``. Determines
            where arjun places candidate parameter names (query string vs.
            request body shape).
        wordlist_path: Optional path to a custom parameter-name wordlist.
            When omitted, arjun's bundled default wordlist is used (unlike
            ``ffuf``, a wordlist is not mandatory here — arjun ships one).
        threads: Concurrent request threads (arjun default is 5).
        chunk_size: Optional override for arjun's ``-c`` chunk size (number
            of candidate parameter names probed per request batch). Left
            unset to use arjun's own adaptive default.
        stealth_mode: When True, apply the same jitter/min-interval
            discipline used by the other recon tool wrappers before
            launching the subprocess.
        extra_headers: Headers to forward (User-Agent is intentionally
            excluded, matching ``run_ffuf``/``run_katana``).
        session_cookies: Session cookies to forward as a ``Cookie`` header
            by name only — values are never logged.

    Returns:
        A de-duplicated, sorted list of discovered parameter names. Empty
        list if arjun finds nothing, is not installed, times out, or the
        target host is out of scope.

    Raises:
        ValueError: If ``method`` is not one of the four values arjun
            supports, or ``threads``/``chunk_size`` are out of a sane
            bounded range.
    """
    parsed = urlparse(target_url)
    target_host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not target_host:
        logger.warning("arjun: refusing malformed target URL")
        return []
    if not is_engagement_target_host(target_host):
        logger.warning(
            "arjun: refusing out-of-scope target host %s; no scan performed",
            target_host,
        )
        return []

    method = method.upper().strip()
    if method not in _VALID_METHODS:
        raise ValueError(f"arjun method must be one of {sorted(_VALID_METHODS)}, got {method!r}")

    if threads < 1 or threads > 50:
        raise ValueError("arjun threads must be between 1 and 50")
    if chunk_size is not None and (chunk_size < 1 or chunk_size > 500):
        raise ValueError("arjun chunk_size must be between 1 and 500")

    if wordlist_path is not None:
        wordlist = Path(wordlist_path).expanduser()
        if not wordlist.is_file():
            logger.warning("arjun: configured wordlist is unavailable; no scan performed")
            return []

    if stealth_mode:
        from webpent.shared.stealth import apply_jitter, enforce_min_interval, extract_host

        apply_jitter(True, label="arjun")
        enforce_min_interval(True, extract_host(target_url))

    settings = get_settings()

    # arjun only writes -oJ when it finds something, so the wrapper owns a
    # private temp path per invocation rather than trusting a fixed path
    # (which would go stale/ambiguous under concurrent crawls of different
    # targets) or parsing stdout (unstructured, ANSI-colored progress text).
    with tempfile.TemporaryDirectory(prefix="webpent-arjun-") as tmp_dir:
        output_path = Path(tmp_dir) / "arjun_result.json"
        cmd = [
            settings.arjun_path,
            "-u",
            target_url,
            "-oJ",
            str(output_path),
            "-q",
            "-t",
            str(threads),
            "-T",
            str(getattr(settings, "arjun_request_timeout", 15)),
            "-m",
            method,
            # Redirects can silently move probing off the declared target
            # host; keep every request on the exact URL under test.
            "--disable-redirects",
        ]
        if wordlist_path is not None:
            cmd.extend(["-w", wordlist_path])
        if chunk_size is not None:
            cmd.extend(["-c", str(chunk_size)])

        header_lines: list[str] = []
        from webpent.shared.http import sanitize_request_headers

        for header_name, header_value in sanitize_request_headers(extra_headers).items():
            if header_name.lower() != "user-agent":
                header_lines.append(f"{header_name}: {header_value}")

        if session_cookies:
            from webpent.shared.http import build_cookie_header

            cookie_header = build_cookie_header(session_cookies)
            if cookie_header:
                header_lines.append(f"Cookie: {cookie_header}")
                logger.info(
                    "arjun: injected %d session cookie(s) by name only",
                    len(session_cookies),
                )

        if header_lines:
            # arjun's --headers takes one value containing newline-separated
            # "Name: value" pairs, not repeated -H flags like ffuf/katana.
            cmd.extend(["--headers", "\n".join(header_lines)])

        timeout = getattr(settings, "arjun_timeout", 180)
        try:
            run_command(cmd, timeout=timeout)
        except ToolExecutionError as exc:
            if "timed out" in (exc.stderr or "").lower():
                logger.warning(
                    "arjun timed out after %ds for %s; checking for partial -oJ output",
                    timeout,
                    target_url,
                )
                # Fall through: arjun writes -oJ incrementally in some
                # versions, so a partial file may still exist even after
                # the subprocess was killed on timeout.
            else:
                logger.error("arjun failed (exit=%s)", exc.returncode)
                raise

        if not output_path.is_file():
            logger.info("arjun completed with zero discovered parameter(s) for %s", target_url)
            return []

        try:
            raw_text = output_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("arjun: could not read output file: %s", exc)
            return []

    params = _parse_arjun_output(raw_text, target_url)
    if params:
        logger.info("arjun discovered %d hidden parameter(s) for %s", len(params), target_url)
    return params


def _parse_arjun_output(raw_text: str, target_url: str) -> list[str]:
    """Parse arjun's ``-oJ`` JSON output and extract discovered parameter names.

    Arjun's JSON shape is ``{"<scanned_url>": {"headers": {...}, "method":
    str, "params": [str, ...]}}``. This wrapper always scans a single URL
    per call, but defensively reads whichever single entry is present
    rather than assuming the key matches ``target_url`` byte-for-byte
    (arjun may normalize trailing slashes or query strings in the key).
    """
    text = (raw_text or "").strip()
    if not text:
        return []
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("arjun: could not parse JSON output for %s", target_url)
        return []
    if not isinstance(decoded, dict) or not decoded:
        return []

    # Single-URL-per-call contract: take the first (only) entry's params.
    entry = next(iter(decoded.values()), None)
    if not isinstance(entry, dict):
        return []
    raw_params = entry.get("params")
    if not isinstance(raw_params, list):
        return []

    seen: set[str] = set()
    params: list[str] = []
    for item in raw_params:
        name = str(item).strip()
        if name and name not in seen:
            seen.add(name)
            params.append(name)
    return sorted(params)
