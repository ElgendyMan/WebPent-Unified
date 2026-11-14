"""Safe wrapper around ffuf for in-scope content and directory discovery."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from webpent.config.settings import get_settings
from webpent.shared.engagement_scope import is_engagement_target_host
from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.registry import register_tool
from webpent.tools.utils.subprocess import run_command

logger = logging.getLogger(__name__)


@register_tool(
    name="ffuf",
    category="recon",
    description="In-scope content and directory discovery with ffuf",
)
def run_ffuf(
    target_url: str,
    wordlist_path: str,
    *,
    extensions: list[str] | None = None,
    threads: int = 10,
    stealth_mode: bool = False,
    session_cookies: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Discover paths below ``target_url`` and return redacted result records.

    The wrapper deliberately requires an explicit wordlist. It never follows
    redirects and only returns records whose URL host remains in the
    engagement scope. The feature is therefore safe to expose behind a
    disabled-by-default settings flag without inventing a wordlist or target.
    """
    parsed = urlparse(target_url)
    target_host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not target_host:
        logger.warning("ffuf: refusing malformed target URL")
        return []
    if not is_engagement_target_host(target_host):
        logger.warning(
            "ffuf: refusing out-of-scope target host %s; no scan performed",
            target_host,
        )
        return []

    wordlist = Path(wordlist_path).expanduser()
    if not wordlist.is_file():
        logger.warning("ffuf: wordlist is unavailable; no scan performed")
        return []

    if threads < 1 or threads > 50:
        raise ValueError("ffuf threads must be between 1 and 50")

    if stealth_mode:
        from webpent.shared.stealth import apply_jitter, enforce_min_interval, extract_host

        apply_jitter(True, label="ffuf")
        enforce_min_interval(True, extract_host(target_url))

    settings = get_settings()
    base = target_url.rstrip("/")
    fuzz_url = base if "FUZZ" in base else f"{base}/FUZZ"
    cmd = [
        settings.ffuf_path,
        "-u",
        fuzz_url,
        "-w",
        str(wordlist),
        "-of",
        "json",
        "-o",
        "-",
        "-s",
        "-t",
        str(threads),
        "-ac",
    ]
    if extensions:
        cleaned_extensions = [e.strip().lstrip(".") for e in extensions if e and e.strip()]
        if cleaned_extensions:
            cmd.extend(["-e", ",".join(cleaned_extensions)])

    from webpent.shared.http import sanitize_request_headers
    for header_name, header_value in sanitize_request_headers(extra_headers).items():
        if header_name.lower() != "user-agent":
            cmd.extend(["-H", f"{header_name}: {header_value}"])

    if session_cookies:
        from webpent.shared.http import build_cookie_header

        cookie_header = build_cookie_header(session_cookies)
        if cookie_header:
            cmd.extend(["-H", f"Cookie: {cookie_header}"])
            logger.info(
                "ffuf: injected %d session cookie(s) by name only",
                len(session_cookies),
            )

    timeout = getattr(settings, "ffuf_timeout", 300)
    try:
        raw_output = run_command(cmd, timeout=timeout)
    except ToolExecutionError as exc:
        if "timed out" in (exc.stderr or "").lower() and exc.stdout:
            logger.warning(
                "ffuf timed out after %ds; processing partial output (%d bytes)",
                timeout,
                len(exc.stdout),
            )
            raw_output = exc.stdout
        else:
            logger.error("ffuf failed (exit=%s)", exc.returncode)
            raise

    records = _parse_ffuf_output(raw_output)
    filtered: list[dict[str, Any]] = []
    dropped = 0
    for record in records:
        result_url = record.get("url")
        if not isinstance(result_url, str) or not result_url:
            continue
        result_host = (urlparse(result_url).hostname or "").lower()
        if not result_host or not is_engagement_target_host(result_host):
            dropped += 1
            continue
        # Keep only stable, non-body fields. ffuf JSON normally contains no
        # body, but this projection prevents accidental response-data storage.
        filtered.append(
            {
                "url": result_url,
                "status": record.get("status"),
                "length": record.get("length"),
                "words": record.get("words"),
                "lines": record.get("lines"),
                "redirectlocation": record.get("redirectlocation"),
                "input": record.get("input"),
            }
        )

    if dropped:
        logger.info("ffuf scope gate dropped %d off-scope result(s)", dropped)
    if not raw_output.strip():
        logger.warning("TOOL_INFRA_FAILURE: ffuf produced no output")
    elif not filtered:
        logger.info("ffuf completed with zero in-scope discoveries")
    else:
        logger.info("ffuf discovered %d in-scope path(s)", len(filtered))
    return filtered


def _parse_ffuf_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse ffuf JSON output and tolerate JSONL from older builds."""
    text = (raw_output or "").strip()
    if not text:
        return []
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        decoded = None
    if isinstance(decoded, dict):
        results = decoded.get("results")
        if isinstance(results, list):
            return [r for r in results if isinstance(r, dict)]
        return []
    if isinstance(decoded, list):
        return [r for r in decoded if isinstance(r, dict)]

    parsed: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            parsed.append(record)
    return parsed
