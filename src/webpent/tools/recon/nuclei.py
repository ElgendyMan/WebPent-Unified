# src/webpent/tools/recon/nuclei.py
"""webpent.tools.recon.nuclei

Wrapper around ProjectDiscovery's ``nuclei`` CLI for template-based
vulnerability scanning.

Nuclei emits results in JSON Lines format when invoked with ``-j`` (the
short form of ``-json``, required by Nuclei v3.10+). Each record
represents a single matched template (a finding). This module returns
the parsed records as a list of dicts; downstream agents convert them
to :class:`webpent.models.findings.Finding` instances.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from webpent.config.settings import get_settings
from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.registry import register_tool
from webpent.tools.utils.subprocess import run_command

logger = logging.getLogger(__name__)


def _private_tool_cache_dir() -> Path:
    """Return a user-private tool cache directory, creating it safely.

    Tool binaries must never be resolved from a predictable shared ``/tmp``
    directory.  An operator may provide ``WEBPENT_TOOL_CACHE_DIR``; otherwise
    a per-UID directory below the platform temp directory is used.  The
    directory is created with mode 0700 and an existing directory must not be
    group/world writable.
    """
    configured = os.environ.get("WEBPENT_TOOL_CACHE_DIR", "").strip()
    if configured:
        cache_dir = Path(configured).expanduser()
    else:
        # Per-user isolation. os.getuid() is POSIX-only; on platforms without
        # it (Windows) fall back to the user's own temp root, which the OS
        # already isolates per-account.
        if hasattr(os, "getuid"):
            user_part = str(os.getuid())
        else:
            user_part = "win"
        cache_dir = Path(tempfile.gettempdir()) / f"webpent-tools-{user_part}"
    cache_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        cache_dir.chmod(0o700)
        mode = cache_dir.stat().st_mode
    except OSError as exc:
        raise RuntimeError("nuclei: private tool cache is unavailable") from exc
    # Windows (NTFS) does not model the POSIX group/other permission bits;
    # the mode check is meaningful only on platforms that report them.
    if hasattr(os, "getuid") and mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RuntimeError("nuclei: private tool cache permissions are unsafe")
    if hasattr(os, "getuid") and cache_dir.stat().st_uid != os.getuid():
        raise RuntimeError("nuclei: private tool cache ownership is unsafe")
    return cache_dir


def _template_dir_from_environment() -> Path | None:
    configured = os.environ.get("WEBPENT_NUCLEI_TEMPLATE_DIR", "").strip()
    return Path(configured).expanduser() if configured else None


def _is_local_target(target_url: str) -> bool:
    """Return whether a target is loopback/private/link-local/reserved.

    Local engagements need a stricter nuclei template policy because the
    installed upstream set also contains OSINT and verification templates that
    intentionally call third-party endpoints. This predicate is deliberately
    based on the target URL, not on lab-specific routes or names.
    """
    from urllib.parse import urlparse

    hostname = (urlparse(target_url).hostname or "").strip().lower().rstrip(".")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname.endswith(".local")
    return bool(
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
    )


def _append_local_template_exclusions(cmd: list[str], template_dir: Path | None) -> None:
    """Prevent external-provider templates during private/local scans.

    ``-ni`` prevents Interactsh, but it does not prevent ordinary HTTP
    templates from contacting RDAP, OSINT, or vendor APIs. Keep the full
    target-relative security set while excluding only the known external
    categories/files. The paths are appended as nuclei ``-et`` values and are
    harmless when a configured template directory does not contain them.
    """
    cmd.extend(["-etags", "osint"])
    if template_dir is None:
        return
    for relative_path in (
        "http/osint",
        "http/exposures/tokens/google/google-gemini-key-exposure.yaml",
        "http/miscellaneous/rdap-whois.yaml",
        "http/misconfiguration/intercom-identity-misconfiguration.yaml",
    ):
        candidate = template_dir / relative_path
        if candidate.exists():
            cmd.extend(["-et", str(candidate)])


def _verify_default_template_set(template_dir: Path) -> None:
    manifest_path = template_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolExecutionError(
            ["nuclei", "template-manifest-check"],
            78,
            message="Nuclei default template manifest is missing or invalid; scan refused",
        ) from exc
    digest = manifest.get("digest") if isinstance(manifest, dict) else None
    file_count = manifest.get("file_count") if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "nuclei-template-manifest-v1"
        or not isinstance(manifest.get("version"), str)
        or not manifest["version"].strip()
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest.lower())
        or not isinstance(file_count, int)
        or file_count < 1
    ):
        raise ToolExecutionError(
            ["nuclei", "template-manifest-check"],
            78,
            message="Nuclei default template manifest failed validation; scan refused",
        )


def _resolve_nuclei_binary(configured_path: str) -> str:
    """Resolve the configured nuclei binary without weakening tool safety.

    A bare ``nuclei`` name remains the default. If it is absent from PATH,
    use only the user-private tool cache or a trusted system path. Custom
    configured paths are returned unchanged so their existing error behavior
    is preserved and can be handled by the caller.
    """
    configured = (configured_path or "nuclei").strip() or "nuclei"
    if os.path.isabs(configured) or os.sep in configured:
        return configured
    if shutil.which(configured):
        return configured
    if configured == "nuclei":
        private_candidate = _private_tool_cache_dir() / "nuclei"
        for candidate in (private_candidate, Path("/usr/local/bin/nuclei")):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                logger.info("nuclei: resolved binary from trusted cache/path: %s", candidate)
                return str(candidate)
    return configured


@register_tool(name="nuclei", category="recon", description="Template-based vulnerability scanner")
def run_nuclei(
    target_url: str,
    templates: list[str] | None = None,
    stealth_mode: bool = False,
    session_cookies: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Scan ``target_url`` with nuclei and return parsed JSON results.

    Args:
        target_url: Absolute URL of the target to scan.
        templates: Optional list of template identifiers or paths. Each
            entry is appended as ``-t <template>``. When ``None``,
            nuclei uses its default template set (all installed
            templates).
        stealth_mode: V5 Sprint 6 — when True, insert randomized jitter
            and enforce minimum inter-request spacing before launching
            nuclei. Helps evade WAF/IDS rate-based detection.

    Returns:
        A list of dictionaries, one per valid JSONL record emitted by
        nuclei. Lines that fail JSON parsing are silently skipped.

    Raises:
        ToolNotFoundError: If ``nuclei`` is not installed.
        ToolExecutionError: If nuclei exits non-zero or times out.
    """
    # V10 P1-8 FIX: scope pre-flight. nuclei does NOT enforce the
    # engagement scope itself — it will happily scan any URL passed via
    # ``-u``, including out-of-scope hosts (e.g. a third-party CDN URL
    # that crawled into a finding). The SSRF transport guards direct
    # httpx requests, but nuclei spawns its own subprocess and bypasses
    # the Python transport entirely. We must enforce scope HERE, before
    # building the command, otherwise an out-of-scope target_url leads
    # to nuclei sending real exploit-y HTTP probes at a host the
    # operator never authorised — a program-rules violation.
    from urllib.parse import urlparse

    from webpent.shared.engagement_scope import is_engagement_target_host

    target_host = urlparse(target_url).hostname
    if not target_host or not is_engagement_target_host(target_host):
        logger.warning(
            "nuclei: REFUSING to scan %s — host %r is NOT in the "
            "engagement scope. Returning empty result list (no scan "
            "performed). This prevents nuclei from probing out-of-scope "
            "hosts that may have crawled into a finding URL.",
            target_url, target_host,
        )
        return []

    # V5 Sprint 6: pre-tool stealth delay. Apply jitter + rate-limit
    # before spawning the subprocess so the target sees a human-paced
    # request burst rather than an immediate machine-paced one.
    if stealth_mode:
        from webpent.shared.stealth import (
            apply_jitter,
            enforce_min_interval,
            extract_host,
        )
        apply_jitter(stealth_mode, label="nuclei")
        enforce_min_interval(stealth_mode, extract_host(target_url))

    settings = get_settings()
    local_target = _is_local_target(target_url)

    cmd = [
        _resolve_nuclei_binary(settings.nuclei_path),
        "-u",
        target_url,
        "-silent",
        "-j",  # Nuclei v3.10+ short form of -json; emits JSON Lines output
        # Keep the full template set, but make the resource envelope explicit
        # and operator-tunable. These are performance controls only; they do
        # not promote a match to a finding or bypass validation/evidence gates.
        "-timeout",
        str(settings.nuclei_request_timeout),
        "-retries",
        str(settings.nuclei_retries),
        "-c",
        str(settings.nuclei_concurrency),
    ]
    if local_target:
        # Local bounded scans must not update, authenticate to, or contact
        # external providers. Redirects and non-HTTP protocols are also
        # disabled because they can leave the declared local target origin.
        cmd.extend(["-duc", "-ni", "-auth=false", "-dr", "-pt", "http"])
    if settings.nuclei_rate_limit > 0:
        cmd.extend(["-rl", str(settings.nuclei_rate_limit)])

    template_dir = _template_dir_from_environment()
    if templates:
        for template in templates:
            template = template.strip()
            if template:
                cmd.extend(["-t", template])
    else:
        if template_dir is not None:
            _verify_default_template_set(template_dir)
            cmd.extend(["-t", str(template_dir)])

    if local_target:
        _append_local_template_exclusions(cmd, template_dir)

    # Keep nuclei aligned with the Python HTTP clients and the target's
    # explicit lab allowlist. Without this header, WAPTLab's bot gate
    # returns 403 before templates can exercise the application.
    user_agent = (settings.http_user_agent or "").replace("\r", " ").replace("\n", " ").strip()
    if user_agent:
        cmd.extend(["-H", f"User-Agent: {user_agent}"])

    # Generic operator headers are bounded and sanitized before subprocess use.
    from webpent.shared.http import sanitize_request_headers
    for header_name, header_value in sanitize_request_headers(extra_headers).items():
        if header_name.lower() != "user-agent":
            cmd.extend(["-H", f"{header_name}: {header_value}"])

    # V7 Phase 4.4: Inject session cookies.
    if session_cookies:
        from webpent.shared.http import build_cookie_header
        cookie_str = build_cookie_header(session_cookies)
        if cookie_str:
            cmd.extend(["-H", f"Cookie: {cookie_str}"])
            logger.info(
                "nuclei: injected %d session cookie(s) (names: %s)",
                len(session_cookies), sorted(session_cookies.keys()),
            )
        else:
            logger.warning(
                "nuclei: session_cookies provided but all values empty "
                "after CRLF sanitization — scanning UNAUTHENTICATED.",
            )

    # V4.5: Handle timeout with partial result processing.
    # V10 P1-2: timeout is env-configurable via NUCLEI_TIMEOUT
    # (settings.nuclei_timeout, default 600). Use the same settings object
    # that supplied the command flags so tests and runtime cannot diverge.
    _nuclei_timeout = settings.nuclei_timeout
    try:
        raw_output = run_command(cmd, timeout=_nuclei_timeout)
    except ToolExecutionError as exc:
        # If this was a timeout, attempt to process partial stdout.
        if "timed out" in (exc.stderr or "").lower() and exc.stdout:
            logger.warning(
                "nuclei timed out after %ds — processing %d bytes of partial output",
                _nuclei_timeout, len(exc.stdout),
            )
            raw_output = exc.stdout
        else:
            logger.error(
                "nuclei FAILED for %s (exit=%d, error_reason=%s)",
                target_url, exc.returncode, (exc.stderr or "")[:200],
            )
            raise

    results: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # Nuclei occasionally interleaves non-JSON progress/banner
            # lines with -json output. Skipping keeps the pipeline
            # resilient without masking genuine failures (which surface
            # via the exit code in run_command).
            continue
        if isinstance(record, dict):
            results.append(record)

    # V7 Phase 6 / V10 P0-3: quarantine actual tool failures. A successful
    # Nuclei process with zero JSONL records is a valid no-match result; it
    # must not be mislabeled as infrastructure failure. Non-zero exits are
    # raised by run_command above, while panic/fatal markers are quarantined
    # here so malformed tool output can never become vulnerability evidence.
    raw_output_lower = (raw_output or "").lower()
    if not raw_output.strip():
        logger.info(
            "nuclei completed successfully with no JSONL matches for %s; "
            "returning an explicit empty result",
            target_url,
        )
        return []

    if "panic:" in raw_output_lower or "fatal" in raw_output_lower:
        logger.error(
            "TOOL_INFRA_FAILURE: nuclei crashed for %s (panic/fatal in "
            "output). Returning 0 records; no Findings will be "
            "constructed from this invocation.",
            target_url,
        )
        return []

    # V10 P1-4: observability — log raw_count, parsed_count, promoted_to_findings
    # so the operator can see the funnel from raw JSONL lines to valid records.
    # Actual process failures are raised by run_command above.
    raw_line_count = len([line for line in raw_output.splitlines() if line.strip()])
    logger.info(
        "nuclei observability: raw_lines=%d, parsed_records=%d, "
        "promoted_to_findings=pending (recon_node converts), "
        "infra_failure=False",
        raw_line_count,
        len(results),
    )

    return results
