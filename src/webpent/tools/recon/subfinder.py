# src/webpent/tools/recon/subfinder.py
"""webpent.tools.recon.subfinder

Wrapper around ProjectDiscovery's ``subfinder`` CLI for passive
subdomain enumeration.

V4.5: Custom timeout (300s) with partial-output recovery on timeout.
"""

from __future__ import annotations

import logging

from webpent.config.settings import get_settings
from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.registry import register_tool
from webpent.tools.utils.subprocess import run_command

logger = logging.getLogger(__name__)


@register_tool(name="subfinder", category="recon", description="Passive subdomain enumeration")
def run_subfinder(domain: str, stealth_mode: bool = False) -> list[str]:
    """Enumerate subdomains for ``domain`` using subfinder.

    Args:
        domain: Root domain to enumerate, e.g. ``"example.com"``.
        stealth_mode: V5 Sprint 6/8 — when True, insert randomized
            jitter and enforce minimum inter-request spacing before
            launching subfinder. Recon tools generate the highest
            traffic volume, so stealth is most impactful here.

    Returns:
        A de-duplicated list of discovered subdomains. Empty list on
        failure or timeout with no partial output.

    Raises:
        ToolNotFoundError: If ``subfinder`` is not installed.
        ToolExecutionError: If subfinder exits non-zero (non-timeout).
    """
    # V5 Sprint 8: pre-tool stealth delay. subfinder hits many passive
    # sources in a burst — pacing matters for WAF/IDS evasion.
    if stealth_mode:
        from webpent.shared.stealth import (
            apply_jitter,
            enforce_min_interval,
        )
        apply_jitter(stealth_mode, label="subfinder")
        # subfinder's target is a bare domain (no scheme), so we
        # synthesize a URL for extract_host. If the domain is already
        # URL-like, extract_host will handle it.
        enforce_min_interval(stealth_mode, domain)

    settings = get_settings()
    cmd = [
        settings.subfinder_path,
        "-d",
        domain,
        "-silent",
    ]

    # V4.5: Custom timeout + partial-output recovery.
    try:
        raw_output = run_command(cmd, timeout=300)
    except ToolExecutionError as exc:
        if "timed out" in (exc.stderr or "").lower() and exc.stdout:
            logger.warning(
                "subfinder timed out after 300s — processing partial output (%d bytes)",
                len(exc.stdout),
            )
            raw_output = exc.stdout
        else:
            logger.error(
                "subfinder FAILED for %s (exit=%d, error_reason=%s)",
                domain, exc.returncode, (exc.stderr or "")[:200],
            )
            raise

    subdomains: list[str] = []
    seen: set[str] = set()
    for line in raw_output.splitlines():
        candidate = line.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        subdomains.append(candidate)

    # V7 Phase 6: Classify tool failure mode.
    if not raw_output.strip():
        logger.warning("TOOL_INFRA_FAILURE: subfinder produced no output.")

    return subdomains
