# src/webpent/tools/recon/nmap.py
"""webpent.tools.recon.nmap

Bounded, double-gated infrastructure probe wrapper around the ``nmap``
CLI.

Context (Ultimate plan 2026-10-27, proposal 5 — reconnaissance depth,
phase 3): the framework's tooling covers HTTP(S) surfaces only; there
is no infrastructure-layer probe at all. This wrapper adds the most
minimal possible one, following the ``tools/recon/arjun.py`` pattern
(subprocess via ``run_command``, never raw subprocess; scope refusal
before spawning; settings flag; bounded output).

The wrapper executes one of exactly two command shapes::

    nmap -Pn -sT --top-ports <settings.nmap_top_ports> \\
        --max-retries 2 --host-timeout <timeout>s <host>

    nmap -Pn -sT -sV -p <ports> --max-retries 2 \\
        --host-timeout <timeout>s <host>   (only when ports are given)

Hard safety rules (deliberately structural — no code path can build
anything else):

  * NEVER ``-sS`` (raw-socket SYN scan): it requires root/CAP_NET_RAW,
    which would turn a recon tool into a privilege-escalation
    surface, and it is materially more intrusive on the target than a
    full-connect ``-sT`` scan.
  * NEVER ``--script`` (NSE): script scanning executes an entire
    exploit-adjacent script catalog against the target — far beyond a
    bounded, authorization-scoped port probe.
  * ``--max-retries 2`` and ``--host-timeout`` bound the probe's
    duration and retry pressure on the target.
  * The port budget when no explicit ports are requested comes from
    the ``nmap_top_ports`` setting (default 100, bounded 10..1000 by
    the settings model itself).

DOUBLE GATE (both must hold before any subprocess is spawned):

  1. the ``enable_infra_scan`` settings flag must be True, AND
  2. the caller must explicitly pass ``infra_scope_confirmed=True``
     after operator confirmation that infrastructure-level scanning of
     the target is authorized (e.g. the scope file carries an explicit
     infra-scan allowance for this host).

Additionally the host must be the engagement's own declared target
(``is_engagement_target_host``) — checked FIRST, before the gates, so
an out-of-scope host can never even reach the gate messages.

The ``nmap`` basename is not in ``tools/utils/subprocess.py``'s frozen
executable manifest; operators must deliberately register it via the
``WEBPENT_ALLOWED_EXECUTABLES`` environment variable (same governance
mechanism as the gau wrapper).

Registration note: ``@register_tool`` fires on IMPORT of this module.
``tools/registry.py``'s ``auto_discover()`` uses a hardcoded module
list that is hash-pinned by the frozen-modules gate, so adding nmap to
that list is deliberately left to a future unfreeze-window change;
until then the graph node wiring imports this module explicitly.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from webpent.config.settings import get_settings
from webpent.shared.engagement_scope import is_engagement_target_host
from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.registry import register_tool
from webpent.tools.utils.subprocess import run_command

logger = logging.getLogger(__name__)

# Bounds
_MIN_TIMEOUT = 30
_MAX_TIMEOUT = 1800
_MAX_PORTS_SPEC_CHARS = 128

# Strict port-spec grammar: comma-separated ports/ranges, digits only
# (nmap's own -p grammar minus protocols/scripts). Validated BEFORE
# spawning so a malformed spec is a loud caller bug, never a wasted
# (or surprising) subprocess invocation.
_PORTS_SPEC_RE = re.compile(r"^\d{1,5}(?:[,\-]\d{1,5})*$")

# nmap's canonical "open port" line: `22/tcp open ssh` (optionally
# with more columns after the service name — all ignored).
_OPEN_PORT_RE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)", re.IGNORECASE)

_MAX_PARSED_PORTS = 1000


@register_tool(
    name="nmap",
    category="recon",
    description=(
        "Bounded, double-gated infrastructure port probe with nmap "
        "(top-N TCP connect scan; never -sS, never NSE scripts)"
    ),
)
def run_nmap(
    target_host: str,
    *,
    ports: str | None = None,
    timeout: int = 300,
    infra_scope_confirmed: bool = False,
) -> dict:
    """Run a bounded nmap port probe against an in-scope host.

    Args:
        target_host: Bare host (``example.com`` / ``10.0.0.5``) or a
            URL (its host part is extracted). Must be the engagement's
            own declared target host.
        ports: Optional explicit port spec (``80,443`` or ``80-90``)
            for a service-detection scan (``-sV``). When omitted, the
            bounded ``--top-ports`` scan from ``settings.nmap_top_ports``
            runs instead.
        timeout: Wall-clock budget in seconds (30..1800); forwarded to
            both ``run_command`` and nmap's own ``--host-timeout``.
        infra_scope_confirmed: The explicit operator-confirmation
            gate — the caller must pass ``True`` AFTER confirming that
            infrastructure-level scanning of this host is authorized.
            Combined with the ``enable_infra_scan`` settings flag this
            forms the double gate; either alone refuses the probe.

    Returns:
        ``{"host": str, "open_ports": [{"port": int, "protocol": str,
        "service": str}, ...], "count": int}``. When the output could
        not be parsed, ``{"host": ..., "open_ports": [], "count": 0,
        "raw_available": True}`` — raw stdout remains available on the
        captured result for manual review (never an exception for a
        mere parse failure).

    Raises:
        ValueError: If ``ports`` is malformed or ``timeout`` is out of
            range (caller bugs).
        ToolExecutionError: If the host is out of engagement scope, or
            either half of the double gate (settings flag / explicit
            infra-scope confirmation) is not satisfied, or the nmap
            process itself fails.
        ToolNotFoundError: If the nmap binary is not on PATH (let
            propagate from run_command).
    """
    host = _extract_host(target_host)
    if not host:
        raise ValueError(
            f"nmap target_host must be a host or URL with a host part, "
            f"got {target_host!r}"
        )

    if not is_engagement_target_host(host):
        logger.warning(
            "nmap: refusing out-of-scope target host %s; no probe performed",
            host,
        )
        raise ToolExecutionError(
            cmd=["nmap", host],
            returncode=-1,
            stdout="",
            stderr="",
            message=(
                f"nmap: refusing out-of-scope target host {host!r} — the host "
                "is not in the engagement's declared target hosts; no "
                "infrastructure probe was performed"
            ),
        )

    settings = get_settings()
    if not settings.enable_infra_scan or not infra_scope_confirmed:
        raise ToolExecutionError(
            cmd=["nmap", host],
            returncode=-1,
            stdout="",
            stderr="",
            message=(
                "nmap infra scan is double-gated and refused: BOTH gates are "
                "required — (1) the enable_infra_scan settings flag is "
                f"currently {settings.enable_infra_scan}, and (2) the caller "
                "must explicitly pass infra_scope_confirmed=True after "
                f"operator confirmation (currently {infra_scope_confirmed})"
            ),
        )

    if timeout < _MIN_TIMEOUT or timeout > _MAX_TIMEOUT:
        raise ValueError(f"nmap timeout must be between {_MIN_TIMEOUT} and {_MAX_TIMEOUT}")

    port_spec: str | None = None
    if ports is not None:
        candidate = ports.strip()
        if not candidate or len(candidate) > _MAX_PORTS_SPEC_CHARS:
            raise ValueError(
                f"nmap ports must be a non-empty spec of at most "
                f"{_MAX_PORTS_SPEC_CHARS} chars, got {ports!r}"
            )
        if not _PORTS_SPEC_RE.match(candidate):
            raise ValueError(
                f"nmap ports must be comma-separated ports/ranges of digits "
                f"(e.g. '80,443' or '80-90'), got {ports!r}"
            )
        for token in re.split(r"[,\-]", candidate):
            if not (1 <= int(token) <= 65535):
                raise ValueError(
                    f"nmap ports spec contains port {token!r} out of range 1..65535"
                )
        port_spec = candidate

    cmd = _build_nmap_command(
        settings.nmap_path,
        host,
        top_ports=int(settings.nmap_top_ports),
        ports=port_spec,
        timeout=timeout,
    )
    stdout = run_command(cmd, timeout=timeout)
    return _parse_nmap_output(stdout, host=host)


def _extract_host(target_host: str) -> str:
    """Extract a bare, lowercased host from a host-or-URL input.

    Accepts ``example.com``, ``https://example.com/path`` and bare IPs;
    returns '' for inputs with no usable host part.
    """
    raw = str(target_host or "").strip()
    if not raw:
        return ""
    if "://" in raw or "/" in raw:
        try:
            extracted = urlparse(raw).hostname or ""
        except ValueError:
            return ""
        return extracted.lower()
    return raw.lower()


def _build_nmap_command(
    nmap_path: str,
    host: str,
    *,
    top_ports: int,
    ports: str | None,
    timeout: int,
) -> list[str]:
    """Assemble one of the two bounded nmap command shapes (pure, testable).

    Structurally CANNOT emit ``-sS`` or ``--script`` — see the module
    docstring's hard safety rules. ``-sT`` (full connect) is the only
    scan type this wrapper is ever allowed to build.
    """
    cmd = [nmap_path, "-Pn", "-sT"]
    if ports is not None:
        # Service detection only for an explicit, operator-chosen port
        # list (bounded surface); never combined with --top-ports.
        cmd.extend(["-sV", "-p", ports])
    else:
        cmd.extend(["--top-ports", str(top_ports)])
    cmd.extend(["--max-retries", "2", "--host-timeout", f"{timeout}s", host])
    return cmd


def _parse_nmap_output(stdout: object, *, host: str) -> dict:
    """Parse nmap stdout into a bounded open-port list.

    Pure function. Matches only canonical ``<port>/<proto> open
    <service>`` lines (closed/filtered lines are ignored by design).
    When nothing could be parsed, the result is empty with
    ``raw_available`` flagging that raw output exists for manual
    review — a parse failure is data, not an exception.
    """
    if isinstance(stdout, bytes):
        text = stdout.decode("utf-8", errors="replace")
    elif isinstance(stdout, str):
        text = stdout
    else:
        text = ""

    open_ports: list[dict[str, object]] = []
    for line in text.splitlines():
        match = _OPEN_PORT_RE.match(line)
        if match is None:
            continue
        open_ports.append(
            {
                "port": int(match.group(1)),
                "protocol": match.group(2).lower(),
                "service": match.group(3)[:64],
            }
        )
        if len(open_ports) >= _MAX_PARSED_PORTS:
            break

    if open_ports:
        return {"host": host, "open_ports": open_ports, "count": len(open_ports)}

    result: dict[str, object] = {"host": host, "open_ports": [], "count": 0}
    if text.strip():
        result["raw_available"] = True
        logger.info(
            "nmap: no parseable open-port lines for %s; raw output available",
            host,
        )
    return result


__all__ = ["run_nmap"]
