"""CEM Watchtower — the scope drift detector (v83, U-CEM-3).

Scope is sacred. This module watches the boundary of the authorized scope
and never crosses it: a subdomain that appears outside the authorized
suffixes is recorded as *observed but out-of-scope* and is excluded from
every touchable set the cycle builds. Two more drift alerts exist, both
from injected observations only:

* IP ownership change for a host inside scope (A-record moved to a
  network the engagement never approved) — HIGH alert.
* Certificate issuer change for the target — LOW alert, since it may be a
  routine provider migration or a hijack indicator.

Pure, bounded, redacted, fail-soft: garbage in, empty report out.
"""

from __future__ import annotations

import logging
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MAX_SCOPE_ENTRIES = 64
MAX_HOSTS_PER_CHECK = 64
MAX_DRIFTS = 64


def _normalize_scope(entries: Any) -> list[str]:
    if not isinstance(entries, (list, tuple, set)):
        return []
    normalized = []
    for entry in list(entries)[:MAX_SCOPE_ENTRIES]:
        if not isinstance(entry, str):
            continue
        cleaned = redact(entry.strip().strip(".").lower())[:200]
        if cleaned and "." in cleaned:
            normalized.append(cleaned)
    return normalized


def _host_in_scope(host: str, scope: list[str]) -> bool:
    """Suffix match: an entry authorizes itself and every subdomain."""
    if not host or not scope:
        return False
    host = host.lower().rstrip(".")
    return any(host == entry or host.endswith("." + entry) for entry in scope)


def evaluate(
    *,
    scope_entries: Any = None,
    observed_subdomains: Any = None,
    old_dns: Any = None,
    new_dns: Any = None,
    old_cert_issuer: Any = None,
    new_cert_issuer: Any = None,
) -> dict[str, Any]:
    """One drift evaluation over injected observations only.

    ``old_dns``/``new_dns`` map host -> IP string (injected by the
    operator's fetcher); nothing here resolves anything by itself.
    Returns a bounded alert report. Everything out of scope is marked
    ``observed_not_touchable`` and never enters an actionable list.
    """
    scope = _normalize_scope(scope_entries)
    drifts: list[dict[str, Any]] = []

    subs = []
    if isinstance(observed_subdomains, (list, tuple, set)):
        subs = [
            str(s).strip().lower()[:200]
            for s in list(observed_subdomains)[:MAX_HOSTS_PER_CHECK] if str(s or "").strip()
        ]

    out_of_scope = sorted({s for s in subs if not _host_in_scope(s, scope)})
    for host in out_of_scope[:MAX_DRIFTS]:
        drifts.append(
            {
                "kind": "scope_drift",
                "host": redact(host)[:200],
                "severity": "high",
                "touchable": False,
                "note": "observed but out-of-scope: never touched",
            }
        )

    old_map = old_dns if isinstance(old_dns, dict) else {}
    new_map = new_dns if isinstance(new_dns, dict) else {}
    for host in sorted(set(old_map) & set(new_map))[:MAX_HOSTS_PER_CHECK]:
        host_name = str(host).lower()[:200]
        if not _host_in_scope(host_name, scope):
            continue  # out-of-scope hosts are never tracked, only noted above
        old_ips = {str(v).strip()[:64] for v in _as_list(old_map[host])}
        new_ips = {str(v).strip()[:64] for v in _as_list(new_map[host])}
        if old_ips and new_ips and old_ips != new_ips:
            drifts.append(
                {
                    "kind": "ip_ownership_change",
                    "host": redact(host_name)[:200],
                    "severity": "high",
                    "touchable": False,
                    "note": "DNS moved: re-verify ownership before any interaction",
                    "from": sorted(old_ips)[:4],
                    "to": sorted(new_ips)[:4],
                }
            )

    old_issuer = redact(str(old_cert_issuer or ""))[:120]
    new_issuer = redact(str(new_cert_issuer or ""))[:120]
    if old_issuer and new_issuer and old_issuer != new_issuer:
        drifts.append(
            {
                "kind": "cert_issuer_change",
                "host": "",
                "severity": "low",
                "touchable": False,
                "note": "certificate issuer changed",
                "from": old_issuer,
                "to": new_issuer,
            }
        )

    drifts = drifts[:MAX_DRIFTS]
    return {
        "scope_entries": scope[:MAX_SCOPE_ENTRIES],
        "observed_count": len(subs),
        "in_scope_count": len(subs) - len(out_of_scope),
        "out_of_scope_count": len(out_of_scope),
        "drifts": drifts,
        "drift_count": len(drifts),
        "highest_severity": _highest(drifts),
        "advisory": True,
    }


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _highest(drifts: list[dict[str, Any]]) -> str:
    if any(d.get("severity") == "high" for d in drifts):
        return "high"
    if any(d.get("severity") == "low" for d in drifts):
        return "low"
    return "none"


def touchable_hosts(report: dict[str, Any]) -> list[str]:
    """The only hosts a downstream cycle may ever act on.

    Every out-of-scope observation is excluded here by construction; this
    function is the single boundary the rest of CEM consumes.
    """
    if not isinstance(report, dict):
        return []
    scope = _normalize_scope(report.get("scope_entries"))
    return scope[:MAX_SCOPE_ENTRIES]


__all__ = [
    "MAX_DRIFTS",
    "MAX_SCOPE_ENTRIES",
    "evaluate",
    "touchable_hosts",
    "_host_in_scope",
]
