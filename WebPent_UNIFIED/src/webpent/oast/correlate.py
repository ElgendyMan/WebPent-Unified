"""Correlation glue between the OAST collector and the OOB engine
(PROPOSALS_ULTIMATE_V2 §1, 2026-10-29).

``webpent.shared.oob`` already owns the identity and matching contracts:
``OOBCollaborator.register_probe`` mints tokens, ``record_callback``
drops unregistered ones (fail-closed against evidence poisoning), and
``poll_callbacks`` enforces the deterministic evidence window. This
module adds only the network bridge:

  * :func:`sync_remote_callbacks` — one round of
    ``poll_remote_collector`` + ingestion into the collaborator.
    Every record's ``source_ip`` goes through the collaborator's own
    fingerprinting on the way in, so no raw address ever reaches the
    evidence store.
  * :func:`wait_for_callback` — a bounded poll loop (deadline + fixed
    interval, injected clock friendly) that returns the in-window
    callbacks as soon as one arrives.

Both are pure plumbing: any failure to poll is INCONCLUSIVE upstream
(the collector returns [] on error) and is never allowed to look like a
refutation — the validator layer owns that mapping.
"""

from __future__ import annotations

import time
from typing import Any

from webpent.shared.oob import OOBBinding, OOBCollaborator, poll_remote_collector

DEFAULT_POLL_INTERVAL_SECONDS = 0.3
_DEFAULT_POLL_TIMEOUT = 5.0


def sync_remote_callbacks(
    collaborator: OOBCollaborator,
    binding: OOBBinding,
    collector_url: str,
    *,
    timeout: float = _DEFAULT_POLL_TIMEOUT,
) -> list[dict[str, Any]]:
    """Poll the collector once and ingest its records into the collaborator.

    Returns the collaborator's in-window callbacks for ``binding``
    (deterministic token + window matching happens THERE, not here —
    this function never invents evidence).
    """
    records = poll_remote_collector(collector_url, token=binding.token, timeout=timeout)
    for record in records:
        if not isinstance(record, dict):
            continue
        seen_at = record.get("seen_at")
        try:
            seen_value = float(seen_at) if seen_at is not None else None
        except (TypeError, ValueError):
            seen_value = None
        collaborator.record_callback(
            binding.token,
            protocol=str(record.get("protocol") or "http"),
            source_ip=str(record.get("source_ip") or "") or None,
            seen_at=seen_value,
            details=str(record.get("details") or "") or None,
        )
    return [
        {
            "token": cb.token,
            "protocol": cb.protocol,
            "seen_at": cb.seen_at,
            "source_fingerprint": cb.source_fingerprint,
            "details": cb.details,
        }
        for cb in collaborator.poll_callbacks(binding)
    ]


def wait_for_callback(
    collaborator: OOBCollaborator,
    binding: OOBBinding,
    collector_url: str,
    *,
    timeout_seconds: float = _DEFAULT_POLL_TIMEOUT,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
    poll_timeout: float = _DEFAULT_POLL_TIMEOUT,
) -> list[dict[str, Any]]:
    """Bounded poll loop until at least one in-window callback arrives.

    Returns [] when the deadline passes with nothing in-window — the
    caller maps that to its own inconclusive/refuted contract (the
    production validators already do: infrastructure failure is never
    a halt and never a refutation).
    """
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    latest: list[dict[str, Any]] = []
    while True:
        latest = sync_remote_callbacks(
            collaborator, binding, collector_url, timeout=poll_timeout
        )
        if latest:
            return latest
        if time.monotonic() >= deadline:
            return latest
        time.sleep(max(0.05, float(poll_interval)))


__all__ = ["sync_remote_callbacks", "wait_for_callback"]
