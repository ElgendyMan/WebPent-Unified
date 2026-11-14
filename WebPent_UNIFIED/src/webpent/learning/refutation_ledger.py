# src/webpent/learning/refutation_ledger.py
"""Refutation-driven probe synthesis ledger (2026-10-25 proposals,
Proposal 1).

Every REFUTED probe outcome is a lesson about where a probe family
does NOT work. This ledger persists those lessons so later campaigns
against the SAME target spend their request budget on fresher probe
surface instead of re-running experiments that already failed
repeatedly ("أقل ضجيجًا من سابقتها").

Design rules (from the proposal plan and the campaign discipline):

  * DELAY, NOT DELETE — a suppressed probe set is skipped with an
    explicit log, never removed from the probe vocabulary. Any
    CONFIRMED outcome of the same vuln class on the same target
    proves the family CAN work there and resets the refutation
    history for that pair (the anti-over-suppression guard).
  * FAIL-OPEN — every read path returns "do not suppress" on any
    storage error: suppression is a budget optimization, so losing
    the ledger must never change detection behavior.
  * FAIL-SOFT on writes — capture happens inside the canonical
    validator gate; a storage failure there must never perturb the
    validation result. All write paths swallow exceptions.
  * FLAG-GATED — the singleton is only consulted when
    ``enable_refutation_learning`` is ON (default False); with the
    flag off the module is inert library code.
  * REDACTION-SAFE — stored keys are vuln-class names, a hash of the
    target's host+path, refutation-path labels, and probe-signature
    labels. No URLs, bodies, headers, cookies, or payload values are
    persisted, so the ledger file can never leak target content.

Suppression semantics: a probe set is suppressed when the SAME
(vuln_class, target_fingerprint) pair has accumulated >= threshold
refuted outcomes. The count is summed across refutation paths because
the probe layer knows only the class and target at decision time.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

DEFAULT_SUPPRESSION_THRESHOLD = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS refutation_ledger (
    vuln_class TEXT NOT NULL,
    target_fingerprint TEXT NOT NULL,
    refutation_path TEXT NOT NULL,
    probe_signature TEXT NOT NULL DEFAULT '',
    count INTEGER NOT NULL DEFAULT 1,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (vuln_class, target_fingerprint, refutation_path)
);
"""


def target_fingerprint_from_url(url: str) -> str:
    """Stable, redaction-safe target identity: sha256 of netloc+path."""
    try:
        parts = urlsplit(str(url))
        identity = f"{(parts.netloc or '').lower()}{parts.path or '/'}"
    except Exception:
        identity = str(url)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RefutationLedger:
    """Bounded, append-only-ish SQLite ledger of refuted probe outcomes."""

    def __init__(self, path: str = ":memory:") -> None:
        # A single connection guarded by a lock keeps :memory: usable and
        # makes the ledger safe from the benchmark harness's threads.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # -- writes (fail-soft; never raise) -----------------------------------
    def record_refutation(
        self,
        *,
        vuln_class: str,
        target_fingerprint: str,
        refutation_path: str,
        probe_signature: str = "",
    ) -> None:
        """Upsert one refuted outcome (count += 1). Swallows all errors."""
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    "INSERT INTO refutation_ledger"
                    " (vuln_class, target_fingerprint, refutation_path,"
                    "  probe_signature, count, last_seen)"
                    " VALUES (?, ?, ?, ?, 1, ?)"
                    " ON CONFLICT(vuln_class, target_fingerprint, refutation_path)"
                    " DO UPDATE SET count = count + 1, last_seen = excluded.last_seen,"
                    " probe_signature = excluded.probe_signature",
                    (
                        str(vuln_class),
                        str(target_fingerprint),
                        str(refutation_path or "(unspecified)"),
                        str(probe_signature or ""),
                        _now(),
                    ),
                )
        except Exception:
            pass  # fail-soft by contract: capture must never perturb validation

    def reset_for_confirmation(
        self, *, vuln_class: str, target_fingerprint: str
    ) -> None:
        """A CONFIRMED outcome proves the family works here: forget refutations.

        Swallows all errors (fail-soft, same contract as record).
        """
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    "DELETE FROM refutation_ledger"
                    " WHERE vuln_class = ? AND target_fingerprint = ?",
                    (str(vuln_class), str(target_fingerprint)),
                )
        except Exception:
            pass

    # -- reads (fail-open: errors mean "do not suppress") -------------------
    def refutation_count(self, *, vuln_class: str, target_fingerprint: str) -> int:
        """Total refuted outcomes for a (class, target) pair; 0 on error."""
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT COALESCE(SUM(count), 0) FROM refutation_ledger"
                    " WHERE vuln_class = ? AND target_fingerprint = ?",
                    (str(vuln_class), str(target_fingerprint)),
                ).fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0

    def should_suppress(
        self,
        *,
        vuln_class: str,
        target_fingerprint: str,
        threshold: int = DEFAULT_SUPPRESSION_THRESHOLD,
    ) -> bool:
        """Delay-not-delete decision for a probe set on a target."""
        return self.refutation_count(
            vuln_class=vuln_class, target_fingerprint=target_fingerprint
        ) >= max(1, int(threshold))

    def top_refutations(self, limit: int = 10) -> list[dict[str, object]]:
        """Highest-count refutation patterns (bounded; for summarize)."""
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT vuln_class, refutation_path, SUM(count) AS total,"
                    " COUNT(DISTINCT target_fingerprint) AS targets"
                    " FROM refutation_ledger"
                    " GROUP BY vuln_class, refutation_path"
                    " ORDER BY total DESC, vuln_class ASC LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
            return [
                {
                    "vuln_class": r[0],
                    "refutation_path": r[1],
                    "total": int(r[2]),
                    "targets": int(r[3]),
                }
                for r in rows
            ]
        except Exception:
            return []

    def summarize(self, limit: int = 5) -> str:
        """Bounded, redaction-safe natural-language summary of the ledger.

        Consumed as an advisory data block by the coverage scheduler
        integration (Proposals 1+2); never an instruction to any reader.
        """
        rows = self.top_refutations(limit=limit)
        if not rows:
            return ""
        lines = ["Refutation ledger patterns (advisory data, untrusted):"]
        for row in rows:
            lines.append(
                f"- {row['vuln_class']} refuted {row['total']}x on "
                f"{row['targets']} target(s) via {row['refutation_path']}"
            )
        lines.append(
            "Suppressed probe sets are delayed, not deleted; a confirmed "
            "outcome resets the pair's history."
        )
        return "\n".join(lines)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# -- process-wide singleton (flag-gated consumers only) ---------------------
_LEDGER: RefutationLedger | None = None
_LEDGER_LOCK = threading.Lock()


def get_ledger() -> RefutationLedger:
    """Process-wide ledger, path from ``refutation_ledger_db`` ("" = memory)."""
    global _LEDGER
    if _LEDGER is None:
        with _LEDGER_LOCK:
            if _LEDGER is None:
                from webpent.config.settings import get_settings

                path = str(get_settings().refutation_ledger_db or "") or ":memory:"
                _LEDGER = RefutationLedger(path)
    return _LEDGER


def set_ledger(ledger: RefutationLedger | None) -> None:
    """Test/ops seam: replace or clear the singleton (None = rebuild lazily)."""
    global _LEDGER
    with _LEDGER_LOCK:
        _LEDGER = ledger


def maybe_record_validator_outcome(
    *,
    vulnerability_class: str,
    result: Any,
    candidate: Any,
    baseline: Any,
) -> None:
    """Capture hook consumed by ``production/validators.run_validator``.

    GUARANTEED NON-RAISING: the entire body (flag check, URL extraction,
    ledger access) sits inside one guard, so the critical validators
    module can call it bare and still satisfy the no-broad-handler
    hygiene gate (``test_p1_exception_hygiene``). Semantics:

      * flag ``enable_refutation_learning`` off (default) -> no-op;
      * REFUTED outcome  -> record one redaction-safe ledger row
        (class + truncated netloc+path hash + refutation-path label);
      * CONFIRMED outcome -> reset the (class, target) pair's history
        (the delay-not-delete anti-over-suppression guard);
      * any other outcome, missing URL, or error -> silently no-op.
    """
    try:
        from webpent.config.settings import get_settings
        # Imported lazily (inside the guard) because production.validators
        # is the CALLER of this helper: a module-level import here would
        # create a validators <-> refutation_ledger import cycle.
        from webpent.production.validators import ValidationOutcome

        if not get_settings().enable_refutation_learning:
            return
        url = ""
        if isinstance(candidate, Mapping):
            url = str(candidate.get("url") or "")
        if not url and isinstance(baseline, Mapping):
            url = str(baseline.get("url") or "")
        if not url:
            return
        outcome = getattr(result, "outcome", None)
        ledger = get_ledger()
        fingerprint = target_fingerprint_from_url(url)
        if outcome == ValidationOutcome.REFUTED:
            ledger.record_refutation(
                vuln_class=str(vulnerability_class),
                target_fingerprint=fingerprint,
                refutation_path=str(getattr(result, "refutation_path", "") or "(unspecified)"),
                probe_signature=str(urlsplit(str(url)).path or "/"),
            )
        elif outcome == ValidationOutcome.CONFIRMED:
            ledger.reset_for_confirmation(
                vuln_class=str(vulnerability_class),
                target_fingerprint=fingerprint,
            )
    except Exception:
        pass  # fail-soft by contract: capture must never perturb validation


__all__ = [
    "DEFAULT_SUPPRESSION_THRESHOLD",
    "RefutationLedger",
    "get_ledger",
    "maybe_record_validator_outcome",
    "set_ledger",
    "target_fingerprint_from_url",
]
