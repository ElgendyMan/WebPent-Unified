"""UM-DR-44 B6(a) — CI grep gate: no NEW raw threading.Thread in src/.

The engagement context (contextvars) is NOT inherited by a bare
``threading.Thread`` — during an active campaign such a thread ran
under the legacy NONE posture (fail-open, fixed by the B6(a) change
and ``EngagementThread``).  This gate prevents NEW raw constructors
from appearing: any file that wants a thread that makes network or
scope decisions must use ``EngagementThread`` (or explicitly wrap the
target in ``contextvars.copy_context().run``).

The 21 pre-existing raw uses at window start are recorded in
PRE_EXISTING_RAW_THREADS below (window baseline) — they are existing
debt documented in the engineering report, NOT newly introduced.  The
gate fails only when a raw constructor appears OUTSIDE that baseline.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Window baseline (2026-11-22, d638af9 + UMDR-44 window commits): every
# src/ file containing a raw threading.Thread( constructor at the time
# this gate was introduced.  Shrinking this set is welcome; growing it
# fails the gate.
PRE_EXISTING_RAW_THREADS = frozenset(
    {
        "src/webpent/adapters/controlled_target/adapter.py",
        "src/webpent/agents/business_logic_fuzzer/agent.py",
        "src/webpent/api/app.py",
        "src/webpent/appsuite/berth.py",
        "src/webpent/appsuite/consign.py",
        "src/webpent/appsuite/corpus.py",
        "src/webpent/appsuite/docvault.py",
        "src/webpent/appsuite/ledgerflow.py",
        "src/webpent/appsuite/market.py",
        "src/webpent/appsuite/permit.py",
        "src/webpent/appsuite/requisitions.py",
        "src/webpent/appsuite/slots.py",
        "src/webpent/appsuite/ticketflow.py",
        "src/webpent/benchmark/fixtures/runner.py",
        "src/webpent/egaie/http_target.py",
        "src/webpent/labsuite/lab_target.py",
        "src/webpent/oast/server.py",
        "src/webpent/production/real_target_qualification_v1_1.py",
        "src/webpent/safety/kill_switch.py",
        "src/webpent/vip/notifications.py",
    }
)

_RAW_THREAD_RE = re.compile(r"threading\.Thread\(")


def test_no_new_raw_thread_constructors_in_src() -> None:
    offenders: list[str] = []
    for path in (REPO_ROOT / "src" / "webpent").rglob("*.py"):
        rel = str(path.relative_to(REPO_ROOT))
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # the EngagementThread implementation itself mentions the raw
        # constructor in its docstring/definition — exempt it.
        if rel == "src/webpent/shared/engagement_scope.py":
            continue
        if _RAW_THREAD_RE.search(text):
            # explicit context propagation next to the constructor is
            # the accepted alternative (business_logic_fuzzer pattern)
            if "contextvars.copy_context().run" in text:
                continue
            offenders.append(rel)
    new_offenders = sorted(set(offenders) - PRE_EXISTING_RAW_THREADS)
    assert not new_offenders, (
        "New raw threading.Thread( constructor(s) in src/ outside the "
        "UM-DR-44 baseline:\n  "
        + "\n  ".join(new_offenders)
        + "\nUse webpent.shared.engagement_scope.EngagementThread so the "
        "campaign context is propagated (threads do not inherit "
        "contextvars)."
    )


def test_engagement_thread_propagates_context() -> None:
    """The sanctioned wrapper actually carries the context (B6 proof)."""
    from webpent.shared.engagement_scope import EngagementThread

    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        is_engagement_origin_allowed,
        set_engagement_target_hosts,
    )

    holder: dict[str, object] = {}
    t = EngagementThread(
        target=lambda: holder.update(
            allowed=is_engagement_origin_allowed(
                "https://gate-check.example.com/"),
            foreign=is_engagement_origin_allowed(
                "https://foreign.example.com/"),
        )
    )
    token = set_engagement_target_hosts("https://gate-check.example.com/")
    try:
        t.start()
        t.join(timeout=5)
    finally:
        clear_engagement_target_hosts(token)
    assert not t.is_alive()
    # the child thread enforces the SAME engagement boundaries as the
    # campaign that spawned it (allowed for the target, denied outside)
    assert holder.get("allowed") is True
    assert holder.get("foreign") is False
