# src/webpent/autonomous/authorization_recheck.py
"""Mid-hunt authorization recheck — the v80 Task 3 gate as a library API.

RETIRED-ALIAS REMOVAL WINDOW (v0.32.0, declared 2026-11-01 in the 0.30.0
CHANGELOG, item ج.2): the retired ``hunt-auto`` CLI command was the only
place this gate lived. Its closure moved here VERBATIM (same load →
verify → typed-reason semantics, same fail-closed posture) so the
security property survives the command's removal: an authorization file
may be replaced, narrowed, expired or deleted MID-HUNT, and a hunt that
wires this recheck stops with a typed ``authorization_revoked_mid_hunt``
reason before any further iteration executes.

Contract (identical to the removed CLI closure):

* the file is RE-READ on every call, never cached;
* any read/parse failure returns a reason string — a broken gate fails
  CLOSED (CR-5), it never waves the hunt through;
* a valid, in-scope, unexpired authorization returns ``None`` and the
  hunt continues;
* the returned callable is passed to
  :func:`webpent.autonomous.hunt_runtime.run_wired_hunt` as its
  ``auth_recheck`` argument, which stops the hunt BLOCKED when the
  callable returns a reason (that runtime behavior is pinned by
  ``tests/test_hunt_intel.py::test_auth_recheck_blocks_mid_hunt_before_further_execution``).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

__all__ = ["make_authorization_recheck"]


def make_authorization_recheck(
    authorization_path: Path | str, target_url: str
) -> Callable[[], str | None]:
    """Build the mid-hunt recheck callable for one engagement.

    The returned callable re-reads ``authorization_path`` and verifies it
    against ``target_url`` on every invocation:

    * ``None``  — the authorization still holds; the hunt may continue;
    * a string — a typed fail-closed reason (the hunt must stop BLOCKED).

    Any exception while reading or parsing the file is swallowed into a
    reason string ON PURPOSE: an unreadable authorization is not a valid
    one (CR-5: the gate fails closed even when the file vanishes).
    """

    def _recheck() -> str | None:
        from webpent.autonomous.authorization import (
            load_authorization,
            verify_authorization,
        )

        try:
            current = load_authorization(authorization_path)
        except Exception as exc:  # noqa: BLE001 - an auth gate fails closed
            return f"authorization file unreadable mid-hunt: {type(exc).__name__}: {exc}"
        ok, reason = verify_authorization(target_url, current)
        return None if ok else reason

    return _recheck
