#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-33 Phase 2 security
window (2026-11-10) per the DR-009 / refreeze protocol.

Documented scope of this refreeze — exactly TWO frozen files:

  1. src/webpent/graph/budget_governor.py — the external hard-budget
     fail-closed fix (Workstream C §5.3): a ``node_step_trace`` key that
     is PRESENT but not a list/tuple is agent-side corruption (the
     channel is declared append-only in state.py and the builder
     materialises ``update["node_step_trace"] = [entry]`` whenever the
     previous value is not a list — no legit write path persists a
     non-list). Corruption now fails CLOSED with the budget fully
     consumed (``reason="fail_closed_corrupted_trace"``) instead of
     deactivating the governor; a genuinely ABSENT key keeps the
     documented legacy-checkpoint deactivation (``inactive_no_trace``,
     pinned by tests/test_rb_budget_governor.py unchanged).

  2. src/webpent/cli/loaders.py — the placeholder-credential rejection
     (Workstream C §5.5): secret-bearing mappings (credentials,
     username/password/email/token, cookies, session_cookies, auth
     headers) reject template placeholders (CHANGE-ME family,
     REPLACE_ME_*, replace-at-runtime, obvious exact markers)
     fail-closed at load time. Form-field-NAME mappings (login_fields,
     registration_fields) are shape-validated only — "password" as a
     field NAME is legitimate. A copied credentials_template.json that
     was never filled in now fails with a precise error naming the
     profile and field instead of silently looking production-ready.

Regression coverage verified BEFORE this re-pin:
  tests/test_umdr33_hard_budget_and_creds.py
    - TestCorruptedTraceFailsClosed (6 tests: string/int/None corruption
      consumes the entire budget; absent key keeps legacy deactivation;
      healthy trace unchanged; valid shapes unaffected)
    - TestPlaceholderCredentialRejection (5 tests: REPLACE_ME family
      rejection incl. the shipped template; real credentials still
      load; nested credentials covered)
  tests/test_rb_budget_governor.py — all pre-existing pins unchanged
  tests/team1_acceptance/test_template_contracts.py — the template
    contract evolved WITH the loader: shape assertions now parse the
    template directly AND the loader rejection is pinned as the
    stronger round-trip proof (UM-DR-33 §5.5 contract evolution,
    documented in the test docstring)
  tests/test_regression_campaign_pipeline.py — unaffected, green

Old pins (recorded for the audit trail):
  graph/budget_governor.py  30715cc8258cd4cf74eaa26c25c869bb85cda0bcdf3a9f6455ec8847070b2012
  cli/loaders.py            18b3d0bfa108983a4f5d504f8215bed0a6f6a7918f6cb6422753cdf9066e61b1

No other frozen file changed. The pre-unfreeze baseline is untouched.
Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr33_phase2_security.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR33_P2_REPINNED_FILES = (
    "src/webpent/graph/budget_governor.py",
    "src/webpent/cli/loaders.py",
)

OLD_PINS = {
    "src/webpent/graph/budget_governor.py":
        "30715cc8258cd4cf74eaa26c25c869bb85cda0bcdf3a9f6455ec8847070b2012",
    "src/webpent/cli/loaders.py":
        "18b3d0bfa108983a4f5d504f8215bed0a6f6a7918f6cb6422753cdf9066e61b1",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = [
        line.strip()
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    entries: list[tuple[str, str]] = []
    repinned = 0
    listed = set()
    for line in lines:
        digest, _, relpath = line.partition("  ")
        if relpath in UMDR33_P2_REPINNED_FILES:
            new_digest = sha256(REPO / relpath)
            if OLD_PINS[relpath] == new_digest:
                print(f"ERROR: {relpath} unchanged on disk — nothing to re-pin")
                return 1
            entries.append((new_digest, relpath))
            repinned += 1
            print(f"re-pinned {relpath}\n  old {OLD_PINS[relpath]}\n  new {new_digest}")
        else:
            entries.append((digest, relpath))
        listed.add(relpath)

    missing = set(UMDR33_P2_REPINNED_FILES) - listed
    if missing:
        print(f"ERROR: declared re-pin files absent from manifest: {sorted(missing)}")
        return 1
    if repinned != len(UMDR33_P2_REPINNED_FILES):
        print(f"ERROR: expected {len(UMDR33_P2_REPINNED_FILES)} re-pins, did {repinned}")
        return 1

    for digest, relpath in entries:
        if sha256(REPO / relpath) != digest:
            print(f"ERROR: self-verification failed for {relpath}")
            return 1

    MANIFEST.write_text(
        "\n".join(f"{digest}  {relpath}" for digest, relpath in entries) + "\n",
        encoding="utf-8",
    )
    print(f"manifest written: {len(entries)} entries ({repinned} re-pinned this window)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
