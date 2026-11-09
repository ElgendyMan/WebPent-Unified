#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the M1-A SECURITY & CONFIG RECOVERY
window (2026-11-05) per the DR-009 protocol. DRIFT_REGISTER entry: UM-DR-11.

This window covers BOTH halves of M1-A (the H-1/H-2 fixes landed in the
prior session's commit, plus M-2/M-3/M-4/L-1/L-3/L-5 landed in this
session).  Every frozen-tree change is verified by regression tests
BEFORE refreeze:

  Prior-session (H-1/H-2, tests test_m1a_tunnel_exposure.py +
  test_m1a_placeholder_rejection.py):

      - src/webpent/api/app.py
        (H-1: forwarded-header trust only when auth off; decision-log
        L-5 redaction choke-point documentation; 401 surface)

      - src/webpent/api/auth.py
        (H-2: _ensure_seeded refuses placeholder WEBPENT_USERS entries
        when auth is on)

      - src/webpent/config/settings.py
        (H-2: _looks_like_placeholder rejection across JWT/AUDIT/CELERY
        secrets; M-3: global_rate_governor_* tuning fields)

  This session (M-2/M-3/M-4/L-1/L-3/L-5):

      - src/webpent/config/settings.py  (see above — M-3 fields)

      - src/webpent/tools/recon/katana.py
        (M-2: explicit -fs fqdn crawl scope pinning)

      - src/webpent/shared/http.py
        (M-3: SSRFPinningTransport.handle_request enforces the
        GlobalRateGovernor ceiling when rate_limit_enabled; new
        RateLimitExceeded(httpx.RequestError); fail-open+CRITICAL on
        governor internal errors)

      - src/webpent/shared/legacy_containment.py
        (M-4: delegation to make_safe_httpx_client; raw-httpx fallback
        REMOVED — fail-closed on authoritative-module ImportError)

      - src/webpent/recon/browser_farm.py
        (L-1: install_playwright_ssrf_guard on every new_context)

      - src/webpent/reporter/poc_recorder.py
        (L-1: install_playwright_ssrf_guard on the POC browser context)

      - src/webpent/cli/unified_hunt.py
        (L-3: _invoke_with_progress sets engagement target hosts around
        the graph stream, cleared in finally — restores external recon
        on the CLI path)

      - src/webpent/memory/decision_log.py
        (L-5: redact_sensitive enforced on metadata at the append
        choke point)

  * NO manifest-path removals;
  * NO scope completions (new test files are outside the frozen gate by
    construction);
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_m1a_recovery.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

# Run AFTER the edits — hashes re-read from the current tree.
WINDOW_CHANGED_FILES = [
    # prior-session M1-A (H-1/H-2)
    "src/webpent/api/app.py",
    "src/webpent/api/auth.py",
    # this session M1-A
    "src/webpent/config/settings.py",
    "src/webpent/tools/recon/katana.py",
    "src/webpent/shared/http.py",
    "src/webpent/shared/legacy_containment.py",
    "src/webpent/recon/browser_farm.py",
    "src/webpent/reporter/poc_recorder.py",
    "src/webpent/cli/unified_hunt.py",
    "src/webpent/memory/decision_log.py",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            print(f"ABORT: unparsable manifest line: {line!r}", file=sys.stderr)
            return 1
        digest, relpath = parts[0], parts[1].strip()
        entries.append((digest, relpath))
        seen.add(relpath)

    for relpath in WINDOW_REMOVED_FILES:
        if relpath not in seen:
            print(f"ABORT: declared removed file is not pinned: {relpath}", file=sys.stderr)
            return 1
        if (REPO / relpath).exists():
            print(f"ABORT: declared removed file still exists in the tree: {relpath}", file=sys.stderr)
            return 1
        entries = [(d, p) for d, p in entries if p != relpath]
        seen.discard(relpath)
        print(f"  {relpath} (removed)")

    for relpath in WINDOW_CHANGED_FILES:
        if relpath not in seen:
            print(f"ABORT: declared changed file is not pinned: {relpath}", file=sys.stderr)
            return 1

    for relpath in WINDOW_SCOPE_COMPLETION:
        if relpath in seen:
            continue
        if not (REPO / relpath).is_file():
            print(f"ABORT: scope-completion file missing from tree: {relpath}", file=sys.stderr)
            return 1
        entries.append(("NEW", relpath))
        seen.add(relpath)

    out_lines: list[str] = []
    changed_count = 0
    for digest, relpath in entries:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"ABORT: pinned path missing from tree: {relpath}", file=sys.stderr)
            return 1
        current = sha256(absolute)
        if current != digest:
            if relpath not in WINDOW_CHANGED_FILES:
                print(
                    f"ABORT: UNDECLARED drift on pinned file {relpath} "
                    "(this window's protocol covers only the files listed "
                    "in WINDOW_CHANGED_FILES)",
                    file=sys.stderr,
                )
                return 1
            changed_count += 1
            out_lines.append(f"{current}  {relpath}")
            print(f"  re-pinned {relpath}")
        else:
            out_lines.append(f"{digest}  {relpath}")

    unexpected = changed_count != len(WINDOW_CHANGED_FILES)
    if unexpected:
        print(
            f"ABORT: expected to re-pin exactly {len(WINDOW_CHANGED_FILES)} "
            f"file(s), re-pinned {changed_count}",
            file=sys.stderr,
        )
        return 1

    MANIFEST.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    total = len(out_lines)

    # Self-check: re-read and re-verify every entry after write.
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, relpath = line.split(None, 1)
        if sha256(REPO / relpath.strip()) != digest:
            print(f"ABORT: post-write self-check failed for {relpath}", file=sys.stderr)
            return 1

    print(
        f"OK: re-pinned {changed_count} file(s); manifest now pins "
        f"{total} file(s); post-write self-check passed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
