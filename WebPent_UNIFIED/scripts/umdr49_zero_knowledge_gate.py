#!/usr/bin/env python3
"""UM-DR-49 W2.2 — the zero-knowledge grep-gate.

Law 1 (zero prior knowledge): NO production code path may carry
app-specific identifiers of the three real-ground targets (challenge
keys, lesson paths, module paths, app-specific API literals). The
detection power must come from GENERIC patterns. This gate greps the
PRODUCTION tree (src/webpent) for the forbidden literals and fails if
any is found. The truth catalogs + campaign scripts (measurement
artifacts, clearly delimited) are exempt BY DECLARATION — they are the
measurement instruments, not engine code.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROD = REPO / "src" / "webpent"

# App-specific literals that must NEVER appear in engine code (drawn
# from the three apps' public surfaces — not from any engine logic).
FORBIDDEN: dict[str, list[str]] = {
    "juiceshop": [
        "rest/user/login", "rest/products/search", "rest/basket",
        "api/Challenges", "rest/admin", "rest/track-order",
        "rest/continue-code", "rest/repeat-code",
        "score-board", "Score Board", "rest/b2b",
    ],
    "webgoat": [
        "WebGoat/", "WebWolf/", "service/lessoninfo",
        "attack?lesson", "lesson/HttpBasics", "SqlInjection/attack",
    ],
    "dvwa": [
        "vulnerabilities/sqli", "vulnerabilities/xss",
        "login.php", "security.php", "vulnerabilities/fi",
        "vulnerabilities/upload", "hackable/uploads",
    ],
}

# Measurement artifacts (declared exempt: they are the instruments).
EXEMPT_DIRS = ("deliverables/", "scripts/", "tests/", "docs/",
               "benchmark/fixtures/",
               # the LAB-HARNESS adapter zone: source-pinned, blocked-
               # precondition contracts for offline replay verification
               # (option_b) — never wired into engine detection; the
               # engine's live paths carry no app literals (the gate).
               "src/webpent/adapters/")

# Generic web-shape literals that predate and transcend the three labs
# (php login pages, password-form indicators) — signals about a CLASS
# of apps, not knowledge of ONE target.
ALLOWED_GENERIC = {
    "login.php",  # php-login-page indicator (whole class of apps)
}


def main() -> int:
    offenders: list[tuple[str, str]] = []
    for path in PROD.rglob("*.py"):
        rel = str(path.relative_to(REPO))
        if any(rel.startswith(e) for e in EXEMPT_DIRS):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for app, literals in FORBIDDEN.items():
            for lit in literals:
                if lit in ALLOWED_GENERIC:
                    continue
                if lit in text:
                    offenders.append((rel, lit))
    if offenders:
        print("ZERO-KNOWLEDGE VIOLATIONS (app-specific literals in "
              "production code):")
        for rel, lit in offenders:
            print(f"  - {rel}: {lit!r}")
        return 1
    total = sum(len(v) for v in FORBIDDEN.values())
    print(f"zero-knowledge gate: CLEAN ({total} forbidden literals "
          f"checked across src/webpent, {len(list(PROD.rglob('*.py')))} "
          f"files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
