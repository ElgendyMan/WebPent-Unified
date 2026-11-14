#!/usr/bin/env python3
"""Phase-2 P2-107 (F-05): block the shared-event-loop pollution pattern.

pytest-asyncio runs with asyncio_mode=auto (pyproject.toml), so the plugin
owns the loop. A manual ``asyncio.run(...)`` inside a test runs a SECOND
loop inside the running one (RuntimeError) or closes the plugin-owned loop
in teardown ("you closed the underlying event loop in a test") — the exact
mechanism that made 8 security-assertion tests fail only in full-suite
order (Phase-1 audit, §3 class-c). Tests must be native ``async def``.

Exit 0 when no manual ``asyncio.run(`` call sites exist under tests/
(comment mentions do not count — this is an AST scan, not a text grep).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"


def _manual_asyncio_run(tree: ast.AST) -> list[int]:
    hits: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "run"
                and isinstance(func.value, ast.Name)
                and func.value.id == "asyncio"
            ):
                hits.append(node.lineno)
    return hits


def main() -> int:
    offenders: list[str] = []
    for path in sorted(TESTS.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for lineno in _manual_asyncio_run(tree):
            offenders.append(f"{path.relative_to(ROOT)}:{lineno}")
    if offenders:
        print("FAIL: manual asyncio.run() call sites found (use native async tests):")
        for o in offenders:
            print("  ", o)
        return 1
    print("OK: no manual asyncio.run() call sites under tests/ (AST scan)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
