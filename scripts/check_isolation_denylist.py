#!/usr/bin/env python3
"""Sprint I-1, item 2.2 — S-1 static CI gate for the dependency isolation
denylist (M3 v1.0 §5.2.1, amended by v1.1 F-03).

Model: scripts/check_orchestrator_construction_authority.py. Reuses that
script's shape (walk every .py file, report file:line violations, --quiet
mode for CI, exit 1 on violation).

Enforces, from config/isolation_denylist.yaml:
  - D-01: strix package/module names — whole-file substring match
    (imports, strings, comments all count — M3 v1.0 §5.2.1: "a Strix
    reference in a comment is still a reference the program must
    adjudicate").
  - D-02: strix report/writer symbol names — qualified-only matching for
    the three colliding native names (build_sarif_report, record_coverage,
    scope_rules — WebPent has its own, unrelated, legitimate symbols with
    these exact names: reporter/export.py:800 build_sarif_report,
    agents/strategist/agent.py:392 record_coverage,
    shared/{target_package_context,package_scope}.py's own scope_rules
    dataclass field, verified this sprint via direct grep before writing
    ANY matching logic here); bare matching for the other, unambiguous
    D-02 names.
  - D-03: strix destination strings/endpoints — whole-file substring
    match, same as D-01.
  - D-04: dynamic-loader AST inspection (unchanged from the original
    Sprint I-1 implementation — see that history for detail).
  - A-01 closure: any top-level third-party import found anywhere under
    src/ that is NOT in A-01 (and is not stdlib, not webpent.*) is a gate
    failure, per the contract's own framing ("Any unknown third-party
    top-level import = gate failure (deny-by-default)").

D-02 matching design (the one genuinely hard part — documented in full
because getting this wrong either misses real Strix references or
false-positives a CI gate against WebPent's own legitimate code):
"Qualified" is implemented as EITHER of:
  (a) the name appears in an import statement (`from X import NAME`,
      `import X.NAME`, or `... import Y as NAME`) where X is not
      webpent.* and not a stdlib top-level module — an import statement
      inherently names an explicit external source, which is exactly
      what "qualified" means in plain English, regardless of what NAME
      itself looks like once imported;
  (b) the name is accessed via dotted attribute (`BASE.NAME`) where BASE
      textually matches a D-01 strix pattern (e.g. `strix_mod.NAME`,
      `strix.report.NAME`).
Deliberately NOT flagged: a bare `ast.Name` reference (a plain function
call or identifier with no dot and no import), and dotted attribute
access whose BASE does not match a strix pattern (e.g. `self.scope_rules`,
`self.context.scope_rules`, `package.scope_rules`) — these are
indistinguishable from WebPent's own legitimate field/attribute access
by any means short of full type inference, and WebPent's own code uses
exactly this shape extensively (verified: package_scope.py,
target_package_context.py). Verified zero false positives against the
real current tree before this script was considered done — see the
sprint changelog for the exact verification transcript.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
CONTRACT_PATH = ROOT / "config" / "isolation_denylist.yaml"

D04_CALL_NAMES = frozenset({
    "import_module", "reload", "__import__", "spec_from_file_location",
    "eval", "exec",
})

EXCLUDED_DIR_NAMES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".mypy_cache", ".pytest_cache", "build", "dist",
}

# Python 3.12 stdlib top-level module names, for the A-01 closure check.
# Built from sys.stdlib_module_names (3.10+) rather than hand-maintained.
_STDLIB_MODULES = frozenset(sys.stdlib_module_names) | {"_typeshed"}


def load_contract() -> dict:
    with CONTRACT_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _resolved_call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _iter_source_files(root: Path):
    for path in root.rglob("*.py"):
        if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        yield path


def find_d01_d03_violations(contract: dict, group_id: str) -> list[tuple[Path, int, str]]:
    """D-01/D-03: whole-file substring match, imports/strings/comments
    all count — checked over the raw file text, not just the AST, since
    a comment mention is still meant to be caught (M3 v1.0 §5.2.1)."""
    group = contract["denylist_groups"][group_id]
    patterns = group["match"]
    violations: list[tuple[Path, int, str]] = []
    for path in _iter_source_files(SRC):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(lines, start=1):
            for pattern in patterns:
                if pattern in line:
                    violations.append((path, lineno, f"{group_id}: matched {pattern!r}"))
    return violations


def _import_base_module(node: ast.ImportFrom | ast.Import) -> str:
    if isinstance(node, ast.ImportFrom):
        return node.module or ""
    return ""


def find_d02_violations(contract: dict) -> list[tuple[Path, int, str]]:
    d02 = contract["denylist_groups"]["D-02"]
    qualified_required = set(d02["qualified_required"])
    bare_match = set(d02["bare_match"])
    all_names = qualified_required | bare_match
    strix_patterns = contract["denylist_groups"]["D-01"]["match"]

    violations: list[tuple[Path, int, str]] = []
    for path in _iter_source_files(SRC):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if not any(name in text for name in all_names):
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            # Bare-match names: any Name reference, Attribute access, or
            # import at all is a hit — these have no legitimate WebPent
            # collision (unlike the three qualified_required names).
            if isinstance(node, ast.Name) and node.id in bare_match:
                violations.append((path, node.lineno, f"D-02: bare reference to {node.id!r}"))
            elif isinstance(node, ast.Attribute) and node.attr in bare_match:
                violations.append((path, node.lineno, f"D-02: attribute reference to {node.attr!r}"))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    imported_name = alias.asname or alias.name
                    base_module = _import_base_module(node) if isinstance(node, ast.ImportFrom) else alias.name
                    if imported_name in bare_match or alias.name in bare_match:
                        violations.append((
                            path, node.lineno,
                            f"D-02: import of bare-match name {alias.name!r}",
                        ))
                    if alias.name in qualified_required or imported_name in qualified_required:
                        top = base_module.split(".")[0] if base_module else alias.name.split(".")[0]
                        if top not in ("webpent",) and top not in _STDLIB_MODULES:
                            violations.append((
                                path, node.lineno,
                                f"D-02: qualified import of colliding name "
                                f"{alias.name!r} from non-webpent/non-stdlib module {base_module or alias.name!r}",
                            ))
            elif isinstance(node, ast.Attribute) and node.attr in qualified_required:
                base_text = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
                if any(p in base_text for p in strix_patterns):
                    violations.append((
                        path, node.lineno,
                        f"D-02: qualified attribute access {base_text}.{node.attr} "
                        "(base matches a D-01 strix pattern)",
                    ))
    return violations


def find_d04_violations(contract: dict) -> tuple[list[tuple[Path, int, str]], list[tuple[Path, int, str]]]:
    d04 = contract["denylist_groups"]["D-04"]
    manual_review_ok = {
        (ROOT / entry["path"], entry["line"])
        for entry in d04.get("manual_review_ok", [])
    }
    violations: list[tuple[Path, int, str]] = []
    ok_sites: list[tuple[Path, int, str]] = []

    for path in _iter_source_files(SRC):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if not any(sym.split(".")[-1] in text for sym in D04_CALL_NAMES):
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolved_call_name(node)
            if call_name not in D04_CALL_NAMES:
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            lineno = node.lineno
            key = (path, lineno)
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                ok_sites.append((path, lineno, f"{call_name}({first_arg.value!r}) — literal"))
                continue
            if key in manual_review_ok:
                ok_sites.append((path, lineno, f"{call_name}(...) — variable, manual_review_ok"))
                continue
            violations.append((
                path, lineno,
                f"{call_name}(...) — first argument is not a compile-time string "
                "literal and this exact site is not in manual_review_ok",
            ))
    return violations, ok_sites


def find_a01_closure_violations(contract: dict) -> list[tuple[Path, int, str]]:
    """Contract framing: "production-reachable modules import ONLY
    stdlib, webpent.*, and A-01. Any unknown third-party top-level
    import = gate failure (deny-by-default)." Scoped to src/ (same as
    every other check here) rather than attempting true production-
    reachability analysis (that is S-2's job, a runtime composition
    test, not a static gate)."""
    a01 = set(contract["allowlist_groups"]["A-01"]["entries"])
    violations: list[tuple[Path, int, str]] = []
    for path in _iter_source_files(SRC):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            tops: list[str] = []
            if isinstance(node, ast.Import):
                tops = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                tops = [node.module.split(".")[0]]
            for top in tops:
                if top == "webpent" or top in _STDLIB_MODULES or top in a01:
                    continue
                violations.append((path, node.lineno, f"A-01: unknown third-party top-level import {top!r}"))
    return violations


def report_pending_groups(contract: dict) -> list[str]:
    pending = []
    for group_id, group in {
        **contract["denylist_groups"], **contract["allowlist_groups"],
    }.items():
        if group.get("status") == "pending_v1_0_source":
            pending.append(group_id)
    return sorted(pending)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="CI mode: minimal output, exit 1 on failure")
    parser.add_argument("--skip-a01-closure", action="store_true",
                         help="Skip the A-01 unknown-third-party-import closure check (diagnostic use only)")
    args = parser.parse_args()

    contract = load_contract()
    pending = report_pending_groups(contract)

    d01_violations = find_d01_d03_violations(contract, "D-01")
    d02_violations = find_d02_violations(contract)
    d03_violations = find_d01_d03_violations(contract, "D-03")
    d04_violations, d04_ok_sites = find_d04_violations(contract)
    a01_violations = [] if args.skip_a01_closure else find_a01_closure_violations(contract)

    all_violations = d01_violations + d02_violations + d03_violations + d04_violations + a01_violations

    if not args.quiet:
        for group_id in pending:
            print(f"WARNING: group {group_id} is status=pending_v1_0_source — NOT enforced.", file=sys.stderr)
        print(f"D-01: {len(d01_violations)} violation(s).")
        print(f"D-02: {len(d02_violations)} violation(s).")
        print(f"D-03: {len(d03_violations)} violation(s).")
        print(f"D-04: {len(d04_ok_sites)} call site(s) verified OK; {len(d04_violations)} violation(s).")
        if not args.skip_a01_closure:
            print(f"A-01 closure: {len(a01_violations)} unknown third-party import(s).")

    if not all_violations:
        if not args.quiet:
            print("OK: no denylist violations.")
        return 0

    print(f"FAIL: {len(all_violations)} isolation-denylist violation(s):", file=sys.stderr)
    for path, lineno, detail in all_violations:
        print(f"  {path.relative_to(ROOT)}:{lineno}: {detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
