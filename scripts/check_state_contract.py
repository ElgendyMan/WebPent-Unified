#!/usr/bin/env python3
"""TEAM-1 Phase 5 — Static state-contract checker.

Fails on undeclared node-written state keys.

Contract enforced (writer -> declaration -> reader):
  Every literal key emitted by a graph node function (``*_node``) in its
  returned state-update dict MUST be declared on ``PentestState``
  (src/webpent/state/state.py) or appear in the explicit dynamic allowlist
  below (keys produced only through ``**helper(...)`` expansions that cannot
  be resolved statically and are covered by targeted unit tests instead).

Usage:
  python scripts/check_state_contract.py            # human-readable report
  python scripts/check_state_contract.py --quiet    # CI: exit 1 on violation

The same logic is exposed as a pytest test in
tests/test_team1_state_contract.py so the regression suite fails closed.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "webpent"
STATE_FILE = SRC / "state" / "state.py"
NODE_PACKAGES = ("agents", "graph", "workers", "shared")

# Keys produced exclusively through dynamic ``**helper()`` expansions. Each of
# these is covered by an explicit unit test asserting the writer's keys match
# the PentestState declaration, so the static checker tolerates them here.
DYNAMIC_ALLOWED: frozenset[str] = frozenset(
    {
        "evidence_contract",  # hypothesis_analyzer _hint_fields_for
    }
)


def declared_state_keys() -> dict[str, str]:
    """Return PentestState field names -> source line."""
    tree = ast.parse(STATE_FILE.read_text(encoding="utf-8"))
    keys: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "PentestState":
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    keys[stmt.target.id] = f"{STATE_FILE}:{stmt.lineno}"
    return keys


def _dict_literal_keys(d: ast.Dict) -> set[str]:
    """Extract literal string keys from a dict literal (top level only)."""
    keys: set[str] = set()
    for k in d.keys:
        if k is None:
            continue
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            keys.add(k.value)
    return keys


def _scoped_statements(fn: ast.FunctionDef | ast.AsyncFunctionDef):
    """Yield statements of ``fn`` without descending into nested functions.

    LangGraph nodes often define inner helper closures that return
    record-level dicts (auth profiles, observations). Those records are
    nested values inside declared state keys, not state updates themselves,
    so their keys must not be attributed to the node's state contract.
    """

    def walk_body(body):
        for stmt in body:
            # A nested function definition anywhere below the node's own
            # body is a separate scope — never descend into it.
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            yield stmt
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    continue
                if isinstance(child, ast.stmt):
                    yield from walk_body([child])
                elif isinstance(child, ast.ExceptHandler):
                    # ``except ...:`` bodies are part of the node's own
                    # scope — fail-closed error-path returns matter.
                    yield from walk_body(child.body)

    yield from walk_body(fn.body)


def _return_keys_from_function(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[set[str], bool]:
    """Return (literal keys, has_dynamic_expansion) for one node function.

    Handles three writer patterns:
      1. ``return {...}`` — direct dict literal.
      2. ``updates = {...} ... return updates`` — literal assigned then
         returned (aliases tracked per function).
      3. ``return {**({"k": v} if cond else {}), "a": 1}`` — conditional
         expansions of inline dict literals contribute their keys.
    """
    keys: set[str] = set()
    aliases: dict[str, set[str]] = {}
    dynamic = False

    def visit_dict(d: ast.Dict, sink: set[str]) -> None:
        # In Python's AST, a ``**expansion`` entry inside a dict literal is
        # represented as a None key paired with the expansion expression as
        # the corresponding value.
        for key, value in zip(d.keys, d.values, strict=True):
            if key is None:  # **expansion entry
                if isinstance(value, ast.Dict):
                    visit_dict(value, sink)
                elif isinstance(value, ast.IfExp) and isinstance(value.body, ast.Dict):
                    visit_dict(value.body, sink)
                    if isinstance(value.orelse, ast.Dict):
                        visit_dict(value.orelse, sink)
                else:
                    nonlocal dynamic
                    dynamic = True
            elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                sink.add(key.value)

    for stmt in _scoped_statements(fn):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Dict):
                sink: set[str] = set()
                visit_dict(stmt.value, sink)
                aliases[target.id] = sink
        if isinstance(stmt, (ast.Return,)):
            value = stmt.value
            if isinstance(value, ast.Dict):
                visit_dict(value, keys)
            elif isinstance(value, ast.Name) and value.id in aliases:
                keys.update(aliases[value.id])
    return keys, dynamic


def collect_node_writers() -> dict[str, tuple[str, set[str], bool]]:
    """Return node_name -> (location, literal keys, has_dynamic)."""
    writers: dict[str, tuple[str, set[str], bool]] = {}
    for pkg in NODE_PACKAGES:
        base = SRC / pkg
        if not base.exists():
            continue
        for py in sorted(base.rglob("*.py")):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except SyntaxError as exc:
                print(f"WARN: syntax error in {py}: {exc}", file=sys.stderr)
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name.endswith("_node"):
                    keys, dynamic = _return_keys_from_function(node)
                    if node.name in writers:
                        prev = writers[node.name]
                        writers[node.name] = (
                            prev[0] + f" + {py}:{node.lineno}",
                            prev[1] | keys,
                            prev[2] or dynamic,
                        )
                    else:
                        writers[node.name] = (f"{py.relative_to(ROOT)}:{node.lineno}", keys, dynamic)
    return writers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="CI mode: exit code only")
    args = parser.parse_args(argv or [])

    declared = declared_state_keys()
    if not declared:
        print("FATAL: PentestState declaration not found", file=sys.stderr)
        return 2

    writers = collect_node_writers()
    violations: list[str] = []
    report: list[str] = [
        "TEAM-1 Phase 5 state-contract report",
        f"declared PentestState keys: {len(declared)}",
        f"node writers inspected:    {len(writers)}",
    ]
    for name, (loc, keys, dynamic) in sorted(writers.items()):
        unknown = sorted(
            k for k in keys
            if k not in declared and k not in DYNAMIC_ALLOWED
        )
        if unknown:
            violations.append(f"{name} ({loc}) writes undeclared keys: {', '.join(unknown)}")
        if args.quiet:
            continue
        status = "OK" if not unknown else "VIOLATION"
        report.append(f"[{status}] {name} ({loc}) -> {len(keys)} literal key(s)"
                      + (" + dynamic **expansion" if dynamic else ""))
        for k in unknown:
            report.append(f"    UNDECLARED: {k}")

    if not args.quiet:
        print("\n".join(report))
    if violations:
        print(
            "\nSTATE CONTRACT VIOLATIONS ("
            f"{len(violations)}): every node-written key must be declared "
            "on PentestState — see docs/state contract policy in "
            "scripts/check_state_contract.py",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1
    if not args.quiet:
        print("\nSTATE CONTRACT: OK — all literal node-written keys are declared.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
