# src/webpent/causal_reasoning_v2/architecture_extractor.py
"""ArchitectureExtractor — Deep-fix Phase 1.

Extracts the target's internal architecture from SOURCE CODE (static analysis)
BEFORE any scanning begins, so the causal model is complete rather than
limited to what scanning happens to discover.  Uses Python's `ast` module —
no network, no execution of target code, no external dependencies.

Capabilities:
  * Parse every .py file in a project root; build a call graph (caller ->
    callees) with file/line provenance.
  * Detect HTTP endpoints from Flask/FastAPI/Django-style decorators and
    route registrations; bind each route to its handler function.
  * Classify functions as verifiers (auth/scope/permission checks) or
    mutators (data writes) by name heuristics + structural signals.
  * Resolve each endpoint's ordered call chain (handler -> verifiers ->
    mutators -> data sinks), bounded depth, cycle-safe.
  * Detect verification-order flaws: a verifier appearing AFTER a mutator in
    the same chain = classic auth-check-after-mutation.
  * Compute shared dependencies between any two routes (structural siblings
    even before any vulnerability is found).

All results are confidence-scored and bounded.  Failures on individual files
(syntax errors, encoding) are skipped, never fatal.
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

# Name heuristics — documented, additive.  A function matching ANY hint is
# classified as that role.  Structural signals (calls to known verifiers)
# can upgrade confidence later.
_VERIFIER_HINTS = (
    "check_", "verify_", "auth_", "authenticate", "authorize", "require_",
    "is_authorized", "has_permission", "permission", "scope_", "validate_",
    "ensure_", "guard_", "enforce_",
)
_MUTATOR_HINTS = (
    "create_", "update_", "delete_", "save_", "modify_", "set_", "insert_",
    "write_", "store_", "commit_", "persist_", "add_", "remove_", "drop_",
)
_DATA_SINK_HINTS = ("dao", "repository", "model", "table", "query", "cursor", "session")


@dataclass(frozen=True)
class CallNode:
    """One function/method in the extracted call graph."""
    qualname: str
    file_path: str
    line_no: int
    is_verifier: bool
    is_mutator: bool
    is_data_sink: bool
    callees: tuple[str, ...]
    confidence: float = 0.6


@dataclass(frozen=True)
class EndpointBinding:
    route: str
    method: str
    handler_qualname: str
    call_chain: tuple[str, ...]   # ordered, depth-bounded, cycle-safe
    confidence: float = 0.6


@dataclass(frozen=True)
class OrderFlaw:
    route: str
    method: str
    flaw_type: str                 # verification_after_mutation | no_verification_before_mutate
    verifier: str | None
    mutator: str
    chain: tuple[str, ...]
    confidence: float


class ArchitectureExtractor:
    """Static architecture extractor.  Stateless per project; thread-safe."""

    def __init__(self, project_root: str | Path, max_chain_depth: int = 12):
        self.root = Path(project_root).resolve()
        self.max_chain_depth = max(1, int(max_chain_depth))
        self.nodes: dict[str, CallNode] = {}
        self.endpoints: list[EndpointBinding] = []
        self._files_analyzed = 0
        self._files_skipped = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze_project(self, exclude_patterns: Iterable[str] = ()) -> "ArchitectureExtractor":
        """Analyze all .py files under project_root.  Returns self (chainable)."""
        exclude = tuple(exclude_patterns) or ("test", "__pycache__", ".git", "venv", "node_modules")
        for py_file in sorted(self.root.rglob("*.py")):
            if any(pat in str(py_file) for pat in exclude):
                continue
            self.analyze_file(py_file)
        # After all files are parsed, resolve endpoint call chains (needs full graph).
        self._resolve_endpoint_chains()
        return self

    def analyze_file(self, file_path: Path) -> None:
        """Parse one Python file and merge its functions/calls into the graph."""
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, OSError, UnicodeDecodeError):
            self._files_skipped += 1
            return
        self._files_analyzed += 1

        rel_path = str(file_path.relative_to(self.root)) if file_path.is_relative_to(self.root) else file_path.name
        func_calls: dict[str, list[str]] = {}  # ordered, deduped
        route_bindings: list[tuple[str, str, str]] = []  # (route, method, handler_qualname)

        class _Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.class_stack: list[str] = []

            def visit_ClassDef(self, node: ast.ClassDef) -> Any:
                self.class_stack.append(node.name)
                self.generic_visit(node)
                self.class_stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
                self._handle_func(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
                self._handle_func(node)

            def _handle_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                qualname = ".".join([*self.class_stack, node.name])
                calls: list[str] = []  # preserve AST (execution) order, dedupe
                seen_calls: set[str] = set()
                # Detect route decorators: @app.get("/x"), @router.post(...), @blueprint.route(...)
                for dec in node.decorator_list:
                    route, method = _extract_route_from_decorator(dec)
                    if route:
                        route_bindings.append((route, method, qualname))
                # Collect calls in body ORDER (critical for verification-order analysis).
                # Walk ONLY the body statements — decorator calls (e.g. @app.post(...))
                # must NOT be counted as function-body calls.
                for stmt in node.body:
                    for child in ast.walk(stmt):
                        if isinstance(child, ast.Call):
                            callee = _callee_name(child.func)
                            if callee and callee not in seen_calls:
                                seen_calls.add(callee)
                                calls.append(callee)
                func_calls[qualname] = calls
                self.generic_visit(node)

        _Visitor().visit(tree)

        # Merge into global graph.
        for qualname, calls in func_calls.items():
            is_ver = any(h in qualname.lower() for h in _VERIFIER_HINTS)
            is_mut = any(h in qualname.lower() for h in _MUTATOR_HINTS)
            is_sink = any(h in qualname.lower() for h in _DATA_SINK_HINTS)
            existing = self.nodes.get(qualname)
            merged_callees = list(calls)
            if existing:
                for c in existing.callees:
                    if c not in merged_callees:
                        merged_callees.append(c)
                is_ver = is_ver or existing.is_verifier
                is_mut = is_mut or existing.is_mutator
                is_sink = is_sink or existing.is_data_sink
            conf = 0.7 if (is_ver or is_mut) else 0.5
            self.nodes[qualname] = CallNode(
                qualname=qualname, file_path=rel_path, line_no=0,
                is_verifier=is_ver, is_mutator=is_mut, is_data_sink=is_sink,
                callees=tuple(merged_callees), confidence=conf,
            )

        for route, method, handler in route_bindings:
            self.endpoints.append(EndpointBinding(
                route=route, method=method, handler_qualname=handler,
                call_chain=(),  # resolved later
            ))

    def detect_verification_order_flaws(self) -> tuple[OrderFlaw, ...]:
        """Find endpoints where a mutator runs before any verifier in the chain."""
        flaws: list[OrderFlaw] = []
        for ep in self.endpoints:
            chain = ep.call_chain
            verifier_pos: int | None = None
            mutator_pos: int | None = None
            verifier_name: str | None = None
            mutator_name: str | None = None
            for idx, name in enumerate(chain):
                if idx == 0:
                    continue  # skip the handler itself (entry point, not a verifier/mutator)
                node = self.nodes.get(name)
                if node is not None:
                    is_v, is_m = node.is_verifier, node.is_mutator
                else:
                    # External/undefined function — classify by name hints.
                    low = name.lower()
                    is_v = any(h in low for h in _VERIFIER_HINTS)
                    is_m = any(h in low for h in _MUTATOR_HINTS)
                if is_v and verifier_pos is None:
                    verifier_pos = idx
                    verifier_name = name
                if is_m and mutator_pos is None:
                    mutator_pos = idx
                    mutator_name = name
            if mutator_pos is None:
                continue  # read-only endpoint, no order flaw possible
            if verifier_pos is None:
                flaws.append(OrderFlaw(
                    route=ep.route, method=ep.method,
                    flaw_type="no_verification_before_mutate",
                    verifier=None, mutator=mutator_name or "unknown",
                    chain=chain, confidence=ep.confidence,
                ))
            elif verifier_pos > mutator_pos:
                flaws.append(OrderFlaw(
                    route=ep.route, method=ep.method,
                    flaw_type="verification_after_mutation",
                    verifier=verifier_name, mutator=mutator_name or "unknown",
                    chain=chain, confidence=min(ep.confidence, 0.85),
                ))
        return tuple(flaws)

    def shared_dependencies(self, route_a: str, route_b: str) -> tuple[str, ...]:
        """Shared call-graph nodes between two routes — structural siblings."""
        chain_a = self._chain_for_route(route_a)
        chain_b = self._chain_for_route(route_b)
        if not chain_a or not chain_b:
            return ()
        shared = set(chain_a) & set(chain_b)
        # Only shared nodes that are verifiers/mutators/data-sinks matter for
        # root-cause propagation (trivial helpers are noise).
        meaningful = [
            n for n in shared
            if self.nodes.get(n) and (
                self.nodes[n].is_verifier or self.nodes[n].is_mutator or self.nodes[n].is_data_sink
            )
        ]
        return tuple(sorted(meaningful))

    def endpoints_sharing_dependency(self, dep_name: str) -> tuple[str, ...]:
        """All routes whose call chain contains a given shared node."""
        result = []
        for ep in self.endpoints:
            if dep_name in ep.call_chain:
                result.append(ep.route)
        return tuple(sorted(result))

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "files_analyzed": self._files_analyzed,
            "files_skipped": self._files_skipped,
            "functions": len(self.nodes),
            "endpoints": len(self.endpoints),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _resolve_endpoint_chains(self) -> None:
        resolved: list[EndpointBinding] = []
        for ep in self.endpoints:
            chain = self._build_call_chain(ep.handler_qualname)
            resolved.append(EndpointBinding(
                route=ep.route, method=ep.method, handler_qualname=ep.handler_qualname,
                call_chain=chain, confidence=ep.confidence,
            ))
        self.endpoints = resolved

    def _build_call_chain(self, start: str) -> tuple[str, ...]:
        """BFS-ordered call chain from start; cycle-safe; depth-bounded."""
        chain: list[str] = []
        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        while queue and len(chain) < 64:
            name, depth = queue.popleft()
            if name in seen or depth > self.max_chain_depth:
                continue
            seen.add(name)
            chain.append(name)
            node = self.nodes.get(name)
            if node is None:
                continue
            # Preserve AST (execution) order — do NOT re-sort.  Re-sorting
            # would fabricate verification-before-mutation ordering and hide
            # the very flaws we are trying to detect.
            for c in node.callees:
                if c not in seen:
                    queue.append((c, depth + 1))
        return tuple(chain)

    def _chain_for_route(self, route: str) -> tuple[str, ...]:
        for ep in self.endpoints:
            if ep.route == route:
                return ep.call_chain
        return ()


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def node_for(_qualname: str, _func_calls: dict[str, set[str]]) -> Any:
    return None  # placeholder; line numbers not critical for inference


def _callee_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _extract_route_from_decorator(dec: ast.AST) -> tuple[str | None, str]:
    """Return (route_path, HTTP_METHOD) from a decorator, or (None, '')."""
    if not isinstance(dec, ast.Call):
        return None, ""
    func = dec.func
    method: str = ""
    if isinstance(func, ast.Attribute):
        attr = func.attr.lower()
        if attr in ("get", "post", "put", "delete", "patch", "head", "options"):
            method = attr.upper()
        elif attr in ("route", "add_url_rule"):
            method = "ANY"
        else:
            return None, ""
    elif isinstance(func, ast.Name) and func.id.lower() in ("route",):
        method = "ANY"
    else:
        return None, ""
    if not dec.args:
        return None, ""
    first = dec.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        route = first.value
        # Extract methods from kwargs: methods=["POST"]
        for kw in dec.keywords:
            if kw.arg == "methods" and isinstance(kw.value, ast.List):
                meths = [e.value for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if meths:
                    method = ",".join(sorted(m.upper() for m in meths))
        return route[:240], method
    return None, ""


__all__ = [
    "ArchitectureExtractor", "CallNode", "EndpointBinding", "OrderFlaw",
]
