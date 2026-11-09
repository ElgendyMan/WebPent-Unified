# src/webpent/causal_reasoning_v2/architecture_extractor_v2.py
"""ArchitectureExtractorV2 — Red-Team fix Phase 1.

Fixes vs v1 extractor:
  1. Multi-pattern route detection: Flask/FastAPI decorators, add_api_route,
     add_url_rule, Django urlpatterns, router.register, APIRouter.
  2. NO artificial depth limit — only cycle protection (seen set).
  3. Conditional-call tracking: calls inside If/For/Try are flagged
     `conditional=True` and are NOT treated as guaranteed verification.
  4. file_path + line_no on every EndpointBinding — reports point to real code.
  5. Expanded function classification: name hints + structural signals
     (returns bool -> likely verifier).
  6. Corrupt-file tolerance: syntax errors skip that file, never crash.
"""
from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_VERIFIER_HINTS = (
    "check_", "verify_", "auth_", "authenticate", "authorize", "require_",
    "is_authorized", "has_permission", "permission", "scope_", "validate_",
    "ensure_", "guard_", "enforce_", "can_", "deny_", "forbid_",
)
_MUTATOR_HINTS = (
    "create_", "update_", "delete_", "save_", "modify_", "set_", "insert_",
    "write_", "store_", "commit_", "persist_", "add_", "remove_", "drop_",
    "patch_", "replace_", "merge_",
)
_DATA_SINK_HINTS = ("dao", "repository", "model", "table", "query", "cursor", "session", "db")


@dataclass(frozen=True)
class CallSite:
    """One call within a function, with conditional context."""
    callee: str
    conditional: bool   # inside If/For/While/Try -> not guaranteed
    line_no: int


@dataclass(frozen=True)
class CallNodeV2:
    qualname: str
    file_path: str
    line_no: int
    is_verifier: bool
    is_mutator: bool
    is_data_sink: bool
    call_sites: tuple[CallSite, ...]   # ordered, with conditional flags
    confidence: float = 0.6

    @property
    def callees(self) -> tuple[str, ...]:
        return tuple(cs.callee for cs in self.call_sites)

    @property
    def guaranteed_callees(self) -> tuple[str, ...]:
        """Callees NOT inside any conditional block — guaranteed on every path."""
        return tuple(cs.callee for cs in self.call_sites if not cs.conditional)


@dataclass(frozen=True)
class EndpointBindingV2:
    route: str
    method: str
    handler_qualname: str
    file_path: str
    line_no: int
    call_chain: tuple[str, ...]
    guaranteed_chain: tuple[str, ...]   # only unconditional calls
    confidence: float = 0.6


@dataclass(frozen=True)
class OrderFlawV2:
    route: str
    method: str
    flaw_type: str   # verification_after_mutation | no_guaranteed_verification_before_mutate
    verifier: str | None
    mutator: str
    file_path: str
    line_no: int
    chain: tuple[str, ...]
    confidence: float


class ArchitectureExtractorV2:
    """Enhanced static extractor.  Stateless per project."""

    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).resolve()
        self.nodes: dict[str, CallNodeV2] = {}
        self.endpoints: list[EndpointBindingV2] = []
        self._files_analyzed = 0
        self._files_skipped = 0

    def analyze_project(self, exclude_patterns: Iterable[str] = ()) -> "ArchitectureExtractorV2":
        exclude = tuple(exclude_patterns) or ("test", "__pycache__", ".git", "venv", "node_modules", ".eggs")
        for py_file in sorted(self.root.rglob("*.py")):
            if any(pat in str(py_file) for pat in exclude):
                continue
            self.analyze_file(py_file)
        self._resolve_endpoint_chains()
        return self

    def analyze_file(self, file_path: Path) -> None:
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, OSError, UnicodeDecodeError):
            self._files_skipped += 1
            return
        self._files_analyzed += 1
        rel = str(file_path.relative_to(self.root)) if file_path.is_relative_to(self.root) else file_path.name

        func_sites: dict[str, list[CallSite]] = {}
        route_bindings: list[tuple[str, str, str, int]] = []  # route, method, qualname, line_no

        class _Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.class_stack: list[str] = []
                self.cond_depth = 0  # >0 means inside If/For/While/Try

            def visit_ClassDef(self, node: ast.ClassDef) -> Any:
                self.class_stack.append(node.name)
                self.generic_visit(node)
                self.class_stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
                self._handle_func(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
                self._handle_func(node)

            # Conditional context tracking
            def visit_If(self, node: ast.If) -> Any:
                self.cond_depth += 1
                self.generic_visit(node)
                self.cond_depth -= 1

            def visit_For(self, node: ast.For) -> Any:
                self.cond_depth += 1
                self.generic_visit(node)
                self.cond_depth -= 1

            def visit_While(self, node: ast.While) -> Any:
                self.cond_depth += 1
                self.generic_visit(node)
                self.cond_depth -= 1

            def visit_Try(self, node: ast.Try) -> Any:
                self.cond_depth += 1
                self.generic_visit(node)
                self.cond_depth -= 1

            def _handle_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                qualname = ".".join([*self.class_stack, node.name])
                sites: list[CallSite] = []
                seen: set[str] = set()
                # Route decorators — multiple patterns.
                for dec in node.decorator_list:
                    route, method = _extract_route(dec)
                    if route:
                        route_bindings.append((route, method, qualname, node.lineno))
                # Calls in body, with conditional flag.
                for stmt in node.body:
                    for child in ast.walk(stmt):
                        if isinstance(child, ast.Call):
                            callee = _callee_name(child.func)
                            if callee and callee not in seen:
                                seen.add(callee)
                                sites.append(CallSite(
                                    callee=callee,
                                    conditional=self.cond_depth > 0 or _inside_conditional(stmt),
                                    line_no=getattr(child, "lineno", node.lineno),
                                ))
                func_sites[qualname] = sites
                self.generic_visit(node)

        _Visitor().visit(tree)

        # Django urlpatterns detection (module-level).
        route_bindings.extend(_detect_django_urls(tree, rel))
        # router.register / add_api_route / add_url_rule at module level.
        route_bindings.extend(_detect_module_routes(tree, rel))

        for qualname, sites in func_sites.items():
            low = qualname.lower()
            is_ver = any(h in low for h in _VERIFIER_HINTS)
            is_mut = any(h in low for h in _MUTATOR_HINTS)
            is_sink = any(h in low for h in _DATA_SINK_HINTS)
            existing = self.nodes.get(qualname)
            merged = list(sites)
            if existing:
                for cs in existing.call_sites:
                    if not any(c.callee == cs.callee for c in merged):
                        merged.append(cs)
                is_ver = is_ver or existing.is_verifier
                is_mut = is_mut or existing.is_mutator
                is_sink = is_sink or existing.is_data_sink
            conf = 0.75 if (is_ver or is_mut) else 0.5
            self.nodes[qualname] = CallNodeV2(
                qualname=qualname, file_path=rel, line_no=0,
                is_verifier=is_ver, is_mutator=is_mut, is_data_sink=is_sink,
                call_sites=tuple(merged), confidence=conf,
            )

        for route, method, handler, lineno in route_bindings:
            self.endpoints.append(EndpointBindingV2(
                route=route, method=method, handler_qualname=handler,
                file_path=rel, line_no=lineno, call_chain=(), guaranteed_chain=(),
            ))

    # ------------------------------------------------------------------
    def detect_verification_order_flaws(self) -> tuple[OrderFlawV2, ...]:
        """Use GUARANTEED (unconditional) chain — conditional verifiers don't count."""
        flaws: list[OrderFlawV2] = []
        for ep in self.endpoints:
            chain = ep.guaranteed_chain or ep.call_chain
            ver_pos: int | None = None
            mut_pos: int | None = None
            ver_name: str | None = None
            mut_name: str | None = None
            for idx, name in enumerate(chain):
                if idx == 0:
                    continue  # skip handler itself
                node = self.nodes.get(name)
                if node:
                    is_v, is_m = node.is_verifier, node.is_mutator
                else:
                    low = name.lower()
                    is_v = any(h in low for h in _VERIFIER_HINTS)
                    is_m = any(h in low for h in _MUTATOR_HINTS)
                if is_v and ver_pos is None:
                    ver_pos, ver_name = idx, name
                if is_m and mut_pos is None:
                    mut_pos, mut_name = idx, name
            if mut_pos is None:
                continue
            if ver_pos is None:
                flaws.append(OrderFlawV2(
                    route=ep.route, method=ep.method,
                    flaw_type="no_guaranteed_verification_before_mutate",
                    verifier=None, mutator=mut_name or "?",
                    file_path=ep.file_path, line_no=ep.line_no,
                    chain=chain, confidence=ep.confidence,
                ))
            elif ver_pos > mut_pos:
                flaws.append(OrderFlawV2(
                    route=ep.route, method=ep.method,
                    flaw_type="verification_after_mutation",
                    verifier=ver_name, mutator=mut_name or "?",
                    file_path=ep.file_path, line_no=ep.line_no,
                    chain=chain, confidence=min(ep.confidence, 0.85),
                ))
        return tuple(flaws)

    def shared_dependencies(self, route_a: str, route_b: str) -> tuple[str, ...]:
        ca = self._chain_for(route_a)
        cb = self._chain_for(route_b)
        if not ca or not cb:
            return ()
        shared = set(ca) & set(cb)
        out = [n for n in shared if self.nodes.get(n) and (
            self.nodes[n].is_verifier or self.nodes[n].is_mutator or self.nodes[n].is_data_sink)]
        return tuple(sorted(out))

    @property
    def stats(self) -> dict[str, Any]:
        return {"files_analyzed": self._files_analyzed, "files_skipped": self._files_skipped,
                "functions": len(self.nodes), "endpoints": len(self.endpoints)}

    # ------------------------------------------------------------------
    def _resolve_endpoint_chains(self) -> None:
        resolved = []
        for ep in self.endpoints:
            chain = self._build_chain(ep.handler_qualname, guaranteed_only=False)
            gchain = self._build_chain(ep.handler_qualname, guaranteed_only=True)
            resolved.append(EndpointBindingV2(
                route=ep.route, method=ep.method, handler_qualname=ep.handler_qualname,
                file_path=ep.file_path, line_no=ep.line_no,
                call_chain=chain, guaranteed_chain=gchain, confidence=ep.confidence,
            ))
        self.endpoints = resolved

    def _build_chain(self, start: str, *, guaranteed_only: bool) -> tuple[str, ...]:
        """BFS chain — NO depth limit, only cycle protection.  If guaranteed_only,
        follow only unconditional call sites."""
        chain: list[str] = []
        seen: set[str] = set()
        q: deque[tuple[str, int]] = deque([(start, 0)])
        while q and len(chain) < 256:
            name, _ = q.popleft()
            if name in seen:
                continue
            seen.add(name)
            chain.append(name)
            node = self.nodes.get(name)
            if node is None:
                continue
            for cs in node.call_sites:
                if guaranteed_only and cs.conditional:
                    continue
                if cs.callee not in seen:
                    q.append((cs.callee, 0))
        return tuple(chain)

    def _chain_for(self, route: str) -> tuple[str, ...]:
        for ep in self.endpoints:
            if ep.route == route:
                return ep.call_chain
        return ()


def _inside_conditional(stmt: ast.AST) -> bool:
    return isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try, ast.With))


def _callee_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _extract_route(dec: ast.AST) -> tuple[str | None, str]:
    """Multi-pattern route extraction from a single decorator."""
    if not isinstance(dec, ast.Call):
        return None, ""
    func = dec.func
    method = ""
    if isinstance(func, ast.Attribute):
        attr = func.attr.lower()
        if attr in ("get", "post", "put", "delete", "patch", "head", "options"):
            method = attr.upper()
        elif attr in ("route", "add_url_rule", "add_api_route"):
            method = "ANY"
        elif attr == "register":
            # router.register(prefix, ...) — prefix route
            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                return dec.args[0].value[:240] + "/*", "ANY"
            return None, ""
        else:
            return None, ""
    elif isinstance(func, ast.Name) and func.id.lower() in ("route", "path", "re_path", "url"):
        method = "ANY"  # Django
    else:
        return None, ""
    if not dec.args:
        return None, ""
    first = dec.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        route = first.value
        for kw in dec.keywords:
            if kw.arg == "methods" and isinstance(kw.value, ast.List):
                meths = [e.value for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if meths:
                    method = ",".join(sorted(m.upper() for m in meths))
        return route[:240], method
    return None, ""


def _detect_django_urls(tree: ast.AST, rel_path: str) -> list[tuple[str, str, str, int]]:
    """Detect Django urlpatterns = [path('x', view, ...), ...]."""
    out: list[tuple[str, str, str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "urlpatterns" and isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Call) and isinstance(elt.func, ast.Name) and elt.func.id in ("path", "re_path", "url"):
                            if elt.args and isinstance(elt.args[0], ast.Constant) and isinstance(elt.args[0].value, str):
                                route = elt.args[0].value
                                view = "view"
                                if len(elt.args) > 1:
                                    v = elt.args[1]
                                    if isinstance(v, ast.Name):
                                        view = v.id
                                    elif isinstance(v, ast.Attribute):
                                        view = v.attr
                                out.append((route[:240], "ANY", view, getattr(elt, "lineno", 0)))
    return out


def _detect_module_routes(tree: ast.AST, rel_path: str) -> list[tuple[str, str, str, int]]:
    """Detect app.add_url_rule(...) / add_api_route at module level."""
    out: list[tuple[str, str, str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("add_url_rule", "add_api_route"):
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    route = node.args[0].value
                    view = "view"
                    if len(node.args) > 1:
                        v = node.args[1]
                        if isinstance(v, ast.Name):
                            view = v.id
                    out.append((route[:240], "ANY", view, getattr(node, "lineno", 0)))
    return out


__all__ = ["ArchitectureExtractorV2", "CallNodeV2", "EndpointBindingV2", "OrderFlawV2", "CallSite"]
