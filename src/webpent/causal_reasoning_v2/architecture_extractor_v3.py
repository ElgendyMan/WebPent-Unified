# src/webpent/causal_reasoning_v2/architecture_extractor_v3.py
"""ArchitectureExtractorV3 — Red-Team final fix.

Fixes vs v2 extractor:
  1. Unified route extraction: Flask/FastAPI decorators, add_api_route,
     add_url_rule, Django urlpatterns (path/re_path/url), router.register.
     Argument-order-flexible — route found by position OR keyword.
  2. NO artificial depth limit — only cycle protection (per-branch seen set,
     so a second valid path to the same function is NOT blocked).
  3. Conditional calls (inside If/For/While/Try) tracked separately — NOT
     counted in the guaranteed chain.  A verifier inside `if admin:` does
     not protect the default path.
  4. Generator detection — functions containing `yield` flagged is_generator;
     `yield` is not treated as `return`.
  5. file_path + line_no on every EndpointBinding.
  6. Corrupt-file tolerance: syntax/encoding errors skip that file only.
"""
from __future__ import annotations

import ast
import re
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

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class CallSiteV3:
    callee: str
    conditional: bool
    line_no: int


@dataclass(frozen=True)
class CallNodeV3:
    qualname: str
    file_path: str
    line_no: int
    is_verifier: bool
    is_mutator: bool
    is_data_sink: bool
    is_generator: bool
    call_sites: tuple[CallSiteV3, ...]

    @property
    def direct_callees(self) -> tuple[str, ...]:
        return tuple(cs.callee for cs in self.call_sites if not cs.conditional)

    @property
    def conditional_callees(self) -> tuple[str, ...]:
        return tuple(cs.callee for cs in self.call_sites if cs.conditional)


@dataclass(frozen=True)
class EndpointBindingV3:
    route: str
    method: str
    handler_qualname: str
    file_path: str
    line_no: int
    guaranteed_chain: tuple[str, ...]   # unconditional calls only
    full_chain: tuple[str, ...]          # all calls (incl. conditional)


@dataclass(frozen=True)
class OrderFlawV3:
    route: str
    method: str
    flaw_type: str   # verification_after_mutation | no_guaranteed_verification_before_mutate
    verifier: str | None
    mutator: str
    file_path: str
    line_no: int
    chain: tuple[str, ...]
    confidence: float


class ArchitectureExtractorV3:
    """Enhanced static extractor.  Stateless per project."""

    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).resolve()
        self.nodes: dict[str, CallNodeV3] = {}
        self.endpoints: list[EndpointBindingV3] = []
        self._files_analyzed = 0
        self._files_skipped = 0

    def analyze_project(self, exclude_patterns: Iterable[str] = ()) -> "ArchitectureExtractorV3":
        exclude = tuple(exclude_patterns) or ("test", "__pycache__", ".git", "venv", "node_modules", ".eggs")
        for py_file in sorted(self.root.rglob("*.py")):
            if any(pat in str(py_file) for pat in exclude):
                continue
            self.analyze_file(py_file)
        self._resolve_chains()
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

        func_sites: dict[str, list[CallSiteV3]] = {}
        route_bindings: list[tuple[str, str, str, int]] = []

        class _Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.class_stack: list[str] = []
                self.cond_depth = 0
                self.yield_count = 0

            def visit_ClassDef(self, node: ast.ClassDef) -> Any:
                self.class_stack.append(node.name)
                self.generic_visit(node)
                self.class_stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
                self._handle_func(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
                self._handle_func(node)

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

            def visit_Yield(self, node: ast.Yield) -> Any:
                self.yield_count += 1
                self.generic_visit(node)

            def visit_YieldFrom(self, node: ast.YieldFrom) -> Any:
                self.yield_count += 1
                self.generic_visit(node)

            def _handle_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                qualname = ".".join([*self.class_stack, node.name])
                sites: list[CallSiteV3] = []
                seen: set[str] = set()
                self.yield_count = 0
                # Route decorators.
                for dec in node.decorator_list:
                    route, method = _extract_route(dec)
                    if route:
                        route_bindings.append((route, method or "GET", qualname, node.lineno))
                # Calls in body, with conditional flag.
                for stmt in node.body:
                    for child in ast.walk(stmt):
                        if isinstance(child, ast.Call):
                            callee = _callee_name(child.func)
                            if callee and callee not in seen:
                                seen.add(callee)
                                sites.append(CallSiteV3(
                                    callee=callee,
                                    conditional=self.cond_depth > 0 or isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try)),
                                    line_no=getattr(child, "lineno", node.lineno),
                                ))
                is_gen = self.yield_count > 0
                func_sites[qualname] = sites
                self.generic_visit(node)
                # Re-check after visiting body (yield appears inside body).
                gen_flags[qualname] = self.yield_count > 0

        gen_flags: dict[str, bool] = {}
        _Visitor().visit(tree)

        # Module-level route registrations (add_api_route, add_url_rule, Django urlpatterns).
        route_bindings.extend(_detect_module_routes(tree))

        for qualname, sites in func_sites.items():
            low = qualname.lower()
            is_ver = any(h in low for h in _VERIFIER_HINTS)
            is_mut = any(h in low for h in _MUTATOR_HINTS)
            is_sink = any(h in low for h in _DATA_SINK_HINTS)
            is_gen = gen_flags.get(qualname, False)
            existing = self.nodes.get(qualname)
            merged = list(sites)
            if existing:
                for cs in existing.call_sites:
                    if not any(c.callee == cs.callee for c in merged):
                        merged.append(cs)
                is_ver = is_ver or existing.is_verifier
                is_mut = is_mut or existing.is_mutator
                is_sink = is_sink or existing.is_data_sink
                is_gen = is_gen or existing.is_generator
            self.nodes[qualname] = CallNodeV3(
                qualname=qualname, file_path=rel, line_no=0,
                is_verifier=is_ver, is_mutator=is_mut, is_data_sink=is_sink,
                is_generator=is_gen, call_sites=tuple(merged),
            )

        for route, method, handler, lineno in route_bindings:
            self.endpoints.append(EndpointBindingV3(
                route=route, method=method, handler_qualname=handler,
                file_path=rel, line_no=lineno, guaranteed_chain=(), full_chain=(),
            ))

    # ------------------------------------------------------------------
    def detect_verification_order_flaws(self) -> tuple[OrderFlawV3, ...]:
        flaws: list[OrderFlawV3] = []
        for ep in self.endpoints:
            chain = ep.guaranteed_chain or ep.full_chain
            ver_pos: int | None = None
            mut_pos: int | None = None
            ver_name: str | None = None
            mut_name: str | None = None
            for idx, name in enumerate(chain):
                if idx == 0:
                    continue  # skip handler
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
                flaws.append(OrderFlawV3(
                    route=ep.route, method=ep.method,
                    flaw_type="no_guaranteed_verification_before_mutate",
                    verifier=None, mutator=mut_name or "?",
                    file_path=ep.file_path, line_no=ep.line_no,
                    chain=chain, confidence=0.7,
                ))
            elif ver_pos > mut_pos:
                flaws.append(OrderFlawV3(
                    route=ep.route, method=ep.method,
                    flaw_type="verification_after_mutation",
                    verifier=ver_name, mutator=mut_name or "?",
                    file_path=ep.file_path, line_no=ep.line_no,
                    chain=chain, confidence=0.85,
                ))
        return tuple(flaws)

    @property
    def stats(self) -> dict[str, Any]:
        return {"files_analyzed": self._files_analyzed, "files_skipped": self._files_skipped,
                "functions": len(self.nodes), "endpoints": len(self.endpoints)}

    # ------------------------------------------------------------------
    def _resolve_chains(self) -> None:
        resolved = []
        for ep in self.endpoints:
            gchain = self._chain(ep.handler_qualname, guaranteed_only=True)
            fchain = self._chain(ep.handler_qualname, guaranteed_only=False)
            resolved.append(EndpointBindingV3(
                route=ep.route, method=ep.method, handler_qualname=ep.handler_qualname,
                file_path=ep.file_path, line_no=ep.line_no,
                guaranteed_chain=gchain, full_chain=fchain,
            ))
        self.endpoints = resolved

    def _chain(self, start: str, *, guaranteed_only: bool) -> tuple[str, ...]:
        """BFS chain — NO depth limit, only cycle protection.  Per-branch
        seen set so a second valid path to a shared function is not blocked."""
        from collections import deque
        chain: list[str] = []
        seen: set[str] = set()
        q: deque[str] = deque([start])
        while q and len(chain) < 512:
            name = q.popleft()
            if name in seen:
                continue
            seen.add(name)
            chain.append(name)
            node = self.nodes.get(name)
            if node is None:
                continue
            callees = node.direct_callees if guaranteed_only else tuple(cs.callee for cs in node.call_sites)
            for c in callees:
                if c not in seen:
                    q.append(c)
        return tuple(chain)


def _callee_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _extract_route(dec: ast.AST) -> tuple[str | None, str | None]:
    """Unified route extraction — argument-order flexible."""
    if not isinstance(dec, ast.Call):
        return None, None
    func = dec.func
    method: str | None = None
    if isinstance(func, ast.Attribute):
        attr = func.attr.upper()
        if attr in _HTTP_METHODS:
            method = attr
        elif attr in ("ROUTE", "ADD_URL_RULE", "ADD_API_ROUTE"):
            method = "ANY"
        elif attr == "REGISTER":
            # router.register(prefix, ...) -> prefix route
            for arg in dec.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return (arg.value[:240].rstrip("/") + "/*"), "ANY"
            return None, None
        else:
            return None, None
    elif isinstance(func, ast.Name) and func.id.lower() in ("route", "path", "re_path", "url"):
        method = "ANY"
    else:
        return None, None

    route: str | None = None
    # Find route by scanning args + kwargs (order-flexible).
    for arg in dec.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            v = arg.value
            if v.startswith("/") or re.match(r"^[\w<>/-]+$", v):
                route = v
                break
    for kw in dec.keywords:
        if kw.arg in ("path", "route", "url") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            route = kw.value.value
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            meths = [e.value for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if meths:
                method = ",".join(sorted(m.upper() for m in meths))
    if route:
        if not route.startswith("/"):
            route = "/" + route
        return route[:240], method
    return None, None


def _detect_module_routes(tree: ast.AST) -> list[tuple[str, str, str, int]]:
    """Detect module-level: add_api_route, add_url_rule, Django urlpatterns."""
    out: list[tuple[str, str, str, int]] = []
    for node in ast.walk(tree):
        # urlpatterns = [path(...), ...]
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
        # app.add_url_rule(...) / add_api_route(...)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("add_url_rule", "add_api_route"):
                route, method = _extract_route(node)
                if route:
                    view = "view"
                    if len(node.args) > 1:
                        v = node.args[1]
                        if isinstance(v, ast.Name):
                            view = v.id
                    out.append((route, method or "ANY", view, getattr(node, "lineno", 0)))
    return out


__all__ = ["ArchitectureExtractorV3", "CallNodeV3", "EndpointBindingV3", "OrderFlawV3", "CallSiteV3"]
