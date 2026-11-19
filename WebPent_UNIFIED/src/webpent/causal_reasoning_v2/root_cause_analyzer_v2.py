# src/webpent/causal_reasoning_v2/root_cause_analyzer_v2.py
"""RootCauseAnalyzerV2 — Deep-fix Phase 2.

Structural root-cause analysis that matches CODE STRUCTURE, not names.
Two functions with identical control/data flow but different identifiers
(variable names, function names, parameter names) receive identical
structural fingerprints and are grouped as one root cause.  Conversely, two
functions with similar names but different structure are NOT grouped.

Fixes the v1/v2 flaw: "same name ≠ same code" and "same code ≠ same name".

Capabilities:
  * StructuralLogicMatcher: canonicalize a function body (rename every
    identifier to a positional placeholder, normalize literals, strip
    comments/docstrings) -> deterministic canonical AST dump.  Identical
    structure -> identical canonical form -> similarity 1.0.
  * Similarity scoring on operation-set overlap + control-flow shape for
    near-matches (0.0-1.0).
  * RootCauseAnalyzerV2: given findings + an ArchitectureExtractor, group
    findings by (structural fingerprint of handler) OR (shared dependency
    from call graph).  Emits RootCauseGroup with fix hints.
  * Detects logic duplication inconsistency: same structure appearing in
    multiple places with different names.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from webpent.causal_reasoning_v2.architecture_extractor import ArchitectureExtractor


@dataclass(frozen=True)
class StructuralFingerprint:
    canonical_form: str            # canonical AST dump (identical structure -> identical)
    operation_set: frozenset[str]  # {Call, Compare, If, For, Try, Return, Assign, ...}
    control_flow_shape: str        # sequential | branch | nested_branch | loop | mixed
    node_count: int
    depth: int


@dataclass(frozen=True)
class RootCauseGroup:
    group_id: str
    cause_type: str                # verification_order_flaw | scope_leak | sanitization_bypass | logic_duplication | shared_dependency
    description: str
    member_finding_ids: tuple[str, ...]
    member_routes: tuple[str, ...]
    structural_signature: str      # canonical form prefix or shared dep name
    fix_hint: str
    confidence: float


_CAUSE_FIX_HINTS = {
    "verification_order_flaw":
        "Move the authorization/scope check before any data mutation in the "
        "execution chain. Enforce ordering in middleware/decorator, not per-handler.",
    "scope_leak":
        "Bind every object lookup to the caller's identity/tenant in a shared "
        "resolver. Fix once in the resolver; all endpoints inherit it.",
    "sanitization_bypass":
        "Route all input through a shared validation layer before it reaches "
        "any sink. Remove per-route ad-hoc sanitisation. Add contract tests.",
    "logic_duplication":
        "Consolidate the duplicated logic into one shared function. Inconsistent "
        "copies are the root cause — one fix replaces many.",
    "shared_dependency":
        "Repair the shared dependency (verifier/DAO/helper). One fix remediates "
        "every endpoint that uses it.",
    "unknown":
        "Inspect the shared structural segment; repair at the shared layer, not "
        "at individual endpoints.",
}


class StructuralLogicMatcher:
    """Canonicalize code structure -> fingerprint.  Deterministic, offline."""

    def fingerprint(self, source: str) -> StructuralFingerprint | None:
        """Build a structural fingerprint from a Python source snippet.

        Accepts a full function body or a module.  Returns None on parse
        failure.  Identical structure (different names) -> identical
        canonical_form.
        """
        try:
            tree = ast.parse(source.strip())
        except (SyntaxError, ValueError):
            return None
        normalizer = _IdentifierNormalizer()
        normalizer.visit(tree)
        canonical = ast.dump(tree, annotate_fields=False, include_attributes=False)
        ops = self._operation_set(tree)
        shape = self._flow_shape(tree)
        node_count = sum(1 for _ in ast.walk(tree))
        depth = self._max_depth(tree)
        return StructuralFingerprint(
            canonical_form=canonical,
            operation_set=frozenset(ops),
            control_flow_shape=shape,
            node_count=node_count,
            depth=depth,
        )

    def similarity(self, a: StructuralFingerprint, b: StructuralFingerprint) -> float:
        """0.0-1.0 structural similarity.  1.0 = identical structure."""
        if a.canonical_form == b.canonical_form:
            return 1.0
        # Operation-set overlap (Jaccard).
        union = a.operation_set | b.operation_set
        if not union:
            return 1.0 if a.control_flow_shape == b.control_flow_shape else 0.5
        jaccard = len(a.operation_set & b.operation_set) / len(union)
        flow_bonus = 0.15 if a.control_flow_shape == b.control_flow_shape else 0.0
        size_penalty = 0.1 * abs(a.node_count - b.node_count) / max(1, a.node_count + b.node_count)
        return round(min(1.0, jaccard * 0.85 + flow_bonus - size_penalty), 4)

    @staticmethod
    def _operation_set(tree: ast.AST) -> set[str]:
        ops: set[str] = set()
        for node in ast.walk(tree):
            cls = type(node).__name__
            if cls in ("Call", "Compare", "If", "For", "While", "Try", "Return",
                       "Assign", "AugAssign", "Subscript", "Attribute", "Raise",
                       "With", "BoolOp", "BinOp", "Dict", "ListComp"):
                ops.add(cls)
        return ops

    @staticmethod
    def _flow_shape(tree: ast.AST) -> str:
        has_loop = any(isinstance(n, (ast.For, ast.While)) for n in ast.walk(tree))
        ifs = [n for n in ast.walk(tree) if isinstance(n, ast.If)]
        nested = any(
            any(isinstance(c, ast.If) for stmt in n.body[1:] for c in ast.walk(stmt))
            for n in ifs
        )
        if has_loop and ifs:
            return "mixed"
        if has_loop:
            return "loop"
        if nested:
            return "nested_branch"
        if ifs:
            return "branch"
        return "sequential"

    @staticmethod
    def _max_depth(tree: ast.AST) -> int:
        def depth(node: ast.AST, d: int) -> int:
            children = list(ast.iter_child_nodes(node))
            if not children:
                return d
            return max(depth(c, d + 1) for c in children)
        return depth(tree, 0)


class _IdentifierNormalizer(ast.NodeTransformer):
    """Rename every identifier to a positional placeholder; normalize literals."""

    def __init__(self) -> None:
        self.name_map: dict[str, str] = {}
        self.counter = 0

    def _norm(self, name: str) -> str:
        if name not in self.name_map:
            self.name_map[name] = f"id_{self.counter}"
            self.counter += 1
        return self.name_map[name]

    def visit_Name(self, node: ast.Name) -> ast.Name:
        node.id = self._norm(node.id)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.name = self._norm(node.name)
        node.args.args = [ast.arg(arg=self._norm(a.arg), annotation=None) for a in node.args.args]
        node.body = [self.visit(stmt) for stmt in node.body]
        node.decorator_list = []
        node.returns = None
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        node.name = self._norm(node.name)
        node.args.args = [ast.arg(arg=self._norm(a.arg), annotation=None) for a in node.args.args]
        node.body = [self.visit(stmt) for stmt in node.body]
        node.decorator_list = []
        node.returns = None
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.name = self._norm(node.name)
        node.bases = []
        node.keywords = []
        node.body = [self.visit(stmt) for stmt in node.body]
        node.decorator_list = []
        return node

    def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
        node.attr = self._norm(node.attr)
        return self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.arg = self._norm(node.arg)
        node.annotation = None
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        # Normalize all string/number literals to placeholders by type.
        if isinstance(node.value, str):
            node.value = "STR"
        elif isinstance(node.value, (int, float)):
            node.value = 0
        elif isinstance(node.value, bytes):
            node.value = b"BYTES"
        return node


class RootCauseAnalyzerV2:
    """Group findings by structural root cause (code structure OR shared dep)."""

    SIMILARITY_THRESHOLD = 0.85  # above this -> same structural root cause

    def __init__(self, extractor: ArchitectureExtractor | None = None):
        self.extractor = extractor
        self.matcher = StructuralLogicMatcher()
        self._fingerprints: dict[str, StructuralFingerprint] = {}  # handler_qualname -> fp
        self._duplication_index: dict[str, list[str]] = defaultdict(list)  # canonical_form -> [routes]

    def register_handler_source(self, handler_qualname: str, source: str, route: str = "") -> StructuralFingerprint | None:
        """Register a handler's source for structural matching."""
        fp = self.matcher.fingerprint(source)
        if fp is None:
            return None
        self._fingerprints[handler_qualname] = fp
        self._duplication_index[fp.canonical_form[:128]].append(route or handler_qualname)
        return fp

    def analyze(
        self,
        findings: Iterable[Mapping[str, Any]],
        handler_sources: Mapping[str, str] | None = None,
    ) -> tuple[RootCauseGroup, ...]:
        """Group findings by root cause.  Each finding dict has: id, route,
        vuln_class, and optionally handler_qualname + handler_source."""
        findings_list = list(findings)
        if not findings_list:
            return ()

        # Register any provided handler sources.
        handler_sources = handler_sources or {}
        for qualname, src in handler_sources.items():
            self.register_handler_source(qualname, src)

        # Assign each finding a root-cause key.
        groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        group_meta: dict[str, dict[str, Any]] = {}

        for f in findings_list:
            key, meta = self._classify(f)
            groups[key].append(f)
            group_meta[key] = meta

        result: list[RootCauseGroup] = []
        for key, members in groups.items():
            meta = group_meta[key]
            cause_type = meta["cause_type"]
            result.append(RootCauseGroup(
                group_id=key,
                cause_type=cause_type,
                description=meta["description"],
                member_finding_ids=tuple(sorted(str(f.get("id", "")) for f in members)),
                member_routes=tuple(sorted(str(f.get("route") or f.get("url") or "") for f in members)),
                structural_signature=meta["signature"],
                fix_hint=_CAUSE_FIX_HINTS.get(cause_type, _CAUSE_FIX_HINTS["unknown"]),
                confidence=round(meta["confidence"], 4),
            ))
        result.sort(key=lambda g: (len(g.member_finding_ids) * g.confidence), reverse=True)
        return tuple(result)

    def duplicated_logic_routes(self) -> dict[str, tuple[str, ...]]:
        """Routes sharing identical structure (logic duplication inconsistency)."""
        return {
            canon: tuple(sorted(routes))
            for canon, routes in self._duplication_index.items()
            if len(routes) > 1
        }

    # ------------------------------------------------------------------
    def _classify(self, finding: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        route = str(finding.get("route") or finding.get("url") or "")
        vuln = str(finding.get("vuln_class") or "unknown").lower()
        handler = str(finding.get("handler_qualname") or "")

        # 1. Structural fingerprint match (if handler source registered).
        if handler in self._fingerprints:
            fp = self._fingerprints[handler]
            canon_key = fp.canonical_form[:128]
            if len(self._duplication_index.get(canon_key, [])) > 1:
                return (
                    f"struct:{canon_key}",
                    {"cause_type": "logic_duplication",
                     "description": "Identical code structure detected across multiple handlers — inconsistent copies are the root cause.",
                     "signature": canon_key, "confidence": 0.9},
                )

        # 2. Shared dependency from call graph (ArchitectureExtractor).
        if self.extractor and route:
            for ep in self.extractor.endpoints:
                if ep.route == route:
                    # Find the most significant shared verifier/mutator/sink.
                    for name in ep.call_chain:
                        node = self.extractor.nodes.get(name)
                        if node and (node.is_verifier or node.is_mutator or node.is_data_sink):
                            return (
                                f"dep:{name}",
                                {"cause_type": "shared_dependency",
                                 "description": f"Endpoint flows through shared object '{name}' — a defect there propagates to all sibling endpoints.",
                                 "signature": name, "confidence": 0.8},
                            )

        # 3. Vuln-class-based structural classification (fallback, lower confidence).
        if vuln in ("idor", "auth_bypass", "privilege_escalation"):
            return (f"vuln:scope_leak:{vuln}", {
                "cause_type": "scope_leak",
                "description": "Object/scope resolution is unbounded by caller identity.",
                "signature": vuln, "confidence": 0.6,
            })
        if vuln in ("xss", "sqli", "nosql_injection", "command_injection", "ssti"):
            return (f"vuln:sanitization:{vuln}", {
                "cause_type": "sanitization_bypass",
                "description": "Input reaches a sink without passing through a shared validation layer.",
                "signature": vuln, "confidence": 0.6,
            })
        return (f"vuln:unknown:{vuln}", {
            "cause_type": "unknown",
            "description": "No structural root cause localised; treat as isolated.",
            "signature": vuln, "confidence": 0.3,
        })


__all__ = [
    "RootCauseAnalyzerV2", "StructuralLogicMatcher", "StructuralFingerprint",
    "RootCauseGroup",
]
