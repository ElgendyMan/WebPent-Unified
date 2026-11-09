# src/webpent/causal_reasoning_v2/structural_matcher_v2.py
"""StructuralMatcherV2 — Red-Team fix Phase 2.

Fixes vs v1 matcher:
  1. SEMANTIC abstraction: keeps operation types (Call, Compare, If, Return,
     Assign, Subscript, Raise) in the canonical form — so `A=B; C=D` does NOT
     falsely match `if X: return Y` (they have different operation sets).
  2. Dynamic thresholds: >=0.95 auto-group; 0.85-0.95 flagged for human
     review; <0.85 ignored.  No false auto-grouping.
  3. Minimum-size guard: functions with <8 AST nodes get NO global fingerprint
     (too short — any match is coincidental).
  4. Context check: two structurally-similar functions are grouped only if
     they share the same ROLE (both verifiers, or both mutators, or both
     handlers).  Same structure + different role = NOT same root cause.
  5. Deterministic canonical form with operation-type prefixes.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

# Operation types that carry semantic meaning and are preserved in canonical form.
_SEMANTIC_OPS = frozenset({
    "Call", "Compare", "If", "For", "While", "Try", "Return", "Assign",
    "AugAssign", "Subscript", "Attribute", "Raise", "With", "BoolOp",
    "BinOp", "Dict", "ListComp", "SetComp", "GeneratorExp", "Lambda",
    "Assert", "Delete", "Import", "ImportFrom", "Global", "Nonlocal",
    "Yield", "Await",
})

MIN_AST_NODES_FOR_FINGERPRINT = 8

# Auto-group thresholds.
THRESHOLD_AUTO_GROUP = 0.95
THRESHOLD_HUMAN_REVIEW = 0.85


@dataclass(frozen=True)
class StructuralFingerprintV2:
    canonical_form: str
    operation_signature: tuple[str, ...]   # ordered sequence of semantic ops
    operation_set: frozenset[str]
    control_flow_shape: str
    node_count: int
    role: str              # verifier | mutator | handler | data_sink | unknown
    depth: int


class StructuralMatcherV2:
    """Semantic structural matcher with dynamic thresholds + role guard."""

    def fingerprint(self, source: str, role: str = "unknown") -> StructuralFingerprintV2 | None:
        try:
            tree = ast.parse(source.strip())
        except (SyntaxError, ValueError):
            return None
        normalizer = _SemanticNormalizer()
        normalizer.visit(tree)
        canonical = ast.dump(tree, annotate_fields=False, include_attributes=False)
        ops = self._operation_sequence(tree)
        op_set = frozenset(ops)
        node_count = sum(1 for _ in ast.walk(tree))
        # Minimum-size guard: too short -> no global fingerprint (return None).
        if node_count < MIN_AST_NODES_FOR_FINGERPRINT:
            return None
        return StructuralFingerprintV2(
            canonical_form=canonical,
            operation_signature=tuple(ops),
            operation_set=op_set,
            control_flow_shape=self._flow_shape(tree),
            node_count=node_count,
            role=role,
            depth=self._max_depth(tree),
        )

    def classify_match(self, a: StructuralFingerprintV2, b: StructuralFingerprintV2) -> str:
        """Return 'auto_group' | 'human_review' | 'no_match'.

        Role guard: different roles -> never auto-group (even if structure
        matches — a verifier and a mutator with same shape are NOT same cause).
        """
        if a.role != "unknown" and b.role != "unknown" and a.role != b.role:
            return "no_match"  # role mismatch — different root cause by definition
        sim = self.similarity(a, b)
        if sim >= THRESHOLD_AUTO_GROUP:
            return "auto_group"
        if sim >= THRESHOLD_HUMAN_REVIEW:
            return "human_review"
        return "no_match"

    def similarity(self, a: StructuralFingerprintV2, b: StructuralFingerprintV2) -> float:
        if a.canonical_form == b.canonical_form:
            return 1.0
        # Operation-set Jaccard (semantic — not just identifiers).
        union = a.operation_set | b.operation_set
        if not union:
            return 1.0 if a.control_flow_shape == b.control_flow_shape else 0.3
        jaccard = len(a.operation_set & b.operation_set) / len(union)
        # Operation-sequence order similarity (longest common subsequence ratio).
        seq_sim = self._sequence_similarity(a.operation_signature, b.operation_signature)
        flow_bonus = 0.1 if a.control_flow_shape == b.control_flow_shape else 0.0
        size_penalty = 0.15 * abs(a.node_count - b.node_count) / max(1, a.node_count + b.node_count)
        score = 0.45 * jaccard + 0.45 * seq_sim + flow_bonus - size_penalty
        return round(min(1.0, max(0.0, score)), 4)

    @staticmethod
    def _sequence_similarity(seq_a: tuple[str, ...], seq_b: tuple[str, ...]) -> float:
        """LCS length / max length — order-aware sequence similarity."""
        if not seq_a or not seq_b:
            return 0.0
        la, lb = len(seq_a), len(seq_b)
        dp = [[0] * (lb + 1) for _ in range(la + 1)]
        for i in range(1, la + 1):
            for j in range(1, lb + 1):
                if seq_a[i - 1] == seq_b[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        return dp[la][lb] / max(la, lb)

    @staticmethod
    def _operation_sequence(tree: ast.AST) -> list[str]:
        ops: list[str] = []
        for node in ast.walk(tree):
            cls = type(node).__name__
            if cls in _SEMANTIC_OPS:
                ops.append(cls)
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


class _SemanticNormalizer(ast.NodeTransformer):
    """Rename identifiers to placeholders, but KEEP operation-type nodes intact."""

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
        if isinstance(node.value, str):
            node.value = "STR"
        elif isinstance(node.value, (int, float)):
            node.value = 0
        elif isinstance(node.value, bytes):
            node.value = b"BYTES"
        return node


__all__ = [
    "StructuralMatcherV2", "StructuralFingerprintV2",
    "THRESHOLD_AUTO_GROUP", "THRESHOLD_HUMAN_REVIEW", "MIN_AST_NODES_FOR_FINGERPRINT",
]
