"""DOM XSS — JS parsing with a fail-closed AST budget (V2 §2, 2026-10-29).

Beautifies minified bundles with ``jsbeautifier`` and parses them with
``esprima`` (pure Python). The one hard rule of the module: a script whose
AST exceeds ``max_nodes`` nodes is REFUSED, never partially analysed — a
half-parsed 5 MB bundle would produce flows that look like conclusions when
they are fragments. Callers must treat :class:`AstBudgetExceeded` as a
skip-with-reason, not an error to retry with a bigger budget.
"""

from __future__ import annotations

from dataclasses import dataclass

import esprima
import jsbeautifier

__all__ = ["AstBudgetExceeded", "ParsedScript", "beautify", "count_nodes", "parse_script", "iter_nodes"]

_DEFAULT_BEAUTIFY_OPTIONS = jsbeautifier.default_options()
_DEFAULT_BEAUTIFY_OPTIONS.indent_size = 2
_DEFAULT_BEAUTIFY_OPTIONS.preserve_newlines = True

_MAX_SOURCE_CHARS = 4_000_000


class AstBudgetExceeded(Exception):
    """The script's AST node count exceeds the configured ceiling."""


@dataclass(frozen=True)
class ParsedScript:
    """A successfully parsed (and bounded) script."""

    tree: object
    node_count: int
    beautified: bool


def beautify(source: str) -> str:
    """Reformat minified JS; plain formatting, never a semantic change."""
    return jsbeautifier.beautify(source, _DEFAULT_BEAUTIFY_OPTIONS)


def iter_nodes(root):  # type: ignore[no-untyped-def]
    """Yield every esprima AST node under ``root`` including ``root``."""
    import esprima.nodes

    node_types = (esprima.nodes.Node,)

    def _push(value) -> None:  # type: ignore[no-untyped-def]
        # attribute values can be nodes, lists of nodes, or (rarely, e.g.
        # nested patterns) lists of lists — recurse until nodes appear.
        if isinstance(value, node_types):
            stack.append(value)
        elif isinstance(value, list):
            for item in value:
                _push(item)

    stack: list = [root] if not isinstance(root, list) else list(root)
    while stack:
        node = stack.pop()
        if node is None:
            continue
        yield node
        for key in node.keys():
            _push(getattr(node, key))


def count_nodes(root) -> int:  # type: ignore[no-untyped-def]
    return sum(1 for _ in iter_nodes(root))


def parse_script(source: str, *, max_nodes: int, beautify_first: bool = True) -> ParsedScript:
    """Parse ``source`` under a hard node budget; refuse above it.

    Fail-closed on all three refusal paths (budget, parse error, oversized
    input) — the caller decides what "skipped" means downstream, this module
    never degrades to a partial tree.
    """
    text = str(source or "")
    if len(text) > _MAX_SOURCE_CHARS:
        raise AstBudgetExceeded(f"source exceeds {_MAX_SOURCE_CHARS} chars")
    budget = int(max_nodes)
    if budget < 1:
        raise ValueError("max_nodes must be >= 1 (fail-closed)")
    was_beautified = False
    if beautify_first and (";" in text or "{" in text) and "\n" not in text:
        # Heuristic for minified single-line bundles; beautifying is only a
        # readability aid for error messages, parsing works either way.
        try:
            text = beautify(text)
            was_beautified = True
        except Exception:  # noqa: BLE001 — beautify is best-effort formatting
            text = str(source)
    try:
        tree = esprima.parseScript(text)
    except esprima.error_handler.Error as exc:
        raise SyntaxError(f"esprima parse failed: {exc}") from exc
    node_count = count_nodes(tree)
    if node_count > budget:
        raise AstBudgetExceeded(
            f"AST has {node_count} nodes, ceiling is {budget} — refusing (fail-closed)"
        )
    return ParsedScript(tree=tree, node_count=node_count, beautified=was_beautified)
