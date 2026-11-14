"""DOM XSS — static taint analysis from source to sink (V2 §2, 2026-10-29).

Deliberately bounded, deliberately ordinal. Real hunters win DOM XSS by
following data from a source (``location.hash``...) to a sink
(``innerHTML``...) inside minified bundles; a full dataflow engine is out
of scope and would drown in false precision. What is implemented:

  * intra-function flow: statements scanned in order, a taint set of local
    names carried forward, assignments from sources propagate taint,
  * inter-procedural flow: a tainted value passed as the Nth argument of a
    function defined in the same script taints that function's Nth
    parameter — at most ``max_depth`` (default 3) hops,
  * known sanitizers (``encodeURIComponent``, ``DOMPurify.sanitize``...)
    break taint: an encoded sink is NOT a flow.

Everything is deterministic string/AST work — no LLM, no network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["TaintFlow", "find_taint_flows"]

_MAX_FUNCTION_SCANS = 500


# (dotted object path, property) — window.location.hash and location.hash
# are the same source; the matcher normalises the leading window/document.
_SOURCE_MEMBERS: tuple[tuple[str, str, str], ...] = (
    # (object chain, property, source label)
    ("location", "hash", "location.hash"),
    ("location", "search", "location.search"),
    ("location", "href", "location.href"),
    ("document", "referrer", "document.referrer"),
    ("document", "baseURI", "document.baseURI"),
    ("document", "documentURI", "document.documentURI"),
    ("window", "name", "window.name"),
    ("window", "location", "window.location"),  # full location object
)

_SOURCE_CALLS: tuple[tuple[str, str], ...] = (
    # (callee chain, label) — matched on CallExpression callee chains.
    ("localStorage.getItem", "localStorage.getItem"),
    ("sessionStorage.getItem", "sessionStorage.getItem"),
    ("window.localStorage.getItem", "localStorage.getItem"),
    ("window.sessionStorage.getItem", "sessionStorage.getItem"),
)

_SANITIZER_CALLS: frozenset[str] = frozenset(
    {
        "encodeURI",
        "encodeURIComponent",
        "escape",
        "DOMPurify.sanitize",
        "dompurify.sanitize",
        "sanitizeHtml",
        "sanitize-html",
        "he.encode",
        "angular.$sanitize",
        "lodash.escape",
        "_.escape",
    }
)

# Sinks: (kind, matcher). Member sinks are written assignments
# (obj.prop = tainted); call sinks are calls with a tainted argument.
_HTML_MEMBER_SINKS: frozenset[str] = frozenset({"innerHTML", "outerHTML"})
_HTML_CALL_SINKS: frozenset[str] = frozenset(
    {"document.write", "document.writeln", "document.writeLn"}
)
_EXEC_CALL_SINKS: frozenset[str] = frozenset({"eval", "Function"})
_TIMER_CALL_SINKS: frozenset[str] = frozenset({"setTimeout", "setInterval", "window.setTimeout", "window.setInterval"})
_NAV_MEMBER_SINKS: frozenset[str] = frozenset({"href"})  # location.href = tainted
_NAV_CALL_SINKS: frozenset[str] = frozenset({"location.assign", "location.replace", "window.location.assign", "window.location.replace", "open", "window.open"})
_JQUERY_CALL_SINKS: frozenset[str] = frozenset({"html", "append", "prepend", "after", "before"})


@dataclass(frozen=True)
class TaintFlow:
    """One source→sink path with enough context to build a probe."""

    source: str
    sink: str
    sink_kind: str  # html | exec | timer | navigation | jquery
    function: str  # "<script>" for top-level flows
    path: tuple[str, ...]  # human-readable steps, source first
    depth: int = 0  # inter-procedural hops used (0 = intra-function)
    line: int = 0


def _member_chain(node) -> str | None:  # type: ignore[no-untyped-def]
    """Return the dotted chain of a MemberExpression path, else None."""
    parts: list[str] = []
    current = node
    while True:
        if getattr(current, "type", "") == "MemberExpression":
            prop = getattr(current, "property", None)
            if getattr(current, "computed", False):
                return None  # dynamic member access: not matchable
            prop_name = getattr(prop, "name", None)
            if not isinstance(prop_name, str):
                return None
            parts.append(prop_name)
            current = getattr(current, "object", None)
        elif getattr(current, "type", "") == "Identifier":
            parts.append(getattr(current, "name", ""))
            break
        elif getattr(current, "type", "") == "ThisExpression":
            parts.append("this")
            break
        else:
            return None
    parts.reverse()
    return ".".join(parts)


def _normalise_chain(chain: str) -> str:
    for lead in ("window.",):
        if chain.startswith(lead):
            alt = chain[len(lead):]
            return alt  # window.x and x are the same binding in browsers
    return chain


def _match_source_member(node) -> str | None:  # type: ignore[no-untyped-def]
    if getattr(node, "type", "") != "MemberExpression":
        return None
    chain = _member_chain(node)
    if not chain:
        return None
    for obj_path, prop, label in _SOURCE_MEMBERS:
        for candidate in (f"{obj_path}.{prop}", f"window.{obj_path}.{prop}", f"document.{obj_path}.{prop}"):
            if chain == candidate:
                if obj_path == "document" and prop in {"referrer", "baseURI", "documentURI"}:
                    if chain.startswith("document"):
                        return label
                    continue
                if obj_path == "window":
                    if chain == f"window.{prop}":
                        return label
                    continue
                return label
    return None


def _match_source_call(node) -> str | None:  # type: ignore[no-untyped-def]
    if getattr(node, "type", "") != "CallExpression":
        return None
    chain = _member_chain(getattr(node, "callee", None))
    if not chain:
        return None
    chain_n = _normalise_chain(chain)
    for callee, label in _SOURCE_CALLS:
        if chain_n == _normalise_chain(callee):
            return label
    return None


def _is_sanitizer_call(node) -> bool:  # type: ignore[no-untyped-def]
    if getattr(node, "type", "") != "CallExpression":
        return False
    chain = _member_chain(getattr(node, "callee", None))
    if not chain:
        return False
    chain_n = _normalise_chain(chain)
    return chain_n in _SANITIZER_CALLS or chain in _SANITIZER_CALLS


def _match_sink(node) -> tuple[str, str] | None:  # type: ignore[no-untyped-def]
    """Classify a node as a sink; returns (sink, kind) or None."""
    ntype = getattr(node, "type", "")

    if ntype == "AssignmentExpression":
        op = getattr(node, "operator", "")
        if op != "=":
            return None
        left = getattr(node, "left", None)
        chain = _member_chain(left) if left is not None else None
        if chain:
            chain_n = _normalise_chain(chain)
            prop = chain_n.rsplit(".", 1)[-1]
            if prop in _HTML_MEMBER_SINKS:
                return chain_n, "html"
            if chain_n in {"location.href", "location", "document.location.href", "window.location.href"}:
                return chain_n, "navigation"
        else:
            # el.innerHTML = tainted where el is a call result
            # (getElementById/querySelector): the chain cannot cross the
            # CallExpression, so match the final non-computed property.
            prop = getattr(getattr(left, "property", None), "name", None)
            if isinstance(prop, str) and prop in _HTML_MEMBER_SINKS:
                return prop, "html"
    elif ntype == "CallExpression":
        callee = getattr(node, "callee", None)
        chain = _member_chain(callee)
        if not chain:
            # jQuery-style chained calls: $("#x").html(tainted) — the
            # member chain cannot cross the CallExpression object, so
            # fall back to the final non-computed property name. Only
            # the DOM-writing jQuery verbs are matched this way.
            prop = getattr(getattr(callee, "property", None), "name", None)
            if isinstance(prop, str) and prop in _JQUERY_CALL_SINKS:
                return prop, "jquery"
            return None
        chain_n = _normalise_chain(chain)
        if chain_n in _HTML_CALL_SINKS:
            return chain_n, "html"
        if chain_n in _EXEC_CALL_SINKS:
            return chain_n, "exec"
        if chain_n in _TIMER_CALL_SINKS:
            return chain_n, "timer"
        if chain_n in _NAV_CALL_SINKS:
            return chain_n, "navigation"
        # jQuery-style: $(sel).html(tainted) — chain's LAST member is the
        # jQuery sink method.
        last = chain_n.rsplit(".", 1)[-1]
        if last in _JQUERY_CALL_SINKS:
            return chain_n, "jquery"
    return None


def _postmessage_source(node) -> str | None:  # type: ignore[no-untyped-def]
    """``event.data`` / ``e.data`` inside a message handler is a source."""
    if getattr(node, "type", "") != "MemberExpression":
        return None
    obj = getattr(node, "object", None)
    if getattr(obj, "type", "") != "Identifier":
        return None
    name = getattr(obj, "name", "")
    if name in {"event", "e", "ev", "msg"} and getattr(getattr(node, "property", None), "name", "") == "data":
        return "postMessage.data"
    return None


def _walk(expr):  # type: ignore[no-untyped-def]
    """Yield every node in an expression subtree (including it)."""
    from .parser import iter_nodes

    yield from iter_nodes(expr)


def _expr_find(expr, tainted: set[str]):  # type: ignore[no-untyped-def]
    """Classify an expression: ("source", label) | ("tainted", name) | None.

    Sanitizer calls anywhere in the expression break taint entirely —
    one ``encodeURIComponent(...)`` wrapper is the developer's intent.
    """
    for node in _walk(expr):
        if _is_sanitizer_call(node):
            return None
    for node in _walk(expr):
        source = _match_source_member(node) or _match_source_call(node) or _postmessage_source(node)
        if source:
            return "source", source
        if getattr(node, "type", "") == "Identifier":
            name = getattr(node, "name", "")
            if name in tainted:
                return "tainted", name
    return None


def _collect_functions(tree) -> dict[str, object]:  # type: ignore[no-untyped-def]
    """Map function names defined at the top level of the script to nodes."""
    registry: dict[str, object] = {}
    body = list(getattr(tree, "body", []))
    for stmt in body:
        stype = getattr(stmt, "type", "")
        if stype == "FunctionDeclaration" and getattr(getattr(stmt, "id", None), "name", None):
            registry[stmt.id.name] = stmt
        elif stype == "VariableDeclaration":
            for decl in getattr(stmt, "declarations", []):
                fname = getattr(getattr(decl, "id", None), "name", None)
                init = getattr(decl, "init", None)
                if fname and getattr(init, "type", "") in {
                    "FunctionExpression",
                    "ArrowFunctionExpression",
                }:
                    registry[fname] = init
        elif stype == "ExpressionStatement":
            expr = getattr(stmt, "expression", None)
            if getattr(expr, "type", "") == "AssignmentExpression":
                left = getattr(expr, "left", None)
                lname = getattr(left, "name", None)
                right = getattr(expr, "right", None)
                if lname and getattr(right, "type", "") in {
                    "FunctionExpression",
                    "ArrowFunctionExpression",
                }:
                    registry[lname] = right
    return registry


def _param_names(fn_node) -> list[str]:  # type: ignore[no-untyped-def]
    names: list[str] = []
    for param in getattr(fn_node, "params", []) or []:
        name = getattr(param, "name", None)
        names.append(name if isinstance(name, str) else f"<complex:{getattr(param, 'type', '?')}>")
    return names


def _function_label(node, fallback: str) -> str:  # type: ignore[no-untyped-def]
    return getattr(getattr(node, "id", None), "name", None) or fallback


def _node_loc(node) -> int:  # type: ignore[no-untyped-def]
    loc = getattr(node, "loc", None)
    return int(getattr(loc, "start", None).line or 0) if loc else 0


def _scan_function(
    fn_node,
    label: str,
    registry: dict[str, object],
    tainted_args: set[str],
    flows: list[TaintFlow],
    depth: int,
    max_depth: int,
) -> None:
    """Scan one function body (or the script's top level) for flows."""
    if depth > max_depth:
        return
    tainted: set[str] = set(tainted_args)
    params = _param_names(fn_node)
    if label == "<script>":
        body = list(getattr(fn_node, "body", []))
    else:
        body = list(getattr(getattr(fn_node, "body", None), "body", []) or [])
    for stmt in body:
        _scan_statement(stmt, label, registry, tainted, flows, depth, max_depth)
    # Nested sinks: a sink inside an if/try/loop body is just as real as a
    # top-level one. The ordered statement pass above exists for taint
    # PROPAGATION (assignment order matters); this full walk exists for
    # sink DISCOVERY at any nesting depth. Duplicates are removed by the
    # caller's (source, sink, function) key.
    for node in _walk(getattr(fn_node, "body", fn_node)):
        ntype = getattr(node, "type", "")
        if ntype in {"AssignmentExpression", "CallExpression"}:
            if ntype == "CallExpression":
                _check_interprocedural(node, label, registry, tainted, flows, depth, max_depth)
            _check_sink(node, label, tainted, flows, depth)


_BLOCK_CONTAINERS = {
    "BlockStatement": ("body",),
    "IfStatement": ("consequent", "alternate"),
    "ForStatement": ("body",),
    "ForInStatement": ("body",),
    "ForOfStatement": ("body",),
    "WhileStatement": ("body",),
    "DoWhileStatement": ("body",),
    "TryStatement": ("block", "handler", "finalizer"),
    "SwitchStatement": ("cases",),
    "SwitchCase": ("consequent",),
    "CatchClause": ("body",),
}


def _iter_statements(stmt):  # type: ignore[no-untyped-def]
    """Yield a statement and, for container statements, recurse."""
    yield stmt
    stype = getattr(stmt, "type", "")
    for attr in _BLOCK_CONTAINERS.get(stype, ()):
        child = getattr(stmt, attr, None)
        if child is None:
            continue
        if isinstance(child, list):
            for item in child:
                if item is not None and getattr(item, "type", ""):
                    yield from _iter_statements(item)
        elif getattr(child, "type", ""):
            yield from _iter_statements(child)


def _scan_statement(stmt, label, registry, tainted, flows, depth, max_depth):  # type: ignore[no-untyped-def]  # noqa: ANN001
    # Walk EVERY statement in this subtree (ifs, loops, try blocks) — a
    # sink buried in an if-block is still a sink.
    for node in _iter_statements(stmt):
        stype = getattr(node, "type", "")
        if stype in _BLOCK_CONTAINERS:
            continue  # containers themselves are not assignments/calls
        if stype == "VariableDeclaration":
            for decl in getattr(node, "declarations", []):
                name = getattr(getattr(decl, "id", None), "name", None)
                init = getattr(decl, "init", None)
                if name and init is not None:
                    _handle_assignment(init, name, label, registry, tainted, flows, depth, max_depth, decl)
        elif stype == "ExpressionStatement":
            expr = getattr(node, "expression", None)
            etype = getattr(expr, "type", "")
            if etype == "AssignmentExpression":
                # plain identifier assignment
                name = getattr(getattr(expr, "left", None), "name", None)
                if name:
                    _handle_assignment(
                        getattr(expr, "right", None), name, label, registry, tainted,
                        flows, depth, max_depth, expr,
                    )
                else:
                    _check_sink(expr, label, tainted, flows, depth)
            elif etype in {"CallExpression", "MemberExpression"}:
                if etype == "CallExpression":
                    # render(location.hash): a plain top-level call into a
                    # same-script function extends the flow interprocedurally.
                    _check_interprocedural(expr, label, registry, tainted, flows, depth, max_depth)
                _check_sink(expr, label, tainted, flows, depth)


def _handle_assignment(rhs, name, label, registry, tainted, flows, depth, max_depth, node):  # type: ignore[no-untyped-def]  # noqa: ANN001
    _check_interprocedural(rhs, label, registry, tainted, flows, depth, max_depth)
    result = _expr_find(rhs, tainted)
    if result is None:
        tainted.discard(name)  # reassignment from a clean value cleans the name
        return
    kind, value = result
    if kind == "source":
        tainted.add(name)
        # remember where the taint came from so the path is real
        _taint_origin[name] = (value, _node_loc(node))
    elif kind == "tainted":
        tainted.add(name)
        # propagate the origin (x = y where y came from a source); the
        # previous function's entry for this name must not leak through
        _taint_origin[name] = _taint_origin.get(value, (value, _node_loc(node)))


_taint_origin: dict[str, tuple[str, int]] = {}


def _check_sink(node, label, tainted, flows, depth):  # type: ignore[no-untyped-def]  # noqa: ANN001
    sink = _match_sink(node)
    if not sink:
        return
    sink_str, sink_kind = sink
    # the tainted expression is the RHS (assignment) or arg 0 (call)
    if getattr(node, "type", "") == "AssignmentExpression":
        candidates = [getattr(node, "right", None)]
    else:
        candidates = list(getattr(node, "arguments", []) or [])[:1]
    for expr in candidates:
        if expr is None:
            continue
        result = _expr_find(expr, tainted)
        if result is None:
            continue
        kind, value = result
        if kind == "source":
            origin = value
        else:
            origin = _taint_origin.get(value, (value, 0))[0]
        flows.append(
            TaintFlow(
                source=origin,
                sink=sink_str,
                sink_kind=sink_kind,
                function=label,
                path=(origin, sink_str),
                depth=depth,
                line=_node_loc(node),
            )
        )


def _check_interprocedural(expr, label, registry, tainted, flows, depth, max_depth):  # type: ignore[no-untyped-def]  # noqa: ANN001
    """A tainted argument into a same-script function extends the flow."""
    if getattr(expr, "type", "") != "CallExpression":
        return
    callee_name = getattr(getattr(expr, "callee", None), "name", None)
    if not isinstance(callee_name, str) or callee_name not in registry:
        return
    if depth + 1 > max_depth:
        return
    fn_node = registry[callee_name]
    args = list(getattr(expr, "arguments", []) or [])
    params = _param_names(fn_node)
    taint_for_callee: set[str] = set()
    for ordinal, arg in enumerate(args):
        if ordinal >= len(params):
            break
        result = _expr_find(arg, tainted)
        if result is not None:
            taint_for_callee.add(params[ordinal])
            # the callee's flows must report the TRUE origin, not the
            # parameter name: carry the caller's source across the hop
            kind, value = result
            if kind == "source":
                _taint_origin[params[ordinal]] = (value, _node_loc(arg))
            else:
                _taint_origin[params[ordinal]] = _taint_origin.get(value, (value, _node_loc(arg)))
    if not taint_for_callee:
        return
    callee_label = f"{callee_name}()"
    _scan_function(fn_node, callee_label, registry, taint_for_callee, flows, depth + 1, max_depth)


def find_taint_flows(tree, *, max_depth: int = 3) -> list[TaintFlow]:  # type: ignore[no-untyped-def]
    """Find all bounded source→sink flows in a parsed script.

    Deterministic; intra-function flows first (the common case), then
    inter-procedural hops up to ``max_depth``.
    """
    _taint_origin.clear()
    flows: list[TaintFlow] = []
    registry = _collect_functions(tree)
    # top-level scan
    _scan_function(tree, "<script>", registry, set(), flows, 0, max_depth)
    # explicit function scans (a function never called at top level can
    # still be reached by the app's own wiring)
    for index, (name, fn_node) in enumerate(registry.items()):
        if index >= _MAX_FUNCTION_SCANS:
            break
        if getattr(fn_node, "type", "") in {"FunctionExpression", "ArrowFunctionExpression", "FunctionDeclaration"}:
            _scan_function(fn_node, f"{name}()", registry, set(), flows, 0, max_depth)
    _taint_origin.clear()
    # dedupe by (source, sink, function)
    seen: set[tuple[str, str, str]] = set()
    unique: list[TaintFlow] = []
    for flow in flows:
        key = (flow.source, flow.sink, flow.function)
        if key in seen:
            continue
        seen.add(key)
        unique.append(flow)
    return unique
