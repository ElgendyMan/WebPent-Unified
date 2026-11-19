"""webpent.jsintel.js_reversing — Fix ف3.2: real AST-based JS reversing.

Registry contract (CANONICAL_PHASE_REGISTRY M3, Part 4 §5):

    "real JS reversing replacing the 2-regex analyzer (Fix ف3.2)"

The legacy engine (``shared/javascript_intelligence.analyze_javascript_source``,
frozen) is regex-only: it cannot see routes assembled from constants
(``const base = "/api/v2"; fetch(base + "/users")``), misreads comments as
code (``// fetch("/api/comment")`` is a "route"), and cannot verify a sink is
an actual assignment rather than the word ``innerHTML`` appearing in prose.

This module is the structural replacement (new file — the frozen engine is
imported for its redaction helpers and fallback, never edited):

1. **esprima AST pass** (tolerant, with source locations): constant string
   propagation, call-site-verified routes (fetch / axios.method / axios(config)
   / XHR ``.open`` / http clients / ``$.ajax``), template literals (dynamic
   segments rendered as ``{expr}``), route-literal values (the same prefix
   grammar, but values only — never comments), assignment/call-verified
   sinks, literal-verified secret candidates and auth hints.
2. **Graceful degradation** (fail-soft, never fail-closed on analysis):
   esprima unavailable → regex fallback + ``js_ast_unavailable_regex_fallback``;
   unparseable source (minified-odd, TS/JSX, corrupt) → regex fallback +
   ``js_ast_parse_failed_regex_fallback``. The regex engine therefore remains
   the safety net, not the primary.
3. **Same typed output** (``JavaScriptIntelligence``), same in-scope-only and
   redaction contract, same caps — a drop-in for the frozen agent behind the
   ``enable_js_ast_reversing`` flag (default False — flag-off behavior is
   byte-identical to today).
"""

from __future__ import annotations

import re
from typing import Any

from webpent.models.javascript_intelligence import (
    JavaScriptAsset,
    JavaScriptAuthHint,
    JavaScriptIntelligence,
    JavaScriptRoute,
    JavaScriptSecretCandidate,
    JavaScriptSink,
    JavaScriptTargetedTask,
)
from webpent.shared.javascript_intelligence import (
    _MAX_SOURCE_BYTES,
    _evidence_ref,
    _redacted_url,
    _same_origin,
    _sha256,
    _source_map_info,
    analyze_javascript_source,
)

_MAX_ROUTES = 1_000
_MAX_SINKS = 1_000
_MAX_SECRETS = 500
_MAX_HINTS = 500
_MAX_TASKS = 1_500
_MAX_CONSTANTS = 2_000

_ROUTE_LITERAL_SUBSTRING_RE = re.compile(
    r"((?:/)(?:api|graphql|gql|v[0-9]+|auth|admin|internal|private)(?:/[^\"'`\s]{0,300})?)",
    re.IGNORECASE,
)
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_ASSIGNMENT_SECRET_KEY_RE = re.compile(
    r"^(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|private[_-]?key)$",
    re.IGNORECASE,
)
_AUTH_HINT_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("role_check", re.compile(r"^(?:isAdmin|is_admin|adminOnly|role|roles|permissions?)$", re.IGNORECASE)),
    ("auth_header", re.compile(r"^(?:authorization|bearer|accessToken|idToken|jwt)$", re.IGNORECASE)),
    ("csrf_hint", re.compile(r"^(?:csrf|xsrf|antiForgery|anti-forgery|csrfToken|xsrfToken)$", re.IGNORECASE)),
)
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_MEMBER_SINKS = frozenset({"innerHTML", "outerHTML"})
_CALL_SINKS = {
    "insertAdjacentHTML": ("html_injection", "insertAdjacentHTML"),
    "write": ("html_injection", "document.write"),
    "writeln": ("html_injection", "document.write"),
    "eval": ("code_execution", "eval"),
    "assign": ("navigation", "location.assign"),
    "replace": ("navigation", "location.replace"),
    "postMessage": ("message_handling", "postMessage"),
}


class _AstReversingError(RuntimeError):
    """Internal: the AST pass could not complete (caller degrades to regex)."""


def _load_esprima() -> Any:
    """Import esprima lazily so absence degrades instead of crashing import."""
    import esprima  # noqa: PLC0415 - deliberate lazy import (degradation path)

    return esprima


class _Collector:
    """One AST walk producing typed observations for a single asset."""

    def __init__(self, *, source: str, asset_url: str, target_url: str) -> None:
        self.source = source
        self.asset_url = asset_url
        self.target_url = target_url
        self.constants: dict[str, str] = {}
        self.routes: list[JavaScriptRoute] = []
        self._route_keys: set[tuple[str, str]] = set()
        self.route_gaps: list[str] = []
        self.sinks: list[JavaScriptSink] = []
        self._sink_keys: set[tuple[str, int]] = set()
        self.secret_candidates: list[JavaScriptSecretCandidate] = []
        self._secret_keys: set[tuple[str, int, str]] = set()
        self.auth_hints: list[JavaScriptAuthHint] = []
        self._hint_keys: set[tuple[str, str, int]] = set()
        self.dynamic_arguments = 0
        self._seen_literal_values: set[str] = set()

    # -- argument resolution ------------------------------------------------

    def _resolve_string(self, node: Any) -> str | None:
        """Resolve a node to its string value (literals, templates, concat,
        constant identifiers). Returns None when structurally dynamic."""
        if node is None:
            return None
        node_type = getattr(node, "type", None)
        if node_type == "Literal" and isinstance(getattr(node, "value", None), str):
            return node.value
        if node_type == "TemplateLiteral":
            parts: list[str] = []
            quasis = list(getattr(node, "quasis", []) or [])
            expressions = list(getattr(node, "expressions", []) or [])
            for index, quasi in enumerate(quasis):
                cooked = getattr(getattr(quasi, "value", None), "cooked", None)
                parts.append(cooked if isinstance(cooked, str) else "")
                if index < len(expressions):
                    resolved = self._resolve_string(expressions[index])
                    if resolved is None:
                        parts.append("{expr}")
                    else:
                        parts.append(resolved)
            return "".join(parts)
        if node_type == "Identifier":
            return self.constants.get(node.name)
        if node_type == "BinaryExpression" and getattr(node, "operator", None) == "+":
            left = self._resolve_string(node.left)
            right = self._resolve_string(node.right)
            if left is not None and right is not None:
                return left + right
            return None
        return None

    def _line(self, node: Any) -> int:
        loc = getattr(node, "loc", None)
        start = getattr(loc, "start", None) if loc is not None else None
        line = getattr(start, "line", None) if start is not None else None
        return line if isinstance(line, int) and line >= 1 else 1

    # -- recorders ----------------------------------------------------------

    def add_route(self, raw_route: str, method: str, kind: str, node: Any) -> None:
        if len(self.routes) >= _MAX_ROUTES:
            return
        route = _redacted_url(raw_route, self.target_url)
        if not route:
            self.route_gaps.append("js_route_out_of_scope" if raw_route.startswith(("http://", "https://")) else "js_route_rejected")
            return
        key = (route, method.upper())
        if key in self._route_keys:
            return
        self._route_keys.add(key)
        self.routes.append(
            JavaScriptRoute(
                route=route,
                source_asset=self.asset_url,
                method_hint=method.upper(),
                discovery_kind=kind,  # type: ignore[arg-type]
                line=self._line(node),
                in_scope=True,
                evidence_ref=_evidence_ref("route", self.asset_url, f"ast:{kind}:{key[0]}:{key[1]}"),
            )
        )

    def add_sink(self, category: str, sink_name: str, node: Any) -> None:
        line = self._line(node)
        key = (sink_name, line)
        if key in self._sink_keys or len(self.sinks) >= _MAX_SINKS:
            return
        self._sink_keys.add(key)
        snippet = self._snippet(node)
        self.sinks.append(
            JavaScriptSink(
                category=category,  # type: ignore[arg-type]
                sink=sink_name,
                source_asset=self.asset_url,
                line=line,
                snippet_sha256=_sha256(snippet),
                evidence_ref=_evidence_ref("sink", self.asset_url, f"ast:{sink_name}:{line}"),
            )
        )

    def _snippet(self, node: Any) -> str:
        loc = getattr(node, "loc", None)
        start = getattr(loc, "start", None) if loc is not None else None
        end = getattr(loc, "end", None) if loc is not None else None
        if start is None or end is None:
            return ""
        # Source is decoded with "replace"; characters may differ from byte
        # offsets, so fall back to a bounded window around the line start.
        try:
            lines = self.source.split("\n")
            line_index = min(max(start.line - 1, 0), len(lines) - 1)
            return "\n".join(lines[line_index : min(end.line, len(lines))])[:160]
        except Exception:  # noqa: BLE001 - snippet is best-effort evidence only
            return ""

    def add_secret(self, kind: str, raw_value: str, node: Any) -> None:
        line = self._line(node)
        key = (kind, line, _sha256(raw_value))
        if key in self._secret_keys or len(self.secret_candidates) >= _MAX_SECRETS:
            return
        self._secret_keys.add(key)
        self.secret_candidates.append(
            JavaScriptSecretCandidate(
                kind=kind,
                source_asset=self.asset_url,
                line=line,
                value_sha256=_sha256(raw_value),
                confidence="medium" if kind in {"aws_access_key", "private_key"} else "low",
                validation_status="advisory",
                evidence_ref=_evidence_ref("secret", self.asset_url, f"ast:{kind}:{line}:{_sha256(raw_value)}"),
            )
        )

    def add_hint(self, hint: str, identifier: str, node: Any) -> None:
        line = self._line(node)
        clipped = identifier[:120]
        key = (hint, clipped.lower(), line)
        if key in self._hint_keys or len(self.auth_hints) >= _MAX_HINTS:
            return
        self._hint_keys.add(key)
        self.auth_hints.append(
            JavaScriptAuthHint(
                hint=hint,
                identifier=clipped,
                source_asset=self.asset_url,
                line=line,
                evidence_ref=_evidence_ref("auth", self.asset_url, f"ast:{hint}:{clipped}:{line}"),
            )
        )

    def note_literal_value(self, value: str, node: Any) -> None:
        """Route-literal parity scan over resolved string values only."""
        if value in self._seen_literal_values:
            return
        self._seen_literal_values.add(value)
        for match in _ROUTE_LITERAL_SUBSTRING_RE.finditer(value):
            kind = (
                "graphql"
                if match.group(1).lower().split("/", 2)[1] in {"graphql", "gql"}
                else "route_literal"
            )
            self.add_route(match.group(1), "UNKNOWN", kind, node)

    # -- the walk -----------------------------------------------------------

    def visit(self, node: Any) -> None:
        if not isinstance(node, (object,)) or not hasattr(node, "type"):
            return
        handler = getattr(self, f"_on_{node.type}", None)
        if handler is not None:
            handler(node)
        for _, child in vars(node).items():
            self._visit_child(child)

    def _visit_child(self, child: Any) -> None:
        if isinstance(child, list):
            for item in child:
                self._visit_child(item)
        elif hasattr(child, "type"):
            self.visit(child)

    # VariableDeclaration: constant string propagation (multi-level: a
    # constant may be initialized from an expression of earlier constants).
    def _on_VariableDeclaration(self, node: Any) -> None:
        for declarator in getattr(node, "declarations", []) or []:
            name_node = getattr(declarator, "id", None)
            init = getattr(declarator, "init", None)
            if getattr(name_node, "type", None) != "Identifier" or init is None:
                continue
            name = name_node.name
            # Secret candidates: a sensitive variable name bound to a long
            # string literal (the regex engine's ``assignment_secret``).
            if (
                _ASSIGNMENT_SECRET_KEY_RE.match(name)
                and getattr(init, "type", None) == "Literal"
                and isinstance(init.value, str)
                and len(init.value) >= 8
            ):
                self.add_secret("assignment_secret", init.value, node)
            if len(self.constants) >= _MAX_CONSTANTS:
                continue
            resolved = self._resolve_string(init)
            if resolved is not None:
                # First binding wins: a re-declared name is not a sound constant.
                self.constants.setdefault(name, resolved)
                self.note_literal_value(resolved, node)

    # AssignmentExpression: member sinks (innerHTML), location.href, secrets.
    def _on_AssignmentExpression(self, node: Any) -> None:
        left = getattr(node, "left", None)
        if getattr(left, "type", None) == "MemberExpression":
            prop = self._member_property_name(left)
            if prop in _MEMBER_SINKS:
                self.add_sink("dom_xss", prop, node)
            elif prop == "href" and self._member_chain(left) in {"location.href", "window.location.href"}:
                self.add_sink("navigation", "location.assign", node)
            right = getattr(node, "right", None)
            if (
                prop is not None
                and _ASSIGNMENT_SECRET_KEY_RE.match(prop)
                and getattr(right, "type", None) == "Literal"
                and isinstance(right.value, str)
                and len(right.value) >= 8
            ):
                self.add_secret("assignment_secret", right.value, node)

    # CallExpression + NewExpression: routes, call sinks, secrets, hints.
    def _on_CallExpression(self, node: Any) -> None:
        self._handle_call(node)

    def _on_NewExpression(self, node: Any) -> None:
        callee_type = getattr(node, "callee", None)
        if getattr(callee_type, "type", None) == "Identifier" and callee_type.name == "Function":
            self.add_sink("code_execution", "Function", node)

    def _handle_call(self, node: Any) -> None:
        callee = getattr(node, "callee", None)
        arguments = list(getattr(node, "arguments", []) or [])
        callee_type = getattr(callee, "type", None)

        # eval(...) — direct call only (member eval is a different function).
        if callee_type == "Identifier" and callee.name == "eval":
            self.add_sink("code_execution", "eval", node)

        # setTimeout/setInterval with a string first argument.
        if callee_type == "Identifier" and callee.name in {"setTimeout", "setInterval"}:
            if arguments and getattr(arguments[0], "type", None) == "Literal" and isinstance(arguments[0].value, str):
                self.add_sink("code_execution", "setTimeout(string)", node)

        # Bare fetch(...) — the common form (callee is a plain Identifier).
        if callee_type == "Identifier" and callee.name == "fetch":
            self._record_route_call(arguments[0] if arguments else None, "GET", "fetch", node)

        if callee_type == "MemberExpression":
            prop = self._member_property_name(callee)
            obj_chain = self._member_chain(callee)
            obj_name = self._base_object_name(callee)

            # fetch / axios.<method> / http clients / jQuery ajax.
            if prop == "fetch" and obj_name in {"window", "self", "globalThis"}:
                self._record_route_call(arguments[0] if arguments else None, "GET", "fetch", node)
            elif obj_name == "axios" and prop and prop.upper() in _HTTP_METHODS:
                self._record_route_call(arguments[0] if arguments else None, prop.upper(), "axios", node)
            elif obj_name in {"$", "jQuery"} and prop == "ajax":
                self._record_object_route(arguments[0] if arguments else None, node, default_method="GET")
            elif prop and prop.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}:
                if obj_name in {"http", "HttpClient"} or obj_chain.startswith("this.http"):
                    self._record_route_call(arguments[0] if arguments else None, prop.upper(), "http_client", node)
                elif obj_name == "axios":
                    self._record_route_call(arguments[0] if arguments else None, prop.upper(), "axios", node)
            else:
                self._maybe_call_sink(prop, obj_name, node)

            # XHR .open(method, url)
            if prop == "open" and arguments and getattr(arguments[0], "type", None) == "Literal" \
                    and isinstance(arguments[0].value, str) and arguments[0].value.upper() in _HTTP_METHODS:
                url_node = arguments[1] if len(arguments) > 1 else None
                self._record_route_call(url_node, arguments[0].value.upper(), "xhr", node)
            return

        # Bare axios(config) form.
        if callee_type == "Identifier" and callee.name == "axios" and arguments:
            self._record_object_route(arguments[0], node, default_method="UNKNOWN")

    def _maybe_call_sink(self, prop: str | None, obj_name: str, node: Any) -> None:
        """Call-verified sinks with receiver restrictions (no String.replace
        false positives: location.replace requires the location receiver)."""
        if prop is None:
            return
        if prop == "postMessage":
            self.add_sink("message_handling", "postMessage", node)
            return
        if prop == "insertAdjacentHTML" and obj_name not in {"document", "location", "window"}:
            self.add_sink("html_injection", "insertAdjacentHTML", node)
            return
        if prop in {"write", "writeln"} and obj_name == "document":
            self.add_sink("html_injection", "document.write", node)
            return
        if prop in {"assign", "replace"} and obj_name == "location":
            self.add_sink("navigation", f"location.{prop}", node)

    def _record_route_call(self, arg: Any, method: str, kind: str, node: Any) -> None:
        if arg is None:
            return
        resolved = self._resolve_string(arg)
        if resolved is None:
            self.dynamic_arguments += 1
            return
        self.add_route(resolved, method, kind, node)

    def _record_object_route(self, arg: Any, node: Any, *, default_method: str) -> None:
        if getattr(arg, "type", None) != "ObjectExpression":
            return
        url_value: str | None = None
        method = default_method
        for prop in getattr(arg, "properties", []) or []:
            key = getattr(prop, "key", None)
            key_name = getattr(key, "name", None) or getattr(key, "value", None)
            value = getattr(prop, "value", None)
            if key_name == "url":
                resolved = self._resolve_string(value)
                if resolved is None:
                    self.dynamic_arguments += 1
                    return
                url_value = resolved
            elif key_name == "method" and getattr(value, "type", None) == "Literal" \
                    and isinstance(value.value, str) and value.value.upper() in _HTTP_METHODS:
                method = value.value.upper()
        if url_value is not None:
            self.add_route(url_value, method, "axios", node)

    # String literals anywhere: route-literal parity + secret patterns.
    def _on_Literal(self, node: Any) -> None:
        value = getattr(node, "value", None)
        if not isinstance(value, str):
            return
        self.note_literal_value(value, node)
        if _AWS_KEY_RE.search(value):
            self.add_secret("aws_access_key", _AWS_KEY_RE.search(value).group(0), node)
        if _PRIVATE_KEY_RE.search(value):
            self.add_secret("private_key", value[:64], node)

    # Template literals anywhere: route-literal parity (static ones only).
    def _on_TemplateLiteral(self, node: Any) -> None:
        if not getattr(node, "expressions", None):
            quasis = list(getattr(node, "quasis", []) or [])
            cooked = "".join(
                q.value.cooked if isinstance(getattr(q, "value", None), object) and isinstance(q.value.cooked, str) else ""
                for q in quasis
            )
            if cooked:
                self.note_literal_value(cooked, node)

    # IfStatement tests + member properties: auth hints.
    def _on_IfStatement(self, node: Any) -> None:
        test = getattr(node, "test", None)
        for identifier in self._identifiers_in(test):
            self._maybe_hint(identifier, node)

    def _on_MemberExpression(self, node: Any) -> None:
        prop = self._member_property_name(node)
        if prop:
            self._maybe_hint(prop, node)

    def _on_Property(self, node: Any) -> None:
        key = getattr(node, "key", None)
        key_name = getattr(key, "name", None) or getattr(key, "value", None)
        if isinstance(key_name, str):
            self._maybe_hint(key_name, node)
            value = getattr(node, "value", None)
            if (
                _ASSIGNMENT_SECRET_KEY_RE.match(key_name)
                and getattr(value, "type", None) == "Literal"
                and isinstance(value.value, str)
                and len(value.value) >= 8
            ):
                self.add_secret("assignment_secret", value.value, node)

    def _maybe_hint(self, identifier: str, node: Any) -> None:
        for hint, pattern in _AUTH_HINT_RES:
            if pattern.match(identifier):
                self.add_hint(hint, identifier, node)
                return

    def _identifiers_in(self, node: Any) -> list[str]:
        found: list[str] = []

        def walk(inner: Any) -> None:
            if isinstance(inner, list):
                for item in inner:
                    walk(item)
                return
            if getattr(inner, "type", None) == "Identifier":
                found.append(inner.name)
            for _, child in vars(inner).items() if hasattr(inner, "__dict__") else []:
                walk(child)

        walk(node)
        return found

    # -- member helpers -----------------------------------------------------

    @staticmethod
    def _member_property_name(member: Any) -> str | None:
        if getattr(member, "computed", False):
            prop = getattr(member, "property", None)
            if getattr(prop, "type", None) == "Literal" and isinstance(prop.value, str):
                return prop.value
            return None
        prop = getattr(member, "property", None)
        name = getattr(prop, "name", None)
        return name if isinstance(name, str) else None

    def _member_chain(self, member: Any) -> str:
        parts: list[str] = []
        cursor = member
        while getattr(cursor, "type", None) == "MemberExpression":
            prop = self._member_property_name(cursor)
            if prop is None:
                return ""
            parts.append(prop)
            cursor = getattr(cursor, "object", None)
        if getattr(cursor, "type", None) == "Identifier":
            parts.append(cursor.name)
        return ".".join(reversed(parts))

    @staticmethod
    def _base_object_name(member: Any) -> str:
        cursor = getattr(member, "object", None)
        while getattr(cursor, "type", None) == "MemberExpression":
            cursor = getattr(cursor, "object", None)
        name = getattr(cursor, "name", None)
        return name if isinstance(name, str) else ""


def _ast_intelligence(
    *,
    esprima_module: Any,
    source: str,
    asset_url: str,
    target_url: str,
    asset: JavaScriptAsset,
) -> JavaScriptIntelligence:
    try:
        tree = esprima_module.parseScript(
            source, {"tolerant": True, "loc": True, "comment": False, "jsx": False}
        )
    except Exception as exc:  # noqa: BLE001 - esprima raises bare Error
        raise _AstReversingError(str(exc)) from exc

    collector = _Collector(source=source, asset_url=asset_url, target_url=target_url)
    for statement in getattr(tree, "body", []) or []:
        collector.visit(statement)

    gaps: list[str] = list(collector.route_gaps)
    if collector.dynamic_arguments:
        gaps.append("js_ast_dynamic_route_arguments")
    if getattr(tree, "errors", None):
        gaps.append("js_ast_tolerant_errors")
    if not collector.routes:
        gaps.append("no_in_scope_js_routes_observed")

    return JavaScriptIntelligence(
        assets=[asset],
        routes=collector.routes,
        sinks=collector.sinks,
        secret_candidates=collector.secret_candidates,
        auth_hints=collector.auth_hints,
        targeted_tasks=_tasks_from(collector, asset_url),
        coverage_gaps=list(dict.fromkeys(gaps)),
    )


def _tasks_from(collector: _Collector, asset_url: str) -> list[JavaScriptTargetedTask]:
    tasks: list[JavaScriptTargetedTask] = []
    task_keys: set[str] = set()

    def add_task(task_type: str, target_ref: str, reason: str) -> None:
        if len(tasks) >= _MAX_TASKS:
            return
        task_id = _sha256("\0".join((task_type, target_ref, asset_url)))[:32]
        if task_id in task_keys:
            return
        task_keys.add(task_id)
        tasks.append(
            JavaScriptTargetedTask(
                task_id=task_id,
                task_type=task_type,  # type: ignore[arg-type]
                target_ref=target_ref,
                source_asset=asset_url,
                reason=reason,
                in_scope=True,
                destructive=False,
            )
        )

    for route in collector.routes:
        add_task(
            "js_route_mapping",
            route.route,
            f"JS-AST-discovered {route.method_hint} route requires targeted mapping",
        )
    if collector.auth_hints:
        add_task(
            "js_auth_review",
            asset_url,
            "client-side authorization or authentication hint requires bounded review",
        )
    return tasks


def reverse_javascript_source(
    *,
    asset_url: str,
    source: str,
    target_url: str,
    content_type: str = "application/javascript",
    status_code: int = 200,
    source_map_content: str | None = None,
    max_bytes: int = _MAX_SOURCE_BYTES,
) -> JavaScriptIntelligence:
    """AST-first analysis of one in-scope JS asset; regex is the fallback.

    Mirrors the frozen analyzer's gates (same-origin, size cap, redaction,
    typed output). When the AST pass cannot run (esprima missing, source
    unparseable) the frozen regex engine's result is returned with the
    matching ``js_ast_*`` coverage gap so the degradation is observable.
    """
    if not _same_origin(asset_url, target_url):
        return JavaScriptIntelligence(coverage_gaps=["js_asset_out_of_scope"])
    encoded = source.encode("utf-8", "replace")
    if len(encoded) > max_bytes or len(encoded) > _MAX_SOURCE_BYTES:
        digest = _sha256(encoded)
        asset = JavaScriptAsset(
            asset_url=asset_url,
            content_type=content_type,
            status_code=status_code,
            size_bytes=len(encoded),
            content_sha256=digest,
            in_scope=True,
            redacted=True,
        )
        return JavaScriptIntelligence(assets=[asset], coverage_gaps=["js_asset_size_limit"])

    try:
        esprima_module = _load_esprima()
    except ImportError:
        return _regex_fallback(
            asset_url=asset_url,
            source=source,
            target_url=target_url,
            content_type=content_type,
            status_code=status_code,
            source_map_content=source_map_content,
            max_bytes=max_bytes,
            gap="js_ast_unavailable_regex_fallback",
        )

    digest = _sha256(encoded)
    source_map_url, source_map_sources = _source_map_info(
        source, asset_url, target_url, source_map_content
    )
    asset = JavaScriptAsset(
        asset_url=asset_url,
        content_type=content_type,
        status_code=status_code,
        size_bytes=len(encoded),
        content_sha256=digest,
        source_map_url=source_map_url,
        source_map_sources=source_map_sources,
        in_scope=True,
        redacted=True,
    )

    try:
        result = _ast_intelligence(
            esprima_module=esprima_module,
            source=source,
            asset_url=asset_url,
            target_url=target_url,
            asset=asset,
        )
    except _AstReversingError:
        return _regex_fallback(
            asset_url=asset_url,
            source=source,
            target_url=target_url,
            content_type=content_type,
            status_code=status_code,
            source_map_content=source_map_content,
            max_bytes=max_bytes,
            gap="js_ast_parse_failed_regex_fallback",
        )

    gaps = list(result.coverage_gaps)
    if source_map_url and not source_map_content \
            and "source_map_discovered_not_fetched" not in gaps:
        gaps.append("source_map_discovered_not_fetched")
    if result.secret_candidates and "secret_candidates_require_safe_validation" not in gaps:
        gaps.append("secret_candidates_require_safe_validation")
    if result.sinks and "client_side_sinks_require_dataflow_validation" not in gaps:
        gaps.append("client_side_sinks_require_dataflow_validation")
    return result.model_copy(update={"coverage_gaps": [g for g in gaps if g]})


def _regex_fallback(
    *,
    asset_url: str,
    source: str,
    target_url: str,
    content_type: str,
    status_code: int,
    source_map_content: str | None,
    max_bytes: int,
    gap: str,
) -> JavaScriptIntelligence:
    legacy = analyze_javascript_source(
        asset_url=asset_url,
        source=source,
        target_url=target_url,
        content_type=content_type,
        status_code=status_code,
        source_map_content=source_map_content,
        max_bytes=max_bytes,
    )
    gaps = list(legacy.coverage_gaps)
    if gap not in gaps:
        gaps.insert(0, gap)
    return legacy.model_copy(update={"coverage_gaps": gaps})


__all__ = ["reverse_javascript_source"]
