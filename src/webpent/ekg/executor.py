"""webpent.ekg.executor — M7 (Part 4 §9): deterministic validation and
argv-typed execution of knowledge items.

The contract (Part 4 §9): "no LLM arbitrary shell; LLM selects action +
fills typed schema, deterministic code validates".

* :func:`validate_fill` — deterministic validation of ANY fill (LLM- or
  human-originated) against the item's typed argument schema: required
  presence, type coercion checks, enum membership, pattern match,
  length bounds. Invalid ⇒ the full error list; nothing executes.
* :func:`render_argv` — renders the template with a VALIDATED fill into
  an argument vector. Each fill becomes exactly ONE argv token — a fill
  like ``"; rm -rf /"`` stays one token and never reaches a shell
  (there is no shell).
* :func:`execute_knowledge_item` — the full gate chain: validate fill →
  authorization capability (the caller's authorize callback — M2's
  ActionAuthority vocabulary) → budget (max_runs) → argv-typed runner.
  The default runner is the frozen argv-typed ``run_command`` (which
  type-rejects any non-list and passes ``shell=False`` explicitly);
  tests inject a spy. Cleanup is invoked best-effort after execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from webpent.ekg.schema import KnowledgeItem

__all__ = [
    "ExecutionResult",
    "execute_knowledge_item",
    "render_argv",
    "validate_fill",
]

_PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}", re.IGNORECASE)

Authorize = Callable[[str, str], bool]
Runner = Callable[[list[str], int], Any]


def validate_fill(
    item: KnowledgeItem, fill: Mapping[str, Any] | None
) -> tuple[dict[str, str], list[str]]:
    """Validate a fill against the item's argument schema.

    Returns ``(coerced, errors)`` — ``coerced`` is non-empty only when
    ``errors`` is empty. Types are coerced to their argv string form
    (integers/booleans rendered deterministically).
    """
    fill = fill if isinstance(fill, Mapping) else {}
    coerced: dict[str, str] = {}
    errors: list[str] = []
    for spec in item.argument_schema:
        raw = fill.get(spec.name)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            if spec.required:
                errors.append(f"missing_required:{spec.name}")
            continue
        if spec.type == "integer":
            if isinstance(raw, bool) or not isinstance(raw, int):
                errors.append(f"type_mismatch:{spec.name}:integer")
                continue
            value = str(raw)
        elif spec.type == "boolean":
            if not isinstance(raw, bool):
                errors.append(f"type_mismatch:{spec.name}:boolean")
                continue
            value = "true" if raw else "false"
        elif spec.type == "enum":
            value = str(raw)
            if value not in spec.enum_values:
                errors.append(
                    f"enum_violation:{spec.name}:not in {spec.enum_values[:8]}"
                )
                continue
        else:  # string
            if not isinstance(raw, str):
                errors.append(f"type_mismatch:{spec.name}:string")
                continue
            value = raw
        if len(value) > spec.max_length:
            errors.append(f"too_long:{spec.name}:{len(value)}>{spec.max_length}")
            continue
        if spec.pattern:
            try:
                if not re.fullmatch(spec.pattern, value):
                    errors.append(f"pattern_mismatch:{spec.name}")
                    continue
            except re.error:
                errors.append(f"invalid_pattern_declared:{spec.name}")
                continue
        coerced[spec.name] = value
    extra = set(fill) - {spec.name for spec in item.argument_schema}
    if extra:
        errors.append(f"undeclared_arguments:{sorted(extra)[:8]}")
    return coerced, errors


def render_argv(item: KnowledgeItem, coerced: Mapping[str, Any]) -> list[str]:
    """Render the template with a validated fill — one token per value."""
    def _substitute(token: str) -> str:
        def _replace(match: re.Match[str]) -> str:
            name = match.group(1)
            return str(coerced.get(name, match.group(0)))

        return _PLACEHOLDER_RE.sub(_replace, token)

    return [_substitute(token) for token in item.safe_execution_template]


@dataclass
class ExecutionResult:
    """One knowledge-item execution outcome (never raises for policy)."""

    item_id: str
    item_version: str
    status: str
    argv: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stdout: Any = None
    budget_remaining: int = 0
    cleanup_invoked: bool = False
    authorization_capability: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "item_version": self.item_version,
            "status": self.status,
            "argv": list(self.argv),
            "errors": list(self.errors),
            "budget_remaining": self.budget_remaining,
            "cleanup_invoked": self.cleanup_invoked,
            "authorization_capability": self.authorization_capability,
        }


class _Budget:
    """Per-(item, engagement) run budget, enforced in-process."""

    def __init__(self) -> None:
        self._spent: dict[str, int] = {}

    def try_spend(self, key: str, max_runs: int) -> tuple[bool, int]:
        spent = self._spent.get(key, 0)
        if spent >= max_runs:
            return False, max_runs - spent
        self._spent[key] = spent + 1
        return True, max_runs - spent - 1


_BUDGETS = _Budget()


def default_runner(argv: list[str], timeout: int) -> Any:
    """The frozen argv-typed runner (list[str]-only, shell=False)."""
    from webpent.tools.utils.subprocess import run_command

    return run_command(argv, timeout=timeout)


def execute_knowledge_item(
    item: KnowledgeItem,
    fill: Mapping[str, Any] | None,
    *,
    engagement_id: str = "",
    authorize: Authorize | None = None,
    runner: Runner | None = None,
    cleanup: Callable[[str], None] | None = None,
) -> ExecutionResult:
    """The full gate chain: validate → authorize → budget → execute.

    Refusal statuses (never exceptions): ``invalid_fill``,
    ``authorization_refused``, ``budget_exhausted``. Success:
    ``executed``. The runner receives ONLY the rendered argv list.
    """
    budget_key = f"{engagement_id}:{item.id}:{item.version}"
    coerced, errors = validate_fill(item, fill)
    if errors:
        return ExecutionResult(
            item_id=item.id,
            item_version=item.version,
            status="invalid_fill",
            errors=errors,
            authorization_capability=item.authorization_capability,
        )

    if authorize is not None:
        try:
            allowed = bool(authorize(item.authorization_capability, engagement_id))
        except Exception as exc:  # noqa: BLE001 — fail-closed authorization
            return ExecutionResult(
                item_id=item.id,
                item_version=item.version,
                status="authorization_refused",
                errors=[f"authorizer_error:{type(exc).__name__}"],
                authorization_capability=item.authorization_capability,
            )
        if not allowed:
            return ExecutionResult(
                item_id=item.id,
                item_version=item.version,
                status="authorization_refused",
                errors=[f"capability_not_granted:{item.authorization_capability}"],
                authorization_capability=item.authorization_capability,
            )

    allowed, remaining = _BUDGETS.try_spend(budget_key, item.max_runs)
    if not allowed:
        return ExecutionResult(
            item_id=item.id,
            item_version=item.version,
            status="budget_exhausted",
            errors=[f"max_runs:{item.max_runs}"],
            budget_remaining=0,
            authorization_capability=item.authorization_capability,
        )

    argv = render_argv(item, coerced)
    resolved_runner = runner or default_runner
    try:
        stdout = resolved_runner(argv, item.timeout_seconds)
        status = "executed"
    except Exception as exc:  # noqa: BLE001 — runner errors are outcomes
        stdout = None
        status = "runner_error"
        errors = [f"runner_error:{type(exc).__name__}"]

    cleanup_invoked = False
    if cleanup is not None and item.cleanup != "none":
        try:
            cleanup(item.cleanup)
            cleanup_invoked = True
        except Exception:  # noqa: BLE001 — cleanup is best-effort
            pass

    return ExecutionResult(
        item_id=item.id,
        item_version=item.version,
        status=status,
        argv=argv,
        errors=errors,
        stdout=stdout,
        budget_remaining=remaining,
        cleanup_invoked=cleanup_invoked,
        authorization_capability=item.authorization_capability,
    )
