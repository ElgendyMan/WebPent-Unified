"""UM-DR-45 K3 — the typing / logging leads, verified by runtime reflection.

The UM-DR-41 lead named four modules with "runtime typing" and "logging
contract" concerns (``Hypothesis`` / ``Iterable`` annotations; ``warn`` arity).
A source read cannot settle them: ``from __future__ import annotations`` makes
every annotation a string that is never evaluated at import, so an annotation
naming a symbol that does not exist at module level imports cleanly and then
breaks the first reflective consumer that calls ``typing.get_type_hints``
(pydantic / dataclass schema generation, runtime type checkers, doc tooling).

These tests perform that reflection for real:

* every function, class, method and dataclass field defined in the three
  modules must resolve through ``typing.get_type_hints``;
* every ``LOGGER.<level>(...)`` call in ``verification/robust.py`` (found by
  AST, so a new call site is covered automatically) must bind against the
  live logger object's method signature.

Measured on a663e37 (UM-DR-45 K3 probe): the two ``shared/`` modules and all
8 logging call sites were already sound — the logging lead is a false positive
on this trunk (UM-DR-41 §5.4 gave ``UnifiedLogger`` the standard-library
aliases with ``(module, message)`` arity). Exactly one defect was live:
``jsintel.api_surface_shadow.shadow_hypothesis_to_state_hypothesis`` annotated
its return as ``"Hypothesis"`` while importing that name only inside the
function body, so ``get_type_hints`` raised ``NameError``.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import typing
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"

TYPING_MODULES = (
    "webpent.jsintel.api_surface_shadow",
    "webpent.shared.cve_advisory",
    "webpent.shared.legacy_disposition",
)
LEVELS = {"debug", "info", "warning", "warn", "error", "exception", "critical"}
# the interface UnifiedLogger documents and every caller relies on
DOCUMENTED_LEVELS = {"debug", "info", "warning", "warn", "error", "critical"}


def _module_symbols(modname: str) -> dict[str, object]:
    """Every function/class defined in the module plus their own methods."""
    module = importlib.import_module(modname)
    short = modname.rsplit(".", 1)[-1]
    found: dict[str, object] = {}
    for name, obj in vars(module).items():
        if getattr(obj, "__module__", None) != modname:
            continue
        if inspect.isfunction(obj) or inspect.isclass(obj):
            found[f"{short}.{name}"] = obj
            if inspect.isclass(obj):
                for mname, member in vars(obj).items():
                    if inspect.isfunction(member) and member.__module__ == modname:
                        found[f"{short}.{name}.{mname}"] = member
    return found


def _unresolvable(modname: str) -> list[str]:
    bad: list[str] = []
    for label, obj in _module_symbols(modname).items():
        try:
            typing.get_type_hints(obj)
        except Exception as exc:  # noqa: BLE001 - the exception type IS the finding
            bad.append(f"{label}: {type(exc).__name__}: {exc}")
    return bad


@pytest.mark.parametrize("modname", TYPING_MODULES)
def test_every_annotation_in_the_named_modules_resolves_at_runtime(modname) -> None:
    symbols = _module_symbols(modname)
    assert len(symbols) >= 15, f"reflection walked only {len(symbols)} symbols of {modname}"
    assert _unresolvable(modname) == []


def test_the_shadow_to_state_converter_is_reflectable() -> None:
    """The concrete defect: the converter is a public wiring helper whose
    return annotation named ``Hypothesis`` without a module-level binding."""
    from webpent.jsintel import api_surface_shadow

    hints = typing.get_type_hints(api_surface_shadow.shadow_hypothesis_to_state_hypothesis)
    assert hints["return"] is not None and hints["return"].__name__ == "Hypothesis"
    assert hints["shadow"].__name__ == "ShadowHypothesis"


def test_logging_call_sites_bind_to_the_live_logger_interface() -> None:
    module = importlib.import_module("webpent.verification.robust")
    tree = ast.parse((SRC / "webpent" / "verification" / "robust.py").read_text(encoding="utf-8"))
    sites = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "LOGGER"
        and node.func.attr in LEVELS
    ]
    assert len(sites) >= 7, "the documented seven-plus call sites must still be walked"
    sentinel = object()
    for node in sites:
        method = getattr(module.LOGGER, node.func.attr)
        kwargs = {kw.arg: sentinel for kw in node.keywords if kw.arg}
        # raises TypeError on an arity mismatch — reported with the line number
        inspect.signature(method).bind(*([sentinel] * len(node.args)), **kwargs)


def test_unified_logger_levels_share_the_module_message_arity() -> None:
    from webpent.verification.robust import UnifiedLogger

    logger = UnifiedLogger()
    for level in sorted(DOCUMENTED_LEVELS):
        sig = inspect.signature(getattr(logger, level))
        assert list(sig.parameters) == ["module", "message"], level
        assert all(p.default is inspect.Parameter.empty for p in sig.parameters.values())
