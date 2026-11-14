# src/webpent/tools/registry.py
"""webpent.tools.registry

Dynamic Tool Registry (Plugin System).

Provides a ``@register_tool(name, category)`` decorator for tool wrappers.
Built-in wrappers are discovered lazily and idempotently on the first lookup,
so importing the package does not import optional binaries or emit discovery
warnings. Agents fetch tools by category (for example,
``registry.get_tools("recon")``) instead of hardcoding wrapper imports.

Usage in a tool wrapper::

    from webpent.tools.registry import register_tool

    @register_tool(name="nuclei", category="recon")
    def run_nuclei(url, **kwargs):
        ...

Usage in an agent::

    from webpent.tools.registry import get_tools

    recon_tools = get_tools("recon")
    for tool in recon_tools:
        result = tool["func"](target_url)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ToolEntry:
    """A registered tool with its metadata."""

    name: str
    category: str
    func: Callable[..., Any]
    description: str = ""
    aliases: list[str] = field(default_factory=list)


# Global registry — maps category → list of ToolEntry.
_REGISTRY: dict[str, list[ToolEntry]] = {}

# Reverse index — maps tool name → ToolEntry (for O(1) lookup by name).
_NAME_INDEX: dict[str, ToolEntry] = {}

# Discovery is lazy and idempotent. Importing ``webpent.tools`` must not
# import every optional wrapper or emit warnings before a caller asks for a
# tool. The guard also prevents recursive discovery while wrapper modules are
# importing and registering themselves.
_DISCOVERY_COMPLETE = False
_DISCOVERY_IN_PROGRESS = False


def register_tool(
    name: str,
    category: str,
    description: str = "",
    aliases: list[str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that registers a tool function in the global registry.

    Args:
        name: Unique tool name (e.g., ``"nuclei"``).
        category: Tool category (e.g., ``"recon"``, ``"exploitation"``).
        description: Optional human-readable description.
        aliases: Optional list of alternative names.

    Returns:
        The original function unchanged (decorator is registration-only).

    Example::

        @register_tool(name="nuclei", category="recon")
        def run_nuclei(url: str, **kwargs) -> list[dict]:
            ...
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        # Sprint I-1, item 2.5 (M3 v1.1 §5.3): gate any extension of the
        # hardcoded module list auto_discover() enumerates. The two
        # packages below are exactly the ones that list currently names
        # (webpent.tools.recon.*, webpent.tools.exploitation.*) — a
        # registration from anywhere else is, by definition, an
        # extension. Fail-closed: denied unless foreign_report_writer_
        # access is explicitly enabled on the resolved spine config.
        origin_module = getattr(func, "__module__", "") or ""
        _ALLOWLISTED_TOOL_PACKAGES = ("webpent.tools.recon.", "webpent.tools.exploitation.")
        if not origin_module.startswith(_ALLOWLISTED_TOOL_PACKAGES):
            from webpent.production.production_spine import _foreign_writer_access_enabled
            from webpent.shared.exceptions import ForeignWriterAccessDenied

            if not _foreign_writer_access_enabled():
                raise ForeignWriterAccessDenied(
                    gate="tools.registry.extension",
                    detail=(
                        f"tool {name!r} registered from module {origin_module!r}, "
                        "outside the allowlisted webpent.tools.recon/exploitation packages"
                    ),
                )
        entry = ToolEntry(
            name=name,
            category=category,
            func=func,
            description=description or func.__doc__ or "",
            aliases=aliases or [],
        )
        if category not in _REGISTRY:
            _REGISTRY[category] = []
        _REGISTRY[category].append(entry)
        _NAME_INDEX[name] = entry
        for alias in entry.aliases:
            _NAME_INDEX[alias] = entry
        logger.debug("Registered tool: %s (category=%s)", name, category)
        return func

    return decorator


def get_tools(category: str) -> list[ToolEntry]:
    """Return all registered tools in ``category``.

    Args:
        category: Tool category (e.g., ``"recon"``).

    Returns:
        A list of :class:`ToolEntry` objects. Empty list if no tools
        are registered in the category.
    """
    ensure_discovered()
    return list(_REGISTRY.get(category, []))


def get_tool(name: str) -> ToolEntry | None:
    """Look up a tool by name or alias.

    Args:
        name: Tool name or alias.

    Returns:
        The :class:`ToolEntry`, or ``None`` if not found.
    """
    ensure_discovered()
    return _NAME_INDEX.get(name)


def get_all_categories() -> list[str]:
    """Return all registered categories."""
    ensure_discovered()
    return list(_REGISTRY.keys())


def list_all_tools() -> dict[str, list[ToolEntry]]:
    """Return the entire registry (category → tools)."""
    ensure_discovered()
    return {cat: list(tools) for cat, tools in _REGISTRY.items()}


def clear_registry() -> None:
    """Clear registered tools and mark discovery as stale (for testing)."""
    global _DISCOVERY_COMPLETE
    _REGISTRY.clear()
    _NAME_INDEX.clear()
    _DISCOVERY_COMPLETE = False


def diagnostics() -> dict[str, Any]:
    """Return redaction-safe registry state for local debugging.

    The result contains only names and counters; it never includes tool
    arguments, environment variables, credentials, or process output.
    """
    return {
        "discovery_complete": _DISCOVERY_COMPLETE,
        "discovery_in_progress": _DISCOVERY_IN_PROGRESS,
        "category_count": len(_REGISTRY),
        "tool_count": len(_NAME_INDEX),
        "categories": sorted(_REGISTRY),
        "tools": sorted(_NAME_INDEX),
    }


def ensure_discovered() -> None:
    """Populate built-in wrappers on first registry access."""
    if not _DISCOVERY_COMPLETE and not _DISCOVERY_IN_PROGRESS:
        auto_discover()


def auto_discover() -> None:
    """Import all tool wrapper modules to trigger @register_tool decorators.

    V6 Kali-Ready P0: Per-import try/except — a single import failure
    (e.g. missing optional dependency) no longer halts the entire loop.
    Each tool is imported independently so valid tools still register.
    """
    global _DISCOVERY_COMPLETE, _DISCOVERY_IN_PROGRESS
    if _DISCOVERY_COMPLETE or _DISCOVERY_IN_PROGRESS:
        return

    import importlib
    import sys

    _DISCOVERY_IN_PROGRESS = True

    modules = [
        ("webpent.tools.recon", "nuclei"),
        ("webpent.tools.recon", "katana"),
        ("webpent.tools.recon", "httpx"),
        ("webpent.tools.recon", "ffuf"),
        ("webpent.tools.recon", "arjun"),
        ("webpent.tools.recon", "subfinder"),
        # ULTIMATE PLAN 2026-10-27, proposal 5: the archive-discovery and
        # bounded infra-probe wrappers. Both are settings-gated (default
        # off) and scope-checked before any subprocess spawn — same
        # wrapper contract as the entries above.
        ("webpent.tools.recon", "gau"),
        ("webpent.tools.recon", "nmap"),
        ("webpent.tools.exploitation", "dalfox"),
        ("webpent.tools.exploitation", "sqlmap"),
        ("webpent.tools.exploitation", "ysoserial"),
        ("webpent.tools.exploitation", "phpggc"),
    ]

    try:
        for package, name in modules:
            module_path = f"{package}.{name}"
            try:
                # ``clear_registry`` is used by tests and plugin reloaders.
                # Python keeps imported modules in sys.modules, so a plain
                # import would not execute decorators a second time and the
                # registry would remain empty. Reload only an already-loaded
                # built-in wrapper; first discovery still uses a normal import.
                if module_path in sys.modules:
                    importlib.reload(sys.modules[module_path])
                else:
                    importlib.import_module(module_path)
            except Exception as exc:
                logger.warning(
                    "Tool auto-discovery: failed to import %s.%s (non-fatal): %s",
                    package,
                    name,
                    exc,
                )
    finally:
        _DISCOVERY_IN_PROGRESS = False
        _DISCOVERY_COMPLETE = True

    logger.info(
        "Tool registry auto-discovery complete: %d categories, %d tools",
        len(_REGISTRY),
        len(_NAME_INDEX),
    )
