# src/webpent/tools/__init__.py
"""webpent.tools — Tool wrappers + dynamic registry.

The registry discovers built-in wrappers lazily on first lookup. Importing
this package is side-effect free; agents can use ``registry.get_tools("recon")``
instead of hardcoding imports.
"""
from webpent.tools.registry import (
    ToolEntry,
    auto_discover,
    clear_registry,
    ensure_discovered,
    get_all_categories,
    get_tool,
    get_tools,
    list_all_tools,
    register_tool,
)

__all__ = [
    "ToolEntry",
    "auto_discover",
    "clear_registry",
    "ensure_discovered",
    "get_all_categories",
    "get_tool",
    "get_tools",
    "list_all_tools",
    "register_tool",
]
