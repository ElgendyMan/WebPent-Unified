"""Compatibility shim for the Juice Shop target adapter.

The target-local implementation lives under ``webpent.adapters.juice_shop``.
"""
from webpent.adapters.juice_shop.adapter import *  # noqa: F401,F403
from webpent.adapters.juice_shop.adapter import __all__ as __all__
