"""Compatibility shim for the Juice Shop oracle contracts.

The target-local implementation lives under ``webpent.adapters.juice_shop``.
"""
from webpent.adapters.juice_shop.oracles import *  # noqa: F401,F403
from webpent.adapters.juice_shop.oracles import __all__ as __all__
