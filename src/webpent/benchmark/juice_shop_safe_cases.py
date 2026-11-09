"""Compatibility shim for the Juice Shop profile case inventory.

The target-local implementation lives under ``webpent.profiles.juice_shop``.
This module remains import-compatible for existing benchmark scripts and tests.
"""
from webpent.profiles.juice_shop.cases import *  # noqa: F401,F403
from webpent.profiles.juice_shop.cases import __all__ as __all__
