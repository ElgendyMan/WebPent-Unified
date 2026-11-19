"""Explicit target-neutral generic web adapter package."""

from webpent.adapters.generic_web.adapter import (
    GENERIC_WEB_CASE_ID,
    GENERIC_WEB_PROFILE_ID,
    GENERIC_WEB_TARGET_ID,
    GenericWebAdapter,
    build_generic_web_registration,
)

__all__ = [
    "GENERIC_WEB_CASE_ID",
    "GENERIC_WEB_PROFILE_ID",
    "GENERIC_WEB_TARGET_ID",
    "GenericWebAdapter",
    "build_generic_web_registration",
]
