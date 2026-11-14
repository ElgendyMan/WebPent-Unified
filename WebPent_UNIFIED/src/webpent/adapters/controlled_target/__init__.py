"""Controlled local validation target adapter."""

from .adapter import (
    CONTROLLED_IDOR_CASE_ID,
    CONTROLLED_TARGET_ID,
    ControlledIDORTarget,
    build_controlled_idor_registration,
    build_controlled_idor_target,
    build_controlled_target_spec,
)

__all__ = [
    "CONTROLLED_IDOR_CASE_ID",
    "CONTROLLED_TARGET_ID",
    "ControlledIDORTarget",
    "build_controlled_idor_registration",
    "build_controlled_idor_target",
    "build_controlled_target_spec",
]
