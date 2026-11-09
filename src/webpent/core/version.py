"""System version and data-format compatibility."""
from __future__ import annotations

__version__ = "2.0.0"
DATA_FORMAT_VERSION = 2


def is_compatible(file_format_version: int) -> tuple[bool, str]:
    """Check if a stored file's format version is compatible with current code."""
    if file_format_version == DATA_FORMAT_VERSION:
        return True, "ok"
    if file_format_version < DATA_FORMAT_VERSION:
        return False, f"stale_format_v{file_format_version}_needs_upgrade_to_v{DATA_FORMAT_VERSION}"
    return False, f"future_format_v{file_format_version}_code_is_v{DATA_FORMAT_VERSION}"
