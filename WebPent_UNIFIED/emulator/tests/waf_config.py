"""Value-aware checks on the emulator's ModSecurity configuration.

The Round-3 war games showed the old test only checked that the string
``setvar:tx.paranoia_level=2`` appears somewhere in the file, so a
behavioral mutation (paranoia 2 -> 1, or the engine flipped to
DetectionOnly) passed the suite. These helpers parse the values, so
the checks fail when the WAF's behavior would actually change.
"""

from __future__ import annotations

import re


def waf_problems(text: str) -> list[str]:
    """Return a list of configuration problems (empty = valid)."""
    problems: list[str] = []
    engine = re.search(r"^\s*SecRuleEngine\s+(\S+)", text, re.MULTILINE)
    if engine is None:
        problems.append("SecRuleEngine directive missing")
    elif engine.group(1) != "On":
        problems.append(
            f"SecRuleEngine must be On, found {engine.group(1)!r}"
        )
    paranoia = re.search(r"setvar:tx\.paranoia_level=(\d+)", text)
    if paranoia is None:
        problems.append("tx.paranoia_level is never set")
    elif paranoia.group(1) != "2":
        problems.append(
            "paranoia_level must be 2, found " + paranoia.group(1)
        )
    return problems


__all__ = ["waf_problems"]
