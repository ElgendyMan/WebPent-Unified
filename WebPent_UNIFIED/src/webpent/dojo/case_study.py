"""U-DOJO-10: the case study writer — sparring matches become lessons.

Laws honored here:
- L-6 ADVERSARIAL HONESTY: the case study records the result as measured,
  red wins included, with no varnish.
- L-7 LESSON FEEDBACK: every exported study is advisory material carrying
  the match's lessons verbatim.
- L-10 NO IMPACT ON REAL CAMPAIGNS: exports are sanitized; secret-shaped
  strings are redacted before anything leaves the Dojo.
"""

from __future__ import annotations

import re

from webpent.dojo.scenario_library import Scenario
from webpent.dojo.sparring import SparringMatchResult

#: secret-shaped strings never survive an export (L-10)
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # bearer values first, so "Authorization: Bearer X" loses X before the
    # header pattern consumes only the word "Bearer"
    (re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{6,}"), "[REDACTED_BEARER]"),
    # the scheme token after the header name travels with the value, so the
    # pattern consumes one token beyond the header name itself
    (re.compile(r"(?i)authorization\s*[:=]\s*\S+(?:\s+\S+)?"), "[REDACTED_AUTH]"),
    (re.compile(r"(?i)cookie\s*[:=]\s*\S+"), "[REDACTED_COOKIE]"),
    (
        re.compile(r"(?i)(?:api[_-]?key|token|password|secret|session)\s*[:=]\s*\S+"),
        "[REDACTED_SECRET]",
    ),
)

#: bounded export length
_MAX_TEXT = 800

_ADVISORY_BANNER = (
    "> advisory: Dojo training material. Simulated target only — no live "
    "host, no operational use, no request outside the sandbox."
)


def _redact(text: str) -> str:
    for pattern, marker in _REDACTIONS:
        text = pattern.sub(marker, text)
    return text[:_MAX_TEXT]


class CaseStudyWriter:
    """Renders one sparring match as a sanitized Markdown case study."""

    @staticmethod
    def from_match(match: SparringMatchResult, scenario: Scenario) -> str:
        lines: list[str] = [
            f"# Dojo Case Study: {match.scenario_id}",
            "",
            _ADVISORY_BANNER,
            "",
            "## Scenario",
            "",
            f"- family: {scenario.family}",
            f"- difficulty: {scenario.difficulty}",
            f"- ground truth: class={scenario.vuln_class} "
            f"location={scenario.location} signature={scenario.signature}",
            "",
            "## Match record",
            "",
            f"- winner: {match.winner}",
            f"- red score: {match.red_score}",
            f"- blue score: {match.blue_score}",
            "",
            "| round | pattern | red success | red score | blue score |",
            "|---|---|---|---|---|",
        ]
        for log in match.rounds_log:
            lines.append(
                f"| {log.round_no} | {log.pattern} | {log.red_success} "
                f"| {log.red_score} | {log.blue_score} |"
            )
        lines.extend(["", "## Lessons", ""])
        for lesson in match.lessons:
            lines.append(f"- {_redact(lesson)}")
        lines.extend(
            [
                "",
                "## Sanitization notice",
                "",
                "Secret-shaped strings are replaced with [REDACTED_*] markers "
                "before export; nothing in this document reaches a real target.",
                "",
            ]
        )
        return "\n".join(lines)
