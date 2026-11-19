"""webpent.deception.sqlmap_differential — M6: the sqlmap internal
differential extraction (the M0-documented, M1-deferred residual).

The M1_PHASE_REPORT deferral line: "sqlmap internal differential
extraction → M6 — M0-documented deferral, evidence-heavy".

The defect being closed: ``parse_sqlmap_confirmation(stdout)`` (frozen,
correct for what it does) inspects ONE run's stdout for confirmation
markers. A deceptive target can emit marker-shaped text in EVERY run —
or an operator-supplied template page can match "appears to be" — and
a single-run check cannot tell an injection effect from ambient text.

The differential contract (this module):

* run sqlmap twice over the SAME request shape — once with the benign
  baseline parameter value, once with the candidate payload;
* the injection is CONFIRMED-EVIDENCE only when the candidate run
  carries a confirmation marker AND the baseline run does NOT;
* both-runs-marker ⇒ ``deceptive_both_runs`` (refused — the marker is
  ambient, not an effect);
* neither-run ⇒ ``not_confirmed``;
* candidate-only ⇒ ``differential_confirmed`` plus the EXTRACTED
  injection facts (type lines, parameter, payload) from the candidate
  stdout — the internal evidence pair, not a banner.

The module never launches sqlmap: it extracts from the stdout pair the
caller already captured (the frozen runner owns process execution).
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "SqlmapDifferential",
    "extract_sqlmap_differential",
]

_MARKER_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"is vulnerable", re.IGNORECASE),
    re.compile(r"appears to be", re.IGNORECASE),
    re.compile(r"(?<!not )injectable", re.IGNORECASE),
    re.compile(r"sqlmap identified the following injection point", re.IGNORECASE),
    re.compile(r"^\s*Type:\s*(?:boolean-based|time-based|error-based|UNION query)", re.IGNORECASE | re.MULTILINE),
)
_TYPE_RE = re.compile(
    r"^\s*Type:\s*(boolean-based|time-based|error-based|UNION query|stacked queries|inline queries)[^\n]*",
    re.IGNORECASE | re.MULTILINE,
)
_PARAMETER_RE = re.compile(r"^Parameter:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_PAYLOAD_RE = re.compile(r"^    Payload:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


class SqlmapDifferential(BaseModel):
    """The extracted internal differential for one request pair."""

    model_config = ConfigDict(extra="forbid")

    outcome: str = Field(min_length=3, max_length=40)
    reasons: list[str] = Field(default_factory=list, max_length=10)
    injection_types: list[str] = Field(default_factory=list, max_length=10)
    parameter: str = Field(default="", max_length=120)
    payload: str = Field(default="", max_length=500)
    baseline_marker_matched: bool = False
    candidate_marker_matched: bool = False
    evidence_kind: str = Field(default="", max_length=60)


def _markers(stdout: str) -> list[str]:
    if not stdout:
        return []
    return [pattern.pattern for pattern in _MARKER_RES if pattern.search(stdout)]


def extract_sqlmap_differential(
    *,
    baseline_stdout: str,
    candidate_stdout: str,
) -> SqlmapDifferential:
    """Extract the injection differential from the internal run pair."""
    baseline_markers = _markers(baseline_stdout or "")
    candidate_markers = _markers(candidate_stdout or "")

    if baseline_markers and candidate_markers:
        return SqlmapDifferential(
            outcome="refuted_deceptive",
            reasons=[
                "deceptive_both_runs:the marker is ambient text, not an injection effect",
                f"baseline_matched:{baseline_markers[0][:60]}",
            ],
            baseline_marker_matched=True,
            candidate_marker_matched=True,
        )
    if not candidate_markers:
        return SqlmapDifferential(
            outcome="not_confirmed",
            reasons=["no_confirmation_marker_in_candidate_run"],
            baseline_marker_matched=bool(baseline_markers),
            candidate_marker_matched=False,
        )

    types = [match.group(1).lower() for match in _TYPE_RE.finditer(candidate_stdout)][:10]
    parameter_match = _PARAMETER_RE.search(candidate_stdout)
    payload_match = _PAYLOAD_RE.search(candidate_stdout)
    return SqlmapDifferential(
        outcome="differential_confirmed",
        reasons=[
            "candidate-only confirmation marker over the internal baseline pair",
        ],
        injection_types=types,
        parameter=(parameter_match.group(1) if parameter_match else "")[:120],
        payload=(payload_match.group(1) if payload_match else "")[:500],
        baseline_marker_matched=False,
        candidate_marker_matched=True,
        evidence_kind="sqlmap_internal_differential",
    )
