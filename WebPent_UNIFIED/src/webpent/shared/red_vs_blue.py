"""webpent.shared.red_vs_blue — red-vs-blue internal detection-hardening loop.

Project Zero-tier item 5: "a separate agent whose job is to try to
'escape' your own detection logic, and the result feeds back to
strengthen detection."

This module is the deterministic "red" side of that loop (the
evasion-attempt generator) plus the feedback wiring into item 6's
Postmortem store (the "strengthen detection" half). It deliberately
composes two already-built Project Zero-tier pieces rather than
re-inventing either:

  * :mod:`webpent.shared.shadow_detector` (item 3) supplies the
    "compare two detector versions" primitive — here used to compare
    a detector against ITSELF run on mutated/evasive inputs instead of
    against a separate canary version. A payload that the detector
    catches in its canonical form but misses in a mutated form is
    exactly a "successful escape": same underlying attack, different
    surface encoding, different verdict.
  * :mod:`webpent.memory.postmortem` (item 6) is where every
    successful escape is recorded as a structured
    ``detection_logic_gap`` — the "strengthen detection" feedback.
    Red-vs-blue without this step is just a fuzzer; wiring it to
    Postmortem is what makes the loop's findings durable and
    aggregable rather than a one-off terminal printout.

The "red agent" itself (:func:`generate_evasion_mutations`) is a
deterministic, dependency-free mutation generator covering the
standard, well-known WAF/filter-evasion technique families (case
variation, inline comments, encoding, whitespace/null-byte insertion,
string-concatenation obfuscation). It is intentionally NOT an LLM —
this keeps the loop fast, free, fully reproducible (same seed payload
always produces the same mutation set), and auditable (every mutation
function is named and can itself be the subject of a Postmortem entry
if it starts wrongly matching too much or too little, i.e. the
mutation generator's OWN false-positive/miss surface is tracked with
the exact same instrument).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from webpent.shared.shadow_detector import extract_detection_keys

# ---------------------------------------------------------------------------
# Red agent: deterministic evasion mutation generator
# ---------------------------------------------------------------------------


def _mutate_case_variation(payload: str) -> str:
    """Alternate character case: ``<script>`` -> ``<ScRiPt>``."""
    return "".join(
        c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)
    )


def _mutate_inline_comment(payload: str) -> str:
    """Insert a SQL inline comment mid-keyword: ``SELECT`` -> ``SEL/**/ECT``.

    Applied generically to the payload's midpoint, not tied to SQL
    keyword detection, so this works as a generic "break up a
    substring match" technique across vuln classes.
    """
    if len(payload) < 4:
        return payload
    mid = len(payload) // 2
    return payload[:mid] + "/**/" + payload[mid:]


def _mutate_whitespace_padding(payload: str) -> str:
    """Insert tabs/newlines instead of plain spaces."""
    return payload.replace(" ", "\t\n")


def _mutate_null_byte_injection(payload: str) -> str:
    """Insert a URL-encoded null byte mid-string: a classic
    string-termination-confusion technique against naive filters.
    """
    if len(payload) < 4:
        return payload
    mid = len(payload) // 2
    return payload[:mid] + "%00" + payload[mid:]


def _mutate_double_url_encoding(payload: str) -> str:
    """Double-encode ``<`` and ``>`` (``%253C`` instead of ``%3C``) — a
    common bypass for a WAF that decodes once and matches raw tags.
    """
    return payload.replace("<", "%253C").replace(">", "%253E")


def _mutate_unicode_homoglyph_padding(payload: str) -> str:
    """Insert a zero-width space (U+200B) between every character —
    breaks naive substring/regex matching without changing the
    payload's rendered/executed meaning in many contexts.
    """
    zwsp = "\u200b"
    return zwsp.join(payload)


def _mutate_string_concat_obfuscation(payload: str) -> str:
    """Break the payload into JS string-concatenation fragments:
    ``alert(1)`` -> ``al'+'ert(1)`` — defeats a literal substring match
    on the function name while remaining semantically equivalent once
    evaluated.
    """
    if len(payload) < 4:
        return payload
    mid = len(payload) // 2
    return payload[:mid] + "'+'" + payload[mid:]


# Registry of (technique_name, mutator_fn). Each entry is independently
# named so a Postmortem record can cite exactly which technique
# succeeded, rather than a generic "evasion worked" note.
_EVASION_TECHNIQUES: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("case_variation", _mutate_case_variation),
    ("inline_comment", _mutate_inline_comment),
    ("whitespace_padding", _mutate_whitespace_padding),
    ("null_byte_injection", _mutate_null_byte_injection),
    ("double_url_encoding", _mutate_double_url_encoding),
    ("unicode_homoglyph_padding", _mutate_unicode_homoglyph_padding),
    ("string_concat_obfuscation", _mutate_string_concat_obfuscation),
)


def generate_evasion_mutations(seed_payload: str) -> dict[str, str]:
    """Deterministically generate the full set of evasion mutations
    for one seed payload.

    Returns:
        A dict of ``{technique_name: mutated_payload}``, one entry per
        technique in :data:`_EVASION_TECHNIQUES`. Deterministic: the
        same ``seed_payload`` always yields the same mutations.
    """
    return {name: fn(seed_payload) for name, fn in _EVASION_TECHNIQUES}


# ---------------------------------------------------------------------------
# Blue side: run the detector against seed + every mutation, find escapes
# ---------------------------------------------------------------------------


@dataclass
class EvasionAttemptResult:
    """One (seed, technique) evasion attempt and whether it escaped."""

    seed_payload_label: str
    """A short, non-sensitive LABEL for the seed (e.g. ``"reflected_xss_basic"``),
    never the raw payload itself — mirrors the taint tracker's
    fingerprint-only posture for anything that might be attacker input."""
    technique: str
    detected_on_seed: bool
    detected_on_mutation: bool
    escaped: bool
    """True iff the detector caught the seed form but missed the
    mutated form — a genuine detection-logic gap, not just "the
    detector never worked on this family at all" (that case is
    ``detected_on_seed=False``, which is a pre-existing gap this loop
    surfaces but doesn't claim credit for finding via evasion)."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "seed_payload_label": self.seed_payload_label,
            "technique": self.technique,
            "detected_on_seed": self.detected_on_seed,
            "detected_on_mutation": self.detected_on_mutation,
            "escaped": self.escaped,
        }


@dataclass
class RedVsBlueReport:
    """Result of running every evasion technique against one detector
    for one seed payload.
    """

    seed_payload_label: str
    attempts: list[EvasionAttemptResult] = field(default_factory=list)

    @property
    def escaped_techniques(self) -> list[EvasionAttemptResult]:
        return [a for a in self.attempts if a.escaped]

    @property
    def escape_rate(self) -> float:
        if not self.attempts:
            return 0.0
        return round(len(self.escaped_techniques) / len(self.attempts), 4)

    def as_dict(self) -> dict[str, Any]:
        return {
            "seed_payload_label": self.seed_payload_label,
            "total_techniques_tried": len(self.attempts),
            "escaped_count": len(self.escaped_techniques),
            "escape_rate": self.escape_rate,
            "attempts": [a.as_dict() for a in self.attempts],
        }


def run_red_vs_blue(
    *,
    seed_payload: str,
    seed_payload_label: str,
    detector: Callable[[str], Any],
) -> RedVsBlueReport:
    """Run the red agent's evasion mutations against one detector.

    Args:
        seed_payload: The raw canonical attack payload (e.g.
            ``"<script>alert(1)</script>"``). Used only in-process to
            drive mutation and detection; never stored by this
            function (see :func:`feed_escapes_to_postmortem` for how
            results are persisted without the raw payload).
        seed_payload_label: A short, non-sensitive label identifying
            the attack family for reporting (e.g.
            ``"reflected_xss_script_tag"``).
        detector: The detection function under test. Called once on
            the raw seed and once per mutation. Its return value is
            normalised via :func:`webpent.shared.shadow_detector.extract_detection_keys`
            — "detected" means the normalised key set is non-empty.

    Returns:
        A :class:`RedVsBlueReport` covering every registered evasion
        technique.
    """
    try:
        seed_result = detector(seed_payload)
    except Exception:  # noqa: BLE001 — a detector crash means "no detection"
        seed_result = None
    detected_on_seed = bool(extract_detection_keys(seed_result))

    attempts: list[EvasionAttemptResult] = []
    for technique, mutated_payload in generate_evasion_mutations(seed_payload).items():
        try:
            mutation_result = detector(mutated_payload)
        except Exception:  # noqa: BLE001
            mutation_result = None
        detected_on_mutation = bool(extract_detection_keys(mutation_result))
        escaped = detected_on_seed and not detected_on_mutation
        attempts.append(
            EvasionAttemptResult(
                seed_payload_label=seed_payload_label,
                technique=technique,
                detected_on_seed=detected_on_seed,
                detected_on_mutation=detected_on_mutation,
                escaped=escaped,
            )
        )

    return RedVsBlueReport(seed_payload_label=seed_payload_label, attempts=attempts)


def feed_escapes_to_postmortem(
    report: RedVsBlueReport,
    *,
    vuln_class: str | None = None,
    detector_name: str = "",
    thread_id: str | None = None,
    postmortem_manager: Any | None = None,
) -> list[Any]:
    """Record every escaped technique in ``report`` as a Postmortem
    ``detection_logic_gap`` entry — the "feeds back to strengthen
    detection" half of item 5.

    This is the closing of the red-vs-blue loop: a successful evasion
    is not just printed to a report and forgotten, it becomes a durable,
    aggregable record (same store, same ``get_category_summary()``
    rollup as every other miss in item 6) that a future detector
    revision can be checked against.

    Args:
        report: The result of :func:`run_red_vs_blue`.
        vuln_class: The vulnerability class the seed payload targets,
            when known (e.g. ``"xss"``, ``"sqli"``).
        detector_name: Name of the detector under test.
        thread_id: Optional engagement/thread identifier.
        postmortem_manager: An existing
            :class:`~webpent.memory.postmortem.PostmortemManager` to
            record into. If ``None``, the process-wide singleton from
            :func:`webpent.memory.postmortem.get_postmortem_manager`
            is used.

    Returns:
        The list of UUIDs recorded, one per escaped technique.
    """
    from webpent.memory.postmortem import get_postmortem_manager
    from webpent.models.postmortem import PostmortemCategory

    manager = postmortem_manager or get_postmortem_manager()
    recorded_ids: list[Any] = []
    for attempt in report.escaped_techniques:
        recorded_ids.append(
            manager.record_missed_finding(
                category=PostmortemCategory.DETECTION_LOGIC_GAP,
                root_cause_detail=(
                    f"Detector '{detector_name}' caught seed payload "
                    f"'{attempt.seed_payload_label}' but missed its "
                    f"'{attempt.technique}' evasion variant — red-vs-blue "
                    "internal loop escape."
                ),
                proposed_fix=(
                    f"Normalise/decode input before matching to neutralise "
                    f"the '{attempt.technique}' evasion technique, or add a "
                    "dedicated signature for this mutation family."
                ),
                vuln_class=vuln_class,
                thread_id=thread_id,
                detector_name=detector_name,
                metadata={
                    "evasion_technique": attempt.technique,
                    "seed_payload_label": attempt.seed_payload_label,
                    "source": "red_vs_blue_internal_loop",
                },
            )
        )
    return recorded_ids


__all__ = [
    "EvasionAttemptResult",
    "RedVsBlueReport",
    "feed_escapes_to_postmortem",
    "generate_evasion_mutations",
    "run_red_vs_blue",
]
