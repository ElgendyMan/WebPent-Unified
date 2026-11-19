"""Detector hardening — close tracked red-vs-blue detector escapes.

Red team finding (2026-10-24, REVIEW_REFREEZE_REPORT item 6): the
``unicode_homoglyph_padding`` evasion technique (see
``webpent.shared.red_vs_blue._mutate_unicode_homoglyph_padding``)
inserts a zero-width space (U+200B) between every character of a
payload. ``webpent.production.validators.extract_ssrf_indicators``
matches literal substrings (``localhost``, ``169.254.169.254``,
``/latest/meta-data``, ...) and token regexes on the RAW text, so a
U+200B-padded payload sails past every marker check — a genuine
detection-logic gap, tracked but deliberately left out of the
catalog-fix bundle because it changes detection semantics.

This module closes that gap WITHOUT touching the frozen validator:
the caller folds evasion padding out of the text first, then the
original frozen extraction logic runs unchanged on the folded text.

Design constraints:

  * Additive only — ``validators.py`` stays byte-identical (frozen
    manifest anchor 5957a1b5…). Nothing here re-opens the unfreeze
    window.
  * The folding is deliberately narrow: it removes characters whose
    sole semantic role in text is "invisible to humans" (zero-width
    joiners/spaces, BOM, word joiner). It does NOT fold homoglyph
    substitutions (Cyrillic "а" for Latin "a"), which would change
    the meaning of identifiers — only padding that breaks literal
    matching while preserving rendered meaning.
  * Fail-soft and pure: no I/O, no network, no state. Any input
    (None, non-str) is coerced exactly like the frozen validator
    coerces (``str(value or "")``).

The hardened extractor is a drop-in detector for
``webpent.shared.red_vs_blue.run_red_vs_blue``: its return type is
the same frozenset-of-strings the raw extractor returns, which
``extract_detection_keys`` normalizes the same way.
"""
from __future__ import annotations

import re
from typing import Any

from webpent.production.validators import extract_ssrf_indicators

# Characters that are invisible (zero-width or non-rendering format
# controls) and are used by the evasion registry purely as padding:
# their removal never changes what a human reader sees.
_ZERO_WIDTH_CHARS = (
    "\u200b",  # ZERO WIDTH SPACE       — used by unicode_homoglyph_padding
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (BOM)
)

_ZERO_WIDTH_RE = re.compile("[" + "".join(_ZERO_WIDTH_CHARS) + "]")

# The technique names from the red-vs-blue evasion registry whose
# payloads this module's folding defeats. Recorded in campaign
# ledgers so a hardened run can cite exactly which tracked gap it
# closed.
FOLDED_TECHNIQUES = ("unicode_homoglyph_padding",)


def fold_evasion_padding(value: Any) -> str:
    """Return the text with zero-width padding characters removed.

    Pure string normalization: no network, no I/O, no behavior change
    for text that contains none of the folded characters (verified by
    the pass-through test).
    """
    return _ZERO_WIDTH_RE.sub("", str(value or ""))


def extract_ssrf_indicators_hardened(value: Any) -> frozenset[str]:
    """``extract_ssrf_indicators`` with evasion padding folded out.

    Same contract as the frozen extractor (frozenset of indicator
    class strings, empty when nothing matches) — computed on
    ``fold_evasion_padding(value)`` so U+200B-style padding no longer
    hides cloud-metadata, internal-host, or credential markers.
    """
    return extract_ssrf_indicators(fold_evasion_padding(value))


__all__ = ["FOLDED_TECHNIQUES", "extract_ssrf_indicators_hardened", "fold_evasion_padding"]
