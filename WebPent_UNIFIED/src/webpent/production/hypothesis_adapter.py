"""UM-DR-44 A2 — the Canonical Hypothesis Adapter.

Every production hypothesis producer built ``Hypothesis(...)`` inline
with its own field set.  The three principal emitters (identity
workflow, adaptive research, rabbit hole) each remembered a different
subset of the contract fields — e.g. rabbit hole omitted
``expected_behavior``/``negative_control``/``preconditions`` entirely,
and only some sites bounded ``origin_detail`` to 500 chars.

The adapter is the ONE canonical emission point:

* REQUIRED fields (statement, vuln_class, origin, origin_detail,
  expected_behavior, negative_control) are enforced — a producer that
  forgets one fails at construction, not at validation time;
* bounded string fields are truncated to the model's documented
  limits exactly once, here;
* fingerprint/id derivation stays with the caller (producers own
  their objective keys);
* the adapter never invents content — it only validates and bounds
  what the producer declared.
"""

from __future__ import annotations

from typing import Any, Mapping

from webpent.models.hypothesis import Hypothesis

__all__ = ["CanonicalHypothesisAdapter", "canonical_hypothesis"]


class HypothesisContractError(ValueError):
    """A producer omitted a required contract field."""


_REQUIRED_FIELDS = (
    "statement",
    "vuln_class",
    "origin",
    "origin_detail",
    "expected_behavior",
    "negative_control",
)

#: (field, max chars) for every bounded string the model documents.
_BOUNDED_STRINGS = {
    "statement": 500,
    "origin_detail": 500,
    "expected_behavior": 500,
    "negative_control": 500,
}


class CanonicalHypothesisAdapter:
    """Validate + bound a producer's fields into a canonical Hypothesis."""

    def build(self, **fields: Any) -> Hypothesis:
        missing = [f for f in _REQUIRED_FIELDS if not str(fields.get(f) or "").strip()]
        if missing:
            raise HypothesisContractError(
                f"canonical_hypothesis: missing required field(s): {missing}"
            )
        bounded: dict[str, Any] = dict(fields)
        for name, limit in _BOUNDED_STRINGS.items():
            if name in bounded and bounded[name] is not None:
                bounded[name] = str(bounded[name])[:limit]
        return Hypothesis(**bounded)


_ADAPTER = CanonicalHypothesisAdapter()


def canonical_hypothesis(**fields: Any) -> Hypothesis:
    """Module-level emission point — every producer goes through this."""
    return _ADAPTER.build(**fields)


def describes_canonical_emission(module_source: str) -> bool:
    """Structural helper used by the contract test: a producer module
    that constructs ``Hypothesis(`` directly (instead of via the
    adapter) is non-canonical."""
    return "Hypothesis(" not in module_source.replace(
        "CanonicalHypothesisAdapter", ""
    ).replace("canonical_hypothesis(", "")
