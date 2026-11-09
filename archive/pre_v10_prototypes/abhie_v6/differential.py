"""Expert differential security analysis for ABHIE v6."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .contracts import DifferentialSignalV6

DIMENSIONS = (
    "identity",
    "role",
    "permission",
    "resource",
    "workflow_state",
    "time_state",
)


class DifferentialAnalysisV6:
    """Compare recorded contexts and expose signals for later validation."""

    VERSION = "abhie-differential-v6"

    def compare(
        self,
        *,
        comparison_id: str,
        left: Mapping[str, object],
        right: Mapping[str, object],
        evidence_refs: Sequence[str] = (),
    ) -> tuple[DifferentialSignalV6, ...]:
        if not isinstance(left, Mapping) or not isinstance(right, Mapping):
            raise TypeError("comparison_contexts_required")
        refs = tuple(sorted({str(item).strip() for item in evidence_refs if str(item).strip()}))
        signals: list[DifferentialSignalV6] = []
        for dimension in DIMENSIONS:
            left_value = str(left.get(dimension, "<missing>"))
            right_value = str(right.get(dimension, "<missing>"))
            different = left_value != right_value
            signals.append(
                DifferentialSignalV6(
                    comparison_id=str(comparison_id).strip() or "v6-comparison",
                    dimension=dimension,
                    left_context=left_value,
                    right_context=right_value,
                    observed_difference=(
                        f"{dimension} differs between recorded contexts"
                        if different
                        else f"{dimension} is equal in recorded contexts"
                    ),
                    security_question=(
                        f"Is the {dimension} difference expected under the documented invariant?"
                    ),
                    evidence_refs=refs,
                    validation_requirement=(
                        "compare candidate and independent negative control "
                        "under the same condition"
                    ),
                    signal=different,
                )
            )
        return tuple(signals)


__all__ = ["DIMENSIONS", "DifferentialAnalysisV6"]
