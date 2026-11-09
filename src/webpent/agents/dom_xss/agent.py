"""DOM XSS agent — analyze scripts, build probes, confirm via browser
(V2 §2, 2026-10-29).

The analysis half is fully deterministic and runs with the flag off by
default (``enable_dom_xss=False``): gate first, parse under the node
budget, taint, payloads. The confirmation half REUSES
``webpent.shared.browser_proof_runner`` — this module builds the three
probes (baseline / candidate / negative control) and the causal predicate
the runner already requires; it never re-implements replay, attestation
or verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from webpent.shared.browser_proof_runner import EphemeralProbe

from . import payloads, taint
from .parser import AstBudgetExceeded, parse_script

__all__ = [
    "DomXssAnalyzer",
    "DomXssCandidate",
    "DomXssReport",
    "dom_xss_causal_predicate",
    "build_browser_probes",
]


@dataclass(frozen=True)
class DomXssCandidate:
    """One flow turned into a concrete, confirmable probe."""

    probe_id: str
    source: str
    sink: str
    sink_kind: str
    function: str
    depth: int
    line: int
    payload: str
    probe_fragment: str  # where the payload goes (e.g. "#<payload>")


@dataclass(frozen=True)
class DomXssReport:
    """Bounded result: candidates, or exactly one skip reason."""

    candidates: tuple[DomXssCandidate, ...] = field(default_factory=tuple)
    skipped: str = ""  # "" | "disabled" | "ast_budget_exceeded" | "parse_error" | "too_large"
    node_count: int = 0


class DomXssAnalyzer:
    """Flag-gated static DOM XSS analysis of one script."""

    def __init__(self, settings: Any) -> None:
        self._enable = bool(getattr(settings, "enable_dom_xss", False))
        self._max_nodes = int(getattr(settings, "dom_xss_max_ast_nodes", 50_000) or 50_000)

    @property
    def enabled(self) -> bool:
        return self._enable

    def analyze(self, source: str, *, probe_prefix: str = "dx") -> DomXssReport:
        if not self._enable:
            return DomXssReport(skipped="disabled")
        try:
            parsed = parse_script(source, max_nodes=self._max_nodes)
        except AstBudgetExceeded:
            return DomXssReport(skipped="ast_budget_exceeded")
        except SyntaxError:
            return DomXssReport(skipped="parse_error")
        except Exception:  # noqa: BLE001 — oversized/garbage input is a skip, never a crash
            return DomXssReport(skipped="too_large")
        flows = taint.find_taint_flows(parsed.tree)
        candidates: list[DomXssCandidate] = []
        for index, flow in enumerate(flows):
            probe_id = f"{probe_prefix}-{index}"
            try:
                payload = payloads.payload_for_sink(flow.sink_kind, probe_id)
                fragment = payloads.probe_fragment_for_source(flow.source, payload)
            except ValueError:
                continue  # non-URL-addressable sources are not silently probed
            candidates.append(
                DomXssCandidate(
                    probe_id=probe_id,
                    source=flow.source,
                    sink=flow.sink,
                    sink_kind=flow.sink_kind,
                    function=flow.function,
                    depth=flow.depth,
                    line=flow.line,
                    payload=payload,
                    probe_fragment=fragment,
                )
            )
        return DomXssReport(candidates=tuple(candidates), node_count=parsed.node_count)


def dom_xss_causal_predicate(marker: str):
    """A CausalPredicate for the browser proof runner.

    Passes only when the CANDIDATE observation carries this candidate's
    marker (in the DOM text, the window flag, or console output) while the
    negative control — a DIFFERENT marker — does not. Dialog-only or
    reflection-only signals fail: the marker must have executed into state
    the page did not already have.
    """

    def _contains_marker(observation: Mapping[str, Any]) -> bool:
        blob = repr(dict(observation))
        return marker in blob

    def predicate(
        baseline: Mapping[str, Any],
        candidate: Mapping[str, Any],
        negative_control: Mapping[str, Any],
    ) -> tuple[bool, str]:
        if _contains_marker(candidate) and not _contains_marker(negative_control):
            return True, "dom_marker_executed_in_candidate_absent_in_negative_control"
        return False, "dom_marker_not_demonstrated_or_not_causal"

    return predicate


def build_browser_probes(candidate: DomXssCandidate, *, probe_value: str | None = None) -> dict[str, Any]:
    """Build the runner-ready probe set for one candidate.

    Returns ``{"baseline", "candidate", "negative_control"}`` EphemeralProbe
    objects, the ``probe_values`` mapping the runner requires, and the
    causal predicate — everything ``BrowserProofRunner.run`` needs on the
    probe side. The value shape is the crafted URL (page URL + fragment)
    when the source is URL-addressable, which the campaign layer supplies;
    here we generate the fragment-based default.
    """
    value = probe_value if probe_value is not None else candidate.probe_fragment
    # Baseline is a benign same-shape fragment: non-empty (the runner
    # refuses empty probe values) but carrying nothing executable.
    baseline_value = "#" if candidate.source == "location.hash" else "?webpent_dx="
    baseline_probe = EphemeralProbe.from_value(role="baseline", value=baseline_value)
    candidate_probe = EphemeralProbe.from_value(role="candidate", value=value)
    negative_probe = EphemeralProbe.from_value(
        role="negative_control",
        # same shape, DIFFERENT marker: reflection alone cannot pass
        value=candidate.probe_fragment.replace(payloads.marker_for(candidate.probe_id), payloads.negative_marker(candidate.probe_id)),
    )
    negative_value = candidate.probe_fragment.replace(
        payloads.marker_for(candidate.probe_id), payloads.negative_marker(candidate.probe_id)
    )
    values = {
        baseline_probe.probe_ref: baseline_value,
        candidate_probe.probe_ref: value,
        negative_probe.probe_ref: negative_value,
    }
    return {
        "baseline": baseline_probe,
        "candidate": candidate_probe,
        "negative_control": negative_probe,
        "probe_values": values,
        "causal_predicate": dom_xss_causal_predicate(payloads.marker_for(candidate.probe_id)),
    }
