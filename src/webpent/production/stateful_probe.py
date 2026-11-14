"""webpent.production.stateful_probe — the deterministic stateful case prober.

UM-DR-25 (red-team window 2026-11-06): the M10-unblock path's first
engineering step. The recorded blind_v3 mode_a baseline (recall 0.137)
is largely a PROBING-METHODOLOGY ceiling, not only an inference-logic
ceiling: the methodology probed each case with exactly three GETs, so
every state-transition case (80 of 120 — the entire reasoning and
compositional families) was methodologically unobservable. This module
adds the missing deterministic capability:

  phase 1 (mode_a reproduction) — the recorded methodology: three GETs
  (baseline / candidate / control) through
  :func:`webpent.cqa_v2.guarded_causal_evaluate`, unchanged.

  phase 2 (stateful discovery) — when phase 1 is not CONFIRMED and the
  case's manifest entry declares ``requires_state_transition`` (MANIFEST
  data only — never ground truth), a BOUNDED discovery of the transition
  endpoints:

  * default (UM-DR-25 behavior, byte-compatible): POST grammar
    candidates derived from the case's own paths — the single verbs
    ``state_<n>`` / ``transition_<n>`` / ``activate_<n>``, then the
    compositional pair vocabulary ``state_<n>`` + ``flag_<n>``;
  * UM-DR-27: when a ``transition_source`` is supplied (see
    :mod:`webpent.production.transition_sources`), grammar-free
    candidates from an OBSERVED surface (endpoint inventory, sitemap,
    OpenAPI, crawl records) — singles first, then bounded unordered
    pairwise composition of the first
    ``transition_sources.MAX_COMPOSITION_CANDIDATES`` candidates.

UM-DR-28 additions (2026-11-07):

  * **evidence_trace** — every probe outcome now carries the ordered
    causal history (read evaluations with per-observation digests and
    verdicts; transition applications with method/path/status). No
    transition silently disappears: the source-driven path records the
    FULL application log (singles stay applied when pairs run on top).
  * **control rotation** — a manifest/mined case may carry
    ``control_alternatives`` (additional negative-control candidates,
    in observation order). When an evaluation lands INCONCLUSIVE and
    alternatives remain, the prober re-evaluates with the next control
    (bounded by ``MAX_CONTROL_ROTATIONS``; each rotation costs two
    reads). The legacy blind_v3 manifest carries no alternatives, so
    the recorded-methodology paths are byte-compatible. Rationale: a
    denied negative control is REQUIRED evidence for confirmation —
    when the structural first guess is itself a clean-looking trap,
    rotating the control is the honest adaptive search for the
    enforcement reference. The causal guard stays the authority.
  * **representation-oracle enrichment** — ``make_observation``
    normalizes JSON bodies through
    :mod:`webpent.cqa_v2.representation_oracle` (canonical semantic
    digest; body-represented authorization semantics surfaced through
    the guard's context channels, headers still winning). The legacy
    projection is available via ``enrich=False`` (control
    measurements). The guard itself is untouched (frozen).

UM-DR-27 docstring-drift fix (kept): the UM-DR-25 docstring claimed
"the candidate path itself" among the grammar candidates; the
implementation never included it.

DISCIPLINE (unchanged from the causal guard's):
  * guarded_causal_evaluate stays the ONLY confirmation authority — the
    prober never confirms anything itself; it only manufactures the
    observable differential the guard requires;
  * bounded: every case costs at most ``MAX_REQUESTS_PER_CASE`` HTTP
    requests (documented, enforced, reported);
  * deterministic: the grammar order is fixed, no randomness, no LLM;
  * read-only probe bodies: transition requests carry no payload — they
    are transition triggers, not exploit attempts;
  * fail-closed: transport errors count against the budget and end the
    probe with the phase-1 verdict.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from webpent.cqa_v2 import guarded_causal_evaluate
from webpent.cqa_v2.causal_guard import _extract_context  # noqa: PLC2701 — the canonical context extractor (internal use)
from webpent.production.transition_sources import (
    MAX_COMPOSITION_CANDIDATES,
    NameGrammarSource,
    TransitionSource,
)

__all__ = [
    "MAX_CONTROL_ROTATIONS",
    "MAX_REQUESTS_PER_CASE",
    "ProbeOutcome",
    "StatefulCaseProber",
    "make_observation",
]

#: The hard per-case request budget (documented + enforced + reported).
MAX_REQUESTS_PER_CASE = 30

#: How many alternative negative controls one evaluation may try
#: (bounded adaptive control rotation; 2 reads each).
MAX_CONTROL_ROTATIONS = 2

#: The POST grammar, in fixed deterministic order. Derived from
#: the case's own family segment — a generic discovery strategy, exactly
#: like a real scanner trying the documented grammar families.
_SINGLE_GRAMMAR = ("state", "transition", "activate")
_COMPOSITION_GRAMMAR = ("state", "flag")

#: A transition request that answers >= 400 did not apply (source-driven
#: phase only): re-evaluating after it would waste budget on a route the
#: target says does not exist.
_ERROR_STATUS = 400


#: The methods the prober will actually ISSUE as transitions. DELETE is
#: deliberately refused: a transition trigger must be a non-destructive
#: probe, and DELETE on a real target can destroy evidence (the source
#: may still list it — the prober is the safety boundary).
_TRANSITION_ISSUE_METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def make_observation(
    response: Any,
    path: str,
    base_url: str = "",
    *,
    enrich: bool = True,
) -> dict[str, Any]:
    """The observation shape guarded_causal_evaluate reads (the same
    projection goed_v1_8_4's differential used).

    UM-DR-28: with ``enrich=True`` (the default) the observation is
    passed through the representation oracle — the semantic digest
    becomes the CANONICAL form's digest when the body parses as JSON
    (the raw digest is preserved as ``raw_digest``; the applied
    normalization rules are recorded), and body-represented
    authorization semantics are surfaced through the guard-readable
    context channels (headers win — enrichment only fills absent
    channels). ``enrich=False`` reproduces the exact pre-UM-DR-28
    projection (control measurements).
    """
    raw_text = str(response.text)
    raw_digest = _sha(raw_text)
    observation: dict[str, Any] = {
        "status_code": response.status_code,
        "body_length": len(raw_text),
        "semantic_digest": raw_digest,
        "response_shape": "json" if raw_text.strip().startswith("{") else "text",
        "request": {"method": "GET", "path": path.split("?")[0],
                    "header_names": ["X-Actor"], "base_url": base_url},
        "headers": {k.lower(): v for k, v in response.headers.items()},
        "body_preview": raw_text[:200],
    }
    if not enrich:
        return observation
    from webpent.cqa_v2.representation_oracle import enrich_observation

    enriched = enrich_observation(observation, body_text=raw_text)
    canonical_digest = enriched.pop("canonical_digest", None)
    if canonical_digest:
        # The semantic channel becomes the CANONICAL form's digest (the
        # raw digest is preserved as ``raw_digest``; the applied rules
        # are recorded for evidence explainability).
        enriched["raw_digest"] = raw_digest
        enriched["semantic_digest"] = canonical_digest
    return enriched


@dataclass
class ProbeOutcome:
    """One case's probe result (audit-friendly)."""
    case_id: str
    verdict: str                     # CONFIRMED / CLEAN / INCONCLUSIVE / BLOCKED
    phase: int                       # 1 = read-only, 2 = stateful discovery
    requests_issued: int = 0
    transitions_applied: list[str] = field(default_factory=list)
    confidence: float = 0.0
    block_reason: str | None = None
    transition_origin: str | None = None   # UM-DR-27: "grammar" | observed provenance
    evidence_trace: list[dict[str, Any]] = field(default_factory=list)
    control_used: str | None = None        # UM-DR-28: the control that decided

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class _Budget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def spend(self, n: int = 1) -> bool:
        if self.used + n > self.limit:
            return False
        self.used += n
        return True

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit


_TRACE_CONTEXT_CHANNELS = (
    "actor_id", "actor_role", "actor_tenant", "authorization_outcome",
    "effective_privilege_granted", "resource_owner", "resource_tenant",
    "resource_type", "resource_id", "privilege_required",
)


def _observed_context(observation: dict[str, Any]) -> dict[str, Any]:
    """The authorization-context VALUES an observation carried (from
    headers or body representation — observed facts only). Recorded on
    read-trace steps so findings can cite the foreign identifiers the
    guard actually saw."""
    context = _extract_context(observation)
    return {
        key: value for key, value in context.items()
        if value is not None and key in _TRACE_CONTEXT_CHANNELS
    }


def _candidate_channels(observation: dict[str, Any]) -> str:
    """The context channels a candidate observation carried (for the
    evidence trace's provenance record)."""
    channels = (
        "actor_id", "actor_role", "actor_tenant", "authorization_outcome",
        "effective_privilege_granted", "resource_owner", "resource_tenant",
        "resource_type", "resource_id", "privilege_required",
    )
    present = [c for c in channels if observation.get(c) is not None]
    if not present:
        headers = observation.get("headers") or {}
        lowered = {str(k).lower() for k in headers}
        present = [
            c for c, header in {
                "actor_id": "x-actor-echo", "actor_role": "x-actor-role",
                "authorization_outcome": "x-authorization-outcome",
                "resource_owner": "x-resource-owner",
                "resource_type": "x-resource-type",
            }.items()
            if header in lowered
        ]
    return ",".join(sorted(present))


class StatefulCaseProber:
    """Deterministic, bounded, manifest-driven stateful case prober."""

    def __init__(
        self,
        client: Any,
        *,
        base_url: str = "",
        evaluate: Callable[..., Any] = guarded_causal_evaluate,
        max_requests: int = MAX_REQUESTS_PER_CASE,
        transition_source: TransitionSource | None = None,
        enrich_observations: bool = True,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._evaluate = evaluate
        self._max_requests = max_requests
        self._transition_source = transition_source
        self._enrich = enrich_observations
        self._grammar = NameGrammarSource()
        self._trace: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    def probe(self, case: Mapping[str, Any]) -> ProbeOutcome:
        """Probe one manifest case. Returns the outcome; never raises on
        transport errors (they end the probe honestly, verdict stays
        phase-1's)."""
        budget = _Budget(self._max_requests)
        self._trace = []
        case_id = str(case.get("case_id") or "")
        requires_transition = bool(case.get("requires_state_transition"))

        # ---- phase 1: the recorded 3-GET methodology ---------------
        phase1 = self._read_evaluate(case, budget)
        if phase1.verdict == "CONFIRMED" or not requires_transition:
            phase1.case_id = case_id
            return self._finish(phase1)

        # ---- phase 2: bounded stateful discovery -------------------
        if self._transition_source is not None:
            return self._finish(self._source_driven_phase2(case, phase1, budget))

        family_seg = self._family_segment(str(case.get("candidate") or ""))
        if family_seg is None:
            phase1.case_id = case_id
            return self._finish(phase1)

        # single-transition grammar
        for verb in _SINGLE_GRAMMAR:
            if budget.exhausted:
                break
            applied = self._apply_transition(case, family_seg, verb, budget)
            if applied is None:
                continue
            after = self._read_evaluate(case, budget)
            if after.verdict == "CONFIRMED":
                after.case_id = case_id
                after.phase = 2
                after.transitions_applied = [applied]
                after.transition_origin = "grammar"
                return self._finish(after)

        # compositional grammar (pairwise, fixed order)
        if not budget.exhausted:
            for first in _COMPOSITION_GRAMMAR:
                for second in _COMPOSITION_GRAMMAR:
                    if first == second or budget.exhausted:
                        continue
                    applied_a = self._apply_transition(case, family_seg, first, budget)
                    applied_b = self._apply_transition(case, family_seg, second, budget)
                    if applied_a is None or applied_b is None:
                        continue
                    after = self._read_evaluate(case, budget)
                    if after.verdict == "CONFIRMED":
                        after.case_id = case_id
                        after.phase = 2
                        after.transitions_applied = [applied_a, applied_b]
                        after.transition_origin = "grammar"
                        return self._finish(after)

        # nothing confirmed — the honest last observation wins
        phase1.case_id = case_id
        phase1.requests_issued = budget.used
        phase1.phase = 2
        return self._finish(phase1)

    # ------------------------------------------------------------------
    def _finish(self, outcome: ProbeOutcome) -> ProbeOutcome:
        """Attach the ordered causal history to the outcome (UM-DR-28
        evidence integrity: nothing silently disappears)."""
        outcome.evidence_trace = [dict(step) for step in self._trace]
        return outcome

    # ------------------------------------------------------------------
    def _source_driven_phase2(
        self,
        case: Mapping[str, Any],
        phase1: ProbeOutcome,
        budget: _Budget,
    ) -> ProbeOutcome:
        """UM-DR-27: grammar-free phase 2. Candidates come from the
        supplied :class:`TransitionSource` (observed surface, composite,
        or an explicit grammar source). Singles first, then bounded
        unordered pairwise composition of the first
        ``MAX_COMPOSITION_CANDIDATES`` candidates. A transition request
        answered >= 400 is skipped (no re-evaluation — budget honesty).

        UM-DR-28 evidence integrity: the applied-transition log is
        CUMULATIVE — singles stay applied when pairs run on top, and a
        confirming pair records every transition applied since probe
        start, in application order."""
        case_id = str(case.get("case_id") or "")
        candidates = self._transition_source.candidates(case)  # type: ignore[union-attr]
        if not candidates:
            phase1.case_id = case_id
            phase1.phase = 2
            phase1.requests_issued = budget.used
            return phase1
        origin = candidates[0].origin or "source"
        applied_log: list[str] = []   # every transition that APPLIED, in order

        # singles (accumulating: an earlier single's transition STAYS
        # applied — a later single may complete a composition; the
        # outcome records every applied transition in application order)
        for candidate in candidates:
            if budget.used + 4 > budget.limit:  # 1 transition + 3 reads
                break
            path = self._request(candidate.method, candidate.path, budget)
            if path is None:
                continue
            applied_log.append(path)
            after = self._read_evaluate(case, budget)
            if after.verdict == "CONFIRMED":
                after.case_id = case_id
                after.phase = 2
                after.transitions_applied = list(applied_log)
                after.transition_origin = origin
                after.requests_issued = budget.used
                return after

        # bounded unordered pairwise composition (on top of the singles
        # already applied — the application log keeps the full chain)
        head = candidates[:MAX_COMPOSITION_CANDIDATES]
        for i in range(len(head)):
            for j in range(i + 1, len(head)):
                if budget.used + 5 > budget.limit:  # 2 transitions + 3 reads
                    break
                path_a = self._request(head[i].method, head[i].path, budget)
                path_b = self._request(head[j].method, head[j].path, budget)
                if path_a is None or path_b is None:
                    continue
                applied_log.append(path_a)
                applied_log.append(path_b)
                after = self._read_evaluate(case, budget)
                if after.verdict == "CONFIRMED":
                    after.case_id = case_id
                    after.phase = 2
                    after.transitions_applied = list(applied_log)
                    after.transition_origin = origin
                    after.requests_issued = budget.used
                    return after

        phase1.case_id = case_id
        phase1.phase = 2
        phase1.requests_issued = budget.used
        phase1.transition_origin = origin
        return phase1

    # ------------------------------------------------------------------
    def _family_segment(self, candidate_path: str) -> str | None:
        """/bv3/<seg>/target_N -> <seg> (the case's own family segment)."""
        parts = [p for p in urlsplit(candidate_path).path.strip("/").split("/") if p]
        if len(parts) >= 2:
            return parts[-2]
        return None

    def _get(self, path: str, budget: _Budget) -> Any | None:
        if not budget.spend(1):
            return None
        try:
            return self._client.get(path, headers={"X-Actor": "attacker"})
        except Exception:  # noqa: BLE001 — transport error = honest stop
            return None

    def _post(self, path: str, budget: _Budget) -> Any | None:
        if not budget.spend(1):
            return None
        try:
            response = self._client.post(path, headers={"X-Actor": "attacker"})
        except Exception:  # noqa: BLE001 — transport error = honest stop
            response = None
        self._trace.append({
            "step": len(self._trace) + 1,
            "kind": "transition",
            "method": "POST",
            "path": str(path),
            "status_code": (
                int(getattr(response, "status_code", 0) or 0)
                if response is not None else None
            ),
        })
        return response

    def _request(self, method: str, path: str, budget: _Budget) -> str | None:
        """UM-DR-27: apply one transition candidate. Methods are limited
        to the non-destructive set (DELETE refused — a transition trigger
        must never destroy evidence); payload-free. Returns the path when
        the target answered < 400 (the transition plausibly applied),
        else None. The path is returned even for no-op 2xx transitions —
        the causal guard, not the status code, decides whether anything
        was confirmed."""
        if method.upper() not in _TRANSITION_ISSUE_METHODS:
            return None
        if not budget.spend(1):
            return None
        status: int | None = None
        try:
            response = self._client.request(
                method.upper(), path, headers={"X-Actor": "attacker"}
            )
        except Exception:  # noqa: BLE001 — transport error = honest stop
            response = None
        if response is not None:
            status = int(getattr(response, "status_code", 0) or 0)
        self._trace.append({
            "step": len(self._trace) + 1,
            "kind": "transition",
            "method": method.upper(),
            "path": str(path),
            "status_code": status,
        })
        if response is None or int(getattr(response, "status_code", 0) or 0) >= _ERROR_STATUS:
            return None
        return path

    # ------------------------------------------------------------------
    def _read_evaluate(
        self,
        case: Mapping[str, Any],
        budget: _Budget,
        *,
        control_path: str | None = None,
        baseline_observation: dict[str, Any] | None = None,
    ) -> ProbeOutcome:
        """The recorded three-GET read evaluation, with UM-DR-28's
        bounded control rotation.

        ``control_path`` overrides the case's control (rotation);
        ``baseline_observation`` allows reusing an already-read baseline
        during rotation (the baseline is a stable reference read —
        re-reading it would double the rotation cost without adding
        evidence)."""
        control = control_path or str(case.get("control") or "")
        baseline = self._get(str(case.get("baseline") or ""), budget) \
            if baseline_observation is None else None
        candidate = self._get(str(case.get("candidate") or ""), budget)
        control_response = self._get(control, budget)
        if baseline_observation is None and (
            baseline is None or candidate is None or control_response is None
        ):
            return ProbeOutcome(
                case_id=str(case.get("case_id") or ""),
                verdict="INCONCLUSIVE", phase=1, requests_issued=budget.used,
                block_reason="transport_error_or_budget",
            )
        if baseline_observation is not None and (
            candidate is None or control_response is None
        ):
            return ProbeOutcome(
                case_id=str(case.get("case_id") or ""),
                verdict="INCONCLUSIVE", phase=1, requests_issued=budget.used,
                block_reason="transport_error_or_budget",
            )
        baseline_o = baseline_observation or make_observation(
            baseline, str(case.get("baseline")), self._base_url,
            enrich=self._enrich,
        )
        candidate_o = make_observation(
            candidate, str(case.get("candidate")), self._base_url,
            enrich=self._enrich,
        )
        control_o = make_observation(
            control_response, control, self._base_url, enrich=self._enrich,
        )
        result = self._evaluate(baseline_o, candidate_o, control_o)
        outcome = ProbeOutcome(
            case_id=str(case.get("case_id") or ""),
            verdict=str(result.verdict.value),
            phase=1,
            requests_issued=budget.used,
            confidence=float(result.confidence),
            block_reason=getattr(result, "block_reason", None),
            control_used=control,
        )
        self._trace.append({
            "step": len(self._trace) + 1,
            "kind": "read",
            "control": control,
            "verdict": outcome.verdict,
            "confidence": outcome.confidence,
            "digests": {
                "baseline": str(baseline_o.get("semantic_digest", ""))[:12],
                "candidate": str(candidate_o.get("semantic_digest", ""))[:12],
                "control": str(control_o.get("semantic_digest", ""))[:12],
            },
            "context_channels": _candidate_channels(candidate_o),
            "observed_context": _observed_context(candidate_o),
        })
        if outcome.verdict != "INCONCLUSIVE":
            return outcome

        # ---- bounded control rotation (UM-DR-28) -------------------
        alternatives = [
            str(alt) for alt in (case.get("control_alternatives") or [])
            if str(alt) and str(alt) != control
        ][:MAX_CONTROL_ROTATIONS]
        for alt in alternatives:
            if budget.used + 2 > budget.limit:
                break
            candidate = self._get(str(case.get("candidate") or ""), budget)
            control_response = self._get(alt, budget)
            if candidate is None or control_response is None:
                break
            candidate_o = make_observation(
                candidate, str(case.get("candidate")), self._base_url,
                enrich=self._enrich,
            )
            control_o = make_observation(
                control_response, alt, self._base_url, enrich=self._enrich,
            )
            result = self._evaluate(baseline_o, candidate_o, control_o)
            outcome = ProbeOutcome(
                case_id=str(case.get("case_id") or ""),
                verdict=str(result.verdict.value),
                phase=1,
                requests_issued=budget.used,
                confidence=float(result.confidence),
                block_reason=getattr(result, "block_reason", None),
                control_used=alt,
            )
            self._trace.append({
                "step": len(self._trace) + 1,
                "kind": "read_rotation",
                "control": alt,
                "verdict": outcome.verdict,
                "confidence": outcome.confidence,
                "digests": {
                    "candidate": str(candidate_o.get("semantic_digest", ""))[:12],
                    "control": str(control_o.get("semantic_digest", ""))[:12],
                },
                "context_channels": _candidate_channels(candidate_o),
                "observed_context": _observed_context(candidate_o),
            })
            if outcome.verdict != "INCONCLUSIVE":
                return outcome
        return outcome

    # ------------------------------------------------------------------
    def _apply_transition(
        self,
        case: Mapping[str, Any],
        family_seg: str,
        verb: str,
        budget: _Budget,
    ) -> str | None:
        """POST one grammar candidate; returns the applied path (or None)."""
        candidate_path = str(case.get("candidate") or "")
        parts = [p for p in urlsplit(candidate_path).path.strip("/").split("/") if p]
        if not parts:
            return None
        n = parts[-1].rsplit("_", 1)[-1]
        path = f"/{parts[0]}/{family_seg}/{verb}_{n}"
        response = self._post(path, budget)
        if response is None:
            return None
        return path
