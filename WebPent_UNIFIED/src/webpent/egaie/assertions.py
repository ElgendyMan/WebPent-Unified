"""L10 Phase 2 — generalized four-valued assertion ledger.

The L9 prerequisite ledger (``webpent.egaie.prerequisites``) tracks
per-hypothesis preconditions. This module generalizes the underlying
state model into an investigation-wide ledger of ASSERTIONS about
the surface, each with explicit provenance and a four-valued
epistemic status:

- VERIFIED: backed by a recorded observation (an observation id the
  ledger can cite).
- INFERRED: hypothesized from the wire model, never verified. An
  INFERRED assertion can never promote itself: the ONLY path to
  VERIFIED is an explicit ``verify()`` (or ``reconcile()``) call
  carrying an observation id whose value agrees with the assertion.
- UNKNOWN: insufficient evidence (never asserted, or demoted after
  an upstream invalidation pending re-evaluation).
- INVALIDATED: contradicted by later evidence; terminal until an
  investigator re-asserts.

The rules this module exists to enforce (never violated, never
relaxed — L10 §Phase 2/§Phase 6):

- no auto-promotion: INFERRED/UNKNOWN state is never treated as
  verified fact; nothing in the ledger moves to VERIFIED without an
  observation id, and no call can create a VERIFIED assertion
  without one;
- contradictions trigger EXPLICIT invalidation: an observation that
  disagrees with an asserted value invalidates the assertion (it
  does not silently overwrite it), and every downstream dependent is
  demoted to UNKNOWN and returned for re-evaluation;
- assertions are state BELIEFS, not evidence: nothing here is or
  produces a security verdict, and no finding ever rests on an
  INFERRED, UNKNOWN or INVALIDATED assertion.

No fixture-specific state machine: the model holds whatever keys an
investigator asserts and reads surface observations only through the
existing relationship view (``seed_from_view`` infers state beliefs
from the view's own description of the surface; nothing else about
any application is known here).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any


class AssertionStatus(StrEnum):
    VERIFIED = "verified"
    INFERRED = "inferred"
    UNKNOWN = "unknown"
    INVALIDATED = "invalidated"


@dataclass(frozen=True, slots=True)
class Provenance:
    """How an assertion came to hold its current status.

    ``source`` names the channel (observation | inference |
    invalidation | reconciliation); ``observation_id`` cites the
    recorded observation that backs a VERIFIED status or contradicts
    an INVALIDATED one; ``detail`` is the free-text rationale.
    """

    source: str
    observation_id: str = ""
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Assertion:
    """One asserted belief about the surface: key -> value + status.

    ``key`` names the thing (e.g. ``state:<workflow path>``); keys
    are opaque strings here — the view adapter chooses them. The
    type system enforces the no-auto-promotion rule: a VERIFIED
    assertion cannot exist without observation-backed provenance.
    """

    key: str
    value: str
    status: AssertionStatus
    provenance: Provenance
    history: tuple[Provenance, ...] = ()

    def __post_init__(self) -> None:
        if (self.status is AssertionStatus.VERIFIED
                and not self.provenance.observation_id):
            raise ValueError(
                "a VERIFIED assertion requires the observation id "
                "that backs it (inferred state is never a verified "
                "fact)")

    @property
    def is_fact(self) -> bool:
        """True only for VERIFIED assertions. Every other status is
        a belief that must never establish a finding."""
        return self.status is AssertionStatus.VERIFIED


@dataclass
class AssertionLedger:
    """Investigation-wide assertion store with a dependency graph.

    The ledger is the single place an assertion's status changes, so
    the rules hold everywhere at once: promotion requires an
    observation id; contradiction invalidates instead of overwrites;
    invalidation demotes every dependent to UNKNOWN and returns the
    re-evaluation set.
    """

    assertions: dict[str, Assertion] = field(default_factory=dict)
    _dependents: dict[str, set[str]] = field(
        default_factory=dict, repr=False)

    # -- dependency graph ---------------------------------------------

    def depends_on(self, key: str, dependent_key: str) -> None:
        """Record that ``dependent_key`` rests on ``key``: an
        invalidation of ``key`` demotes ``dependent_key`` (and
        everything downstream of it) to UNKNOWN for re-evaluation."""
        self._dependents.setdefault(key, set()).add(dependent_key)

    def dependents(self, key: str,
                   seen: frozenset[str] = frozenset()) -> set[str]:
        """Transitive dependents of one key, dependents-of-
        dependents included, cycles tolerated."""
        out: set[str] = set()
        for dep in self._dependents.get(key, ()):
            if dep in seen:
                continue
            out.add(dep)
            out |= self.dependents(dep, seen | {key})
        return out

    # -- assertion (INFERRED / UNKNOWN) --------------------------------

    def infer(self, key: str, value: str, detail: str = "",
              source: str = "inference") -> Assertion:
        """Record an INFERRED belief. Never VERIFIED, whatever the
        source claims: promotion is ``verify()``'s job alone."""
        assertion = Assertion(
            key=key, value=value,
            status=AssertionStatus.INFERRED,
            provenance=Provenance(source=source, detail=detail),
            history=(Provenance(source=source, detail=detail),))
        self.assertions[key] = assertion
        return assertion

    def mark_unknown(self, key: str, detail: str = "") -> Assertion:
        """Explicitly park a key at UNKNOWN (insufficient evidence),
        whatever it was before. Never a verdict either way."""
        assertion = Assertion(
            key=key, value=self.assertions[key].value if key in
            self.assertions else "",
            status=AssertionStatus.UNKNOWN,
            provenance=Provenance(source="re-evaluation",
                                  detail=detail),
            history=(*self._history(key),
                     Provenance(source="re-evaluation", detail=detail),))
        self.assertions[key] = assertion
        return assertion

    # -- promotion (the ONLY path to VERIFIED) -------------------------

    def verify(self, key: str, value: str, observation_id: str,
               detail: str = "") -> tuple[Assertion, set[str]]:
        """Promote an assertion to VERIFIED on the strength of a
        recorded observation, or invalidate it when the observation
        contradicts the asserted value.

        Returns ``(assertion, reevaluate)``: the assertion in its new
        status, and — on contradiction — the transitive dependents
        demoted to UNKNOWN for re-evaluation (empty on agreement).

        Raises ``KeyError`` on a key that was never asserted: an
        observation verifies or contradicts a BELIEF; it never
        creates one. ``ValueError`` on an empty observation id (a
        verification without a recorded observation is exactly the
        auto-promotion this module exists to forbid)."""
        if not observation_id:
            raise ValueError(
                f"verifying {key!r} requires an observation id "
                "(no auto-promotion of inferred state)")
        if key not in self.assertions:
            raise KeyError(
                f"{key!r} was never asserted: an observation "
                "verifies or contradicts a belief, it never creates "
                "one")
        current = self.assertions[key]
        if current.status is AssertionStatus.INVALIDATED:
            raise ValueError(
                f"{key!r} is INVALIDATED: re-assert it (infer or "
                "mark_unknown) before verifying again")
        if current.value != value:
            return self._contradict(key, value, observation_id, detail)
        provenance = Provenance(source="observation",
                                observation_id=observation_id,
                                detail=detail)
        verified = replace(current, status=AssertionStatus.VERIFIED,
                           provenance=provenance,
                           history=(*current.history, provenance))
        self.assertions[key] = verified
        return verified, set()

    def reconcile(self, key: str, value: str,
                  observation_id: str) -> tuple[Assertion, set[str]]:
        """A later observation about an already-VERIFIED key:
        agreement keeps it VERIFIED (with the new provenance on the
        trail), disagreement invalidates. Same contract as
        ``verify``."""
        return self.verify(key, value, observation_id,
                           detail="reconciliation")

    # -- invalidation ---------------------------------------------------

    def invalidate(self, key: str, observation_id: str = "",
                   reason: str = "") -> tuple[Assertion, set[str]]:
        """Explicitly invalidate one assertion and demote its
        transitive dependents to UNKNOWN for re-evaluation.

        Returns ``(invalidated, reevaluate)``. INVALIDATED is
        terminal: no later observation re-verifies an invalidated
        assertion until it is re-asserted (an investigator must look
        again on purpose; nothing auto-recovers)."""
        current = self.assertions.get(key)
        provenance = Provenance(source="invalidation",
                                observation_id=observation_id,
                                detail=reason)
        invalidated = Assertion(
            key=key,
            value=current.value if current else "",
            status=AssertionStatus.INVALIDATED,
            provenance=provenance,
            history=(current.history if current else ()) +
            (provenance,))
        self.assertions[key] = invalidated
        reevaluate = self._demote_dependents(key)
        return invalidated, reevaluate

    # -- reads -----------------------------------------------------------

    def get(self, key: str) -> Assertion | None:
        return self.assertions.get(key)

    def status(self, key: str) -> AssertionStatus:
        return (self.assertions[key].status if key in self.assertions
                else AssertionStatus.UNKNOWN)

    def value(self, key: str) -> str:
        return self.assertions[key].value if key in self.assertions \
            else ""

    def is_fact(self, key: str) -> bool:
        """True only when the key holds a VERIFIED assertion."""
        return key in self.assertions and self.assertions[
            key].is_fact

    def all_status(self) -> dict[str, AssertionStatus]:
        return {k: a.status for k, a in self.assertions.items()}

    # -- surface adapter ---------------------------------------------------

    def seed_from_view(self, view: Any) -> list[Assertion]:
        """Infer state beliefs from the relationship view's own
        description of the surface: one INFERRED ``state:<path>``
        assertion per observed workflow path, valued at the state
        the view last observed. This is a BELIEF (the view's
        first-observation), not a fact: only a re-read verify()
        call can promote it. No fixture-specific state machine —
        the chains, targets and states come from the view alone."""
        seeded: list[Assertion] = []
        for path in sorted(view.workflow_paths):
            state = view.workflow_state.get(path)
            if not state:
                continue
            seeded.append(self.infer(
                f"state:{path}", state,
                detail="seeded from the relationship view's "
                       "first-observed state"))
        return seeded

    # -- accounting ---------------------------------------------------------

    def tally(self) -> dict[str, int]:
        """Counts by status (UNKNOWN includes never-asserted keys,
        which the ledger cannot enumerate)."""
        tally = {s.value: 0 for s in AssertionStatus}
        for assertion in self.assertions.values():
            tally[assertion.status.value] += 1
        return tally

    # -- internals ------------------------------------------------------------

    def _contradict(self, key: str, observed: str,
                    observation_id: str,
                    detail: str) -> tuple[Assertion, set[str]]:
        """An observation disagrees with the asserted value: the
        assertion is INVALIDATED (never overwritten), provenance
        records both the contradicting observation and the value it
        showed, and dependents are demoted for re-evaluation."""
        current = self.assertions[key]
        provenance = Provenance(
            source="invalidation", observation_id=observation_id,
            detail=(detail or "observation contradicts the "
                    "asserted value") +
            f" (observed {observed!r} vs asserted "
            f"{current.value!r})")
        invalidated = replace(
            current, status=AssertionStatus.INVALIDATED,
            provenance=provenance,
            history=(*current.history, provenance))
        self.assertions[key] = invalidated
        reevaluate = self._demote_dependents(key)
        return invalidated, reevaluate

    def _demote_dependents(self, key: str) -> set[str]:
        """Demote every transitive dependent of an invalidated key to
        UNKNOWN and return the set that actually changed (the
        re-evaluation set). An INVALIDATED dependent stays
        INVALIDATED: invalidation is terminal until re-asserted."""
        changed: set[str] = set()
        for dep in sorted(self.dependents(key)):
            current = self.assertions.get(dep)
            if current is None:
                continue
            if current.status is AssertionStatus.INVALIDATED:
                continue
            if current.status is not AssertionStatus.UNKNOWN:
                changed.add(dep)
                self.mark_unknown(
                    dep, detail=f"rests on invalidated {key!r}")
        return changed

    def _history(self, key: str) -> tuple[Provenance, ...]:
        return self.assertions[key].history if key in \
            self.assertions else ()


def summarize(ledger: AssertionLedger,
              keys: Iterable[str]) -> list[dict[str, str]]:
    """A provenance-carrying summary of named keys, for records and
    evidence bundles: key, value, status, source, observation id.
    Belief statuses appear verbatim — a summary never renders an
    INFERRED assertion as if it were fact."""
    out: list[dict[str, str]] = []
    for key in keys:
        a = ledger.get(key)
        if a is None:
            continue
        out.append({
            "key": key, "value": a.value,
            "status": a.status.value,
            "source": a.provenance.source,
            "observation_id": a.provenance.observation_id,
        })
    return out
