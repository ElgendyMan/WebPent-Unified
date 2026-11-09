"""webpent.production.transition_sources — grammar-free transition discovery.

UM-DR-27 (the recall-program generalization window, 2026-11-07). The
UM-DR-25 stateful prober lifted the blind_v3 methodology ceiling (the
3-GET read-only triad) by GUESSING transition routes with a fixed name
grammar (``state_<n>`` / ``transition_<n>`` / ``activate_<n>`` /
``flag_<n>``). That grammar is the replica corpus's own naming
convention — on a real target it is content-discovery luck, not target
understanding. This module generalizes the capability:

  * :class:`TransitionCandidate` — one state-changing route candidate
    (method + path + provenance + origin), no naming assumptions.
  * :class:`ObservedSurfaceSource` — transition candidates derived from
    an OBSERVED surface (an endpoint inventory in the
    ``shared.family_feeds`` vocabulary: OpenAPI routes, crawl surface
    records, forms, JS shadow endpoints). Case-scoped by the resource-id
    token convention (``_<n>`` suffix or ``/<n>/`` segment — the same
    resource-seed concept the r6c identity ladder uses), deterministically
    ordered, stateful-methods only.
  * :class:`NameGrammarSource` — the EXACT legacy UM-DR-25 behavior,
    byte-compatible (same verbs, same order), kept as the fallback.
  * :class:`CompositeTransitionSource` — observed surface first, name
    grammar as fallback, de-duplicated by (method, path).
  * :func:`observed_source_from_campaign_state` — the production
    adapter: real campaign state (crawled_data / openapi routes /
    shadow endpoints) → :class:`ObservedSurfaceSource` via
    ``family_feeds.endpoint_inventory_from_state``.

DISCIPLINE (unchanged): candidates only MANUFACTURE observables — the
causal guard stays the only confirmation authority; sources are
deterministic; nothing here reads ground truth; no broad exception
handlers (the repo's broad-exception gate pins the non-frozen set).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from webpent.shared.family_feeds import endpoint_inventory_from_state

__all__ = [
    "CompositeTransitionSource",
    "NameGrammarSource",
    "ObservedSurfaceSource",
    "TransitionCandidate",
    "TransitionSource",
    "observed_source_from_campaign_state",
]

#: The methods that can carry a state transition. GET/HEAD/OPTIONS are
#: excluded on purpose: they cannot flip server state in this grammar.
STATEFUL_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: The legacy UM-DR-25 name grammar, in its exact fixed order (single
#: verbs first, then the compositional pair vocabulary).
LEGACY_SINGLE_VERBS: tuple[str, ...] = ("state", "transition", "activate")
LEGACY_COMPOSITION_VERBS: tuple[str, ...] = ("state", "flag")

#: Maximum composed-pair fan-out the prober will consider from a source
#: (bounded search: the first ``MAX_COMPOSITION_CANDIDATES`` candidates
#: in deterministic order define at most K*(K-1)/2 ordered pairs).
MAX_COMPOSITION_CANDIDATES = 4


@dataclass(frozen=True)
class TransitionCandidate:
    """One state-changing route candidate. No naming assumptions."""

    method: str
    path: str
    origin: str                      # "observed" | "grammar"
    provenance: str = ""

    def key(self) -> tuple[str, str]:
        return (self.method.upper(), self.path)


class TransitionSource(Protocol):
    """Anything that yields deterministic transition candidates for a case."""

    def candidates(self, case: Mapping[str, Any]) -> list[TransitionCandidate]:
        ...  # pragma: no cover — protocol shape only


# ---------------------------------------------------------------------------
# helpers (shared with the prober's case parsing — kept local and honest)
# ---------------------------------------------------------------------------

def _path_parts(path: str) -> list[str]:
    return [p for p in urlsplit(str(path or "")).path.strip("/").split("/") if p]


def _case_number(case: Mapping[str, Any]) -> str | None:
    """The case's resource-id token: the trailing ``_<n>`` of the candidate
    path's last segment (``target_46`` → ``46``)."""
    parts = _path_parts(str(case.get("candidate") or ""))
    if not parts:
        return None
    tail = parts[-1].rsplit("_", 1)[-1]
    return tail if tail else None


def _case_directory(case: Mapping[str, Any]) -> str | None:
    """The case's directory prefix: all but the last segment of the
    candidate path (``/bv3/rsng/target_46`` → ``bv3/rsng``)."""
    parts = _path_parts(str(case.get("candidate") or ""))
    if len(parts) < 2:
        return None
    return "/".join(parts[:-1])


def _token_matches(token: str, number: str) -> bool:
    """A route segment references the case's resource when it ends with
    ``_<n>`` or is exactly ``<n>`` (RESTful object-id conventions)."""
    return token == number or token.rsplit("_", 1)[-1] == number


# ---------------------------------------------------------------------------
# observed-surface source
# ---------------------------------------------------------------------------

class ObservedSurfaceSource:
    """Transition candidates from an OBSERVED endpoint surface.

    ``entries`` is the family_feeds inventory vocabulary (dicts with
    ``method`` / ``path`` / optional ``stateful`` flag and ``provenance``)
    — or plain path strings (assumed POST). Entries are:

      * filtered to stateful methods (``stateful`` flag honored when
        present, else the method itself);
      * scoped to the case: same directory prefix AND a last-segment
        resource-id token matching the case's (the resource-seed
        convention);
      * de-duplicated by (method, path), stable in first-observed order.
    """

    def __init__(self, entries: Iterable[Any], *, origin: str = "observed") -> None:
        self._entries: list[dict[str, Any]] = []
        for entry in entries:
            if isinstance(entry, str):
                self._entries.append({"method": "POST", "path": entry})
            elif isinstance(entry, Mapping):
                self._entries.append(dict(entry))
        self._origin = str(origin or "observed")

    def candidates(self, case: Mapping[str, Any]) -> list[TransitionCandidate]:
        number = _case_number(case)
        directory = _case_directory(case)
        if number is None or directory is None:
            return []
        out: list[TransitionCandidate] = []
        seen: set[tuple[str, str]] = set()
        for entry in self._entries:
            method = str(entry.get("method") or "POST").upper()
            path = str(entry.get("path") or entry.get("url") or "")
            if not path:
                continue
            stateful_flag = entry.get("stateful")
            # The explicit flag WINS when present (the observer knows
            # better than the method heuristic — e.g. a state-mutating
            # GET); absent a flag, the method itself decides.
            is_stateful = bool(stateful_flag) if isinstance(stateful_flag, bool) else (
                method in STATEFUL_METHODS
            )
            if not is_stateful:
                continue
            parts = _path_parts(path)
            if len(parts) < 2:
                continue
            if "/".join(parts[:-1]) != directory:
                continue
            if not _token_matches(parts[-1], number):
                continue
            candidate = TransitionCandidate(
                method=method,
                path="/" + "/".join(parts),
                origin=self._origin,
                provenance=str(entry.get("provenance") or ""),
            )
            if candidate.key() in seen:
                continue
            seen.add(candidate.key())
            out.append(candidate)
        return out[:MAX_COMPOSITION_CANDIDATES + 4]


# ---------------------------------------------------------------------------
# legacy name grammar (byte-compatible with UM-DR-25's prober)
# ---------------------------------------------------------------------------

class NameGrammarSource:
    """The EXACT UM-DR-25 name-grammar behavior: ``/<root>/<seg>/<verb>_<n>``
    for the single verbs, then the compositional pair vocabulary. Order is
    fixed; no randomness; provenance self-declares the grammar origin."""

    def __init__(
        self,
        single_verbs: Sequence[str] = LEGACY_SINGLE_VERBS,
        composition_verbs: Sequence[str] = LEGACY_COMPOSITION_VERBS,
    ) -> None:
        self._single = tuple(single_verbs)
        self._composition = tuple(composition_verbs)

    def candidates(self, case: Mapping[str, Any]) -> list[TransitionCandidate]:
        candidate_path = str(case.get("candidate") or "")
        parts = _path_parts(candidate_path)
        if not parts:
            return []
        n = parts[-1].rsplit("_", 1)[-1]
        family_seg = parts[-2] if len(parts) >= 2 else None
        if family_seg is None or not n:
            return []
        out: list[TransitionCandidate] = []
        for verb in self._single:
            out.append(self._one(parts[0], family_seg, verb, n))
        for verb in self._composition:
            if verb not in self._single:
                out.append(self._one(parts[0], family_seg, verb, n))
        return out

    def _one(self, root: str, seg: str, verb: str, n: str) -> TransitionCandidate:
        return TransitionCandidate(
            method="POST",
            path=f"/{root}/{seg}/{verb}_{n}",
            origin="grammar",
            provenance="name_grammar:um-dr-25",
        )


# ---------------------------------------------------------------------------
# composite
# ---------------------------------------------------------------------------

class CompositeTransitionSource:
    """Observed surface first, name grammar as fallback. De-duplicated by
    (method, path); deterministic; the observed surface wins conflicts."""

    def __init__(self, *sources: TransitionSource) -> None:
        self._sources = tuple(sources)

    def candidates(self, case: Mapping[str, Any]) -> list[TransitionCandidate]:
        out: list[TransitionCandidate] = []
        seen: set[tuple[str, str]] = set()
        for source in self._sources:
            for candidate in source.candidates(case):
                if candidate.key() in seen:
                    continue
                seen.add(candidate.key())
                out.append(candidate)
        return out


# ---------------------------------------------------------------------------
# production adapter
# ---------------------------------------------------------------------------

def observed_source_from_campaign_state(
    state: Mapping[str, Any] | Any,
) -> ObservedSurfaceSource:
    """Real campaign state → an :class:`ObservedSurfaceSource`.

    The exact production seam: ``family_feeds.endpoint_inventory_from_state``
    derives the endpoint inventory from real state channels (explicit
    inventory → OpenAPI routes → crawl surface records → forms → JS shadow
    endpoints → plain endpoint/link lists), and this adapter turns it into
    transition candidates for the stateful prober. Callers stay flag-gated
    and fail-soft; nothing here mutates state or reads ground truth.
    """
    try:
        inventory = endpoint_inventory_from_state(state)
    except (TypeError, ValueError, KeyError, AttributeError):
        inventory = []
    return ObservedSurfaceSource(inventory)
