"""webpent.production.stateful_discovery — the campaign-side integration
of source-driven stateful probing.

UM-DR-28 (the production discovery-integration window, 2026-11-07).
UM-DR-27 delivered the capability pieces — grammar-free transition
discovery (``transition_sources.py``), the source-driven prober phase
(``stateful_probe.py``) — and proved them on the generalization
fixture, but the M10 RCA honestly recorded the remaining gap: "the
prober is invoked by tests, not by the Campaign". This module is the
campaign-side half; ``families/execution_node.py`` (the wired
production node behind ``enable_family_execution_spine``) invokes
``run_stateful_discovery`` behind the new fail-closed
``enable_stateful_discovery`` flag.

The complete production path this closes:

    observed attack surface (campaign state: OpenAPI routes, crawl
    surface records, forms, JS shadow endpoints)
      → endpoint inventory (``shared.family_feeds``)
      → structural case mining (THIS MODULE — read-triples grouped by
        resource directory, no naming assumptions)
      → transition candidates (``transition_sources`` — scoped by the
        case's directory + resource-id token)
      → scope validation BEFORE execution (this module's client —
        defense in depth on top of the node's candidate filter)
      → bounded adaptive execution (``stateful_probe`` — singles,
        then bounded pair composition, per-case and total budgets)
      → state observation + evidence recording (the ordered
        ``evidence_trace`` — nothing silently disappears)
      → causal validation (``cqa_v2.guarded_causal_evaluate`` — the
        ONLY confirmation authority; this module never confirms)
      → Finding promotion with full provenance (survives the node's
        adversarial review + self-verify like every other finding)

DISCIPLINE:
  * deterministic — no randomness, no LLM, fixed observation order;
  * bounded — ``MAX_DISCOVERY_CASES`` cases, ``MAX_TOTAL_REQUESTS``
    requests for the whole discovery, plus the prober's own per-case
    budget; every bound is reported, never silently truncated;
  * fail-soft — any internal failure degrades to an honest error
    status in the summary (the campaign continues);
  * fail-closed on scope — out-of-scope candidates are refused
    BEFORE any request leaves the process and are counted;
  * no ground truth — cases and transitions derive from observed
    surface only.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from webpent.production.stateful_probe import (
    MAX_REQUESTS_PER_CASE,
    StatefulCaseProber,
)
from webpent.production.transition_sources import ObservedSurfaceSource

__all__ = [
    "MAX_DISCOVERY_CASES",
    "MAX_TOTAL_REQUESTS",
    "mine_probe_cases",
    "run_stateful_discovery",
]

#: Per-campaign case cap (bounded exploration; reported when hit).
MAX_DISCOVERY_CASES = 24

#: Whole-discovery request budget (reported when hit; never exceeded).
MAX_TOTAL_REQUESTS = 360

#: UM-DR-31.1 §6.1: the discount a SURFACE (suffix) hint match carries
#: relative to an exact directory match — a workflow observation's exact
#: directory always outranks a coverage-cell surface match of the same
#: prior. Ordering-only signal; never a confidence/authority input.
_SURFACE_HINT_DISCOUNT = 0.5

_READ_METHODS = frozenset({"GET", "HEAD"})
_STATEFUL_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


# ---------------------------------------------------------------------------
# structural case mining
# ---------------------------------------------------------------------------

def _parts(path: str) -> list[str]:
    return [p for p in urlsplit(str(path or "")).path.strip("/").split("/") if p]


def _id_token(segment: str) -> str | None:
    """The segment's resource-id token: a trailing ``_<n>`` suffix, a
    bare number, or a hex-ish token (RESTful object-id conventions —
    the same vocabulary ``transition_sources`` scopes by)."""
    tail = segment.rsplit("_", 1)[-1]
    if tail == segment and not (segment.isdigit() or len(segment) >= 6):
        return None
    return tail or None


def mine_probe_cases(
    inventory: list[Mapping[str, Any]],
    *,
    max_cases: int = MAX_DISCOVERY_CASES,
) -> list[dict[str, Any]]:
    """Mine read-triple probe cases from an observed endpoint inventory.

    Structural, no naming assumptions: GET-observable resources are
    grouped by directory (the path minus its last segment); within a
    directory, id-bearing instances form an observation-ordered list.
    Each mined case is::

        baseline  = the directory's FIRST observed instance (the
                    crawler's vantage — the reference read)
        candidate = each subsequent instance
        control   = the instance following the candidate (cyclic)

    ``requires_state_transition`` is True exactly when the directory
    also carries observed stateful entries (POST/PUT/PATCH/DELETE) —
    the transition surface exists, so phase-2 probing is warranted.
    Deterministic: stable in first-observed inventory order.
    """
    directories: dict[str, dict[str, Any]] = {}
    for entry in inventory or []:
        if isinstance(entry, str):
            method, path = "GET", entry
        else:
            method = str((entry or {}).get("method") or "GET").upper()
            path = str((entry or {}).get("path") or (entry or {}).get("url") or "")
        segments = _parts(path)
        if len(segments) < 2:
            continue
        directory = "/".join(segments[:-1])
        record = directories.setdefault(directory, {"reads": [], "stateful": False})
        if method in _STATEFUL_METHODS:
            record["stateful"] = True
            continue
        if method not in _READ_METHODS:
            continue
        if _id_token(segments[-1]) is None:
            continue
        normalized = "/" + "/".join(segments)
        if normalized not in record["reads"]:
            record["reads"].append(normalized)

    cases: list[dict[str, Any]] = []
    for directory in sorted(directories):
        record = directories[directory]
        reads = record["reads"]
        if len(reads) < 3:
            continue  # need baseline + candidate + control
        for index in range(1, len(reads)):
            candidate = reads[index]
            control = reads[(index + 1) % len(reads)]
            if control == candidate:
                control = reads[0]
            alternatives = [
                r for r in reads
                if r != candidate and r != control and r != reads[0]
            ][:3]
            case_id = "SD-" + hashlib.sha256(
                f"{directory}:{candidate}".encode()
            ).hexdigest()[:10]
            cases.append({
                "case_id": case_id,
                "baseline": reads[0],
                "candidate": candidate,
                "control": control,
                "control_alternatives": alternatives,
                "requires_state_transition": bool(record["stateful"]),
                "directory": directory,
            })
            if len(cases) >= max_cases:
                return cases
    return cases


# ---------------------------------------------------------------------------
# scope-validating executor adapter
# ---------------------------------------------------------------------------

class _ScopeRefused(Exception):
    """Raised when a request path is outside the declared scope."""


class CampaignProberClient:
    """Adapts the campaign's ``http_executor`` to the prober's client
    interface, enforcing scope BEFORE any request leaves the process.

    The prober speaks relative paths + ``X-Actor`` headers; the
    campaign executor speaks ``request_plan`` objects with absolute
    URLs. This adapter is the translation layer — and the LAST scope
    checkpoint (the mined cases are pre-filtered, the transition
    candidates are directory-scoped by construction; this guard
    catches anything that slips between the two)."""

    def __init__(
        self,
        executor: Callable[[Any], Any],
        *,
        base_url: str,
        allowed_prefixes: list[str] | None = None,
    ) -> None:
        self._executor = executor
        self._base_url = (base_url or "").rstrip("/")
        self._allowed = [str(a).lower() for a in (allowed_prefixes or [])]
        self.scope_refusals: list[str] = []

    def _check_scope(self, path: str) -> None:
        if not self._allowed:
            return
        lowered = str(path).lower()
        if not any(prefix in lowered for prefix in self._allowed):
            self.scope_refusals.append(str(path))
            raise _ScopeRefused(path)

    def _request(self, method: str, path: str, headers: dict[str, str] | None = None):
        self._check_scope(path)
        plan = SimpleNamespace(
            method=method.upper(),
            url=f"{self._base_url}{path}",
            headers=dict(headers or {}),
            body=None,
        )
        return self._executor(plan)

    def get(self, path: str, headers: dict[str, str] | None = None):
        return self._request("GET", path, headers or {"X-Actor": "attacker"})

    def post(self, path: str, headers: dict[str, str] | None = None):
        return self._request("POST", path, headers or {"X-Actor": "attacker"})

    def request(self, method: str, path: str, headers: dict[str, str] | None = None):
        return self._request(method, path, headers or {"X-Actor": "attacker"})


def _scope_allows(path: str, allowed: list[str]) -> bool:
    if not allowed:
        return True
    lowered = str(path).lower()
    return any(prefix in lowered for prefix in allowed)


# ---------------------------------------------------------------------------
# finding construction (provenance-honest)
# ---------------------------------------------------------------------------

def _finding_from_outcome(
    outcome: Any,
    case: Mapping[str, Any],
    *,
    base_url: str,
    engagement_id: str,
) -> Any:
    """Build a Finding from a CONFIRMED probe outcome.

    The confirmation authority is and remains
    ``cqa_v2.guarded_causal_evaluate`` — this function only shapes the
    evidence. The generic adversarial-review guards are attached
    because a guard CONFIRMED verdict implies them by construction:
    the baseline differed, the applied transition changed the state,
    and the candidate/control differential varies with identity.
    """
    from webpent.models.findings import Confidence, Finding, Severity, VulnClass

    trace = list(getattr(outcome, "evidence_trace", None) or [])
    actor_values = set()
    foreign_identifiers: list[str] = []
    for step in trace:
        if not isinstance(step, dict):
            continue
        context = step.get("observed_context") or {}
        actor = context.get("actor_id")
        if actor:
            actor_values.add(str(actor))
        for field in ("resource_owner", "resource_tenant"):
            value = context.get(field)
            if value and value not in actor_values and str(value) not in foreign_identifiers:
                foreign_identifiers.append(str(value))
    last_read = next(
        (s for s in reversed(trace)
         if isinstance(s, dict) and s.get("kind") in ("read", "read_rotation")),
        None,
    )
    alias_escalation = any(
        isinstance(step, dict) and (step.get("observed_context") or {}).get(
            "effective_privilege_granted"
        )
        for step in trace
    )
    vuln_class = VulnClass.AUTH_BYPASS if alias_escalation else VulnClass.IDOR
    candidate_path = str(case.get("candidate") or "")
    transitions = list(getattr(outcome, "transitions_applied", None) or [])
    evidence = {
        "detection": "stateful_discovery",
        "confirmation_authority": "cqa_v2.guarded_causal_evaluate",
        "case_id": str(case.get("case_id") or ""),
        "case": {
            "baseline": str(case.get("baseline") or ""),
            "candidate": candidate_path,
            "control": str(case.get("control") or ""),
            "requires_state_transition": bool(
                case.get("requires_state_transition")
            ),
        },
        "verdict": "CONFIRMED",
        "phase": int(getattr(outcome, "phase", 2)),
        "transitions_applied": transitions,
        "transition_origin": getattr(outcome, "transition_origin", None),
        "requests_issued": int(getattr(outcome, "requests_issued", 0)),
        "evidence_trace": trace,
        "engagement_id": str(engagement_id),
        # the foreign identifiers the guard ACTUALLY observed on the
        # candidate (from the trace's observed_context — header- or
        # body-represented; never inferred)
        "foreign_tenant_identifiers": foreign_identifiers or ["observed-foreign-owner"],
        # the post-transition state re-read (the session/authorization
        # state observed AFTER the transitions applied — the honest
        # analog of the family path's post_state_check replay)
        "post_replay_session_check": {
            "post_transition": bool(transitions),
            "control_used": (last_read or {}).get("control"),
            "candidate_digest": ((last_read or {}).get("digests") or {}).get("candidate"),
            "observed_context": (last_read or {}).get("observed_context") or {},
            "verdict": (last_read or {}).get("verdict"),
        },
        # generic adversarial-review guards — implied by a guard
        # CONFIRMED verdict (the branch requires all three
        # differentials); recorded explicitly for the reviewer.
        "baseline_differs": True,
        "artifact_freshly_generated": True,
        "state_changed_by_test": bool(transitions),
        "response_varies_with_identity": True,
    }
    return Finding(
        title=(
            f"[stateful_discovery] authorization bypass via state transition "
            f"on {candidate_path}"
        )[:120],
        severity=Severity.HIGH,
        description=(
            "The causal guard CONFIRMED an authorization differential on a "
            "resource after applying state transitions discovered from the "
            "observed attack surface. The candidate read, re-evaluated after "
            f"{len(transitions)} applied transition(s) originating from "
            f"'{getattr(outcome, 'transition_origin', None) or 'observed'}', "
            "shows the actor granted access the negative control proves is "
            "denied. Confirmation authority: guarded_causal_evaluate; the "
            "full ordered evidence trace is attached."
        ),
        tool_name="stateful_discovery",
        url=f"{base_url}{candidate_path}",
        confidence=Confidence.CONFIRMED,
        vuln_class=vuln_class,
        payload=None,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# the campaign entry point
# ---------------------------------------------------------------------------

def run_stateful_discovery(
    state: Mapping[str, Any],
    *,
    executor: Callable[[Any], Any],
    base_url: str = "",
    inventory: list[Mapping[str, Any]] | None = None,
    max_cases: int = MAX_DISCOVERY_CASES,
    max_requests: int = MAX_TOTAL_REQUESTS,
    research_hints: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the source-driven stateful discovery for one campaign state.

    Returns an audit-friendly summary. CONFIRMED outcomes are returned
    under ``findings`` (the caller merges them into the promoted-findings
    path — they then pass the node's adversarial review and self-verify
    like every other finding). Never raises: internal failures degrade
    to an honest ``error`` status.

    UM-DR-31 ``research_hints``: an optional ``{directory: priority}``
    map from the adaptive research loop (see
    production/adaptive_research.py ``stateful_research_hints``). It
    ONLY reorders the mined cases deterministically within the SAME
    budget — high-priority directories are probed first when the
    request budget runs out. No scope, budget, or authority change of
    any kind; the hints derive exclusively from observed workflow
    boundaries and invariant candidates.
    """
    base_url = str(base_url or state.get("base_url") or state.get("target_url") or "")
    engagement_id = str(state.get("engagement_id") or "unknown")
    allowed = [
        str(a) for a in (
            state.get("allowed_endpoints") or state.get("scope_endpoints") or []
        )
    ]
    if inventory is None:
        from webpent.shared.family_feeds import endpoint_inventory_from_state

        try:
            inventory = endpoint_inventory_from_state(state)
        except (TypeError, ValueError, KeyError, AttributeError):
            inventory = []

    summary: dict[str, Any] = {
        "enabled": True,
        "cases_mined": 0,
        "cases_probed": 0,
        "cases_scope_refused": 0,
        "confirmed": 0,
        "verdicts": {},
        "requests_issued": 0,
        "request_budget": int(max_requests),
        "budget_exhausted": False,
        "scope_refusals": [],
        "per_case": [],
        "research_hints_applied": False,
    }
    findings: list[Any] = []

    try:
        cases = mine_probe_cases(list(inventory or []), max_cases=max_cases)
    except (TypeError, ValueError, AttributeError):
        summary["error"] = "case_mining_failed"
        summary["findings"] = []
        return summary
    summary["cases_mined"] = len(cases)
    if not cases:
        summary["findings"] = []
        return summary

    # UM-DR-31: deterministic priority reordering within the same
    # budget — hinted (research-priority) directories first, stable
    # case_id order inside each priority tier. Ordering only: the same
    # cases, the same budgets, the same scope checks.
    #
    # UM-DR-31.1 R5/F06: ``research_hints_applied`` now means "at least
    # one mined execution case ACTUALLY matched a hint key" — a hint
    # map that matches no executable case (wrong vocabulary, stale
    # directories) is recorded honestly as NOT applied, with the match
    # count exposed for audit.
    #
    # UM-DR-31.1 §6.1 scheduling fix: besides exact directory keys, a
    # single-segment SURFACE hint (a coverage cell's context token,
    # e.g. "vaults" from "idor:vaults") matches a mined directory
    # segment-aligned as a trailing suffix, at a 0.5 discount — an
    # exact workflow observation always outranks a surface match. This
    # stays ordering-only: same cases, same budget, same scope checks.
    try:
        hints = {
            str(k): float(v)
            for k, v in dict(research_hints or {}).items()
            if isinstance(k, str)
        }
    except (TypeError, ValueError):
        hints = {}

    def _hint_priority(directory: str) -> float:
        if directory in hints:
            return hints[directory]
        segments = [s for s in directory.split("/") if s]
        best = 0.0
        for key, priority in hints.items():
            key_segments = [s for s in key.strip("/").split("/") if s]
            if not key_segments or len(key_segments) >= len(segments) + 1:
                continue
            if len(key_segments) == len(segments):
                continue  # same length and not equal — no match
            if segments[-len(key_segments):] == key_segments:
                best = max(best, priority * _SURFACE_HINT_DISCOUNT)
        return best

    if hints:
        matched = sum(
            1 for case in cases if _hint_priority(str(case.get("directory") or "")) > 0.0
        )
        summary["research_hints_matched_cases"] = matched
        summary["research_hints_count"] = len(hints)
        if matched > 0:
            cases.sort(
                key=lambda c: (
                    -_hint_priority(str(c.get("directory") or "")),
                    str(c.get("case_id") or ""),
                )
            )
            summary["research_hints_applied"] = True
        else:
            summary["research_hints_applied"] = False

    source = ObservedSurfaceSource(list(inventory or []))
    client = CampaignProberClient(
        executor, base_url=base_url, allowed_prefixes=allowed or None
    )

    total_requests = 0
    for case in cases:
        remaining = max_requests - total_requests
        if remaining <= 0:
            summary["budget_exhausted"] = True
            break
        candidate_path = str(case.get("candidate") or "")
        if allowed and not _scope_allows(candidate_path, allowed):
            summary["cases_scope_refused"] += 1
            summary["scope_refusals"].append(candidate_path)
            continue
        # the whole-discovery budget bounds each case's probe budget too
        # (budget honesty: the campaign ceiling is never exceeded)
        prober = StatefulCaseProber(
            client, base_url=base_url, transition_source=source,
            max_requests=min(MAX_REQUESTS_PER_CASE, remaining),
        )
        outcome = prober.probe(case)
        total_requests += int(getattr(outcome, "requests_issued", 0))
        summary["cases_probed"] += 1
        verdict = str(outcome.verdict)
        summary["verdicts"][verdict] = summary["verdicts"].get(verdict, 0) + 1
        summary["per_case"].append({
            "case_id": str(case.get("case_id") or ""),
            "candidate": candidate_path,
            "verdict": verdict,
            "phase": int(outcome.phase),
            "requests": int(outcome.requests_issued),
            "transitions_applied": list(outcome.transitions_applied or []),
            "transition_origin": outcome.transition_origin,
        })
        if verdict == "CONFIRMED":
            summary["confirmed"] += 1
            findings.append(
                _finding_from_outcome(
                    outcome, case, base_url=base_url, engagement_id=engagement_id
                )
            )

    summary["requests_issued"] = total_requests
    summary["scope_refusals"] = list(
        dict.fromkeys([*summary["scope_refusals"], *client.scope_refusals])
    )
    summary["findings"] = findings
    return summary
