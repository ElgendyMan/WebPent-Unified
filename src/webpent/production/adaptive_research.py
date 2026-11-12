"""UM-DR-31 — the evidence-driven adaptive research loop.

The UM-DR-30 window wired the coverage gap map and the invariant review
as ADVISORY producers: their output landed on declared state channels
(``coverage_gap_report``, ``invariant_review``) but no consumer changed
a research decision — the honest matrix recorded both as
CAMPAIGN_INTEGRATED/advisory. This module closes that loop. It is the
campaign-side research engine that turns those signals (plus the
workflow authorization-boundary observations) into structured, testable
hypotheses in the REAL hypothesis pool, so the existing strategist
promotion checkpoint — the production planner — ranks them in the same
pass and the existing authorized execution path (strategist promotion
gates → payload_generator → execution_sandbox, and the family execution
spine's stateful discovery) can execute them.

The complete operational data flow this module establishes:

    recon/discovery observations (campaign state)
      → research signal inventory (THIS MODULE — coverage ledger
        projection + invariant review + workflow boundary observations,
        each classified per the UM-DR-31 classification contract
        (``classify_coverage_status`` — F12/F08-corrected vocabulary))
      → adaptive hypothesis generation (THIS MODULE — deterministic
        vuln-class mapping, bounded templates, stable fingerprints,
        dedup against the existing pool by deterministic uuid5 ids)
      → the REAL hypothesis pool (``state["hypotheses"]``)
      → the existing strategist planner (ranking + promotion gates —
        unchanged; a research-loop hypothesis is an ORDINARY hypothesis)
      → the existing authorized execution path (scope, budgets, rate
        limits, HITL — all inherited, none bypassed)
      → causal verification (``cqa_v2.guarded_causal_evaluate`` — the
        ONLY confirmation authority, unchanged by this module)
      → ProofBundle + coverage ledger updates
      → the next research_loop invocation consumes the UPDATED state
        (execution outcomes change which signals are actionable).

DISCIPLINE (the UM-DR-31 contract):
  * deterministic — no randomness, no LLM, no network I/O, fixed order;
  * bounded — ``max_research_iterations`` invocations that do work,
    ``max_research_hypotheses_per_iteration`` new hypotheses per
    invocation, signal scan capped; every bound is reported, never
    silently truncated;
  * fail-closed — flag off (default) or unavailable settings ⇒ the node
    is a no-op; invalid mandatory limits ⇒ no-op (fail closed);
  * fail-soft — any internal failure degrades to an honest error
    status in the telemetry (the campaign continues);
  * non-promoting — this module NEVER creates a Finding, NEVER confirms
    anything, NEVER grants authority. A hypothesis is a belief, not a
    result; the causal guard stays the sole confirmation authority;
  * no fabrication — signals derive from observed state only. A
    confirmed negative (ledger status ``clean``) is NOT a gap; a
    confirmed vulnerability (``tool_confirmed``) is NOT re-hypothesized;
    an unmapped ledger class is recorded, never guessed;
  * scope-respecting — out-of-scope invariant results
    (``out_of_scope_transition_must_not_be_processed``) generate NO
    hypothesis: probing a scope-denied transition would violate the
    authorization contract this loop exists to honor.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit
from uuid import NAMESPACE_URL, uuid5

logger = logging.getLogger(__name__)

#: Stable LangGraph node name (the state-channel key is
#: ``research_loop``; the node name carries the wire provenance).
RESEARCH_LOOP_NODE_NAME = "research_loop"

#: Provenance window tag carried in every telemetry block.
RESEARCH_LOOP_WINDOW = "UM-DR-31"

#: Hard cap on signals scanned per invocation (bounding the scan cost).
MAX_SIGNALS_SCANNED = 400

#: Hard cap on workflow observations inspected per invocation.
_MAX_WORKFLOW_OBSERVATIONS = 200

#: Hard cap on invariant review entries inspected per invocation.
_MAX_INVARIANT_ENTRIES = 200

#: The ledger's open statuses that carry research value (mirrored from
#: the gap detector so the classification is self-describing).
_ACTIONABLE_COVERAGE_STATUSES = frozenset({
    "not_scanned",             # observed but not tested
    "inconclusive",            # tested but inconclusive
    "blocked_by_precondition", # blocked — operational retry may succeed
    "infrastructure_failure",  # blocked — operational retry may succeed
})

#: Ledger statuses that must NOT produce a hypothesis (the UM-DR-31
#: "a confirmed negative result must not be treated as an unexplored
#: area" rule, plus the operator-constraint classes).
_NON_ACTIONABLE_COVERAGE_STATUSES = frozenset({
    "policy_block",       # operator constraint — never probe
    "human_review_only",  # deliberate human gate — never probe
    "missing-validator",  # capability gap — hypothesis unexecutable
    "clean",              # tested and safely rejected
    "tool_confirmed",     # confirmed vulnerability — already found
    "candidate",          # owned by the causal/human pipeline
})

# ---------------------------------------------------------------------------
# UM-DR-31.1 R6/F08/F12/F20 — the explicit classification contract
# ---------------------------------------------------------------------------

#: The classification vocabulary (the pure function ``classify_coverage_status``
#: returns EXACTLY these strings — the tested contract):
#:   actionable      — observed_not_tested, tested_inconclusive, blocked_operational
#:   non-actionable  — blocked_policy, non_actionable, tested_rejected,
#:                     confirmed_vulnerability
#:   fail-closed     — unknown_status (an unrecognized input status is never
#:                     silently converted into an executable opportunity; it is
#:                     classified, counted and recorded — F20)
CLASSIFICATION_ACTIONABLE = frozenset({
    "observed_not_tested",
    "tested_inconclusive",
    "blocked_operational",
})
CLASSIFICATION_NON_ACTIONABLE = frozenset({
    "blocked_policy",
    "non_actionable",
    "tested_rejected",
    "confirmed_vulnerability",
    "unknown_status",
})
CLASSIFICATION_VOCABULARY = CLASSIFICATION_ACTIONABLE | CLASSIFICATION_NON_ACTIONABLE

#: Raw ledger status → canonical projected status aliases. These are the
#: producer-vocabulary spellings the projection deliberately reconciles
#: (``shared/campaigns.py`` writes ``not_observed``/``tested``; the pinned
#: projection contract maps both onto ``not_scanned`` and lets the attempt
#: count refine the classification). ANY OTHER unrecognized status is NOT
#: aliased — it projects to ``unknown_status`` (fail-closed, F20).
_RAW_LEDGER_STATUS_ALIASES = frozenset({"not_observed", "tested"})

#: Deterministic information-gain priors per signal classification
#: (explainable, traceable prioritization input — NOT a score the
#: strategist is forced to obey; the strategist's own ranking formula
#: stays the ranking authority).
_INFO_GAIN_PRIORS: dict[str, float] = {
    "coverage.observed_not_tested": 0.60,
    "coverage.tested_inconclusive": 0.45,
    "coverage.blocked_operational": 0.30,
    "invariant.authorization_context_must_be_present": 0.65,
    "invariant.state_must_progress_or_reject_replay": 0.55,
    "workflow.boundary.cross_identity": 0.55,
    "workflow.boundary.object_scoped": 0.50,
    "workflow.boundary.role_scoped": 0.45,
}

#: Deterministic estimated-cost lookup by vuln class value (the Phase 6
#: cost-vs-value vocabulary; ``_COST_CEILING`` is 10.0).
_CLASS_COST_LOOKUP: dict[str, float] = {
    "idor": 4.0,
    "privilege_differential": 5.0,
    "business_logic": 7.0,
    "tenant_isolation": 6.0,
    "auth_bypass": 6.0,
    "multi_step_auth_bypass": 8.0,
}
_DEFAULT_CLASS_COST = 6.0

#: Deterministic probing-risk estimate by vuln class value (input to
#: approval-tier selection downstream, never a bypass).
_CLASS_RISK_LOOKUP: dict[str, float] = {
    "business_logic": 0.5,
    "multi_step_auth_bypass": 0.5,
    "privilege_differential": 0.3,
    "idor": 0.2,
    "tenant_isolation": 0.3,
    "auth_bypass": 0.3,
}
_DEFAULT_CLASS_RISK = 0.3

#: Ledger class-prefix → VulnClass value mapping (deterministic; the
#: ledger keys are ``"<class>:<context>"`` shaped — see the campaign
#: ledger producer and the UM-DR-30 gap report tests).
_LEDGER_CLASS_MAP: dict[str, str] = {
    "xss": "xss",
    "sqli": "sqli",
    "ssrf": "ssrf",
    "blind_ssrf": "blind_ssrf",
    "lfi": "lfi",
    "rfi": "rfi",
    "rce": "rce",
    "ssti": "ssti",
    "open_redirect": "open_redirect",
    "xxe": "xxe",
    "xxe_oob": "xxe_oob",
    "blind_sqli": "blind_sqli",
    "csrf": "csrf",
    "deserialization": "deserialization",
    "path_traversal": "path_traversal",
    "command_injection": "command_injection",
    "nosql_injection": "nosql_injection",
    "info_disclosure": "info_disclosure",
    "race_condition": "race_condition",
    "idor": "idor",
    "auth_bypass": "auth_bypass",
    "mass_assignment": "mass_assignment",
    "request_smuggling": "request_smuggling",
    "brute_force": "brute_force",
    "captcha": "captcha",
    "weak_session": "weak_session",
    "csp": "csp",
    "javascript": "javascript",
    "cryptography": "cryptography",
    "api_issue": "api_issue",
    "subdomain_takeover": "subdomain_takeover",
    "cloud_storage_exposure": "cloud_storage_exposure",
    "jwt_weakness": "jwt_weakness",
    "jwt_key_confusion": "jwt_key_confusion",
    "business_logic": "business_logic",
    "multi_step_auth_bypass": "multi_step_auth_bypass",
    "tenant_isolation": "tenant_isolation",
    "exploit_chain": "exploit_chain",
    "oauth": "oauth",
    "graphql_introspection_exposure": "graphql_introspection_exposure",
    "graphql_batching_abuse": "graphql_batching_abuse",
    "graphql_field_suggestion_leak": "graphql_field_suggestion_leak",
    "graphql_depth_complexity_dos": "graphql_depth_complexity_dos",
    "prototype_pollution": "prototype_pollution",
    "oauth_misconfiguration": "oauth_misconfiguration",
    "cache_poisoning": "cache_poisoning",
    "web_cache_deception": "web_cache_deception",
    "privilege_differential": "privilege_differential",
}

#: The invariant identifiers this loop knows how to turn into a
#: testable hypothesis (anything else is recorded, not guessed).
_ACTIONABLE_INVARIANTS = frozenset({
    "authorization_context_must_be_present",
    "state_must_progress_or_reject_replay",
})


# ---------------------------------------------------------------------------
# fail-closed settings access
# ---------------------------------------------------------------------------

def _research_loop_limits() -> tuple[int, int] | None:
    """Return ``(max_iterations, max_per_iteration)`` fail-closed.

    Any unavailable/invalid mandatory limit ⇒ ``None`` ⇒ the node is a
    no-op (the UM-DR-31 "fail closed when mandatory limits are
    unavailable" rule).
    """
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        max_iterations = int(getattr(settings, "max_research_iterations", 0) or 0)
        max_per_iter = int(
            getattr(settings, "max_research_hypotheses_per_iteration", 0) or 0
        )
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return None
    if max_iterations < 1 or max_per_iter < 1:
        return None
    # hard upper bounds: configuration cannot remove boundedness
    return (min(max_iterations, 16), min(max_per_iter, 64))


def research_loop_enabled() -> bool:
    """Flag + mandatory limits both available (fail-closed)."""
    try:
        from webpent.config.settings import get_settings

        if not bool(get_settings().enable_adaptive_research_loop):
            return False
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False
    return _research_loop_limits() is not None


# ---------------------------------------------------------------------------
# signal inventory — the UM-DR-31/31.1 classification contract
# ---------------------------------------------------------------------------

def classify_coverage_status(status: str, attempts: int) -> str:
    """Classify one ledger cell — the pure, tested classification contract.

    UM-DR-31.1 R6 (F08/F12/F20): this function is the SINGLE authority for
    ledger-status → research-classification. The vocabulary is exactly
    ``CLASSIFICATION_VOCABULARY`` (7 canonical classes + the fail-closed
    ``unknown_status`` bucket):

    ============================  ==============  ===============
    classification                actionable?     source statuses
    ============================  ==============  ===============
    observed_not_tested           YES (0.60)      not_scanned, attempts==0
    tested_inconclusive           YES (0.45)      inconclusive; not_scanned
                                                  with attempts>0
    blocked_operational           YES (0.30)      blocked_by_precondition,
                                                  infrastructure_failure
    blocked_policy                NO              policy_block
    non_actionable                NO              human_review_only,
                                                  missing-validator,
                                                  candidate (F08: a candidate
                                                  cell is owned by the
                                                  causal/human pipeline and
                                                  is NOT an unexplored gap)
    tested_rejected               NO              clean
    confirmed_vulnerability       NO              tool_confirmed
    unknown_status                NO (fail-closed, observable)  any other
                                                  unrecognized status (F20)
    ============================  ==============  ===============

    Pure function of ``(status, attempts)`` — no state, no I/O, no
    detector dependency, deterministic. Unknown/malformed inputs are
    classified, never guessed and never actionable.
    """
    text = str(status or "")
    if text == "clean":
        return "tested_rejected"
    if text == "tool_confirmed":
        return "confirmed_vulnerability"
    if text in {"candidate", "human_review_only", "missing-validator"}:
        # F08: "candidate" joins the explicit non-actionable set — a
        # candidate signal is already owned by the causal/human pipeline;
        # treating it as an unexplored area would re-hypothesize work that
        # the confirmation pipeline already owns.
        return "non_actionable"
    if text == "policy_block":
        return "blocked_policy"
    if text in {"blocked_by_precondition", "infrastructure_failure"}:
        return "blocked_operational"
    if text == "inconclusive":
        return "tested_inconclusive"
    if text == "unknown_status":
        return "unknown_status"
    if int(attempts or 0) > 0:
        # not_scanned with backing attempts: the outcome was executed
        # but produced no recognized status — honest inconclusive.
        return "tested_inconclusive"
    if text == "not_scanned" or not text:
        return "observed_not_tested"
    # F20 fail-closed: an unrecognized status is explicitly non-actionable
    # and observable — never silently converted into an open opportunity.
    return "unknown_status"


def _classify_coverage_status(status: str, attempts: int) -> str:
    """Backward-compatible private alias for :func:`classify_coverage_status`."""
    return classify_coverage_status(status, attempts)


def _base_url(state: Mapping[str, Any]) -> str:
    return str(
        state.get("base_url")
        or state.get("target_url")
        or ""
    ).rstrip("/")


def _normalize_url(url: str) -> str:
    """Canonical form used for endpoint identity and fingerprints.

    UM-DR-31.1 R4 (F10/F11):
      * scheme and hostname are lower-cased case-insensitively (F11 —
        ``https://X.com`` and ``https://x.com`` are the same target);
      * the query string is PRESERVED and sorted deterministically
        (F10 — ``…?account=1`` and ``…?account=2`` are different
        objects); duplicate parameters are kept (parse_qsl + sort of the
        pair list, never a dict fold);
      * the fragment is stripped (never semantically relevant to a
        server-side probe);
      * the trailing slash is stripped (trailing-slash equivalence);
      * relative references (no scheme) are returned trimmed, unchanged.

    The transform is idempotent and deterministic.
    """
    text = str(url or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        # malformed URL — keep the trimmed input; the scope filter is
        # the authority that decides what may be admitted
        return text.rstrip("/")
    if not parts.scheme:
        return text.rstrip("/")
    netloc = parts.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, _, netloc = netloc.rpartition("@")
    if netloc.startswith("["):
        # IPv6 literal: lower-case the literal, keep any port suffix
        host, _, suffix = netloc.partition("]")
        netloc = f"{host.lower()}]{suffix}"
    else:
        host, sep, _port = netloc.partition(":")
        netloc = f"{host.lower()}{sep}{_port}"
    if userinfo:
        netloc = f"{userinfo}@{netloc}"
    normalized = f"{parts.scheme.lower()}://{netloc}{parts.path}"
    if parts.query:
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True)
        except ValueError:
            pairs = []
        if pairs:
            normalized += "?" + urlencode(sorted(pairs))
    return normalized.rstrip("/")


def _effective_port(scheme: str, port: str | None) -> int | None:
    """Resolve the effective port for an origin (scheme default applied)."""
    try:
        if port:
            return int(port)
    except ValueError:
        return None
    return {"http": 80, "https": 443}.get(scheme, None)


def _campaign_origin(base_url: str) -> tuple[str, str, int | None] | None:
    """Derive the authorized campaign origin ``(scheme, host, port)``.

    R3: the origin comes from the ACTUAL campaign configuration (the
    state's ``base_url``/``target_url`` — the same value every executor
    scope gate derives its prefixes from). ``None`` when the state
    carries no usable target (fail closed — no origin, no admission).
    """
    text = str(base_url or "").strip()
    if not text:
        return None
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.hostname:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    return (scheme, parts.hostname.lower(), _effective_port(scheme, str(port) if port else None))


def _admit_endpoint(
    endpoint: str,
    origin: tuple[str, str, int | None] | None,
    base_url: str = "",
) -> tuple[str, str]:
    """Hypothesis-admission scope filter for a workflow endpoint (R3/F05).

    Returns ``(normalized_endpoint, "")`` when the endpoint is admitted,
    or ``("", rejection_reason)`` when it must never become an executable
    research candidate. Deliberate rules:

      * the endpoint must parse as a valid http(s) URL after optional
        joining with the campaign base_url (relative references are
        joined exactly as the pre-31.1 code joined them — full base_url
        including any path prefix; a relative reference with NO usable
        base is rejected — no target context is ever fabricated);
      * the scheme must be http or https (ftp://, file://, data:// … are
        rejected before hypothesis admission);
      * the host must equal the authorized origin host case-insensitively
        (foreign hosts are rejected here, BEFORE the hypothesis pool —
        the execution-time scope gate stays the authoritative second
        gate; this is defense in depth, not a replacement);
      * the effective port (explicit or scheme default) must equal the
        origin's effective port — a different port is a different
        service, not the authorized origin.
    """
    text = str(endpoint or "").strip()
    if not text:
        return "", "empty_endpoint"
    if origin is None:
        return "", "no_campaign_origin"
    origin_scheme, origin_host, origin_port = origin
    candidate = text
    if "//" not in candidate:
        # relative reference — join against the campaign base_url
        # (same join the pre-31.1 code performed: full base_url)
        base = str(base_url or "").rstrip("/")
        if not base:
            return "", "no_campaign_origin"
        candidate = f"{base}/{text.lstrip('/')}"
    try:
        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return "", "malformed_url"
    if scheme not in {"http", "https"}:
        return "", f"scheme_not_http_s:{scheme or 'none'}"
    if not hostname:
        return "", "malformed_url_no_host"
    # UM-DR-32 §10.1: the COMPLETE normalized origin must match — scheme
    # too. An https origin must never admit an http endpoint (and vice
    # versa) merely because host and effective port coincide: a matching
    # numeric port under a different scheme is a DIFFERENT origin
    # (https://lab:443 and http://lab:443 are distinct origins).
    if scheme != origin_scheme:
        return "", f"scheme_mismatch:{scheme}_vs_{origin_scheme}"
    if hostname.lower() != origin_host:
        return "", "foreign_host"
    candidate_port = _effective_port(scheme, str(port) if port else None)
    if candidate_port != origin_port:
        return "", "port_mismatch"
    return _normalize_url(candidate), ""


def research_signal_inventory(state: Mapping[str, Any]) -> dict[str, Any]:
    """Build the classified research signal inventory from observed state.

    Deterministic, read-only, network-free. Sources:

    1. the shared coverage ledger projection (the same code path the
       UM-DR-30 coverage_gap_report node uses — consistency by
       construction);
    2. the invariant review channel (business_logic/invariant_checker
       results, UM-DR-30 wiring);
    3. the workflow observation channel (authorization boundaries that
       were OBSERVED but never tested).

    Every signal carries its source references; nothing is fabricated
    from missing data.
    """
    inventory: dict[str, Any] = {
        "coverage": [],
        "invariants": [],
        "workflow_boundaries": [],
        "scope_violations": [],
        "unmapped_ledger_classes": [],
        "counts": {
            "coverage_scanned": 0,
            "invariants_scanned": 0,
            "workflow_scanned": 0,
            "non_actionable": 0,
        },
    }

    # -- 1. coverage ledger projection --------------------------------
    coverage_gaps: list[dict[str, Any]] = []
    try:
        from webpent.coverage.gap_detector import CoverageGapDetector

        coverage_gaps = [
            dict(gap)
            for gap in CoverageGapDetector().detect(state)
            if isinstance(gap, Mapping)
        ]
    except Exception as exc:  # noqa: BLE001 — inventory must be fail-soft
        logger.debug("Research loop: coverage projection unavailable: %s", exc)
        inventory["coverage_error"] = str(exc)[:200]

    for gap in coverage_gaps[:MAX_SIGNALS_SCANNED]:
        key = str(gap.get("key") or "")
        if not key:
            continue
        status = str(gap.get("status") or "not_scanned")
        attempts = int(gap.get("attempts") or 0)
        classification = classify_coverage_status(status, attempts)
        inventory["counts"]["coverage_scanned"] += 1
        if classification in {"tested_rejected", "confirmed_vulnerability"}:
            # A confirmed negative is NOT an unexplored area; a
            # confirmed vulnerability is already found. No signal.
            continue
        if classification == "unknown_status":
            # F20 second gate: an unrecognized status is recorded and
            # counted, never turned into a research opportunity (the
            # projection's ``unknown_status`` is the first gate — the
            # detector never emits it as a gap).
            inventory["counts"]["non_actionable"] += 1
            inventory.setdefault("unknown_status_keys", []).append(key)
            continue
        if classification == "blocked_policy":
            inventory["counts"]["non_actionable"] += 1
            continue
        if classification == "non_actionable":
            inventory["counts"]["non_actionable"] += 1
            continue
        vuln_value = _LEDGER_CLASS_MAP.get(key.split(":", 1)[0].strip().lower())
        if vuln_value is None:
            # unmapped class: record honestly, never guess a class
            inventory["unmapped_ledger_classes"].append(key)
            continue
        inventory["coverage"].append({
            "signal_id": f"cov:{key}",
            "source": "coverage_ledger",
            "key": key,
            "status": status,
            "attempts": attempts,
            "classification": classification,
            "vuln_class": vuln_value,
            "evidence_refs": [f"ledger:{key}"],
            "reason": str(gap.get("reason") or "")[:200],
        })

    # -- 2. invariant review -------------------------------------------
    invariant_entries = [
        item for item in (state.get("invariant_review") or [])
        if isinstance(item, Mapping)
    ]
    for entry in invariant_entries[:_MAX_INVARIANT_ENTRIES]:
        inventory["counts"]["invariants_scanned"] += 1
        invariant = str(entry.get("invariant") or "")
        fingerprint = str(entry.get("observation_fingerprint") or "")
        if not invariant or not fingerprint:
            continue
        if invariant == "out_of_scope_transition_must_not_be_processed":
            # scope-respecting rule: NO hypothesis for a scope-denied
            # transition (recorded for audit only)
            inventory["scope_violations"].append({
                "signal_id": f"inv:{fingerprint}",
                "invariant": invariant,
            })
            continue
        if invariant not in _ACTIONABLE_INVARIANTS:
            inventory["counts"]["non_actionable"] += 1
            continue
        inventory["invariants"].append({
            "signal_id": f"inv:{fingerprint}:{invariant}",
            "source": "invariant_review",
            "invariant": invariant,
            "observation_fingerprint": fingerprint,
            "reason": str(entry.get("reason") or "")[:200],
            "evidence_refs": [
                ref for ref in (entry.get("evidence_refs") or [])
                if isinstance(ref, str)
            ][:8] or [f"invariant:{fingerprint}"],
        })

    # -- 3. workflow authorization boundaries ---------------------------
    observations = [
        item for item in (state.get("workflow_observations") or [])
        if isinstance(item, Mapping)
    ]
    # Semantic dedup (UM-DR-31 §5.3, the precise-merge direction): an
    # actionable invariant candidate IS the reviewed form of its source
    # observation's boundary signal — the invariant hypothesis covers
    # that observation. Observations with a DIFFERENT fingerprint
    # still generate their own boundary hypothesis (no over-merging).
    invariant_fingerprints = {
        str(entry.get("observation_fingerprint") or "")
        for entry in inventory["invariants"]
    }
    base_url = _base_url(state)
    campaign_origin = _campaign_origin(base_url)
    for observation in observations[:_MAX_WORKFLOW_OBSERVATIONS]:
        inventory["counts"]["workflow_scanned"] += 1
        boundary = str(observation.get("authorization_boundary") or "unknown")
        if boundary not in {"cross_identity", "role_scoped", "object_scoped"}:
            continue
        if str(observation.get("scope_decision") or "unknown") != "allowed":
            # never build a probe for a denied/unknown-scope transition
            continue
        if str(observation.get("fingerprint") or "") in invariant_fingerprints:
            # covered by the invariant hypothesis (same observation)
            continue
        endpoint = str(observation.get("endpoint") or "")
        if not endpoint:
            continue
        # R3/F05 hypothesis-admission scope filter: a foreign host, a
        # non-http(s) scheme, or a malformed URL must never become an
        # executable research candidate. Rejections are recorded, not
        # silently dropped (the execution-time scope gate remains the
        # authoritative gate; this is defense in depth).
        admitted, rejection = _admit_endpoint(endpoint, campaign_origin, base_url)
        if not admitted:
            inventory["scope_violations"].append({
                "signal_id": f"wf:{observation.get('fingerprint') or ''}:{boundary}",
                "endpoint": endpoint[:200],
                "reason": rejection,
                "stage": "hypothesis_admission",
            })
            continue
        endpoint = admitted
        inventory["workflow_boundaries"].append({
            "signal_id": f"wf:{observation.get('fingerprint') or ''}:{boundary}",
            "source": "workflow_observations",
            "boundary": boundary,
            "endpoint": _normalize_url(endpoint),
            "method": str(observation.get("method") or "GET").upper(),
            "from_state": str(observation.get("from_state") or "unknown"),
            "to_state": str(observation.get("to_state") or "unknown"),
            "prerequisites": [
                str(p) for p in (observation.get("prerequisites") or [])
                if isinstance(p, str)
            ][:8],
            "principal_refs": sorted({
                str(ref)
                for ref in [
                    observation.get("identity_ref"),
                    *(observation.get("identity_context") or []),
                ]
                if ref
            })[:6],
            "evidence_refs": [
                ref for ref in (observation.get("evidence_refs") or [])
                if isinstance(ref, str)
            ][:8] or [f"workflow:{observation.get('fingerprint') or ''}"],
        })

    inventory["counts"]["actionable"] = (
        len(inventory["coverage"])
        + len(inventory["invariants"])
        + len(inventory["workflow_boundaries"])
    )
    return inventory


# ---------------------------------------------------------------------------
# hypothesis fingerprints — stable, security-relevant-difference preserving
# ---------------------------------------------------------------------------

def hypothesis_fingerprint(
    *,
    target_url: str,
    vuln_class: str,
    objective_key: str,
    principal_refs: list[str] | tuple[str, ...] = (),
    preconditions: list[str] | tuple[str, ...] = (),
    state_keys: list[str] | tuple[str, ...] = (),
) -> str:
    """The stable fingerprint of a research hypothesis.

    Two hypotheses merge ONLY when they share target, class, objective,
    principals, preconditions and state keys — so hypotheses that look
    similar but differ in a security-relevant identity, authorization
    context, or state transition NEVER merge (UM-DR-31 §5.3).
    Deterministic sha256 over a canonical JSON document.
    """
    canonical = {
        "t": _normalize_url(target_url),
        "v": str(vuln_class).lower(),
        "o": str(objective_key),
        "p": sorted({str(p) for p in principal_refs if p}),
        "c": sorted({str(p) for p in preconditions if p}),
        "s": sorted({str(k) for k in state_keys if k}),
    }
    import json

    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:40]


def _hypothesis_id(fingerprint: str):
    """Deterministic uuid5 id (the workflow-understanding convention)."""
    return uuid5(NAMESPACE_URL, f"webpent:umdr31:{fingerprint}")


# ---------------------------------------------------------------------------
# hypothesis construction (deterministic templates, bounded)
# ---------------------------------------------------------------------------

def _confidence(evidence_ref_count: int) -> float:
    return min(0.60, 0.35 + 0.05 * min(int(evidence_ref_count), 4))


def _hypothesis_from_coverage_signal(
    signal: Mapping[str, Any],
    *,
    target_url: str,
) -> Any | None:
    from webpent.models.hypothesis import Hypothesis, HypothesisOrigin

    key = str(signal.get("key") or "")
    vuln_value = str(signal.get("vuln_class") or "")
    classification = str(signal.get("classification") or "")
    if not key or not vuln_value or not target_url:
        return None
    fingerprint = hypothesis_fingerprint(
        target_url=target_url,
        vuln_class=vuln_value,
        objective_key=f"ledger:{key}",
    )
    prior = _INFO_GAIN_PRIORS.get(f"coverage.{classification}", 0.45)
    if classification == "tested_inconclusive":
        statement = (
            f"Retest the inconclusively-tested {key} coverage cell with a "
            "fresh evidence-backed strategy; the prior attempt produced no "
            "recognized outcome."
        )[:500]
    elif classification == "blocked_operational":
        statement = (
            f"Retry the operationally-blocked {key} coverage cell; the prior "
            "attempt was blocked by a precondition or infrastructure failure, "
            "not by a security rejection."
        )[:500]
    else:
        statement = (
            f"The {key} coverage cell is observed but untested; validating it "
            "is expected to add security knowledge the campaign does not have."
        )[:500]
    return Hypothesis(
        id=_hypothesis_id(fingerprint),
        target_url=target_url,
        statement=statement,
        vuln_class=vuln_value,
        status="unexplored",
        confidence_score=_confidence(len(signal.get("evidence_refs") or [])),
        evidence_refs=list(signal.get("evidence_refs") or [])[:8],
        origin=HypothesisOrigin.COVERAGE_GAP,
        origin_detail=(
            f"umdr31_research_loop fp={fingerprint} signal={signal.get('signal_id')} "
            f"classification={classification}"
        )[:500],
        estimated_cost=_CLASS_COST_LOOKUP.get(vuln_value, _DEFAULT_CLASS_COST),
        info_gain=prior,
        risk=_CLASS_RISK_LOOKUP.get(vuln_value, _DEFAULT_CLASS_RISK),
        preconditions=["coverage-cell-open"],
        expected_behavior=(
            "A guarded probe of the open coverage cell either yields a "
            "candidate signal for the causal guard or a clean negative that "
            "closes the cell."
        )[:500],
        negative_control=(
            "The probe's negative control (baseline identity and randomized "
            "nonexistent target) must NOT show the effect."
        )[:500],
        alternatives=["the cell is open because the surface is absent"],
        hint_provenance=["umdr31_coverage_gap"],
    )


def _hypothesis_from_invariant_signal(
    signal: Mapping[str, Any],
    *,
    target_url: str,
) -> Any | None:
    from webpent.models.hypothesis import Hypothesis, HypothesisOrigin

    invariant = str(signal.get("invariant") or "")
    if invariant not in _ACTIONABLE_INVARIANTS or not target_url:
        return None
    if invariant == "authorization_context_must_be_present":
        vuln_value = "idor"
        objective = f"invariant:{invariant}"
        statement = (
            "An observed role- or cross-identity workflow transition lacks "
            "identity context; the transition's authorization boundary may "
            "be enforced inconsistently and is worth a guarded cross-identity "
            "probe."
        )[:500]
        expected = (
            "If the boundary is not enforced, the same transition executed "
            "under an unauthorized identity produces an authorization "
            "differential the causal guard can evaluate."
        )[:500]
        control = (
            "The same transition under the authorized baseline identity plus "
            "a randomized nonexistent identity must NOT produce the "
            "differential."
        )[:500]
        preconditions = ["observed-transition-with-identity-context-gap"]
    else:  # state_must_progress_or_reject_replay
        vuln_value = "business_logic"
        objective = f"invariant:{invariant}"
        statement = (
            "A destructive workflow transition reports an unchanged state; "
            "the transition may accept replay or lack a state-machine guard "
            "and is worth a bounded replay probe."
        )[:500]
        expected = (
            "If the state machine is missing, a replayed destructive "
            "transition is accepted where it must be rejected."
        )[:500]
        control = (
            "The replay against a fresh, differently-ordered state must be "
            "rejected; an identical acceptance on the control invalidates "
            "the candidate."
        )[:500]
        preconditions = ["observed-destructive-transition"]
    fingerprint = hypothesis_fingerprint(
        target_url=target_url,
        vuln_class=vuln_value,
        objective_key=objective,
        principal_refs=(),
        preconditions=preconditions,
        state_keys=(str(signal.get("observation_fingerprint") or ""),),
    )
    prior = _INFO_GAIN_PRIORS.get(f"invariant.{invariant}", 0.5)
    return Hypothesis(
        id=_hypothesis_id(fingerprint),
        target_url=target_url,
        statement=statement,
        vuln_class=vuln_value,
        status="unexplored",
        confidence_score=_confidence(len(signal.get("evidence_refs") or [])),
        evidence_refs=list(signal.get("evidence_refs") or [])[:8],
        origin=HypothesisOrigin.INVARIANT,
        origin_detail=(
            f"umdr31_research_loop fp={fingerprint} signal={signal.get('signal_id')}"
        )[:500],
        estimated_cost=_CLASS_COST_LOOKUP.get(vuln_value, _DEFAULT_CLASS_COST),
        info_gain=prior,
        risk=_CLASS_RISK_LOOKUP.get(vuln_value, _DEFAULT_CLASS_RISK),
        preconditions=preconditions,
        expected_behavior=expected,
        negative_control=control,
        alternatives=["the observation redaction dropped the identity context"],
        hint_provenance=["umdr31_invariant_review"],
    )


def _hypothesis_from_workflow_signal(
    signal: Mapping[str, Any],
    *,
    target_url: str,
) -> Any | None:
    from webpent.models.hypothesis import Hypothesis, HypothesisOrigin

    boundary = str(signal.get("boundary") or "")
    endpoint = str(signal.get("endpoint") or "")
    if boundary not in {"cross_identity", "role_scoped", "object_scoped"}:
        return None
    if not endpoint:
        return None
    vuln_value = "privilege_differential" if boundary == "role_scoped" else "idor"
    principals = [str(p) for p in (signal.get("principal_refs") or [])]
    preconditions = [str(p) for p in (signal.get("prerequisites") or [])] or [
        "observed-authorized-transition"
    ]
    state_keys = [
        str(signal.get("from_state") or ""),
        str(signal.get("to_state") or ""),
    ]
    fingerprint = hypothesis_fingerprint(
        target_url=endpoint or target_url,
        vuln_class=vuln_value,
        objective_key=f"boundary:{boundary}",
        principal_refs=principals,
        preconditions=preconditions,
        state_keys=state_keys,
    )
    prior = _INFO_GAIN_PRIORS.get(f"workflow.boundary.{boundary}", 0.5)
    return Hypothesis(
        id=_hypothesis_id(fingerprint),
        target_url=endpoint or target_url,
        statement=(
            f"The observed {boundary.replace('_', '-')} transition on "
            f"{endpoint} was never tested across its authorization boundary; "
            "a guarded differential probe is expected to add knowledge about "
            "whether the boundary is enforced."
        )[:500],
        vuln_class=vuln_value,
        status="unexplored",
        confidence_score=_confidence(len(signal.get("evidence_refs") or [])),
        evidence_refs=list(signal.get("evidence_refs") or [])[:8],
        origin=HypothesisOrigin.INVARIANT,
        origin_detail=(
            f"umdr31_research_loop fp={fingerprint} signal={signal.get('signal_id')} "
            f"boundary={boundary}"
        )[:500],
        estimated_cost=_CLASS_COST_LOOKUP.get(vuln_value, _DEFAULT_CLASS_COST),
        info_gain=prior,
        risk=_CLASS_RISK_LOOKUP.get(vuln_value, _DEFAULT_CLASS_RISK),
        preconditions=preconditions,
        expected_behavior=(
            "If the boundary is unenforced, the same transition under a "
            "different principal produces a response differential the causal "
            "guard can evaluate against its negative control."
        )[:500],
        negative_control=(
            "The authorized principal's baseline request and a randomized "
            "nonexistent-object request must NOT show the differential."
        )[:500],
        alternatives=["the boundary is enforced and the probe returns clean"],
        hint_provenance=["umdr31_workflow_boundary"],
        request_method=str(signal.get("method") or "GET").upper()[:10],
    )


# ---------------------------------------------------------------------------
# pool-aware generation with dedup
# ---------------------------------------------------------------------------

def _pool_index(hypotheses: Any) -> dict[str, str]:
    """Map ``str(id)`` → status for the existing pool (both shapes)."""
    index: dict[str, str] = {}
    for hypothesis in hypotheses or []:
        if isinstance(hypothesis, Mapping):
            hid = hypothesis.get("id")
            status = hypothesis.get("status")
        else:
            hid = getattr(hypothesis, "id", None)
            status = getattr(hypothesis, "status", None)
        if hid is not None:
            index[str(hid)] = str(status or "unexplored")
    return index


def _closed_status(status: str) -> bool:
    return status in {
        "promoted", "resolved_true", "resolved_false", "abandoned", "learned",
    }


def generate_research_hypotheses(
    state: Mapping[str, Any],
    *,
    max_new: int,
) -> tuple[list[Any], dict[str, Any]]:
    """Generate deduplicated research hypotheses from the signal inventory.

    Returns ``(new_hypotheses, detail)``. Suppression is by deterministic
    id against the existing pool: an OPEN pool entry with the same id is
    already queued (suppressed_open); a CLOSED entry was already decided
    — conclusively rejected or promoted hypotheses are NEVER repeated
    (suppressed_closed, the UM-DR-31 §5.3 rule).

    UM-DR-36.4: when the campaign has recorded measured outcomes
    (``information_gain`` channel), the measured evidence-derived priors
    OVERRIDE the static priors for signal classes with enough samples —
    the next research decision is genuinely influenced by prior outcomes.
    UM-DR-36.5: candidate selection is FAIR — deterministic round-robin
    interleave across the signal pools (coverage / invariant / workflow),
    so one attractive branch cannot starve the others within the budget.
    """
    from webpent.models.hypothesis import Hypothesis  # noqa: F401 — re-export guard

    inventory = research_signal_inventory(state)
    target_url = _base_url(state)
    detail: dict[str, Any] = {
        "signals_actionable": inventory["counts"]["actionable"],
        "signals_non_actionable": inventory["counts"]["non_actionable"],
        "coverage_signals": len(inventory["coverage"]),
        "invariant_signals": len(inventory["invariants"]),
        "workflow_signals": len(inventory["workflow_boundaries"]),
        "scope_violations_recorded": len(inventory["scope_violations"]),
        "unmapped_ledger_classes": sorted(
            set(inventory["unmapped_ledger_classes"])
        )[:32],
        "suppressed_open": 0,
        "suppressed_closed": 0,
        "generated": 0,
        "capped": False,
    }
    if not target_url:
        # No target context: nothing observable to anchor a hypothesis
        # to. Fail closed to zero — never fabricate a target.
        detail["reason"] = "no_target_context"
        return [], detail

    # UM-DR-36.4: measured (evidence-derived) priors override the static
    # table when the campaign has recorded enough outcomes per class.
    try:
        from webpent.production.information_gain import (
            ledger_from_state,
            merge_measured_priors,
        )

        measured_ledger = ledger_from_state(state)
        effective_priors = merge_measured_priors(_INFO_GAIN_PRIORS, measured_ledger)
        if measured_ledger.outcomes:
            detail["measured_priors_applied"] = measured_ledger.measured_priors()
            detail["measured_outcomes"] = len(measured_ledger.outcomes)
    except (AttributeError, ImportError, RuntimeError, TypeError, ValueError):
        effective_priors = dict(_INFO_GAIN_PRIORS)

    pool = _pool_index(state.get("hypotheses"))

    # UM-DR-36.5: FAIR scheduling — per-pool candidate lists, each sorted
    # by (measured-aware) info gain desc, then interleaved round-robin so
    # every pool's best candidate gets an investigation opportunity before
    # any pool's second candidate. Deterministic and bounded.
    pools: dict[str, list[tuple[float, int, Any]]] = {
        "coverage": [], "invariant": [], "workflow": [],
    }
    order = 0
    for signal in inventory["coverage"]:
        hypothesis = _hypothesis_from_coverage_signal(signal, target_url=target_url)
        if hypothesis is not None:
            gain = _effective_signal_gain(
                hypothesis, signal, effective_priors, "coverage")
            pools["coverage"].append((gain, order, hypothesis))
            order += 1
    for signal in inventory["invariants"]:
        hypothesis = _hypothesis_from_invariant_signal(signal, target_url=target_url)
        if hypothesis is not None:
            gain = _effective_signal_gain(
                hypothesis, signal, effective_priors, "invariant")
            pools["invariant"].append((gain, order, hypothesis))
            order += 1
    for signal in inventory["workflow_boundaries"]:
        hypothesis = _hypothesis_from_workflow_signal(signal, target_url=target_url)
        if hypothesis is not None:
            gain = _effective_signal_gain(
                hypothesis, signal, effective_priors, "workflow")
            pools["workflow"].append((gain, order, hypothesis))
            order += 1

    for pool_name in pools:
        pools[pool_name].sort(key=lambda item: (-item[0], item[1]))

    # Round-robin interleave (fair): take the best remaining candidate
    # from each pool in turn; a pool is skipped once exhausted.
    candidates: list[tuple[float, int, Any]] = []
    pool_order = [name for name in ("coverage", "invariant", "workflow")
                  if pools[name]]
    cursors = {name: 0 for name in pool_order}
    while len(candidates) < sum(len(p) for p in pools.values()):
        progressed = False
        for name in pool_order:
            idx = cursors[name]
            if idx < len(pools[name]):
                candidates.append(pools[name][idx])
                cursors[name] = idx + 1
                progressed = True
        if not progressed:
            break
    detail["fair_interleave_pools"] = {n: len(p) for n, p in pools.items() if p}

    new_hypotheses: list[Any] = []
    for _prior, _order, hypothesis in candidates:
        if len(new_hypotheses) >= max_new:
            detail["capped"] = True
            break
        hid = str(hypothesis.id)
        existing_status = pool.get(hid)
        if existing_status is None:
            new_hypotheses.append(hypothesis)
            pool[hid] = "unexplored"
        elif _closed_status(existing_status):
            detail["suppressed_closed"] += 1
        else:
            detail["suppressed_open"] += 1
    detail["generated"] = len(new_hypotheses)
    return new_hypotheses, detail


def _effective_signal_gain(
    hypothesis: Any,
    signal: Mapping[str, Any],
    effective_priors: Mapping[str, float],
    pool_name: str,
) -> float:
    """Measured-aware gain for one candidate hypothesis.

    Combines the hypothesis's own gain with the (possibly measured)
    prior for its signal class. Prioritization input ONLY — this value
    never gates admission, scope, budget, or confirmation.
    """
    base = float(hypothesis.info_gain or 0.5)
    signal_class = None
    if isinstance(signal, Mapping):
        for key in ("signal_class", "ledger_class", "class", "kind"):
            value = signal.get(key)
            if value:
                signal_class = str(value)
                break
    if signal_class:
        for candidate_key in (
            f"{pool_name}.{signal_class}",
            signal_class,
        ):
            if candidate_key in effective_priors:
                base = max(base, float(effective_priors[candidate_key]))
                break
    return base


# ---------------------------------------------------------------------------
# stateful discovery hints — planner → authorized stateful execution
# ---------------------------------------------------------------------------

def stateful_research_hints(state: Mapping[str, Any]) -> dict[str, float]:
    """Priority keys for the stateful discovery, from open research signals.

    Two evidence-derived hint families (UM-DR-31.1 §6.1 scheduling fix):

    1. EXACT directory hints — derived ONLY from observed workflow
       observations with stateful methods and open authorization
       boundaries (the UM-DR-31 mechanism, unchanged). The key is the
       mined-case directory vocabulary ("/".join(segments[:-1]) — no
       leading slash).
    2. SURFACE hints (new) — derived from the classified coverage
       ledger: an actionable cell's key is "<class>:<context>"; the
       context's last path segment (e.g. "vaults" from "idor:vaults")
       is emitted as a single-segment hint key carrying the cell's
       classification prior. The consumer matches it against mined
       directories with a segment-aligned SUFFIX rule at a 0.5 discount
       (an exact workflow observation outranks a surface match). This
       is the measured bottleneck fix: a coverage-cell hypothesis used
       to receive NO execution opportunity at all (the UM-DR-31
       coverage-only ablation arm: 1 hypothesis, 0 confirmations,
       behavior identical to baseline) because exact hints require a
       workflow observation the coverage signal does not carry.

    The consumer (``run_stateful_discovery``) uses the map to ORDER the
    mined cases within the SAME budget — no scope, budget, or authority
    change of any kind. Hints are scheduling signals, never confidence,
    severity, or confirmation inputs.
    """
    hints: dict[str, float] = {}
    observations = [
        item for item in (state.get("workflow_observations") or [])
        if isinstance(item, Mapping)
    ][:_MAX_WORKFLOW_OBSERVATIONS]
    base_url = _base_url(state)
    campaign_origin = _campaign_origin(base_url)
    for observation in observations:
        method = str(observation.get("method") or "GET").upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        boundary = str(observation.get("authorization_boundary") or "unknown")
        if boundary not in {"cross_identity", "role_scoped", "object_scoped"}:
            continue
        if str(observation.get("scope_decision") or "unknown") != "allowed":
            continue
        endpoint = str(observation.get("endpoint") or "")
        # R3 hygiene: the hints directory vocabulary only makes sense for
        # same-origin http(s) endpoints; foreign/scheme-invalid
        # observations produce no hint (the mined cases are always
        # campaign-surface cases anyway).
        admitted, _rejection = _admit_endpoint(endpoint, campaign_origin, base_url)
        if not admitted:
            continue
        parts = [p for p in urlsplit(admitted).path.strip("/").split("/") if p]
        if len(parts) < 2:
            continue
        # the SAME directory vocabulary mine_probe_cases produces
        # ("/".join(segments[:-1]) — no leading slash): a hint key that
        # does not match a mined case's directory silently prioritizes
        # nothing (the exact bug the ablation run exposed).
        directory = "/".join(parts[:-1])
        priority = {
            "cross_identity": 1.0,
            "object_scoped": 0.8,
            "role_scoped": 0.6,
        }.get(boundary, 0.5)
        hints[directory] = max(hints.get(directory, 0.0), priority)

    # UM-DR-31.1 surface hints from the classified coverage ledger —
    # the SAME inventory the hypothesis generation consumes (one
    # classification authority; no second vocabulary).
    try:
        inventory = research_signal_inventory(state)
    except Exception:  # noqa: BLE001 — hints are advisory, fail-soft
        inventory = {"coverage": []}
    for signal in inventory.get("coverage") or []:
        if not isinstance(signal, Mapping):
            continue
        key = str(signal.get("key") or "")
        prior = _INFO_GAIN_PRIORS.get(
            f"coverage.{str(signal.get('classification') or '')}", 0.0
        )
        if not key or prior <= 0.0:
            continue
        context = key.split(":", 1)[1] if ":" in key else key
        surface = [p for p in str(context).strip("/").split("/") if p]
        if not surface:
            continue
        token = surface[-1].lower()
        if len(token) < 3:
            # too short to be a meaningful surface identity — skip
            continue
        hints[token] = max(hints.get(token, 0.0), prior)

    # UM-DR-32 identity hints — the identity/alias layer's ordering
    # signals (confirmed cross-representation differentials, object
    # surfaces with open differential questions). Same contract as the
    # families above: ordering ONLY within the same budget, never
    # confidence/severity/confirmation inputs. The channel is produced
    # by the identity_workflow node (production/identity_workflow.py).
    for directory, priority in (
        (state.get("identity_research_hints") or {}).items()
        if isinstance(state.get("identity_research_hints"), Mapping)
        else []
    ):
        try:
            value = float(priority)
        except (TypeError, ValueError):
            continue
        key = str(directory)
        if key and value > 0.0:
            hints[key] = max(hints.get(key, 0.0), value)
    return dict(sorted(hints.items())[:64])


# ---------------------------------------------------------------------------
# the LangGraph node
# ---------------------------------------------------------------------------

def research_loop_node(state: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node — one bounded adaptive research iteration.

    Double-gated fail-closed: the builder wires the node only when
    ``enable_adaptive_research_loop`` is on, and the node re-checks the
    flag + mandatory limits at runtime (the coverage_gap_report /
    stateful_discovery double-gate precedent). Invocation count is
    bounded by ``max_research_iterations``; beyond the cap the node is
    an honest pass-through (``capped`` telemetry, no work).

    Returns a partial state update with AT MOST:
      * ``hypotheses`` — new deduplicated research hypotheses (ordinary
        pool citizens; the strategist's ranking and promotion gates are
        unchanged and remain the only path to execution);
      * ``research_loop`` — advisory telemetry (per-iteration detail,
        cumulative counters, fingerprints, stateful hints).
    NEVER findings, NEVER confirmations, NEVER authority.
    """
    try:
        from webpent.config.settings import get_settings

        if not bool(get_settings().enable_adaptive_research_loop):
            return {}
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return {}
    limits = _research_loop_limits()
    if limits is None:
        return {}
    max_iterations, max_per_iter = limits

    telemetry: dict[str, Any] = {
        "window": RESEARCH_LOOP_WINDOW,
        "enabled": True,
    }
    raw_channel = state.get("research_loop")
    if raw_channel is not None and not isinstance(raw_channel, Mapping):
        # R7/F18 fail-closed: a corrupted (non-mapping) channel must NOT
        # re-arm the iteration limit. The only safe repair is to flood the
        # counter to the cap — corruption can consume the remaining
        # research budget, never create new budget — and record the
        # diagnostic. No hypothesis work happens on this pass.
        logger.warning(
            "Research loop: corrupted research_loop channel (%s) — "
            "fail-closed, iteration budget consumed",
            type(raw_channel).__name__,
        )
        return {
            "research_loop": {
                "window": RESEARCH_LOOP_WINDOW,
                "enabled": True,
                "last_status": "state_invalid_fail_closed",
                "reason": "research_loop_channel_not_mapping",
                "state_invalid": True,
                "capped": True,
                "iterations_used": max_iterations,
                "observed_channel_type": type(raw_channel).__name__,
            }
        }
    try:
        channel = raw_channel or {}
        iterations_used = int(channel.get("iterations_used") or 0)
        generated_total = int(channel.get("hypotheses_generated_total") or 0)
        suppressed_total = int(channel.get("duplicates_suppressed_total") or 0)

        if iterations_used >= max_iterations:
            telemetry.update({
                "iterations_used": iterations_used,
                "last_status": "capped",
                "capped": True,
            })
            return {"research_loop": telemetry}

        new_hypotheses, detail = generate_research_hypotheses(
            state, max_new=max_per_iter
        )
        iteration = iterations_used + 1
        generated_total += detail["generated"]
        suppressed_total += (
            detail["suppressed_open"] + detail["suppressed_closed"]
        )
        fingerprints = [
            str(h.id) for h in new_hypotheses
        ]  # deterministic ids ARE the fingerprints' stable handles

        telemetry.update({
            "iterations_used": iteration,
            "hypotheses_generated_total": generated_total,
            "duplicates_suppressed_total": suppressed_total,
            "last_status": "ok",
            "capped": bool(detail.get("capped")),
            "last_iteration_detail": detail,
            "iterations": {
                f"iter_{iteration}": {
                    "generated": detail["generated"],
                    "suppressed_open": detail["suppressed_open"],
                    "suppressed_closed": detail["suppressed_closed"],
                    "signals_actionable": detail["signals_actionable"],
                    "capped": bool(detail.get("capped")),
                },
            },
            "generated_hypothesis_ids": fingerprints,
            "stateful_priority_directories": stateful_research_hints(state),
            "confirmation_authority": "cqa_v2.guarded_causal_evaluate (unchanged)",
        })
        update: dict[str, Any] = {"research_loop": telemetry}
        if new_hypotheses:
            update["hypotheses"] = new_hypotheses
        return update
    except Exception as exc:  # noqa: BLE001 — the loop must be fail-soft
        logger.warning("Research loop iteration failed soft: %s", exc)
        return {
            "research_loop": {
                "window": RESEARCH_LOOP_WINDOW,
                "enabled": True,
                "last_status": "error",
                "reason": "research_loop_iteration_failed_fail_soft",
            }
        }


__all__ = [
    "CLASSIFICATION_ACTIONABLE",
    "CLASSIFICATION_NON_ACTIONABLE",
    "CLASSIFICATION_VOCABULARY",
    "MAX_SIGNALS_SCANNED",
    "RESEARCH_LOOP_NODE_NAME",
    "RESEARCH_LOOP_WINDOW",
    "classify_coverage_status",
    "generate_research_hypotheses",
    "hypothesis_fingerprint",
    "research_loop_enabled",
    "research_loop_node",
    "research_signal_inventory",
    "stateful_research_hints",
]
