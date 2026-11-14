"""WebPent Milestone 6 + GAP-R1 — advisory candidate in-line registration and
hypothesis publication into the research-campaign channel.

Remediation (Team-Red audit):
  D3  — quota clamped to 1-19 INSIDE register function, not only at import.
  D7  — publish overflow beyond cap 50 now terminates with terminal event +
        telemetry counter + audit (no silent drop).
  D8  — audit write is fail-closed: if audit_chain is supplied and append
        raises, the exception propagates. None (unit test) is the only silent
        path, documented.
  D9  — published hypothesis carries advisory_only=True (M7 v1.2 marker).
  D10 — hypothesis carries _audit_chain (matching I-2 _build_hypothesis shape).
  D11 — spine-call guard: direct invocation outside the modern spine is
        refused unless the test-only escape env is set (mirrors the existing
        orchestrator construction-authority pattern).
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Final, MutableSet, Optional

_ADVISORY_WINDOW_QUOTA_RAW = int(os.environ.get("WEBPENT_ADVISORY_WINDOW_QUOTA", "5"))
ADVISORY_WINDOW_QUOTA = max(1, min(19, _ADVISORY_WINDOW_QUOTA_RAW))
RECON_WINDOW_TOTAL = int(os.environ.get("WEBPENT_RECON_WINDOW_TOTAL", "20"))
HYPOTHESIS_CHANNEL_CAP = int(os.environ.get("WEBPENT_HYPOTHESIS_CHANNEL_CAP", "50"))

TERMINAL_QUEUED = "intake.queued"
TERMINAL_WINDOW_OVERFLOW = "intake.window_overflow"
TERMINAL_BUDGET_EXHAUSTED = "intake.budget_exhausted"
TERMINAL_DUPLICATE = "intake.duplicate"
TERMINAL_EXECUTED = "intake.executed"
TERMINAL_HYPOTHESIS_OVERFLOW = "intake.hypothesis_channel_overflow"

COUNTER_CANDIDATES_UNREACHABLE = "advisory.intake.candidates_unreachable_due_to_window"
COUNTER_HYPOTHESIS_UNPUBLISHED = "advisory.intake.candidates_unpublished_due_to_channel_cap"

PRINCIPAL_USER_A = "User_A"
PRINCIPAL_USER_B = "User_B"

# D11 FIX: test-only escape, mirroring WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_... pattern.
_TEST_ESCAPE_ENV = "WEBPENT_ALLOW_DIRECT_ADVISORY_REGISTRATION_TEST_ONLY"

# M2-impl WP-A (NF-R2-06): the test-only env escape is contained to test
# processes. Outside pytest the env var alone never bypasses the guard.
def _test_escape_active() -> bool:
    if os.environ.get(_TEST_ESCAPE_ENV) != "1":
        return False
    return "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ


def _assert_spine_caller(token: Optional[Any] = None) -> None:
    """D11 + M2-impl WP-A (NF-R2-06): refuse direct call outside the modern
    spine integration point.

    Authorization ladder (fail-closed):
      1. OBJECT-IDENTITY TOKEN — the real integration point passes the
         SPINE_CALL_TOKEN object by reference. Object identity cannot be
         forged by filename, module-name tricks, or stack fabrication.
      2. TEST ESCAPE (contained) — the test-only env var is honored only
         inside a pytest process (sys.modules/PYTEST_CURRENT_TEST). Outside
         a test run the env var is inert.
      3. REFUSE — anything else raises, loudly.
    """
    try:
        from webpent.production.modern_spine_integration import SPINE_CALL_TOKEN
        if token is SPINE_CALL_TOKEN:
            return
    except ImportError:  # pragma: no cover — seam module always importable
        pass
    if _test_escape_active():
        return
    raise RuntimeError(
        "advisory registration/publish may only be invoked from the modern spine "
        "integration point (verified by object-identity token, not filename "
        "substring — NF-R2-06). Direct call refused — ModernOrchestrator is the "
        f"only scheduler (invariant #5). Set {_TEST_ESCAPE_ENV}=1 inside a test "
        "process only.")


@dataclass
class RegisteredAdvisoryCandidate:
    intake_id: str
    dedupe_key: str
    artifact_ref: str
    endpoint_template: str
    allowed_method: str
    object_reference_plan: dict[str, Any]
    advisory_kwargs: dict[str, Any]
    hypothesis: dict[str, Any] = field(default_factory=dict)
    terminal_state: str = TERMINAL_QUEUED


def _audit(audit_chain: Optional[Any], event_name: str, payload: dict[str, Any]) -> None:
    """D8 FIX + M2-impl WP-A (NF-R2-04): value-free audit event against the
    REAL EngagementAuditChain API (``append_event(*, event_type, details)``).
    Fail-closed: any chain-side exception propagates."""
    if audit_chain is None:
        return  # unit-test context only; production insertion point always supplies it
    safe = {k: v for k, v in payload.items() if k not in ("raw", "secret", "value", "body")}
    # NF-R2-04 fix: the previous call used a non-existent ``append()`` API —
    # every real-chain write raised AttributeError (masked while the chain
    # was transport-dead). append_event is the hash-chained, append-only API.
    audit_chain.append_event(event_type=event_name, details=safe)  # propagate (fail-closed)


def register_advisory_candidates_inline(
    state: dict[str, Any], intake_records: list[dict[str, Any]],
    audit_chain: Optional[Any] = None, quota: int = ADVISORY_WINDOW_QUOTA,
    token: Optional[Any] = None,
    dedupe_registry: Optional[MutableSet[str]] = None,
) -> tuple[list[RegisteredAdvisoryCandidate], dict[str, int]]:
    _assert_spine_caller(token)
    # D3 FIX: clamp the quota param itself — never disableable, 1-19 only.
    quota = max(1, min(19, int(quota)))
    counters = {COUNTER_CANDIDATES_UNREACHABLE: 0, "advisory.intake.duplicate": 0,
                "advisory.intake.budget_exhausted": 0,
                "advisory.intake.noncanonical_record": 0,
                COUNTER_HYPOTHESIS_UNPUBLISHED: 0}
    ordered = sorted(intake_records, key=lambda r: str(r.get("intake_id", "")))
    # NF-R2-07 fix: the dedupe set is seeded from the durable per-engagement
    # registry (CampaignState-backed) when the seam supplies one.
    seen_dedupe: set[str] = set(dedupe_registry) if dedupe_registry else set()
    registered: list[RegisteredAdvisoryCandidate] = []
    budget_remaining = state.get("campaign_budget_remaining", RECON_WINDOW_TOTAL)

    for record in ordered:
        intake_id = record.get("intake_id", "")
        dedupe_key = record.get("dedupe_key", "")
        # R4/type discipline: canonical identity fields only. A hostile
        # record whose intake_id/dedupe_key is not a non-empty string is
        # REJECTED (counted + audited) — never coerced, never crashed on
        # (the previous code raised TypeError: unhashable on dict keys).
        if (not isinstance(intake_id, str) or not intake_id
                or not isinstance(dedupe_key, str) or not dedupe_key):
            counters["advisory.intake.noncanonical_record"] += 1
            _audit(audit_chain, "intake.noncanonical_record",
                   {"intake_id_repr": repr(intake_id)[:64]})
            continue
        if dedupe_key in seen_dedupe:
            counters["advisory.intake.duplicate"] += 1
            _audit(audit_chain, TERMINAL_DUPLICATE, {"intake_id": intake_id})
            continue
        seen_dedupe.add(dedupe_key)
        if budget_remaining <= 0:
            counters["advisory.intake.budget_exhausted"] += 1
            _audit(audit_chain, TERMINAL_BUDGET_EXHAUSTED, {"intake_id": intake_id})
            continue
        if len(registered) >= quota:
            counters[COUNTER_CANDIDATES_UNREACHABLE] += 1
            _audit(audit_chain, TERMINAL_WINDOW_OVERFLOW, {"intake_id": intake_id, "quota": quota})
            continue
        advisory_kwargs = dict(record.get("advisory_kwargs") or {})
        advisory_kwargs.setdefault("distinct_actor", True)
        advisory_kwargs.setdefault("independent_negative_control", True)
        registered.append(RegisteredAdvisoryCandidate(
            intake_id=intake_id, dedupe_key=dedupe_key,
            artifact_ref=record.get("source_artifact_ref", ""),
            endpoint_template=record.get("endpoint_template", ""),
            allowed_method=record.get("allowed_method", "GET"),
            object_reference_plan=record.get("object_reference_plan") or {},
            advisory_kwargs=advisory_kwargs))
        budget_remaining -= 1
        if dedupe_registry is not None:
            # NF-R2-07 fix: durable, per-engagement dedupe — the key survives
            # this invocation and blocks re-registration later.
            dedupe_registry.add(dedupe_key)
        _audit(audit_chain, TERMINAL_QUEUED,
               {"intake_id": intake_id, "dedupe_key": dedupe_key[:19],
                "distinct_actor": advisory_kwargs["distinct_actor"],
                "independent_negative_control": advisory_kwargs["independent_negative_control"]})

    state["recon_window_remaining"] = max(0, RECON_WINDOW_TOTAL - len(registered))
    state["advisory_registered_count"] = len(registered)
    state.setdefault("advisory_telemetry", {}).update(counters)
    return registered, counters


def build_advisory_hypothesis(
    candidate: RegisteredAdvisoryCandidate, matrix_row_spec: dict[str, Any],
    target_url: str, audit_chain: Optional[Any] = None,
) -> dict[str, Any]:
    plan = candidate.object_reference_plan or {}
    owner_invoice = plan.get("owner_object_ref", matrix_row_spec.get("owner_object_ref", "INV-B-204"))
    candidate_invoice = plan.get("candidate_object_ref", matrix_row_spec.get("candidate_object_ref", owner_invoice))
    negative_control_invoice = plan.get("negative_control_object_ref",
                                        matrix_row_spec.get("negative_control_object_ref", "INV-X-000"))
    endpoint = candidate.endpoint_template
    method = candidate.allowed_method

    def _role_spec(actor_alias: str, invoice: str, role: str) -> dict[str, Any]:
        return {"method": method,
                "path": endpoint.replace("{id}", invoice).replace(":id", invoice),
                "headers": {"X-User": actor_alias},
                "principal_alias": actor_alias, "principal_role": role}

    return {
        "id": f"adv_{candidate.intake_id}",
        "vulnerability_class": "IDOR",
        "api_type": "rest",
        "path": endpoint,
        "information_value": matrix_row_spec.get("information_value", 0.9),
        "resource_owner": PRINCIPAL_USER_B,
        "engagement_id": matrix_row_spec.get("engagement_id", "advisory"),
        "source": "advisory_intake",
        "advisory_ref": candidate.artifact_ref,
        "advisory_kwargs": dict(candidate.advisory_kwargs),
        "advisory_only": True,  # D9 FIX: M7 v1.2 advisory marker
        "_audit_chain": audit_chain,  # D10 FIX: matches I-2 _build_hypothesis
        "requests": {
            "baseline": _role_spec(PRINCIPAL_USER_B, owner_invoice, "owner"),
            "candidate": _role_spec(PRINCIPAL_USER_A, candidate_invoice, "foreign-user"),
            "negative_control": _role_spec(PRINCIPAL_USER_A, negative_control_invoice, "foreign-user"),
        },
    }


def publish_advisory_hypotheses(
    state: dict[str, Any], registered: list[RegisteredAdvisoryCandidate],
    matrix_row_spec: dict[str, Any], target_url: str,
    audit_chain: Optional[Any] = None,
    token: Optional[Any] = None,
) -> int:
    _assert_spine_caller(token)
    channel = state.setdefault("hypotheses", [])
    published = 0
    for candidate in registered:
        if len(channel) >= HYPOTHESIS_CHANNEL_CAP:
            # D7 FIX: no silent drop — terminal event + counter + audit.
            state.setdefault("advisory_telemetry", {})[COUNTER_HYPOTHESIS_UNPUBLISHED] = (
                state.get("advisory_telemetry", {}).get(COUNTER_HYPOTHESIS_UNPUBLISHED, 0) + 1)
            _audit(audit_chain, TERMINAL_HYPOTHESIS_OVERFLOW,
                   {"intake_id": candidate.intake_id, "cap": HYPOTHESIS_CHANNEL_CAP})
            candidate.terminal_state = TERMINAL_HYPOTHESIS_OVERFLOW
            continue
        hyp = build_advisory_hypothesis(candidate, matrix_row_spec, target_url, audit_chain)
        candidate.hypothesis = hyp
        channel.append(hyp)
        published += 1
        _audit(audit_chain, TERMINAL_EXECUTED,
               {"intake_id": candidate.intake_id, "hypothesis_id": hyp["id"],
                "vulnerability_class": hyp["vulnerability_class"]})
    state["advisory_hypotheses_published"] = published
    return published


# M2-impl WP-D (R4 of Ruling M2-001): the ONLY fields a hypothesis may carry
# into the campaign dispatch. Everything else on a caller-supplied or
# hostile dict is dropped — hostile payloads cannot ride through AVI.
_CANONICAL_DISPATCH_FIELDS: Final[frozenset[str]] = frozenset({
    "id", "vulnerability_class", "path", "method", "api_type",
    "information_value", "resource_owner", "engagement_id", "source",
    "advisory_ref", "advisory_kwargs",
})
_DISPATCH_STR_FIELDS: Final[frozenset[str]] = frozenset({
    "vulnerability_class", "path", "method", "api_type", "engagement_id",
    "source", "advisory_ref",
})


def canonicalize_campaign_hypothesis(
    raw: Any, default_vulnerability_class: str = "IDOR",
) -> tuple[dict[str, Any] | None, str | None]:
    """WP-D: coerce ONE hypothesis into the canonical dispatch form.

    Returns ``(canonical_dict, None)`` on success or ``(None, reason)`` on
    rejection. Non-mapping inputs, missing/empty identity, and non-string
    identity fields are REJECTED (never coerced into garbage, never
    dispatched raw — RED-2 P-4.1 proved experiments EXECUTE on a hostile
    dict). Extra fields are dropped; ``advisory_kwargs`` must be a mapping.
    """
    if not isinstance(raw, dict):
        return None, "not_a_mapping"
    hyp_id = raw.get("id", raw.get("hypothesis_id"))
    if not isinstance(hyp_id, str) or not hyp_id.strip():
        return None, "missing_or_nonstring_identity"
    out: dict[str, Any] = {"id": hyp_id}
    vuln = raw.get("vulnerability_class", default_vulnerability_class)
    if not isinstance(vuln, str) or not vuln.strip():
        return None, "nonstring_vulnerability_class"
    out["vulnerability_class"] = vuln.upper()
    # P2-10 (0.33.0): renamed loop variable — it shadowed the `field`
    # import (ruff F402) in this scope.
    for fname in _DISPATCH_STR_FIELDS:
        if fname == "vulnerability_class":
            continue
        value = raw.get(fname)
        if value is None:
            continue
        if not isinstance(value, str):
            return None, f"nonstring_{fname}"
        out[fname] = value
    path = out.get("path") or (raw.get("endpoint") if isinstance(raw.get("endpoint"), str) else None) or "/api/"
    out["path"] = path
    out.setdefault("method", "GET")
    info_value = raw.get("information_value")
    if info_value is not None:
        if isinstance(info_value, bool) or not isinstance(info_value, (int, float)):
            return None, "nonnumeric_information_value"
        out["information_value"] = float(info_value)
    kwargs = raw.get("advisory_kwargs")
    if kwargs is not None:
        if not isinstance(kwargs, dict):
            return None, "nonmapping_advisory_kwargs"
        out["advisory_kwargs"] = dict(kwargs)
    # UM-DR-36 corrective closure: preserve the advisory semantic-model hint
    # (in the evidence_contract) so the AVI experiment selector's
    # deterministic semantic priority can actually fire on the canonical
    # dispatch form. Bounded, advisory-only, never an authority input.
    evidence_contract = raw.get("evidence_contract")
    if evidence_contract is not None:
        if not isinstance(evidence_contract, dict):
            return None, "nonmapping_evidence_contract"
        appmodel_hint = evidence_contract.get("appmodel_hint")
        if appmodel_hint is not None:
            if not isinstance(appmodel_hint, dict):
                return None, "nonmapping_appmodel_hint"
            out["evidence_contract"] = {"appmodel_hint": dict(appmodel_hint)}
    return out, None


def verify_research_campaign_edge(graph_edges: dict[str, set[str]]) -> bool:
    recon_nodes = [n for n in graph_edges if "RECON" in n.upper()]
    for src in recon_nodes:
        for dst in graph_edges.get(src, set()):
            if "RESEARCH_CAMPAIGN" in dst.upper():
                return True
    raise RuntimeError(
        "GAP-R2 fail-closed: NODE_RECON -> NODE_RESEARCH_CAMPAIGN edge missing "
        "from default graph composition; advisory routing cannot reach "
        "_research_campaign_node.")


class AdvisoryRegistration:
    """Small compatibility facade for callers that address M6 as a service.

    Note (WP-A): facade callers carry NO spine token — they are subject to
    the (contained) test-escape path exactly like any other direct caller.
    The facade cannot mint authority.
    """

    register_advisory_candidates_inline = staticmethod(register_advisory_candidates_inline)
    publish_advisory_hypotheses = staticmethod(publish_advisory_hypotheses)
