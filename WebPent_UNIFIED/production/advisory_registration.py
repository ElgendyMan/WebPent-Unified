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
from dataclasses import dataclass, field
from typing import Any, Optional

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


def _assert_spine_caller() -> None:
    """D11: refuse direct call outside the modern spine integration point."""
    if os.environ.get(_TEST_ESCAPE_ENV) == "1":
        return
    import traceback
    stack = traceback.format_stack()
    if any("modern_spine_integration" in frame for frame in stack):
        return
    raise RuntimeError(
        "advisory registration/publish may only be invoked from the modern spine "
        "integration point (modern_spine_integration.py). Direct call refused — "
        "ModernOrchestrator is the only scheduler (invariant #5). Set "
        f"{_TEST_ESCAPE_ENV}=1 for unit tests only.")


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
    """D8 FIX: value-free audit event; fail-closed if a real chain is supplied."""
    if audit_chain is None:
        return  # unit-test context only; production insertion point always supplies it
    safe = {k: v for k, v in payload.items() if k not in ("raw", "secret", "value", "body")}
    audit_chain.append(event_name=event_name, payload=safe)  # propagate any exception (fail-closed)


def register_advisory_candidates_inline(
    state: dict[str, Any], intake_records: list[dict[str, Any]],
    audit_chain: Optional[Any] = None, quota: int = ADVISORY_WINDOW_QUOTA,
) -> tuple[list[RegisteredAdvisoryCandidate], dict[str, int]]:
    _assert_spine_caller()
    # D3 FIX: clamp the quota param itself — never disableable, 1-19 only.
    quota = max(1, min(19, int(quota)))
    counters = {COUNTER_CANDIDATES_UNREACHABLE: 0, "advisory.intake.duplicate": 0,
                "advisory.intake.budget_exhausted": 0, COUNTER_HYPOTHESIS_UNPUBLISHED: 0}
    ordered = sorted(intake_records, key=lambda r: r.get("intake_id", ""))
    seen_dedupe: set[str] = set()
    registered: list[RegisteredAdvisoryCandidate] = []
    budget_remaining = state.get("campaign_budget_remaining", RECON_WINDOW_TOTAL)

    for record in ordered:
        intake_id = record.get("intake_id", "")
        dedupe_key = record.get("dedupe_key", "")
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
) -> int:
    _assert_spine_caller()
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
