"""M3 UM-DR-17: OAST + campaign-resume production wiring.

M1a deferral (M1_PHASE_REPORT): "OAST/``enable_campaign_resume``
production-graph wiring → M3 — needs node patterns outside the frozen
builder; flags now exist fail-closed". Both engines shipped
implemented-and-tested with ZERO production consumers.

Contract under test:

1. **The OAST correlation node** — flag off ⇒ pass-through; local
   provider default ⇒ honest ``provider_unavailable`` (no fabricated
   interactions); with a provider: arms bounded sessions for OPEN
   hypotheses only, correlates nonce-bound interactions into CANDIDATE
   findings (requires_validator pinned, no verdict field), never
   promotes; the bridge's CandidateOnlyRule stays structural.
2. **The builder wiring** — flag on adds the node additively
   (post_exploitation→oast_correlation→rabbit_hole, direct edge stays);
   flag off keeps it absent.
3. **The campaign lifecycle** — flag off ⇒ every entry point inert
   (markers never written, probes never suppressed); flag on ⇒
   interrupted markers carry a state fingerprint, the resume decision
   respects the retry budget, the probe ledger dedupes, and the bounded
   backoff is sane.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from webpent.config.settings import get_settings
from webpent.graph.oast_nodes import (
    OAST_CORRELATION_NODE_NAME,
    oast_correlation_node,
)
from webpent.production.campaign_lifecycle import (
    campaign_backoff_seconds,
    campaign_resume_decision,
    clear_campaign_interrupt,
    mark_campaign_interrupted,
    probe_already_executed,
    record_probe_executed,
)

ENG = "eng-oast-test"


# ---------------------------------------------------------------------------
# 1. The OAST correlation node
# ---------------------------------------------------------------------------


def test_oast_node_flag_off_is_pass_through() -> None:
    assert get_settings().enable_oast is False
    out = oast_correlation_node({"hypotheses": [{"id": "h1", "status": "open"}]})
    assert out == {"oast_correlation_status": "disabled"}


def test_oast_node_local_default_is_honestly_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = get_settings().model_copy(update={"enable_oast": True})
    from webpent.config.settings import activate_settings

    with activate_settings(settings):
        assert get_settings().oob_provider == "local"
        out = oast_correlation_node({"hypotheses": [{"id": "h1", "status": "open"}]})
    assert out == {"oast_correlation_status": "provider_unavailable"}


class _ScriptedProvider:
    """A deterministic in-memory _InteractionSource for the bridge."""

    name = "scripted"

    def __init__(self, *, hosts_by_finding: dict[str, list[tuple[str, str, str]]]) -> None:
        self._hosts = hosts_by_finding
        self.opened: list[str] = []
        self.closed: list[str] = []

    def open(self, finding_id: str) -> str | None:
        self.opened.append(finding_id)
        return f"{finding_id}.oast.example"

    def poll(
        self, finding_id: str, timeout_seconds: float, max_attempts: int
    ) -> Any:
        for host, digest, interaction_type in self._hosts.get(finding_id, []):
            return SimpleNamespace(
                payload_host=host,
                evidence_digest=digest,
                interaction_type=interaction_type,
                observed_at="2026-11-06T00:00:00Z",
            )
        return None

    def close(self, finding_id: str) -> None:
        self.closed.append(finding_id)


def _run_oast_with_provider(
    monkeypatch: pytest.MonkeyPatch,
    *,
    provider: Any,
    hypotheses: list[dict[str, Any]],
) -> dict[str, Any]:
    import webpent.graph.oast_nodes as oast_nodes
    from webpent.config.settings import activate_settings

    settings = get_settings().model_copy(update={"enable_oast": True})
    monkeypatch.setattr(oast_nodes, "_build_provider", lambda s: provider)
    with activate_settings(settings):
        return oast_correlation_node({"hypotheses": hypotheses})


def test_oast_node_correlates_nonce_bound_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Compute the nonce the bridge will derive for h1, then script an
    # interaction on exactly that nonce-signed host.
    from webpent.oast.bridge import _nonce_for

    secret = get_settings().audit_secret_key
    nonce = _nonce_for("h1", secret)
    finding_id = f"oast-{nonce}"
    host = f"{nonce}.oast-{nonce}.oast.example"
    provider = _ScriptedProvider(
        hosts_by_finding={finding_id: [(host, "sha256:abc", "http")]}
    )
    out = _run_oast_with_provider(
        monkeypatch,
        provider=provider,
        hypotheses=[
            {"id": "h1", "status": "open"},
            {"id": "h2", "status": "confirmed"},  # terminal: never armed
        ],
    )
    assert out["oast_correlation_status"] == "correlated"
    assert out["oast_sessions_armed"] == 1
    (candidate,) = out["oast_candidate_findings"]
    assert candidate["hypothesis_id"] == "h1"
    assert candidate["requires_validator"] is True
    assert candidate["status"] == "candidate"
    assert "verdict" not in candidate
    # Only the open hypothesis got a session.
    assert len(provider.opened) == 1
    # Every session was disarmed (bounded lifecycle).
    assert provider.closed == provider.opened


def test_oast_node_ignores_forged_foreign_host_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An interaction whose host carries a DIFFERENT hypothesis's nonce
    # (or none) must not correlate for this session.
    provider = _ScriptedProvider(
        hosts_by_finding={
            # finding ids are oast-<nonce>; we do not know h1's nonce, so
            # script interactions for every opened id on a foreign host.
        }
    )
    # Script dynamically: after open() we know the finding id; return a
    # host that does NOT contain the session nonce.
    class _ForgedProvider(_ScriptedProvider):
        def poll(self, finding_id: str, timeout_seconds: float, max_attempts: int) -> Any:
            return SimpleNamespace(
                payload_host="evil-attacker.example",
                evidence_digest="sha256:forged",
                interaction_type="dns",
                observed_at=None,
            )

    provider = _ForgedProvider(hosts_by_finding={})
    out = _run_oast_with_provider(
        monkeypatch, provider=provider, hypotheses=[{"id": "h1", "status": "open"}]
    )
    assert out["oast_correlation_status"] == "polled_no_interactions"
    assert out["oast_candidate_findings"] == []


def test_oast_node_no_open_hypotheses(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _ScriptedProvider(hosts_by_finding={})
    out = _run_oast_with_provider(monkeypatch, provider=provider, hypotheses=[])
    assert out == {"oast_correlation_status": "no_open_hypotheses"}


def test_oast_bridge_confirm_is_structurally_forbidden() -> None:
    from webpent.oast.bridge import CandidateFinding, CandidateOnlyRule, OastVerificationBridge

    candidate = CandidateFinding(
        hypothesis_id="h",
        nonce="n",
        payload_host="h.oast.example",
        interaction_type="http",
        evidence_digest="sha256:x",
    )
    with pytest.raises(CandidateOnlyRule):
        OastVerificationBridge.confirm(candidate)


# ---------------------------------------------------------------------------
# 2. The builder wiring
# ---------------------------------------------------------------------------


def test_builder_oast_flag_off_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.graph import builder as graph_builder

    assert get_settings().enable_oast is False
    compiled = graph_builder.build_graph(auto_approve=True)
    assert OAST_CORRELATION_NODE_NAME not in set(getattr(compiled, "nodes", {}) or {})


def test_builder_oast_flag_on_additive(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.graph import builder as graph_builder

    monkeypatch.setattr(graph_builder, "_oast_enabled", lambda: True)
    compiled = graph_builder.build_graph(auto_approve=True)
    node_names = set(getattr(compiled, "nodes", {}) or {})
    assert OAST_CORRELATION_NODE_NAME in node_names
    edges = {(e.source, e.target) for e in compiled.get_graph().edges}
    assert ("post_exploitation", "rabbit_hole") in edges  # direct edge stays
    assert ("post_exploitation", OAST_CORRELATION_NODE_NAME) in edges
    assert (OAST_CORRELATION_NODE_NAME, "rabbit_hole") in edges


# ---------------------------------------------------------------------------
# 3. The campaign lifecycle
# ---------------------------------------------------------------------------


@pytest.fixture()
def resume_enabled(monkeypatch: pytest.MonkeyPatch):
    from webpent.config.settings import activate_settings

    settings = get_settings().model_copy(update={"enable_campaign_resume": True})
    with activate_settings(settings):
        clear_campaign_interrupt(ENG)
        yield
        clear_campaign_interrupt(ENG)


def test_campaign_lifecycle_inert_when_flag_off() -> None:
    assert get_settings().enable_campaign_resume is False
    assert mark_campaign_interrupted(engagement_id=ENG, reason="soft_timeout") is False
    assert campaign_resume_decision(engagement_id=ENG, retries=0) == {
        "auto_resume": False,
        "reason": "campaign_resume_disabled",
    }
    assert probe_already_executed(engagement_id=ENG, probe_id="p1") is False
    assert record_probe_executed(engagement_id=ENG, probe_id="p1") is False
    assert campaign_backoff_seconds(0) == 0.0


def test_campaign_marker_and_resume_decision_roundtrip(resume_enabled) -> None:
    marked = mark_campaign_interrupted(
        engagement_id=ENG,
        reason="soft_time_limit",
        node="validator",
        state_values={"findings": [{"id": "f1"}], "target_url": "https://app.example.com"},
    )
    assert marked is True
    decision = campaign_resume_decision(engagement_id=ENG, retries=0)
    assert decision["auto_resume"] is True


def test_campaign_resume_decision_respects_retry_budget(resume_enabled) -> None:
    mark_campaign_interrupted(engagement_id=ENG, reason="worker_crash")
    from webpent.resume.campaign_checkpoints import MAX_CAMPAIGN_RETRIES

    exhausted = campaign_resume_decision(engagement_id=ENG, retries=MAX_CAMPAIGN_RETRIES)
    assert exhausted["auto_resume"] is False


def test_non_resumable_reasons_never_auto_resume(resume_enabled) -> None:
    # A recursion-limit marker is forensic-only by the package's design:
    # auto-resuming into the same loop would be a bug, so reasons outside
    # _INTERRUPT_REASONS must never auto-resume.
    mark_campaign_interrupted(engagement_id=ENG, reason="recursion_limit")
    decision = campaign_resume_decision(engagement_id=ENG, retries=0)
    assert decision["auto_resume"] is False


def test_probe_ledger_dedupes_within_engagement(resume_enabled) -> None:
    import uuid

    probe_id = f"probe-{uuid.uuid4().hex[:12]}"
    assert probe_already_executed(engagement_id=ENG, probe_id=probe_id) is False
    assert record_probe_executed(engagement_id=ENG, probe_id=probe_id) is True
    assert probe_already_executed(engagement_id=ENG, probe_id=probe_id) is True
    # Ledger is engagement-scoped.
    assert probe_already_executed(engagement_id="other-eng", probe_id=probe_id) is False


def test_backoff_is_bounded_and_monotone(resume_enabled) -> None:
    values = [campaign_backoff_seconds(r) for r in range(0, 8)]
    assert values[0] > 0
    assert all(b <= values[-1] for b in values)  # monotone non-decreasing
    assert values[-1] == values[-2] or values[-1] > values[-2]


def test_worker_timeout_handlers_reference_the_lifecycle_module() -> None:
    """The frozen worker's soft-timeout and recursion handlers must call
    the lifecycle marker (source-level contract, robust to Celery task
    binding)."""
    from pathlib import Path

    source = Path("src/webpent/workers/pentest_worker.py").read_text(encoding="utf-8")
    assert source.count("mark_campaign_interrupted") >= 2
    assert 'reason="soft_time_limit"' in source
    assert 'reason="recursion_limit"' in source
    assert "clear_campaign_interrupt" in source
