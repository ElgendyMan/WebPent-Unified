"""webpent.graph.oast_nodes — M3 UM-DR-17: the OAST correlation node
(production wiring of the ق1-revival bridge).

M1a deferral note (M1_PHASE_REPORT): "OAST/``enable_campaign_resume``
production-graph wiring → M3 — needs node patterns outside the frozen
builder; flags now exist fail-closed". The flags were declared in M1-C
(UM-DR-12); the bridge (``oast/bridge.py``), the collaborator
(``shared/oob.py``) and the providers (``shared/oob_provider.py``) were
all implemented and tested with ZERO production consumers.

This module is the missing node pattern (NEW file, outside the frozen
gate; the builder gains one flag-gated additive wiring):

* ``oast_correlation_node`` — runs AFTER post_exploitation: arms one
  OAST session per OPEN hypothesis (bounded), polls the configured
  provider, and emits **candidate findings only** — the bridge's
  CandidateOnlyRule is structural (no verdict field, promotion belongs
  to the deterministic validator). Flag off ⇒ pass-through. Provider
  unavailable (local default with no collector) ⇒ honest
  ``provider_unavailable`` status — interactions are never fabricated.
* ``wire_oast_correlation`` — adds POST_EXPLOITATION → OAST →
  RABBIT_HOLE additively (the direct edge stays; super-step semantics
  make rabbit_hole wait for both branches) — same additive-only pattern
  as the family execution spine.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage

from webpent.config.settings import get_settings
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

OAST_CORRELATION_NODE_NAME = "oast_correlation"

_NODE_POST_EXPLOITATION = "post_exploitation"
_NODE_RABBIT_HOLE = "rabbit_hole"

_MAX_HYPOTHESES_DEFAULT = 24


def _open_hypothesis_ids(state: PentestState, cap: int) -> list[str]:
    hypotheses = state.get("hypotheses") or []
    ids: list[str] = []
    for hypothesis in hypotheses:
        if len(ids) >= cap:
            break
        if isinstance(hypothesis, dict):
            status = str(hypothesis.get("status") or "").lower()
            hypothesis_id = str(hypothesis.get("id") or hypothesis.get("hypothesis_id") or "").strip()
        else:
            status = str(getattr(hypothesis, "status", "") or "").lower()
            hypothesis_id = str(
                getattr(hypothesis, "id", None) or getattr(hypothesis, "hypothesis_id", "") or ""
            ).strip()
        if not hypothesis_id:
            continue
        # Only OPEN/UNEXPLORED hypotheses are worth an OAST session:
        # confirmed/refuted ones already have their verdict path.
        if status in {"confirmed", "refuted", "debunked", "false_positive", "duplicate"}:
            continue
        ids.append(hypothesis_id)
    return ids


def _build_provider(settings: Any) -> Any | None:
    """The explicitly configured provider, or None (honest unavailability).

    The local callback collector is a long-running receiver the operator
    starts separately (oast/server.py + the M-5 loopback rule); a graph
    node must never silently spawn a network listener. Local default ⇒
    None ⇒ provider_unavailable unless the operator's collaborator
    domain flow is engaged elsewhere.
    """
    try:
        provider_name = str(getattr(settings, "oob_provider", "local")).strip().lower()
    except Exception:  # pragma: no cover - defensive
        provider_name = "local"
    if provider_name != "interactsh":
        return None
    try:
        from webpent.shared.oob_provider import InteractshProvider

        provider = InteractshProvider(
            binary=str(getattr(settings, "interactsh_binary", "interactsh-client") or ""),
            server=str(getattr(settings, "interactsh_server", "") or ""),
            token=str(getattr(settings, "interactsh_token", "") or ""),
            poll_interval_seconds=1,
        )
        return provider if provider.enabled else None
    except Exception as exc:  # noqa: BLE001 — fail-soft, advisory column
        logger.debug("OAST provider construction failed: %s", type(exc).__name__)
        return None


def oast_correlation_node(state: PentestState) -> dict[str, Any]:
    """Correlate out-of-band interactions into CANDIDATE findings (only)."""
    settings = get_settings()
    if not getattr(settings, "enable_oast", False):
        return {"oast_correlation_status": "disabled"}

    provider = _build_provider(settings)
    if provider is None:
        return {"oast_correlation_status": "provider_unavailable"}

    secret = str(getattr(settings, "audit_secret_key", "") or "")
    if not secret:
        # Fail-closed: without an engine-held secret the nonces cannot be
        # HMAC-bound, and un-bound nonces would let forged callbacks
        # correlate. Honest refusal, never a weakened mode.
        return {"oast_correlation_status": "bridge_secret_unavailable"}

    from webpent.oast.bridge import OastVerificationBridge

    bridge = OastVerificationBridge(
        provider,
        secret=secret,
        poll_timeout_seconds=float(
            getattr(settings, "oob_poll_timeout_seconds", 5.0) or 5.0
        ),
        max_attempts=int(getattr(settings, "oob_poll_max_attempts", 3) or 3),
    )

    cap = _MAX_HYPOTHESES_DEFAULT
    hypothesis_ids = _open_hypothesis_ids(state, cap)
    if not hypothesis_ids:
        return {"oast_correlation_status": "no_open_hypotheses"}

    armed = 0
    candidates: list[dict[str, Any]] = []
    for hypothesis_id in hypothesis_ids:
        try:
            nonce = bridge.arm(hypothesis_id)
        except Exception as exc:  # noqa: BLE001 — per-hypothesis fail-soft
            logger.debug("OAST arm failed for %s: %s", hypothesis_id, type(exc).__name__)
            continue
        if not nonce:
            continue
        armed += 1
        try:
            candidates.extend(candidate.to_dict() for candidate in bridge.poll(hypothesis_id))
        except Exception as exc:  # noqa: BLE001 — per-hypothesis fail-soft
            logger.debug("OAST poll failed for %s: %s", hypothesis_id, type(exc).__name__)
        finally:
            try:
                bridge.disarm(hypothesis_id)
            except Exception:  # noqa: BLE001 — cleanup is best-effort
                pass

    status = "correlated" if candidates else "polled_no_interactions"
    message = AIMessage(
        content=(
            f"OAST correlation: {armed} session(s) armed, "
            f"{len(candidates)} candidate finding(s) (validator-required, "
            "never auto-promoted)."
        )
    )
    return {
        "oast_correlation_status": status,
        "oast_sessions_armed": armed,
        "oast_candidate_findings": candidates,
        "messages": [message],
    }


def wire_oast_correlation(graph: Any) -> None:
    """Add the OAST node between post_exploitation and rabbit_hole.

    Additive-only: the direct POST_EXPLOITATION → RABBIT_HOLE edge stays;
    super-step semantics make rabbit_hole wait for both branches.
    """
    graph.add_node(OAST_CORRELATION_NODE_NAME, oast_correlation_node)
    graph.add_edge(_NODE_POST_EXPLOITATION, OAST_CORRELATION_NODE_NAME)
    graph.add_edge(OAST_CORRELATION_NODE_NAME, _NODE_RABBIT_HOLE)


__all__ = [
    "OAST_CORRELATION_NODE_NAME",
    "oast_correlation_node",
    "wire_oast_correlation",
]
