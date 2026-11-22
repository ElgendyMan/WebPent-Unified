"""UM-DR-44 B4 — granted_full from superficial body values must not
carry header-grade weight.

The chain (verified on the current tree):

1. ``representation_oracle._normalize_outcome`` maps generic body
   values — ``"ok"``, ``"success"``, ``"allowed"``, ``true`` — onto
   the header grammar's ``granted_full``.
2. ``causal_guard._authorization_enforced`` treats ANY
   ``authorization_outcome == "granted_full"`` as the "strongest
   signal" and returns True (enforced) whenever no mismatch fires.

So an application body that merely says ``{"status": "ok"}`` (an HTTP
health-check shape carrying ZERO authorization semantics) could satisfy
the confirmation gate's "authorization enforced in control" premise,
and a body ``{"access": true}`` could elevate ``granted_full`` to
header grade.  The mission: tighten WITHOUT weakening the legitimate
paths — the header channel and the strict body vocabulary
(``granted``/``granted_full``/``authorized``/``permitted``) must keep
their exact current behavior.

Fix contract:

* the header ``X-Authorization-Outcome: granted_full`` keeps its full
  strength (unchanged);
* a STRICT body vocabulary value (``granted``, ``granted_full``,
  ``authorized``, ``permitted``, boolean True under an authorization
  alias) keeps its current strength (unchanged);
* a SUPERFICIAL body value (``ok``, ``success``, ``allowed``,
  ``permit``) no longer satisfies ``granted_full``-grade checks on its
  own — the observation falls back to the ordinary status+mismatch
  analysis instead of being treated as an explicit grant.
"""

from __future__ import annotations

from webpent.cqa_v2.causal_guard import (
    _authorization_enforced,
    _authorization_mismatch,
)
from webpent.cqa_v2.representation_oracle import (
    _normalize_outcome,
    authorization_semantics,
    enrich_observation,
)


def _obs(body_outcome: str | None = None, header_outcome: str | None = None,
         status: int = 200, owner: str | None = None,
         actor: str | None = "alice") -> dict:
    obs: dict = {"status_code": status, "headers": {}, "body_text": ""}
    if body_outcome is not None:
        obs["body_preview"] = f'{{"outcome": "{body_outcome}"}}'
    if header_outcome is not None:
        obs["headers"]["X-Authorization-Outcome"] = header_outcome
    if actor:
        obs["headers"]["X-Actor-Echo"] = actor
    if owner:
        obs["headers"]["X-Resource-Owner"] = owner
    return obs


class TestSuperficialValuesDowngraded:
    def test_health_check_ok_is_not_granted_full(self) -> None:
        """RED on the current tree: 'ok' normalizes to granted_full."""
        assert _normalize_outcome("ok") != "granted_full"

    def test_success_is_not_granted_full(self) -> None:
        assert _normalize_outcome("success") != "granted_full"

    def test_allowed_is_not_granted_full(self) -> None:
        assert _normalize_outcome("allowed") != "granted_full"

    def test_permit_is_not_granted_full(self) -> None:
        assert _normalize_outcome("permit") != "granted_full"

    def test_strict_vocabulary_unchanged(self) -> None:
        assert _normalize_outcome("granted") == "granted_full"
        assert _normalize_outcome("granted_full") == "granted_full"
        assert _normalize_outcome("authorized") == "granted_full"
        assert _normalize_outcome("permitted") == "granted_full"
        assert _normalize_outcome(True) == "granted_full"

    def test_denied_vocabulary_unchanged(self) -> None:
        assert _normalize_outcome("denied") == "denied"
        assert _normalize_outcome(False) == "denied"
        assert _normalize_outcome("forbidden") == "denied"


class TestEnforcedGateWithSuperficialBody:
    def test_ok_body_with_owner_match_is_not_enforcement_proof(self) -> None:
        """RED on the current tree: {"outcome": "ok"} + owner==actor
        (the legitimate-shape control) previously satisfied the
        'strongest signal' branch and returned True — a health-check
        body carried header-grade confirmation weight.  After the fix
        the observation falls back to plain status analysis (200 +
        owner==actor + no explicit grant stays True only via the
        ordinary owner-access branch, which is the correct semantics —
        the point is that 'ok' itself proves nothing)."""
        obs = _obs(body_outcome="ok", owner="alice", actor="alice")
        enriched = enrich_observation(obs)
        # 'ok' no longer registers as an explicit grant at all
        assert enriched.get("authorization_outcome") != "granted_full"

    def test_ok_body_alone_stays_inconclusive(self) -> None:
        obs = _obs(body_outcome="ok")
        enriched = enrich_observation(obs)
        assert _authorization_enforced(enriched) is None

    def test_header_granted_full_still_strongest(self) -> None:
        """Header channel keeps full strength — legitimate owner case."""
        obs = _obs(header_outcome="granted_full", owner="alice", actor="alice")
        assert _authorization_enforced(obs) is True

    def test_strict_body_granted_keeps_strength(self) -> None:
        obs = _obs(body_outcome="granted", owner="alice", actor="alice")
        enriched = enrich_observation(obs)
        assert _authorization_enforced(enriched) is True

    def test_strict_grant_with_real_mismatch_still_bypass(self) -> None:
        """The IDOR pattern must not get WEAKER: a STRICT grant with a
        different owner stays a mismatch signal."""
        obs = _obs(body_outcome="granted", owner="bob", actor="alice")
        enriched = enrich_observation(obs)
        assert _authorization_mismatch(enriched) is True

    def test_header_grant_with_real_mismatch_still_bypass(self) -> None:
        obs = _obs(header_outcome="granted_full", owner="bob", actor="alice")
        assert _authorization_mismatch(obs) is True


class TestSemanticsExtraction:
    def test_authorization_semantics_ok_not_granted(self) -> None:
        ctx, rules = authorization_semantics('{"outcome": "ok"}')
        assert ctx.get("authorization_outcome") != "granted_full"

    def test_authorization_semantics_granted_still_granted(self) -> None:
        ctx, _rules = authorization_semantics('{"outcome": "granted"}')
        assert ctx.get("authorization_outcome") == "granted_full"

    def test_boolean_true_under_alias_still_granted(self) -> None:
        ctx, _rules = authorization_semantics('{"granted": true}')
        assert ctx.get("authorization_outcome") == "granted_full"
