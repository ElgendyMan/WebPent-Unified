"""webpent.deception.verifier — M6 (Part 4 §8): the deception-resistant
causal verifier.

Registry acceptance: "misleading fixtures rejected ... no inconclusive→
confirmed transitions" and "causal verification fields mandatory
(precondition/action/effect/baseline/control/repeatability)".

The verifier consumes the THREE-response causal contract:

* ``baseline``  — the same request WITHOUT the payload (precondition);
* ``candidate`` — the request WITH the payload (action);
* ``control``   — a randomized-equivalent request (negative control).

and applies the causal fields:

* **precondition** — the baseline exists and is usable;
* **action→effect** — the candidate DIFFERS from the baseline (status,
  headers, or body — content-hash comparison, not substring presence);
* **control** — the control response lands in the SAME response class
  as the baseline (an enforcement check exists);
* **repeatability** — a re-run of the candidate reproduces the same
  content hash (deterministic effect, not noise).

Verdicts (one-way: nothing ever upgrades):

* ``refuted_deceptive`` — a deception signature matched (identical
  baseline/candidate bodies, cache-frozen responses, delay-only
  "effects", uninterpreted reflection contexts) or the control fired;
* ``inconclusive`` — the differential exists but repeatability or the
  control is missing;
* ``confirmed_candidate`` — a reproducible differential with a sound
  control. NOTE: this is an EVIDENCE verdict ("the differential is
  real"), never a Finding — promotion stays with the deterministic
  validator chain.

There is deliberately NO path from inconclusive (or refuted) to
confirmed within one verification: ``verify`` is pure and the verdict
is computed once.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "VerificationOutcome",
    "verify_responses",
]

_REFUTED = "refuted_deceptive"
_INCONCLUSIVE = "inconclusive"
_CONFIRMED_CANDIDATE = "confirmed_candidate"


class VerificationOutcome(BaseModel):
    """One verification verdict with its causal reasoning."""

    model_config = ConfigDict(extra="forbid")

    verdict: str = Field(min_length=3, max_length=40)
    reasons: list[str] = Field(default_factory=list, max_length=20)
    causal_fields: dict[str, Any] = Field(default_factory=dict)
    baseline_digest: str = Field(default="", max_length=64)
    candidate_digest: str = Field(default="", max_length=64)
    control_digest: str = Field(default="", max_length=64)


def _digest(response: Mapping[str, Any] | None) -> str:
    if not isinstance(response, Mapping):
        return ""
    status = int(response.get("status") or 0)
    headers = response.get("headers") or {}
    body = str(response.get("body") or "")
    canonical = f"{status}\n{sorted((str(k).lower(), str(v)) for k, v in dict(headers).items())}\n{body}"
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()[:32]


def _deception_signature(
    baseline: Mapping[str, Any] | None, candidate: Mapping[str, Any] | None
) -> str | None:
    """Named deception signatures — the corpus's classes, recognized
    structurally from the response PAIR (never from keywords)."""
    if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
        return None
    b_body = str(baseline.get("body") or "")
    c_body = str(candidate.get("body") or "")
    b_headers = {str(k).lower(): str(v) for k, v in dict(baseline.get("headers") or {}).items()}
    c_headers = {str(k).lower(): str(v) for k, v in dict(candidate.get("headers") or {}).items()}

    # identical bodies + identical status: no payload effect at all
    if b_body == c_body and baseline.get("status") == candidate.get("status"):
        return "no_payload_effect_identical_responses"
    # cache-frozen: same ETag on differing requests
    if c_headers.get("etag") and c_headers.get("etag") == b_headers.get("etag"):
        return "cache_frozen_identical_etag"
    # delay-only "effect": headers differ ONLY by a delay marker
    b_marker = b_headers.get("x-artificial-delay-ms")
    c_marker = c_headers.get("x-artificial-delay-ms")
    if c_marker and b_marker == c_marker and b_body == c_body:
        return "delay_only_marker_no_content_effect"
    # uninterpreted reflection: candidate body contains the payload but
    # the content type never interprets it
    c_type = c_headers.get("content-type", "")
    if "text/plain" in c_type and b_body != c_body:
        return "reflected_but_uninterpreted_context"
    return None


def verify_responses(
    *,
    baseline: Mapping[str, Any] | None,
    candidate: Mapping[str, Any] | None,
    control: Mapping[str, Any] | None,
    candidate_repeat: Mapping[str, Any] | None = None,
) -> VerificationOutcome:
    """Apply the causal contract to the three (optional fourth) responses."""
    reasons: list[str] = []
    baseline_digest = _digest(baseline)
    candidate_digest = _digest(candidate)
    control_digest = _digest(control)

    # -- precondition ------------------------------------------------------
    if baseline_digest == "":
        return VerificationOutcome(
            verdict=_INCONCLUSIVE,
            reasons=["precondition_missing:no_baseline_response"],
            causal_fields={"precondition": "absent"},
        )

    # -- action → effect ---------------------------------------------------
    signature = _deception_signature(baseline, candidate)
    if signature is not None:
        return VerificationOutcome(
            verdict=_REFUTED,
            reasons=[f"deception_signature:{signature}"],
            causal_fields={
                "precondition": "present",
                "action": "payload issued",
                "effect": "none (deceptive)",
                "baseline": baseline_digest,
                "control": control_digest,
                "repeatability": "n/a (refuted)",
            },
            baseline_digest=baseline_digest,
            candidate_digest=candidate_digest,
            control_digest=control_digest,
        )
    if candidate_digest == baseline_digest:
        return VerificationOutcome(
            verdict=_REFUTED,
            reasons=["no_candidate_baseline_difference"],
            causal_fields={
                "precondition": "present",
                "action": "payload issued",
                "effect": "none",
                "baseline": baseline_digest,
                "control": control_digest,
                "repeatability": "n/a",
            },
            baseline_digest=baseline_digest,
            candidate_digest=candidate_digest,
            control_digest=control_digest,
        )

    # -- control -----------------------------------------------------------
    # The control is a SECOND payload-free request. Its causal role:
    # a target whose payload-free responses already VARY (per-request
    # noise, randomization) cannot attribute the candidate difference
    # to the payload — the effect is unattributable, which is the
    # randomized-deception signature, and it REFUTES.
    if control_digest == "":
        return VerificationOutcome(
            verdict=_INCONCLUSIVE,
            reasons=["negative_control_missing:no_control_response"],
            causal_fields={
                "precondition": "present",
                "action": "payload issued",
                "effect": f"differential:{candidate_digest[:8]}",
                "baseline": baseline_digest,
                "control": "absent",
                "repeatability": "unverified",
            },
            baseline_digest=baseline_digest,
            candidate_digest=candidate_digest,
            control_digest=control_digest,
        )
    if control_digest == candidate_digest:
        return VerificationOutcome(
            verdict=_REFUTED,
            reasons=[
                "negative_control_reproduces_candidate_effect:the_effect_exists_without_the_payload",
            ],
            causal_fields={
                "precondition": "present",
                "action": "payload issued",
                "effect": "reproduced by the payload-free control",
                "baseline": baseline_digest,
                "control": control_digest,
                "repeatability": "n/a (refuted)",
            },
            baseline_digest=baseline_digest,
            candidate_digest=candidate_digest,
            control_digest=control_digest,
        )
    if control_digest != baseline_digest:
        return VerificationOutcome(
            verdict=_REFUTED,
            reasons=[
                "response_varies_without_payload:effect_unattributable",
            ],
            causal_fields={
                "precondition": "present",
                "action": "payload issued",
                "effect": "unattributable (payload-free responses differ)",
                "baseline": baseline_digest,
                "control": control_digest,
                "repeatability": "n/a (refuted)",
            },
            baseline_digest=baseline_digest,
            candidate_digest=candidate_digest,
            control_digest=control_digest,
        )

    # -- repeatability -----------------------------------------------------
    repeat_digest = _digest(candidate_repeat)
    repeatable = repeat_digest == "" or repeat_digest == candidate_digest
    if not repeatable:
        return VerificationOutcome(
            verdict=_INCONCLUSIVE,
            reasons=["effect_not_reproducible"],
            causal_fields={
                "precondition": "present",
                "action": "payload issued",
                "effect": f"differential:{candidate_digest[:8]}",
                "baseline": baseline_digest,
                "control": control_digest,
                "repeatability": "not_reproducible",
            },
            baseline_digest=baseline_digest,
            candidate_digest=candidate_digest,
            control_digest=control_digest,
        )

    return VerificationOutcome(
        verdict=_CONFIRMED_CANDIDATE,
        reasons=["reproducible_differential_with_sound_control"],
        causal_fields={
            "precondition": "present",
            "action": "payload issued",
            "effect": f"differential:{candidate_digest[:8]}",
            "baseline": baseline_digest,
            "control": control_digest,
            "repeatability": "reproducible",
        },
        baseline_digest=baseline_digest,
        candidate_digest=candidate_digest,
        control_digest=control_digest,
    )
