"""Race-condition scenario catalog (TOCTOU / concurrency family)."""
from __future__ import annotations

from webpent.families.base import EvidenceRequirement, FamilyId, ScenarioSpec

RACE_SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        scenario_id="RACE-001-double-spend",
        family=FamilyId.RACE_CONDITION,
        name="Double-spend / balance decrement race",
        description=(
            "Two concurrent withdrawal/transfer/purchase requests against the "
            "same balance may both succeed if the check-then-act window is "
            "not serialized, crediting or debiting more than allowed."
        ),
        preconditions=["stateful_balance", "mutating_endpoint"],
        discriminator_experiment=(
            "Fire N identical mutating requests in a single synchronized "
            "burst (last-byte sync) against the same balance, then re-read "
            "the balance and count committed side effects."
        ),
        expected_signal=(
            ">1 request returns 2xx AND final balance reflects >1 committed "
            "decrement where business rules permit at most 1."
        ),
        negative_control=(
            "Sequentially replayed identical requests: only 1 succeeds; "
            "subsequent attempts are rejected with the business-rule error."
        ),
        evidence_requirements=[
            EvidenceRequirement(kind="burst_timeline", description="Per-request timestamps proving concurrency"),
            EvidenceRequirement(kind="post_state_read", description="Balance/state read after the burst settles"),
        ],
        severity="high",
        references=["OWASP WSTG-BUSL-05", "CWE-362", "CWE-367"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="RACE-002-coupon-reuse",
        family=FamilyId.RACE_CONDITION,
        name="One-time coupon / promo-code reuse",
        description=(
            "A single-use discount code applied concurrently may be consumed "
            "more than once if redemption is not atomic."
        ),
        preconditions=["promo_code", "checkout_endpoint"],
        discriminator_experiment=(
            "Burst-apply the same single-use code to N checkouts; count "
            "successful applications and the code's remaining-use counter."
        ),
        expected_signal=">1 checkout confirms the discount for a code with max_uses=1.",
        negative_control="Sequential application: second attempt returns 'code already used'.",
        evidence_requirements=[
            EvidenceRequirement(kind="burst_timeline", description="Concurrent apply timeline"),
            EvidenceRequirement(kind="code_state_read", description="Remaining-uses counter after burst"),
        ],
        severity="medium",
        references=["CWE-362"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="RACE-003-toctou-file-upload",
        family=FamilyId.RACE_CONDITION,
        name="TOCTOU on file/resource state",
        description=(
            "A resource validated in one request and consumed in a second "
            "may be swapped in the window between check and use."
        ),
        preconditions=["two_step_resource_flow", "upload_or_import"],
        discriminator_experiment=(
            "Race the validation step and a replacement upload so the "
            "consumed content differs from the validated content."
        ),
        expected_signal="Server consumes the post-validation (unvalidated) content.",
        negative_control="Sequential check-then-use consumes the validated content only.",
        evidence_requirements=[
            EvidenceRequirement(kind="swap_timeline", description="Validation vs replacement timestamps"),
            EvidenceRequirement(kind="consumed_fingerprint", description="Hash of actually consumed bytes"),
        ],
        severity="high",
        references=["CWE-367"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="RACE-004-rate-limit-burst-bypass",
        family=FamilyId.RACE_CONDITION,
        name="Synchronized burst bypasses sliding-window rate limit",
        description=(
            "A fixed or sliding window that is not atomic at the boundary "
            "permits a synchronized burst to exceed the per-window quota."
        ),
        preconditions=["rate_limited_endpoint"],
        discriminator_experiment=(
            "Synchronize N requests to land in the same millisecond at the "
            "window boundary and count 2xx vs 429."
        ),
        expected_signal="More 2xx responses than the configured window limit.",
        negative_control="Same total request count spread across windows is throttled to the limit.",
        evidence_requirements=[
            EvidenceRequirement(kind="burst_timeline", description="Arrival timestamps within one window"),
            EvidenceRequirement(kind="throttle_counts", description="2xx vs 429 counts in burst vs spread"),
        ],
        severity="medium",
        references=["CWE-770", "CWE-362"],
        safe_in_production=True,
    ),
    ScenarioSpec(
        scenario_id="RACE-005-account-takeover-reset",
        family=FamilyId.RACE_CONDITION,
        name="Password-reset / OTP token race",
        description=(
            "Concurrent password-reset or OTP verification requests may "
            "leave a valid token outstanding or accept a stale token."
        ),
        preconditions=["password_reset_flow", "otp_or_mfa"],
        discriminator_experiment=(
            "Issue two reset flows concurrently and verify whether an older "
            "token/OTP remains accepted after the newer flow completes."
        ),
        expected_signal="An older token/OTP is accepted after a newer flow invalidated it.",
        negative_control="Sequential flows: older token rejected after newer flow issued.",
        evidence_requirements=[
            EvidenceRequirement(kind="token_timeline", description="Issue vs acceptance timestamps"),
            EvidenceRequirement(kind="token_replay", description="Replay of older token after newer flow"),
        ],
        severity="high",
        references=["CWE-640", "CWE-362"],
        safe_in_production=False,
    ),
)

__all__ = ["RACE_SCENARIOS"]
