"""Multi-step auth-bypass scenario catalog."""
from __future__ import annotations

from webpent.families.base import EvidenceRequirement, FamilyId, ScenarioSpec

MULTI_STEP_AUTH_SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        scenario_id="MSAUTH-001-step-skip-to-final",
        family=FamilyId.MULTI_STEP_AUTH_BYPASS,
        name="Skip intermediate auth steps (direct final-step POST)",
        description=(
            "A multi-step login / password-reset / onboarding flow enforces "
            "step progression only in the UI. Replaying the final step "
            "directly (with a step token or none) completes the flow without "
            "the intermediate factor."
        ),
        preconditions=["multi_step_auth_flow"],
        discriminator_experiment=(
            "Capture each step's request shape; replay the final step "
            "directly without completing earlier steps."
        ),
        expected_signal="Final step returns success / issues a session without prior steps.",
        negative_control="Full sequential flow completes; direct replay of an intermediate step is rejected.",
        evidence_requirements=[
            EvidenceRequirement(kind="step_inventory", description="Captured request per step"),
            EvidenceRequirement(kind="direct_final_replay", description="Final step replayed out of order"),
            EvidenceRequirement(kind="session_check", description="Post-replay authenticated session check"),
        ],
        severity="critical",
        references=["OWASP WSTG-ATHN-03", "CWE-863", "CWE-306"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="MSAUTH-002-step-token-tamper",
        family=FamilyId.MULTI_STEP_AUTH_BYPASS,
        name="Tamper step / state token to advance flow",
        description=(
            "The flow's progress is stored in a client-controlled token "
            "(JWT, signed cookie, hidden field) that is trusted without "
            "server-side step binding. Tampering the step counter or user "
            "identifier advances the flow for another account."
        ),
        preconditions=["multi_step_auth_flow", "client_side_state_token"],
        discriminator_experiment=(
            "Modify the step field / target account inside the state token "
            "and replay; observe whether the server accepts it."
        ),
        expected_signal="Server accepts tampered token and advances / completes the flow.",
        negative_control="Untampered token behaves normally; tampered signature is rejected.",
        evidence_requirements=[
            EvidenceRequirement(kind="token_analysis", description="Structure of the state token"),
            EvidenceRequirement(kind="tampered_replay", description="Replay with modified step/account"),
        ],
        severity="critical",
        references=["CWE-472", "CWE-565", "CWE-345"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="MSAUTH-003-partial-auth-escalation",
        family=FamilyId.MULTI_STEP_AUTH_BYPASS,
        name="Partial-authentication session accesses protected routes",
        description=(
            "After step 1 (e.g. username/password) the server issues a "
            "partial session that is accepted by protected endpoints that "
            "should require the full multi-factor completion."
        ),
        preconditions=["multi_step_auth_flow", "partial_session_issued"],
        discriminator_experiment=(
            "Stop after step 1, keep the partial session, and replay "
            "protected endpoints that should require MFA completion."
        ),
        expected_signal="Protected endpoint returns 2xx with the partial (pre-MFA) session.",
        negative_control="Same endpoint with no session returns 401/403.",
        evidence_requirements=[
            EvidenceRequirement(kind="partial_session_capture", description="Session issued mid-flow"),
            EvidenceRequirement(kind="protected_route_replay", description="Replay against protected routes"),
        ],
        severity="high",
        references=["CWE-306", "CWE-287"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="MSAUTH-004-step-order-tampering",
        family=FamilyId.MULTI_STEP_AUTH_BYPASS,
        name="Reorder steps to weaken the strongest factor",
        description=(
            "The flow permits executing steps in an arbitrary order; doing "
            "the weakest factor last (or skipping a factor the server "
            "assumes already happened) downgrades authentication strength."
        ),
        preconditions=["multi_step_auth_flow", "stateful_step_sequence"],
        discriminator_experiment=(
            "Execute steps in a permuted order and verify whether the flow "
            "still completes."
        ),
        expected_signal="Flow completes under a step order that omits / weakens a required factor.",
        negative_control="Only the canonical order completes.",
        evidence_requirements=[
            EvidenceRequirement(kind="permuted_order_replay", description="Replayed step permutations"),
        ],
        severity="high",
        references=["CWE-863", "CWE-650"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="MSAUTH-005-mfa-bypass-response-manipulation",
        family=FamilyId.MULTI_STEP_AUTH_BYPASS,
        name="MFA step bypass via response-code manipulation",
        description=(
            "The MFA step's success is determined by a client-observable "
            "response (status code, JSON field, redirect location) that can "
            "be forged or that the client treats as authoritative."
        ),
        preconditions=["multi_step_auth_flow", "mfa_step"],
        discriminator_experiment=(
            "Submit a wrong OTP; if the response contains a success flag or "
            "the next-step URL, replay that path directly."
        ),
        expected_signal="A wrong-OTP response still yields a valid session or the next-step token.",
        negative_control="Wrong OTP with no manipulation is rejected and no session is issued.",
        evidence_requirements=[
            EvidenceRequirement(kind="wrong_otp_response", description="Response to wrong OTP"),
            EvidenceRequirement(kind="session_check", description="Session validity after attempted bypass"),
        ],
        severity="critical",
        references=["CWE-804", "CWE-287", "CWE-602"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="MSAUTH-006-password-reset-cross-account",
        family=FamilyId.MULTI_STEP_AUTH_BYPASS,
        name="Multi-step password reset binds to wrong account",
        description=(
            "In a reset flow (request -> verify code -> set password), the "
            "account to reset is carried client-side between steps and can "
            "be swapped at the final step to reset a victim's password."
        ),
        preconditions=["password_reset_flow", "multi_step"],
        discriminator_experiment=(
            "Start reset for account A, submit a valid code for A, but set "
            "the account identifier to B at the final set-password step."
        ),
        expected_signal="Account B's password is changed using account A's valid code.",
        negative_control="Final step with mismatched account is rejected.",
        evidence_requirements=[
            EvidenceRequirement(kind="account_swap_replay", description="Final step with swapped account"),
            EvidenceRequirement(kind="post_reset_login", description="Verify which account's password changed"),
        ],
        severity="critical",
        references=["CWE-640", "CWE-472"],
        safe_in_production=False,
    ),
)

__all__ = ["MULTI_STEP_AUTH_SCENARIOS"]
