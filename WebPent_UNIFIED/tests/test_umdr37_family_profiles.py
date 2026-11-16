"""UM-DR-37 §8 — family security profile tests."""

from __future__ import annotations

from webpent.research.failure_taxonomy import REASON_CODES
from webpent.research.family_profiles import (
    ADVISORY,
    IMPLEMENTED,
    INTEGRATED,
    PRODUCTION_PATH_VERIFIED,
    FAMILY_PROFILES,
    FamilySecurityProfile,
    families_for_entity,
    profiles_by_status,
)

REQUIRED_ASPECTS = (
    "relevant_entities", "security_invariants", "hypothesis_templates",
    "required_preconditions", "safe_experiment_strategy",
    "expected_observations", "negative_controls",
    "evidence_requirements", "confirmation_criteria",
    "failure_classifications",
)

EXPECTED_FAMILIES = {
    "broken_access_control", "authentication_session", "injection",
    "cross_site_scripting", "server_side_request_forgery",
    "business_logic", "security_misconfiguration",
    "sensitive_information_disclosure",
}


def test_all_eight_families_present() -> None:
    assert set(FAMILY_PROFILES) == EXPECTED_FAMILIES
    assert len(FAMILY_PROFILES) == 8


def test_every_profile_covers_all_ten_aspects() -> None:
    for name, profile in FAMILY_PROFILES.items():
        for aspect in REQUIRED_ASPECTS:
            value = getattr(profile, aspect)
            assert value and (isinstance(value, str) or len(value) > 0), (
                f"{name}.{aspect} is empty — every family must cover all "
                "ten aspects"
            )


def test_hypothesis_templates_are_hypotheses_not_findings() -> None:
    for name, profile in FAMILY_PROFILES.items():
        for template in profile.hypothesis_templates:
            lowered = template.lower()
            assert " may " in lowered or " might " in lowered, (
                f"{name}: template must be phrased as a hypothesis: "
                f"{template}"
            )
            for banned in ("confirmed", "vulnerable endpoint", "is a "
                           "vulnerability"):
                assert banned not in lowered, (name, template)


def test_confirmation_criteria_route_through_the_legal_chain() -> None:
    for name, profile in FAMILY_PROFILES.items():
        criteria = profile.confirmation_criteria.lower()
        assert "causalguard" in criteria, name
        assert "bundle" in criteria and "replay" in criteria, name


def test_failure_classifications_reference_the_closed_taxonomy() -> None:
    for name, profile in FAMILY_PROFILES.items():
        for code in profile.failure_classifications:
            assert code in REASON_CODES, (name, code)


def test_statuses_are_honest_and_point_at_evidence() -> None:
    allowed = {PRODUCTION_PATH_VERIFIED, INTEGRATED, IMPLEMENTED, ADVISORY}
    for name, profile in FAMILY_PROFILES.items():
        assert profile.implementation_status in allowed, name
        assert profile.evidence_pointer and (
            "tests/" in profile.evidence_pointer
            or "artifacts/" in profile.evidence_pointer
            or "families/" in profile.evidence_pointer
            or "agents/" in profile.evidence_pointer
        ), name
    # exactly one family claims production verification (the one proven
    # by the 3/3 campaigns); the rest stay at their real level
    assert profiles_by_status(PRODUCTION_PATH_VERIFIED) == [
        "broken_access_control"]
    assert profiles_by_status(INTEGRATED) == [
        "authentication_session", "business_logic"]


def test_entity_index_supports_reasoning() -> None:
    # identity is reasoned about by the access-control, authn and
    # business-logic families; endpoint by most
    assert "broken_access_control" in families_for_entity("identity")
    assert "authentication_session" in families_for_entity("identity")
    assert len(families_for_entity("endpoint")) >= 5
    assert families_for_entity("workflow") == [
        "authentication_session", "business_logic", "injection",
        "server_side_request_forgery"]


def test_profiles_are_frozen_records() -> None:
    profile = FAMILY_PROFILES["broken_access_control"]
    assert isinstance(profile, FamilySecurityProfile)
    try:
        profile.family = "renamed"  # type: ignore[misc]
        raised = False
    except Exception:
        raised = True
    assert raised, "profiles are frozen declarations"
