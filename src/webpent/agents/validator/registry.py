"""Deterministic validator capability registry.

The registry is intentionally additive: it describes the existing dispatch
contract without extracting or duplicating the validator implementations.
Unknown or structural-only classes remain explicitly unvalidated rather than
being routed through an LLM-only confirmation path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class ValidatorCapability:
    """Contract metadata for one vulnerability-class validator."""

    vuln_class: str
    validator_id: str | None
    status: str
    evidence_mode: str


_IMPLEMENTED_VALIDATORS: Final[dict[str, str]] = {
    "xss": "xss",
    "sqli": "sqli",
    "csrf": "csrf",
    "ssrf": "ssrf",
    "rce": "rce",
    "deserialization": "deserialization",
    "lfi": "lfi",
    "rfi": "rfi",
    "ssti": "ssti",
    "xxe": "xxe",
    "path_traversal": "path_traversal",
    "command_injection": "command_injection",
    "open_redirect": "open_redirect",
    "info_disclosure": "info_disclosure",
    "idor": "idor",
    "nosql_injection": "nosql_injection",
    "csp": "csp",
    "weak_session": "weak_session",
    "javascript": "javascript",
    "auth_bypass": "auth_bypass",
    "api_issue": "api_issue",
    "cryptography": "cryptography",
    "captcha": "captcha",
    "brute_force": "brute_force",
    # Offline weak-secret verification emits a sealed ProofBundle and a
    # wrong-secret negative control; the central validator revalidates it.
    "jwt_weakness": "jwt_weakness",
    "race_condition": "race_condition",
    # POST-P0 Phase 5: classes promoted from offline-fixture parking to
    # live deterministic validators (postp0_checks.py). Each defines
    # explicit confirm / negative / inconclusive outcomes and routes
    # through the strict replay verifier — LLM cannot sole-confirm.
    "mass_assignment": "mass_assignment",
    "request_smuggling": "request_smuggling",
    "subdomain_takeover": "subdomain_takeover",
    "jwt_key_confusion": "jwt_key_confusion",
    # Validator coverage engine: the last three offline-fixture classes,
    # now with live deterministic validators (postp0_checks.py, section 6).
    # Note: elasticsearch_snapshot_traversal and xslt_injection still have
    # no live producer agent — the validators make the dispatch path
    # deterministic and close the registry gap, but candidate supply for
    # those two remains a producer gap (tracked, not hidden).
    "cloud_storage_exposure": "cloud_storage_exposure",
    "elasticsearch_snapshot_traversal": "elasticsearch_snapshot_traversal",
    "xslt_injection": "xslt_injection",
    # ULTIMATE PLAN 2026-10-27, proposal 1/7: the five donorC family
    # classes dispatch through the live family-validator bridge
    # (family_checks.dispatch_family_validator) — deterministic replay
    # + negative-control promotion, same contract as the entries
    # above. This closes the documented donorC-lineage registry gap
    # (test_five_families' expected six, race_condition was already
    # registered).
    "business_logic": "business_logic",
    "multi_step_auth_bypass": "multi_step_auth_bypass",
    "tenant_isolation": "tenant_isolation",
    "exploit_chain": "exploit_chain",
    "oauth": "oauth",
    # ULTIMATE PLAN 2026-10-27, proposal 7: the new deterministic
    # detector classes. Their validators live in validators/
    # (graphql_validator.py, oauth_misconfig_validator.py) and
    # shared/cache_poisoning_detector.py — pure functions over captured
    # evidence, promotion stays with the existing authority chain.
    "graphql_introspection_exposure": "graphql_introspection_exposure",
    "graphql_batching_abuse": "graphql_batching_abuse",
    "graphql_field_suggestion_leak": "graphql_field_suggestion_leak",
    "graphql_depth_complexity_dos": "graphql_depth_complexity_dos",
    "prototype_pollution": "prototype_pollution",
    "oauth_misconfiguration": "oauth_misconfiguration",
    "cache_poisoning": "cache_poisoning",
    "web_cache_deception": "web_cache_deception",
    # UM-DR-32 §6.5: the privilege_differential route closure. The
    # validator itself (production/privilege_validator.py::
    # validate_privilege_differential) and its VALIDATORS dispatch entry
    # existed since UM-DR-31.1, but this capability registry lacked the
    # class — so the strategist recorded every privilege_differential
    # hypothesis as missing-validator and downgraded PROMOTE to DEFER
    # (UMDR31_1_EXECUTION_REPORT limitation). Registered here with the
    # UM-DR-32 multi-identity producer (production/multi_identity.py
    # builds the typed owner-on-R / foreign-on-R / foreign-on-C triple
    # with negative controls), the class is end-to-end routable:
    # hypothesis -> registry capability -> deterministic validator ->
    # CausalGuard stays the sole confirmation authority.
    "privilege_differential": "privilege_differential",
}

_OFFLINE_FIXTURE_VALIDATORS: Final[dict[str, str]] = {
    # Empty since the validator coverage engine (Phase 6): the earlier
    # parked classes were promoted to live validators in order —
    # mass_assignment / request_smuggling / subdomain_takeover /
    # jwt_key_confusion (Phase 5), then cloud_storage_exposure /
    # elasticsearch_snapshot_traversal / xslt_injection (Phase 6). The
    # dict is kept so capability_for still fails closed, honestly, for any
    # class that ever joins _ALL_CLASSES without a validator.
}

# Critique A1/C8: a class whose dispatch path is deterministic but which
# has no live producer agent still cannot be hunted end to end. The gap is
# machine-readable here rather than only in prose docs: ``producer_gap``
# is True for exactly these classes until a producer supplies candidates.
_PRODUCER_GAP_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "elasticsearch_snapshot_traversal",
        "xslt_injection",
    }
)

_ALL_CLASSES: Final[tuple[str, ...]] = (
    "xss",
    "sqli",
    "ssrf",
    "lfi",
    "rfi",
    "rce",
    "ssti",
    "open_redirect",
    "xxe",
    "csrf",
    "deserialization",
    "path_traversal",
    "command_injection",
    "nosql_injection",
    "info_disclosure",
    "race_condition",
    "idor",
    "auth_bypass",
    "mass_assignment",
    "request_smuggling",
    "brute_force",
    "captcha",
    "weak_session",
    "csp",
    "javascript",
    "cryptography",
    "api_issue",
    "subdomain_takeover",
    "cloud_storage_exposure",
    "jwt_weakness",
    "jwt_key_confusion",
    "elasticsearch_snapshot_traversal",
    "xslt_injection",
    # ULTIMATE PLAN 2026-10-27, proposal 1/7: the family classes and the
    # new detector classes (documented above).
    "business_logic",
    "multi_step_auth_bypass",
    "tenant_isolation",
    "exploit_chain",
    "oauth",
    "graphql_introspection_exposure",
    "graphql_batching_abuse",
    "graphql_field_suggestion_leak",
    "graphql_depth_complexity_dos",
    "prototype_pollution",
    "oauth_misconfiguration",
    "cache_poisoning",
    "web_cache_deception",
    "unknown",
)


def validator_id_for(vuln_class: str) -> str | None:
    """Return the registered validator id, or ``None`` when unsupported."""
    return _IMPLEMENTED_VALIDATORS.get(str(vuln_class))


def capability_for(vuln_class: str) -> ValidatorCapability:
    """Return an explicit capability record for any known or unknown class."""
    vuln_class = str(vuln_class)
    validator_id = validator_id_for(vuln_class)
    if validator_id:
        return ValidatorCapability(
            vuln_class=vuln_class,
            validator_id=validator_id,
            status="tested",
            evidence_mode="deterministic",
        )
    offline_id = _OFFLINE_FIXTURE_VALIDATORS.get(vuln_class)
    if offline_id:
        return ValidatorCapability(
            vuln_class=vuln_class,
            validator_id=offline_id,
            status="offline-fixture",
            evidence_mode="offline-contract",
        )
    if vuln_class == "unknown":
        return ValidatorCapability(
            vuln_class=vuln_class,
            validator_id=None,
            status="not_applicable",
            evidence_mode="human-review",
        )
    return ValidatorCapability(
        vuln_class=vuln_class,
        validator_id=None,
        status="missing-validator",
        evidence_mode="human-review",
    )


def all_capabilities() -> tuple[ValidatorCapability, ...]:
    """Return the stable capability matrix used by coverage reporting."""
    return tuple(capability_for(vuln_class) for vuln_class in _ALL_CLASSES)


def coverage_gap(vuln_class: str) -> dict[str, str | None | bool]:
    """Return a serializable coverage record for a finding class.

    ``producer_gap`` is True when the validator dispatch path is
    deterministic but no live producer agent supplies candidates for the
    class (critique A1/C8): a consumer of this record sees the gap
    without reading prose docs.
    """
    capability = capability_for(vuln_class)
    return {
        "vuln_class": capability.vuln_class,
        "validator_id": capability.validator_id,
        "status": capability.status,
        "evidence_mode": capability.evidence_mode,
        "producer_gap": capability.vuln_class in _PRODUCER_GAP_CLASSES,
    }


__all__ = [
    "ValidatorCapability",
    "all_capabilities",
    "capability_for",
    "coverage_gap",
    "validator_id_for",
]


# End of registry.py
