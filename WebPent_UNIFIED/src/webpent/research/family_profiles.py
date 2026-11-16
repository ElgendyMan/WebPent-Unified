"""UM-DR-37 §8 — family security profiles (the family-agnostic core's
per-family reasoning interfaces).

One declarative profile per vulnerability family covering the ten
aspects the mission requires: relevant application entities, security
invariants, hypothesis templates, required preconditions, safe
experiment strategies, expected observations, negative controls,
evidence requirements, confirmation criteria, and failure
classifications (linked to the §7 taxonomy).

Honesty rules:

  * ``implementation_status`` states what ACTUALLY exists —
    PRODUCTION_PATH_VERIFIED (proven through run_unified_hunt
    campaigns), INTEGRATED (wired + lab-tested behind a flag),
    IMPLEMENTED (hypothesis generation + validators exist), ADVISORY
    (templates/contracts only) — never inflated;
  * hypothesis templates are HYPOTHESES, never findings;
  * confirmation criteria always route through CausalGuard ->
    ProofBundle -> Replay (the sole authority);
  * failure classifications reference the closed §7 reason-code
    registry.
"""
from __future__ import annotations

from dataclasses import dataclass

#: implementation statuses (honest, never inflated)
PRODUCTION_PATH_VERIFIED = "PRODUCTION_PATH_VERIFIED"
INTEGRATED = "INTEGRATED"
IMPLEMENTED = "IMPLEMENTED"
ADVISORY = "ADVISORY"


@dataclass(frozen=True)
class FamilySecurityProfile:
    family: str
    relevant_entities: tuple[str, ...]
    security_invariants: tuple[str, ...]
    hypothesis_templates: tuple[str, ...]
    required_preconditions: tuple[str, ...]
    safe_experiment_strategy: str
    expected_observations: tuple[str, ...]
    negative_controls: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    confirmation_criteria: str
    failure_classifications: tuple[str, ...]
    implementation_status: str
    evidence_pointer: str


FAMILY_PROFILES: dict[str, FamilySecurityProfile] = {
    "broken_access_control": FamilySecurityProfile(
        family="broken_access_control",
        relevant_entities=("identity", "endpoint", "resource", "owns",
                           "authenticates_as"),
        security_invariants=(
            "a resource is readable only by its owner or an explicitly "
            "authorized role",
            "an enforced denial observed for one principal proves the "
            "boundary is mediated for that resource class",
        ),
        hypothesis_templates=(
            "a user may access another user's resource through this "
            "endpoint",
            "an alternate endpoint may expose the same resource without "
            "the ownership check",
        ),
        required_preconditions=(
            ">=2 authenticated identities with distinct sessions",
            "a resource with a recorded owner binding",
            "an observed denial (401/403/404) for a non-owner on the "
            "same resource class",
        ),
        safe_experiment_strategy=(
            "read-only differential probes: owner baseline, foreign "
            "candidate, denied/missing negative control — no state "
            "mutation, bounded retries"),
        expected_observations=(
            "owner 2xx while a foreign principal reproduces 2xx on the "
            "same resource",
            "identical resource semantics for both principals",
        ),
        negative_controls=(
            "enforced 403/404 on a known resource for the foreign "
            "principal",
            "public resource must never confirm",
        ),
        evidence_requirements=(
            "actor/owner/outcome context on every observation row",
            "target-backed request/response digests",
        ),
        confirmation_criteria=(
            "CausalGuard cross-actor ownership-boundary CONFIRMED -> "
            "sealed ProofBundle -> verified replay"),
        failure_classifications=(
            "identity_profiles_dropped", "json_manifest_unparsed",
            "identifier_gate_too_strict",
            "guard_inconclusive_insufficient_auth_context",
        ),
        implementation_status=PRODUCTION_PATH_VERIFIED,
        evidence_pointer=(
            "tests/test_umdr37_root_cause_fixes.py (live e2e) + "
            "artifacts/umdr37_production_campaigns.json (3/3 runs "
            "confirm both boundary violations; negative controls, the "
            "decoy route and the out-of-scope origin stay unconfirmed)"),
    ),
    "authentication_session": FamilySecurityProfile(
        family="authentication_session",
        relevant_entities=("identity", "tenant", "workflow",
                           "authenticates_as", "observation"),
        security_invariants=(
            "an authentication state is valid only within its intended "
            "boundary and lifetime",
            "a session for one principal must not act as another",
        ),
        hypothesis_templates=(
            "an authentication state may be reused beyond its intended "
            "boundary",
            "a workflow may accept an expired or foreign session",
        ),
        required_preconditions=(
            ">=2 recorded identities with distinct credentials",
            "an authenticated workflow reachable with both sessions",
        ),
        safe_experiment_strategy=(
            "read-only authenticated traversals comparing principal "
            "attribution; no credential brute force, no session "
            "fixation writes"),
        expected_observations=(
            "a session attributed to principal A acting as principal B",
        ),
        negative_controls=(
            "the same workflow under an anonymous session is refused",
        ),
        evidence_requirements=(
            "session-identity binding recorded on both observations",
        ),
        confirmation_criteria=(
            "CausalGuard identity-confusion branch CONFIRMED -> "
            "ProofBundle -> replay"),
        failure_classifications=(
            "identity_profiles_dropped", "experiment_inconclusive",
        ),
        implementation_status=INTEGRATED,
        evidence_pointer=(
            "families/oauth + families/multi_step_auth (spine, "
            "flag-gated) + production/stateful_discovery session "
            "continuity (tests/test_umdr28_campaign_stateful_e2e.py)"),
    ),
    "injection": FamilySecurityProfile(
        family="injection",
        relevant_entities=("endpoint", "workflow", "observation"),
        security_invariants=(
            "untrusted input never reaches an interpreter without "
            "contextual handling",
        ),
        hypothesis_templates=(
            "a parameter may influence a server-side resource reference",
            "an input may reach an interpreter without adequate "
            "contextual handling",
        ),
        required_preconditions=(
            "an endpoint with a reflected or persisted parameter",
            "a safe, non-destructive probe payload",
        ),
        safe_experiment_strategy=(
            "canonical benign canary payloads only; no data exfiltration, "
            "no destructive commands, bounded payload count"),
        expected_observations=(
            "a class-specific technical signal (validator-recorded) on "
            "the candidate and absent from baseline/control",
        ),
        negative_controls=(
            "the same parameter with a benign value shows no signal",
        ),
        evidence_requirements=(
            "validator-recorded technical signal + semantic differential "
            "vs control",
        ),
        confirmation_criteria=(
            "CausalGuard content-differential branch CONFIRMED (recorded "
            "class signal, control independence) -> bundle -> replay"),
        failure_classifications=(
            "experiment_inconclusive", "candidate_refuted",
            "observation_unparseable",
        ),
        implementation_status=IMPLEMENTED,
        evidence_pointer=(
            "hypothesis_analyzer URL/parameter signatures + "
            "agents/validator/{active,structural}_checks.py (SQLi/XSS/"
            "template classes); AVI advisory contracts"),
    ),
    "cross_site_scripting": FamilySecurityProfile(
        family="cross_site_scripting",
        relevant_entities=("endpoint", "observation"),
        security_invariants=(
            "untrusted content is never interpreted as markup in a "
            "trusted origin context",
        ),
        hypothesis_templates=(
            "a reflected parameter may execute in the browser context "
            "of the application origin",
        ),
        required_preconditions=(
            "an endpoint reflecting input into an HTML/JS context",
        ),
        safe_experiment_strategy=(
            "non-executing canary markers with context signatures; "
            "reflection analysis, never live execution"),
        expected_observations=(
            "the canary reflected unencoded into an executable context",
        ),
        negative_controls=(
            "benign input shows no reflection in executable context",
        ),
        evidence_requirements=(
            "reflection context recorded + encoded-control differential",
        ),
        confirmation_criteria=(
            "CausalGuard content-differential CONFIRMED with the XSS "
            "validator's recorded signal -> bundle -> replay"),
        failure_classifications=(
            "experiment_inconclusive", "candidate_refuted",
        ),
        implementation_status=IMPLEMENTED,
        evidence_pointer=(
            "agents/validator/active_checks.py XSS reflection classes + "
            "hypothesis templates (vuln_class xss)"),
    ),
    "server_side_request_forgery": FamilySecurityProfile(
        family="server_side_request_forgery",
        relevant_entities=("endpoint", "workflow", "observation"),
        security_invariants=(
            "a server-side fetch destination must satisfy the "
            "deployment's destination policy",
        ),
        hypothesis_templates=(
            "a server-side URL fetch may violate the intended "
            "destination policy",
        ),
        required_preconditions=(
            "a parameter or workflow that plausibly influences a "
            "server-side fetch target",
            "an observable, authorized out-of-band or in-scope "
            "destination marker",
        ),
        safe_experiment_strategy=(
            "first-party loopback/in-scope markers ONLY — never third "
            "party hosts, never metadata endpoints, no blind SSRF"),
        expected_observations=(
            "the authorized marker fetched server-side while the control "
            "destination is not",
        ),
        negative_controls=(
            "a non-fetchable parameter value produces no marker request",
        ),
        evidence_requirements=(
            "marker-request observation + parameter differential + "
            "destination-policy record",
        ),
        confirmation_criteria=(
            "CausalGuard content-differential CONFIRMED with the SSRF "
            "validator's recorded signal -> bundle -> replay"),
        failure_classifications=(
            "experiment_inconclusive", "candidate_refuted",
            "budget_exhausted",
        ),
        implementation_status=IMPLEMENTED,
        evidence_pointer=(
            "agents/validator/active_checks.py SSRF marker classes; "
            "OOB loopback trust is first-party-only "
            "(shared/oob.py, M1-C contract)"),
    ),
    "business_logic": FamilySecurityProfile(
        family="business_logic",
        relevant_entities=("workflow", "identity", "state", "resource"),
        security_invariants=(
            "a state transition requires the authorization its workflow "
            "declares",
            "a workflow invariant holds across identities",
        ),
        hypothesis_templates=(
            "a workflow may allow a state transition without the "
            "required authorization",
        ),
        required_preconditions=(
            "an observed workflow with declared state transitions",
            "read-only reachability of the transition endpoints",
        ),
        safe_experiment_strategy=(
            "invariant observation first; state-advancing probes ONLY "
            "behind the state-advancing gate with bounded budget"),
        expected_observations=(
            "a forbidden transition succeeding for an unauthorized "
            "principal, or an invariant violated across identities",
        ),
        negative_controls=(
            "the same transition refused for the anonymous principal",
        ),
        evidence_requirements=(
            "before/after state observations + identity context on both",
        ),
        confirmation_criteria=(
            "CausalGuard (state-advance or content differential with "
            "the family validator's signal) -> bundle -> replay"),
        failure_classifications=(
            "experiment_inconclusive", "ownership_assumption_contradicted",
            "budget_exhausted",
        ),
        implementation_status=INTEGRATED,
        evidence_pointer=(
            "families/business_logic (6 scenarios) + AVI registry "
            "(tests/test_umdr31_campaign_e2e_ablation.py arms)"),
    ),
    "security_misconfiguration": FamilySecurityProfile(
        family="security_misconfiguration",
        relevant_entities=("endpoint", "application", "observation"),
        security_invariants=(
            "security-relevant headers and transport settings match the "
            "deployment policy",
        ),
        hypothesis_templates=(
            "an endpoint may expose a misconfigured security posture "
            "(headers, methods, TLS, verbose errors)",
        ),
        required_preconditions=(
            "an in-scope endpoint with a comparable policy baseline",
        ),
        safe_experiment_strategy="read-only OPTIONS/HEAD/GET inspection",
        expected_observations=(
            "a policy deviation recorded against the baseline",
        ),
        negative_controls=(
            "a compliant endpoint records no deviation",
        ),
        evidence_requirements=(
            "recorded response headers/methods vs the declared baseline",
        ),
        confirmation_criteria=(
            "CausalGuard structural-differential confirmation (recorded "
            "baseline deviation as the class signal) -> bundle -> "
            "replay; advisory severity, never auto-promoted"),
        failure_classifications=(
            "observation_unparseable", "experiment_inconclusive",
        ),
        implementation_status=IMPLEMENTED,
        evidence_pointer=(
            "agents/validator/structural_checks.py (header/method/"
            "transport classes)"),
    ),
    "sensitive_information_disclosure": FamilySecurityProfile(
        family="sensitive_information_disclosure",
        relevant_entities=("endpoint", "observation", "identity"),
        security_invariants=(
            "responses expose only data authorized for the requesting "
            "principal",
        ),
        hypothesis_templates=(
            "an endpoint may disclose data beyond the requesting "
            "principal's authorization",
        ),
        required_preconditions=(
            "an authenticated endpoint whose response contains "
            "principal-scoped data",
            "a second principal to compare against",
        ),
        safe_experiment_strategy=(
            "read-only authenticated comparison; no data extraction "
            "beyond the minimal discriminating fields"),
        expected_observations=(
            "foreign-principal response containing owner-scoped fields",
        ),
        negative_controls=(
            "the same endpoint for the owner shows the fields "
            "legitimately; anonymous is refused",
        ),
        evidence_requirements=(
            "per-principal response digests + field-level disclosure "
            "record",
        ),
        confirmation_criteria=(
            "CausalGuard content-differential CONFIRMED (disclosure "
            "signal isolated from control) -> bundle -> replay"),
        failure_classifications=(
            "experiment_inconclusive", "observation_unparseable",
        ),
        implementation_status=IMPLEMENTED,
        evidence_pointer=(
            "agents/validator/active_checks.py disclosure classes + "
            "api_testing agent (field-level checks)"),
    ),
}


def families_for_entity(entity_kind: str) -> list[str]:
    """Which families reason about a given appmodel entity kind."""
    return sorted(
        name for name, profile in FAMILY_PROFILES.items()
        if entity_kind in profile.relevant_entities
    )


def profiles_by_status(status: str) -> list[str]:
    return sorted(
        name for name, profile in FAMILY_PROFILES.items()
        if profile.implementation_status == status
    )
