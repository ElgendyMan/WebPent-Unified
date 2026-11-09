# src/webpent/causal_reasoning/architecture_inferrer.py
"""ArchitectureInferrer — Proposal #1, Component 1.

Given one confirmed finding and the current target knowledge projection
(TargetKnowledgeV2), infer the *architectural weakness* that caused it and
propagate that weakness across the knowledge graph to enumerate sibling
regions likely vulnerable for the same reason.

This is a deterministic, rule-based causal engine — no LLM calls, no
network, no execution authority.  Every inference carries a confidence and
a rationale string; downstream agents decide whether to act on it.

Design notes
------------
* The causal rule table maps (vuln_class, context_signals) -> weakness
  category with a base confidence.  Rules are additive; adding a rule
  never changes existing inferences.
* Propagation walks the knowledge graph: for the inferred weakness, find
  all entities of the relevant kinds that share the discriminating
  attribute (e.g. same role, same data-flow, same security-control gap),
  and emit them as AtRiskRegion.
* Regions already covered (a finding already exists there) are flagged
  `already_covered=True` and down-weighted, so the engine pushes the
  search toward UNCOVERED siblings — the core value of the proposal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from webpent.causal_reasoning.contracts import (
    AtRiskRegion,
    CausalHypothesis,
    InferenceLifecycle,
    InferenceResult,
    WeaknessCategory,
    route_to_glob,
    stable_id,
)

# Severity proxy per vuln class bucket — used only to prioritise, never as
# ground truth.  Bounded [0.2, 1.0].
_SEVERITY_PROXY: dict[str, float] = {
    "rce": 1.0, "sqli": 0.95, "ssrf": 0.9, "deserialization": 0.9,
    "command_injection": 0.95, "xxe": 0.85, "lfi": 0.8, "rfi": 0.8,
    "ssti": 0.9, "idor": 0.85, "auth_bypass": 0.95, "jwt_key_confusion": 0.9,
    "mass_assignment": 0.75, "privilege_escalation": 0.9, "csrf": 0.6,
    "xss": 0.65, "open_redirect": 0.4, "info_disclosure": 0.45,
    "path_traversal": 0.75, "nosql_injection": 0.9, "race_condition": 0.7,
    "request_smuggling": 0.8, "weak_session": 0.7, "jwt_weakness": 0.7,
    "csp": 0.3, "captcha": 0.3, "brute_force": 0.5, "javascript": 0.4,
    "cryptography": 0.7, "api_issue": 0.5, "subdomain_takeover": 0.8,
    "cloud_storage_exposure": 0.85, "unknown": 0.5,
}


@dataclass(frozen=True)
class CausalRule:
    """One (vuln_class -> weakness) mapping with discriminating attributes.

    sibling_kinds: entity kinds in the knowledge graph that share this
        weakness pattern (e.g. ENDPOINT + PARAMETER for missing validation).
    discriminating_attr: metadata key whose equal value implies shared
        weakness (e.g. "auth_policy", "validation_layer", "role_scope").
        If None, all entities of sibling_kinds are considered siblings.
    base_confidence: prior confidence of the causal link.
    """

    vuln_class: str
    weakness_category: WeaknessCategory
    rationale: str
    sibling_kinds: tuple[str, ...]
    discriminating_attr: str | None = None
    base_confidence: float = 0.6


# The causal rule table.  Order matters only for tie-breaking; rules are
# evaluated independently and a finding may fire several hypotheses.
CAUSAL_RULES: tuple[CausalRule, ...] = (
    CausalRule(
        vuln_class="idor",
        weakness_category=WeaknessCategory.DIRECT_OBJECT_REFERENCE_WITHOUT_SCOPE,
        rationale=(
            "IDOR at one endpoint indicates object references are resolved "
            "without scoping to the caller's identity.  Every endpoint that "
            "accepts an object identifier and shares the same resolver/role "
            "scope is at risk for the same architectural cause."
        ),
        sibling_kinds=("endpoint", "parameter", "data_flow"),
        discriminating_attr="object_resolver",
        base_confidence=0.75,
    ),
    CausalRule(
        vuln_class="auth_bypass",
        weakness_category=WeaknessCategory.AUTH_CHECK_AFTER_MUTATION,
        rationale=(
            "Auth bypass where the check occurs after data mutation means the "
            "request handler ordering is wrong.  Any route using the same "
            "handler pattern / middleware ordering shares the defect."
        ),
        sibling_kinds=("endpoint", "workflow"),
        discriminating_attr="handler_pattern",
        base_confidence=0.7,
    ),
    CausalRule(
        vuln_class="privilege_escalation",
        weakness_category=WeaknessCategory.BROKEN_ACCESS_CONTROL_LAYER,
        rationale=(
            "Privilege escalation indicates the shared access-control layer "
            "fails to enforce role boundaries.  All role-protected endpoints "
            "relying on that same layer are suspect."
        ),
        sibling_kinds=("endpoint", "role", "permission"),
        discriminating_attr="acl_layer",
        base_confidence=0.8,
    ),
    CausalRule(
        vuln_class="mass_assignment",
        weakness_category=WeaknessCategory.MASS_ASSIGNMENT_UNBOUND_FIELDS,
        rationale=(
            "Mass assignment means the binder accepts fields without an "
            "allow-list.  Every endpoint binding the same resource/model "
            "without a field allow-list shares the defect."
        ),
        sibling_kinds=("endpoint", "parameter", "resource"),
        discriminating_attr="bound_model",
        base_confidence=0.7,
    ),
    CausalRule(
        vuln_class="sqli",
        weakness_category=WeaknessCategory.INCONSISTENT_INPUT_SANITISATION,
        rationale=(
            "SQL injection at one parameter indicates query construction is "
            "string-concatenated rather than parameterised.  Parameters on "
            "endpoints sharing the same data-access pattern / ORM bypass are "
            "at risk."
        ),
        sibling_kinds=("parameter", "endpoint", "data_flow"),
        discriminating_attr="data_access_pattern",
        base_confidence=0.65,
    ),
    CausalRule(
        vuln_class="xss",
        weakness_category=WeaknessCategory.INCONSISTENT_INPUT_SANITISATION,
        rationale=(
            "XSS indicates output encoding is applied inconsistently across "
            "rendering paths.  Parameters reflected on endpoints sharing the "
            "same rendering/template layer are at risk."
        ),
        sibling_kinds=("parameter", "endpoint"),
        discriminating_attr="render_layer",
        base_confidence=0.6,
    ),
    CausalRule(
        vuln_class="ssrf",
        weakness_category=WeaknessCategory.TRUSTED_CLIENT_SIDE_CONTROL,
        rationale=(
            "SSRF indicates the server fetches a user-supplied URL without a "
            "fetch allow-list.  Any endpoint accepting a URL/host parameter "
            "and sharing the same fetch helper is at risk."
        ),
        sibling_kinds=("parameter", "endpoint"),
        discriminating_attr="fetch_helper",
        base_confidence=0.7,
    ),
    CausalRule(
        vuln_class="info_disclosure",
        weakness_category=WeaknessCategory.ERROR_HANDLING_LEAKS_INTERNALS,
        rationale=(
            "Verbose error disclosure indicates the global error handler leaks "
            "internals.  Every route sharing the same error-handling middleware "
            "will leak similarly under failure conditions."
        ),
        sibling_kinds=("endpoint", "service"),
        discriminating_attr="error_handler",
        base_confidence=0.8,
    ),
    CausalRule(
        vuln_class="jwt_weakness",
        weakness_category=WeaknessCategory.WEAK_OR_MISSING_AUTHN_POLICY,
        rationale=(
            "JWT weakness indicates the authentication policy is misconfigured "
            "globally (alg=none, weak secret, no expiry).  Every endpoint "
            "relying on the same JWT verification helper shares the policy."
        ),
        sibling_kinds=("endpoint", "security_control"),
        discriminating_attr="jwt_verifier",
        base_confidence=0.85,
    ),
    CausalRule(
        vuln_class="jwt_key_confusion",
        weakness_category=WeaknessCategory.WEAK_OR_MISSING_AUTHN_POLICY,
        rationale=(
            "JWT key confusion is a global verifier defect; every endpoint "
            "authenticated by the same verifier is bypassable."
        ),
        sibling_kinds=("endpoint", "security_control"),
        discriminating_attr="jwt_verifier",
        base_confidence=0.9,
    ),
    CausalRule(
        vuln_class="weak_session",
        weakness_category=WeaknessCategory.SESSION_FIXATION_OR_WEAK_BINDING,
        rationale=(
            "Weak session binding indicates the session manager does not "
            "rotate/rebind on privilege change.  All auth-state-changing "
            "workflows share the defect."
        ),
        sibling_kinds=("endpoint", "workflow", "security_control"),
        discriminating_attr="session_manager",
        base_confidence=0.75,
    ),
    CausalRule(
        vuln_class="api_issue",
        weakness_category=WeaknessCategory.MISSING_SHARED_VALIDATION,
        rationale=(
            "API-level validation defect indicates a shared validation layer "
            "is absent or bypassed.  Endpoints on the same API surface without "
            "a shared validator are at risk."
        ),
        sibling_kinds=("endpoint", "parameter"),
        discriminating_attr="validation_layer",
        base_confidence=0.6,
    ),
)


def _rules_for(vuln_class: str) -> list[CausalRule]:
    vc = str(vuln_class or "").strip().lower()
    return [r for r in CAUSAL_RULES if r.vuln_class == vc]


def _severity_proxy(vuln_class: str) -> float:
    return _SEVERITY_PROXY.get(str(vuln_class or "").strip().lower(), 0.5)


def _covered_keys(findings: Iterable[Mapping[str, Any]] | None) -> set[str]:
    """Build a set of canonical route+param keys already covered by findings."""
    covered: set[str] = set()
    if not findings:
        return covered
    for f in findings:
        route = str(f.get("route") or f.get("url") or "")
        param = str(f.get("target_param") or "")
        glob = route_to_glob(route)
        covered.add(f"{glob}|{param.lower()}")
        covered.add(glob)
    return covered


@dataclass
class ArchitectureInferrer:
    """Stateless inferrer; holds only tunable weights.

    Usage:
        result = ArchitectureInferrer().ingest_finding(
            finding_dict, knowledge_v2_entities, existing_findings,
        )
    """

    # Weight of coverage-gap bonus: uncovered regions get this multiplier.
    coverage_gap_weight: float = 1.5
    # Cap on sibling regions per hypothesis (safety bound).
    max_regions_per_hypothesis: int = 60

    def ingest_finding(
        self,
        finding: Mapping[str, Any],
        knowledge_entities: Mapping[str, Mapping[str, Any]] | None = None,
        knowledge_relations: Iterable[Mapping[str, Any]] | None = None,
        existing_findings: Iterable[Mapping[str, Any]] | None = None,
    ) -> InferenceResult:
        """Ingest one finding and return hypotheses + at-risk regions.

        finding: a dict shaped like webpent.models.findings.Finding (or its
            model_dump).  Only vuln_class, url/route, target_param, id,
            severity, description are read.
        knowledge_entities: {entity_id: {kind, canonical_key, metadata, ...}}
            from TargetKnowledgeV2.entities.  Optional; with no graph the
            engine still emits hypotheses and a single self-region.
        existing_findings: list of finding dicts already confirmed, used to
            mark covered regions and down-weight them.
        """
        finding_id = str(finding.get("id") or finding.get("finding_id") or "unknown")[:200]
        vuln_class = str(finding.get("vuln_class") or "unknown").strip().lower()
        route = str(finding.get("route") or finding.get("url") or "")
        param = str(finding.get("target_param") or "")
        severity_proxy = _severity_proxy(vuln_class)
        covered = _covered_keys(existing_findings)

        rules = _rules_for(vuln_class)
        if not rules:
            # Unknown class — emit a low-confidence generic hypothesis so the
            # engine never silently drops a finding, but no propagation.
            hyp = CausalHypothesis(
                hypothesis_id=stable_id("hyp", finding_id, WeaknessCategory.UNKNOWN.value),
                source_finding_id=finding_id,
                weakness_category=WeaknessCategory.UNKNOWN,
                rationale=(
                    "No causal rule registered for vuln_class="
                    f"{vuln_class!r}; recorded without propagation."
                ),
                confidence=0.1,
                predicted_sibling_count=0,
            )
            return InferenceResult(
                source_finding_id=finding_id,
                hypotheses=(hyp,),
                at_risk_regions=(),
            )

        hypotheses: list[CausalHypothesis] = []
        regions: dict[str, AtRiskRegion] = {}

        for rule in rules:
            hyp_id = stable_id("hyp", finding_id, rule.weakness_category.value)
            siblings = self._collect_siblings(
                rule=rule,
                finding_route=route,
                finding_param=param,
                knowledge_entities=knowledge_entities or {},
                knowledge_relations=knowledge_relations or (),
            )
            hyp = CausalHypothesis(
                hypothesis_id=hyp_id,
                source_finding_id=finding_id,
                weakness_category=rule.weakness_category,
                rationale=rule.rationale,
                confidence=rule.base_confidence,
                predicted_sibling_count=len(siblings),
                evidence_refs=(finding_id,),
                metadata={"vuln_class": vuln_class, "rule_vuln_class": rule.vuln_class},
            )
            hypotheses.append(hyp)

            for sib in siblings[: self.max_regions_per_hypothesis]:
                region_id = sib["region_id"]
                key = sib["match_key"]
                is_covered = key in covered or sib["canonical_key"] in covered
                # priority = confidence * severity_proxy, with coverage gap
                # bonus for uncovered regions (the engine's core value).
                priority = hyp.confidence * severity_proxy
                if not is_covered:
                    priority = min(1.0, priority * self.coverage_gap_weight)
                existing = regions.get(region_id)
                if existing is None or priority > existing.priority_score:
                    supporting = tuple(
                        dict.fromkeys(list(existing.supporting_hypothesis_ids if existing else ()) + [hyp_id])
                    )
                    regions[region_id] = AtRiskRegion(
                        region_id=region_id,
                        kind=sib["kind"],
                        canonical_key=sib["canonical_key"],
                        supporting_hypothesis_ids=supporting,
                        priority_score=round(priority, 4),
                        rationale=(
                            f"Shares weakness {rule.weakness_category.value} "
                            f"with finding {finding_id[:16]}… via "
                            f"{rule.discriminating_attr or 'same-kind'}."
                        ),
                        already_covered=is_covered,
                    )

        return InferenceResult(
            source_finding_id=finding_id,
            hypotheses=tuple(hypotheses),
            at_risk_regions=tuple(regions.values()),
        )

    # ------------------------------------------------------------------
    # Internal: sibling collection over the knowledge graph
    # ------------------------------------------------------------------
    def _collect_siblings(
        self,
        *,
        rule: CausalRule,
        finding_route: str,
        finding_param: str,
        knowledge_entities: Mapping[str, Mapping[str, Any]],
        knowledge_relations: Iterable[Mapping[str, Any]],
    ) -> list[dict[str, str]]:
        """Return sibling region dicts sharing the rule's weakness pattern.

        With a discriminating_attr, siblings = entities whose metadata[attr]
        equals the finding entity's value.  Without it, siblings = all
        entities of the rule's sibling_kinds (bounded).  Always includes the
        finding's own route glob so the self-region is represented.
        """
        siblings: list[dict[str, str]] = []
        seen: set[str] = set()

        # Always include the finding's own route glob (self reference).
        self_glob = route_to_glob(finding_route)
        self_key = f"{self_glob}|{finding_param.lower()}"
        self_region = {
            "region_id": stable_id("region", "self", self_glob, finding_param),
            "kind": "endpoint",
            "canonical_key": self_glob,
            "match_key": self_key,
        }
        siblings.append(self_region)
        seen.add(self_region["region_id"])

        if not knowledge_entities:
            return siblings

        # Find the finding's own entity to extract the discriminating value.
        discrim_value: str | None = None
        if rule.discriminating_attr:
            for ent in knowledge_entities.values():
                meta = ent.get("metadata") or {}
                canon = str(ent.get("canonical_key") or "")
                if canon and (canon in finding_route or finding_route.endswith(canon)):
                    val = meta.get(rule.discriminating_attr)
                    if val is not None:
                        discrim_value = str(val)[:120]
                        break

        for ent_id, ent in knowledge_entities.items():
            kind = str(ent.get("kind") or "").strip().lower()
            if kind not in {k.lower() for k in rule.sibling_kinds}:
                continue
            canon = str(ent.get("canonical_key") or ent_id)[:320]
            if not canon:
                continue
            meta = ent.get("metadata") or {}
            if rule.discriminating_attr and discrim_value is not None:
                ent_val = meta.get(rule.discriminating_attr)
                if ent_val is None or str(ent_val)[:120] != discrim_value:
                    # If the finding entity didn't reveal a value, fall back
                    # to same-kind propagation (weaker, but still useful).
                    continue
            glob = route_to_glob(canon if "/" in canon else f"/{canon}")
            match_key = f"{glob}|{finding_param.lower()}"
            region_id = stable_id("region", kind, glob, rule.weakness_category.value)
            if region_id in seen:
                continue
            seen.add(region_id)
            siblings.append({
                "region_id": region_id,
                "kind": kind,
                "canonical_key": glob,
                "match_key": match_key,
            })

        return siblings


__all__ = ["ArchitectureInferrer", "CausalRule", "CAUSAL_RULES"]
