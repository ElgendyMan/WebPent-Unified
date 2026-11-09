# src/webpent/causal_reasoning/root_cause_analyzer.py
"""RootCauseAnalyzer — Proposal #1, Component 3.

Given the full set of confirmed findings (and their CausalHypotheses from
ArchitectureInferrer), cluster findings by *architectural root cause* — not
by vuln class.  Two IDOR findings on different endpoints may share one root
cause (broken object-resolver scope); an IDOR and an auth_bypass may share
another (auth-check-after-mutation).  The analyzer exposes this so one fix
addresses many findings, and so the search can target the UNCONFIRMED
sibling paths of each root cause.

This module is read-only and deterministic.  It never promotes a hypothesis
to a finding; it only groups and enumerates.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from webpent.causal_reasoning.architecture_inferrer import ArchitectureInferrer
from webpent.causal_reasoning.contracts import (
    InferenceResult,
    RootCauseCluster,
    WeaknessCategory,
    route_to_glob,
    stable_id,
)

_REMEDIATION_HINTS: dict[WeaknessCategory, str] = {
    WeaknessCategory.DIRECT_OBJECT_REFERENCE_WITHOUT_SCOPE:
        "Introduce a shared object-resolver that scopes every lookup to the "
        "caller's identity/tenant. Fix in the resolver once; all sibling "
        "endpoints inherit it. Add an integration test asserting cross-identity "
        "access is denied for every object-id endpoint.",
    WeaknessCategory.AUTH_CHECK_AFTER_MUTATION:
        "Move authentication/authorisation checks into middleware that runs "
        "before any handler mutation, or enforce via a decorator ordering test. "
        "Audit every handler using the same pattern for ordering defects.",
    WeaknessCategory.BROKEN_ACCESS_CONTROL_LAYER:
        "Replace the broken shared ACL layer with a policy engine (e.g. "
        "relationship-based access control) and enforce it at the data-access "
        "layer, not the route layer. Re-run full role matrix on all protected "
        "endpoints after the fix.",
    WeaknessCategory.MASS_ASSIGNMENT_UNBOUND_FIELDS:
        "Adopt explicit field allow-lists (DTOs / serializers) for every write "
        "endpoint binding a domain model. Reject unknown fields by default at "
        "the framework binder level.",
    WeaknessCategory.INCONSISTENT_INPUT_SANITISATION:
        "Centralise input validation and output encoding in a shared layer; "
        "remove per-route ad-hoc sanitisation. Parameterise all queries; "
        "enable auto-escaping in every render layer.",
    WeaknessCategory.TRUSTED_CLIENT_SIDE_CONTROL:
        "Never trust client-supplied URLs/hosts for server-side fetch. Enforce "
        "an allow-list of destinations and block private-IP ranges at the fetch "
        "helper. Remove the fetch helper from any endpoint that does not need it.",
    WeaknessCategory.WEAK_OR_MISSING_AUTHN_POLICY:
        "Fix the JWT/session verifier configuration globally: pin the algorithm, "
        "rotate/strengthen the secret, enforce expiry and issuer/audience. One "
        "config change remediates every authenticated endpoint.",
    WeaknessCategory.ERROR_HANDLING_LEAKS_INTERNALS:
        "Replace the global error handler with one that returns generic messages "
        "to clients and logs details server-side only. Map all exception paths "
        "to the generic handler.",
    WeaknessCategory.SESSION_FIXATION_OR_WEAK_BINDING:
        "Rotate the session identifier on every privilege-state change (login, "
        "role change, password reset). Bind session to user-agent/IP where "
        "acceptable and enforce re-auth for sensitive actions.",
    WeaknessCategory.MISSING_SHARED_VALIDATION:
        "Introduce a shared schema-validation layer (e.g. OpenAPI contract "
        "validation middleware) applied to every endpoint. Reject non-conforming "
        "requests at the edge.",
    WeaknessCategory.CORS_MISCONFIGURATION_WILDCARD:
        "Replace wildcard/origin-reflection with an explicit allow-list of "
        "trusted origins, and never echo credentials with arbitrary origins. "
        "Apply at the middleware layer so all endpoints inherit it.",
    WeaknessCategory.UNPATCHED_FRAMEWORK_PATTERN:
        "Upgrade the affected framework/component to a patched version and pin "
        "it. Re-scan the dependency tree for transitive uses of the vulnerable "
        "component.",
}


@dataclass
class RootCauseAnalyzer:
    """Clusters findings by inferred root cause and enumerates siblings."""

    inferrer: ArchitectureInferrer | None = None
    min_cluster_confidence: float = 0.4

    def __post_init__(self) -> None:
        if self.inferrer is None:
            self.inferrer = ArchitectureInferrer()

    def analyze(
        self,
        findings: Iterable[Mapping[str, Any]],
        knowledge_entities: Mapping[str, Mapping[str, Any]] | None = None,
        knowledge_relations: Iterable[Mapping[str, Any]] | None = None,
    ) -> tuple[RootCauseCluster, ...]:
        """Run causal inference on every finding, then cluster by root cause.

        Returns clusters sorted by (member_count * confidence) desc.  Each
        cluster carries the predicted sibling paths (union of all
        AtRiskRegion canonical_keys from member findings) — these are the
        paths to probe next, and the remediation hint is the "fix once"
        guidance.
        """
        findings_list = list(findings)
        if not findings_list:
            return ()

        # 1. Ingest every finding through the inferrer.
        inference_by_finding: dict[str, InferenceResult] = {}
        for f in findings_list:
            fid = str(f.get("id") or f.get("finding_id") or "unknown")[:200]
            inference_by_finding[fid] = self.inferrer.ingest_finding(
                f,
                knowledge_entities=knowledge_entities,
                knowledge_relations=knowledge_relations,
                existing_findings=findings_list,
            )

        # 2. Cluster by weakness_category.  A finding may belong to multiple
        #    clusters if multiple hypotheses fired — we assign it to the
        #    highest-confidence hypothesis only (single root cause per finding).
        cluster_members: dict[str, list[str]] = defaultdict(list)
        cluster_conf: dict[str, float] = defaultdict(float)
        cluster_siblings: dict[str, set[str]] = defaultdict(set)

        for fid, inf in inference_by_finding.items():
            if not inf.hypotheses:
                continue
            best = max(inf.hypotheses, key=lambda h: h.confidence)
            if best.confidence < self.min_cluster_confidence:
                # Still record under UNKNOWN so nothing is silently dropped.
                key = WeaknessCategory.UNKNOWN.value
            else:
                key = best.weakness_category.value
            cluster_members[key].append(fid)
            cluster_conf[key] = max(cluster_conf[key], best.confidence)
            for region in inf.at_risk_regions:
                if not region.already_covered:
                    cluster_siblings[key].add(region.canonical_key)

        # 3. Build cluster objects.
        clusters: list[RootCauseCluster] = []
        for key, members in cluster_members.items():
            try:
                weak = WeaknessCategory(key)
            except ValueError:
                weak = WeaknessCategory.UNKNOWN
            siblings = tuple(sorted(cluster_siblings.get(key, set())))[:512]
            clusters.append(RootCauseCluster(
                cluster_id=stable_id("rcc", key, *sorted(members)[:8]),
                weakness_category=weak,
                member_finding_ids=tuple(sorted(members)),
                sibling_paths_predicted=siblings,
                confidence=round(cluster_conf.get(key, 0.0), 4),
                remediation_hint=_REMEDIATION_HINTS.get(weak, "")[:600],
            ))

        clusters.sort(key=lambda c: (c.size * c.confidence), reverse=True)
        return tuple(clusters)

    def root_cause_for_finding(
        self,
        finding: Mapping[str, Any],
        all_findings: Iterable[Mapping[str, Any]] | None = None,
        knowledge_entities: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> RootCauseCluster | None:
        """Convenience: return the root-cause cluster for a single finding."""
        all_findings = list(all_findings or [finding])
        if finding not in all_findings:
            all_findings = [finding, *all_findings]
        clusters = self.analyze(all_findings, knowledge_entities=knowledge_entities)
        fid = str(finding.get("id") or finding.get("finding_id") or "")[:200]
        for c in clusters:
            if fid in c.member_finding_ids:
                return c
        return None


__all__ = ["RootCauseAnalyzer"]
