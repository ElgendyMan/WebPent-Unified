# src/webpent/models/findings.py
"""webpent.models.findings

Finding model for the WebPent Framework V3.5.

A ``Finding`` represents a single security observation produced by any
agent or tool during an engagement. Findings are aggregated by the
orchestrator and rendered into the final report.

V3.5 Changes:
  * Added :class:`VulnClass` enum to eliminate reliance on string matching
    within titles/descriptions for routing and classification.
  * Added ``vuln_class`` field to the :class:`Finding` model.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Severity(str, Enum):
    """CVSS-aligned severity buckets (low -> critical)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Confidence in the finding's validity (mitigates false positives)."""

    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"


class VulnClass(str, Enum):
    """Vulnerability categories used for deterministic routing.

    Replaces fragile keyword-based matching on finding titles/descriptions.
    Each finding is classified into one of these categories at creation
    time, enabling the graph router and validator to dispatch to the
    correct tool without string parsing.
    """

    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    RCE = "rce"
    SSTI = "ssti"
    OPEN_REDIRECT = "open_redirect"
    XXE = "xxe"
    CSRF = "csrf"
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    NOSQL_INJECTION = "nosql_injection"
    INFO_DISCLOSURE = "info_disclosure"
    # V9 P1 FIX: business_logic_fuzzer_node has always constructed
    # Finding(vuln_class="race_condition", ...) when it detects >1
    # concurrent 2xx in a burst, but no matching enum member existed —
    # every such Finding() call raised a pydantic ValidationError. This
    # was effectively dormant (the burst-thread Context-reentrancy bug
    # meant >1 concurrent success almost never happened in practice);
    # fixing that bug makes race-condition detection actually reachable,
    # which surfaced this. Deliberately NOT added to EXPLOITABLE_CLASSES
    # in this file — race conditions are confirmed by the burst
    # mechanism itself, not by payload injection, so they should not be
    # routed into the payload_generator/validator exploit pipeline.
    RACE_CONDITION = "race_condition"
    # V10 P0-1 (RCA follow-up): new members required so that
    # access_control/agent.py, api_testing/agent.py, request_smuggling
    # /agent.py, business_logic_fuzzer/agent.py and the new P1
    # detectors (csp/weak_session/javascript/auth_bypass/cryptography/
    # captcha/brute_force) can construct Finding objects without raising
    # pydantic ValidationError. Previously these call sites passed raw
    # strings ("idor", "auth_bypass", "mass_assignment",
    # "request_smuggling") that were silently swallowed by the outer
    # try/except in their parent nodes — real detections were lost.
    # mass_assignment is intentionally NOT routed into the
    # payload_generator (it is structural, not payload-injection
    # exploitable), so it lives outside EXPLOITABLE_CLASSES.
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    MASS_ASSIGNMENT = "mass_assignment"
    REQUEST_SMUGGLING = "request_smuggling"
    BRUTE_FORCE = "brute_force"
    CAPTCHA = "captcha"
    WEAK_SESSION = "weak_session"
    CSP = "csp"
    JAVASCRIPT = "javascript"
    CRYPTOGRAPHY = "cryptography"
    API_ISSUE = "api_issue"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    CLOUD_STORAGE_EXPOSURE = "cloud_storage_exposure"
    JWT_WEAKNESS = "jwt_weakness"
    JWT_KEY_CONFUSION = "jwt_key_confusion"
    # Validator coverage engine (Phase 6): the registry and dispatch
    # already route these two classes, but the enum could not represent
    # them — no producer (or test) could construct a Finding of these
    # classes without a pydantic ValidationError. Added so the classes
    # are first-class citizens end to end.
    ELASTICSEARCH_SNAPSHOT_TRAVERSAL = "elasticsearch_snapshot_traversal"
    XSLT_INJECTION = "xslt_injection"
    # ------------------------------------------------------------------
    # ULTIMATE PLAN 2026-10-27, proposal 1/7. Two member groups, both
    # additive (no existing value changes → no backward-compat break):
    #
    # (a) The five donorC family classes. The family framework
    #     (families/, agents/validator/family_checks.py,
    #     families/promotion.py) already validates and promotes these
    #     classes, but the merged l6 findings.py carried no enum
    #     members for them — every promotion silently fell back to
    #     VulnClass.UNKNOWN and the registry reported
    #     missing-validator. This was the documented donorC-lineage gap
    #     (MERGE_20261026.md §6, test_five_families); adding the
    #     members closes it end to end.
    #
    # (b) The new deterministic detector classes (proposal 7): GraphQL
    #     (4), cache poisoning, web cache deception, prototype
    #     pollution, OAuth/SSO misconfiguration. Produced by the new
    #     detector nodes (graph/detector_nodes.py) and validators
    #     (validators/). None are payload-injection exploitable, so
    #     none join EXPLOITABLE_CLASSES — same posture as the
    #     structural classes above.
    # ------------------------------------------------------------------
    BUSINESS_LOGIC = "business_logic"
    MULTI_STEP_AUTH_BYPASS = "multi_step_auth_bypass"
    TENANT_ISOLATION = "tenant_isolation"
    EXPLOIT_CHAIN = "exploit_chain"
    OAUTH = "oauth"
    GRAPHQL_INTROSPECTION_EXPOSURE = "graphql_introspection_exposure"
    GRAPHQL_BATCHING_ABUSE = "graphql_batching_abuse"
    GRAPHQL_FIELD_SUGGESTION_LEAK = "graphql_field_suggestion_leak"
    GRAPHQL_DEPTH_COMPLEXITY_DOS = "graphql_depth_complexity_dos"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    OAUTH_MISCONFIGURATION = "oauth_misconfiguration"
    CACHE_POISONING = "cache_poisoning"
    WEB_CACHE_DECEPTION = "web_cache_deception"
    # UM-DR-25 (red-team window 2026-11-06): the blind OOB families
    # (production/oob_validator.py — BLIND_SSRF / XXE_OOB /
    # BLIND_SQLI) were merged with validators, dispatch registration
    # and tests, but the enum carried no members for them — Findings
    # of these classes could not be constructed, and the
    # never-exploitable contract could not even be asserted.
    # Confirmation is callback-differential (the collaborator's token
    # match inside the evidence window), never payload-injection
    # exploitation, so — like the structural families above — they
    # stay OUTSIDE EXPLOITABLE_CLASSES.
    BLIND_SSRF = "blind_ssrf"
    XXE_OOB = "xxe_oob"
    BLIND_SQLI = "blind_sqli"
    # UM-DR-25: the session-pool privilege-differential family —
    # cross-principal access confirmed by an observed behavioral
    # differential (production/privilege_validator.py). Structural,
    # not payload-injection exploitable: outside EXPLOITABLE_CLASSES
    # like the blind families above.
    PRIVILEGE_DIFFERENTIAL = "privilege_differential"
    UNKNOWN = "unknown"


# V3.5 Obsidian Master: Centralized exploitable classes frozenset.
# Imported by graph/builder.py, payload_generator/agent.py, and
# payload_optimizer/agent.py to eliminate DRY violation.
EXPLOITABLE_CLASSES: frozenset[str] = frozenset(
    {
        VulnClass.XSS.value,
        VulnClass.SQLI.value,
        VulnClass.SSRF.value,
        VulnClass.LFI.value,
        VulnClass.RFI.value,
        VulnClass.RCE.value,
        VulnClass.SSTI.value,
        VulnClass.OPEN_REDIRECT.value,
        VulnClass.COMMAND_INJECTION.value,
        VulnClass.NOSQL_INJECTION.value,
        VulnClass.CSRF.value,
        VulnClass.DESERIALIZATION.value,
        VulnClass.XXE.value,
        VulnClass.PATH_TRAVERSAL.value,
    }
)


class Finding(BaseModel):
    """A single security finding.

    Attributes:
        id: Stable UUID for cross-referencing across agents and reports.
        title: Short human-readable summary (<=120 chars).
        severity: CVSS-aligned severity bucket.
        description: Detailed description, including impact and context.
        tool_name: Name of the producing agent or external tool.
        payload: The exact payload, request body, or query string used.
        url: Affected URL (including query string if applicable).
        confidence: How sure the producing tool is (default: ``tentative``).
        evidence: Free-form structured evidence (e.g. raw HTTP exchange).
        references: Links to CWE/CVE/OWASP entries.
        created_at: UTC timestamp of creation.
        cvss_score: CVSS v3.1 vector string and/or numeric score.
        business_impact: 1–2 sentence business impact statement.
        vuln_class: Deterministic vulnerability category used for routing.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    id: UUID = Field(
        default_factory=uuid4,
        description="Stable identifier for cross-referencing.",
    )
    title: str = Field(
        ...,
        min_length=3,
        max_length=120,
        description="Short human-readable summary.",
    )
    severity: Severity = Field(
        ...,
        description="CVSS-aligned severity bucket.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Detailed description, impact, and context.",
    )
    tool_name: str = Field(
        ...,
        min_length=1,
        description="Name of the producing agent or external tool.",
    )
    payload: str | None = Field(
        default=None,
        description="Exact payload, request body, or query string used.",
    )
    # Optional structured request context copied from a discovered form.
    # Values are bounded/redacted upstream and are used only by separately
    # gated validators; legacy findings remain endpoint-only.
    request_method: str = Field(
        default="GET",
        min_length=3,
        max_length=10,
        description="HTTP method used by the validator request.",
    )
    request_data: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Redacted form or JSON fields used to build a validator request; "
            "nested JSON values are allowed for transport-compatible replays."
        ),
    )
    target_param: str | None = Field(
        default=None,
        max_length=200,
        description="Parameter selected for targeted validation, when known.",
    )
    url: str = Field(
        ...,
        description="Affected URL (including query string if applicable).",
    )
    campaign_id: str | None = Field(
        default=None,
        max_length=160,
        description="Optional redacted campaign identifier for lifecycle notifications.",
    )
    route: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional affected route projection for lifecycle notifications.",
    )
    confidence: Confidence = Field(
        default=Confidence.TENTATIVE,
        description="Confidence in the finding's validity.",
    )
    evidence: dict[str, Any] | None = Field(
        default=None,
        description="Structured evidence (raw HTTP, screenshots, etc.).",
    )
    references: list[str] = Field(
        default_factory=list,
        description="Links to CWE/CVE/OWASP entries.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of finding creation.",
    )
    cvss_score: str | None = Field(
        default=None,
        description=(
            "CVSS v3.1 vector string and/or numeric score, populated "
            "by the CVSS engine agent for confirmed findings."
        ),
    )
    business_impact: str | None = Field(
        default=None,
        description=(
            "1-2 sentence business impact statement, populated by the "
            "business-impact agent for confirmed findings."
        ),
    )
    vuln_class: VulnClass = Field(
        default=VulnClass.UNKNOWN,
        description=(
            "Deterministic vulnerability category used for routing and "
            "validator dispatch. Eliminates reliance on keyword matching."
        ),
    )
    confidence_level: str = Field(
        default="Pending",
        description=(
            "V4.5 PoC-or-GTFO tier: 'Tool-Confirmed' (verified by a "
            "deterministic tool), 'AI-Assessed' (no tool available, "
            "LLM evaluation only), 'Needs Human Review' (V5 Sprint 9: "
            "result is ambiguous due to environmental limitations such "
            "as SPA-only rendering or SameSite cookie presence — a "
            "human must verify before acting on the finding), or "
            "'Pending' (not yet validated)."
        ),
    )
    reasoning: str = Field(
        default="",
        description=(
            "V5 Audit Trail: Brief LLM justification for scores, "
            "assessments, or classifications. Provides an audit trail "
            "for AI-driven decisions."
        ),
    )
    oob_token: str = Field(
        default_factory=lambda: secrets.token_hex(16),
        description=(
            "V5 Sprint 8: Per-finding random token used to authenticate "
            "OOB callbacks. Replaces the global shared secret, which "
            "allowed a malicious target to spoof callbacks for unrelated "
            "findings. Defaults to a securely generated 32-char hex "
            "string at creation time."
        ),
    )
    advisory_evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "R3 E-1 (Ruling R3-002, amendment B): ADDITIVE, OPTIONAL, "
            "default-empty, AUTHORITY-NEUTRAL out-of-band advisory "
            "evidence records. Appended by the OOB callback path "
            "deduplicated per correlation token; this field NEVER "
            "influences confidence, confidence_level, promotion, or "
            "sealing decisions, and is never surfaced as confirmation "
            "semantics by any consumer. It exists so correlated OOB "
            "observations remain visible as advisory context without "
            "re-opening the BYP-02 confirmation bypass."
        ),
    )
    canary_token: str | None = Field(
        default=None,
        description=(
            "V5 Sprint 10: Dynamic UUID4 token embedded in each exploit "
            "payload at runtime. Replaces static verification markers "
            "(e.g. 'webpent_verified', '4444') that an attacker could "
            "predict or a WAF could fingerprint. The validator searches "
            "the HTTP response specifically for this token to confirm "
            "in-band exploitation. None when no payload has been "
            "generated yet."
        ),
    )
    evidence_bundle: dict[str, Any] | None = Field(
        default=None,
        description=(
            "V5 Sprint 10: Full reproducible evidence attached to every "
            "confirmed finding. Structured as a mini-HAR dict with "
            "'request' (method, url, headers, body) and 'response' "
            "(status_code, headers, body, elapsed_ms) keys. Populated "
            "for all 'Tool-Confirmed' findings so human auditors can "
            "verify the exploit without re-running the tool. None for "
            "findings that have not yet been confirmed."
        ),
    )
    compliance_tags: list[str] = Field(
        default_factory=list,
        description=(
            "V5 Sprint 11: Auto-tagged industry-standard compliance "
            "references (e.g. 'OWASP-A03:2021', 'CWE-89', "
            "'PCI-DSS-6.5.1'). Populated by utils/compliance.py based "
            "on the finding's vuln_class."
        ),
    )
    evidence_hash: str | None = Field(
        default=None,
        description=(
            "V5 Sprint 11: SHA-256 hash of the evidence_bundle JSON. "
            "Computed by utils/crypto.py to provide a cryptographic "
            "audit trail proving the evidence has not been altered "
            "post-exploitation. None when no evidence_bundle is set."
        ),
    )
    evidence_contract: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Generic proof contract inherited from the originating hypothesis. "
            "The validator evaluates it only after existing execution gates pass."
        ),
    )
    hint_provenance: list[str] = Field(
        default_factory=list,
        description="Bounded reasoning-method provenance inherited from the hypothesis.",
    )
    human_review_decision: str | None = Field(
        default=None,
        description="Optional operator decision: accepted or rejected.",
    )
    post_exploitation_data: dict[str, Any] | None = Field(
        default=None,
        description=(
            "V5 Sprint 12: Post-exploitation metadata captured by the "
            "post_exploitation_node after a finding is confirmed. "
            "Contains safe, non-destructive enumeration results such "
            "as database schema (--schema), database list (--dbs), "
            "current user (id/whoami), and hostname. All operations "
            "are restricted to read-only safe commands — destructive "
            "operations (--dump, --os-shell, DROP, etc.) are blocked "
            "by the safe-pwning wrappers."
        ),
    )
    strategic_confidence_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "V7 Cognitive Upgrade — Phase 4: Informational-only numeric "
            "confidence score in [0, 1], computed by the deterministic "
            "weighted formula in webpent.shared.confidence. Used purely "
            "as a Dynamic-Prioritization input — NEVER a replacement "
            "for `confidence` (tentative/firm/confirmed) or "
            "`confidence_level` (Tool-Confirmed/AI-Assessed/Needs Human "
            "Review/Pending). Those categorical tiers are load-bearing "
            "for reporting, compliance tagging, and the existing "
            "PoC-or-GTFO validation pipeline; this numeric score is an "
            "additional, informational field only. None when the "
            "finding was produced by a pre-V7 code path that didn't "
            "set it (e.g., recon_node's nuclei findings, exploit_chainer "
            "candidates) — treat None as 'not scored' rather than 0."
        ),
    )
    hypothesis_id: UUID | None = Field(
        default=None,
        description=(
            "V7 Cognitive Upgrade — Phase 4: Back-reference to the "
            "Hypothesis this finding was promoted from, closing the "
            "audit loop from belief -> investigation -> finding. None "
            "for findings produced directly by a tool (recon nuclei "
            "findings, exploit_chainer candidates, deep-prober "
            "findings) — those didn't pass through the hypothesis "
            "pool. Set by webpent.shared.prioritization."
            "promote_hypothesis_to_finding when a hypothesis is "
            "promoted. The back-reference makes the chain of 'why did "
            "we end up investigating this' always traceable in the "
            "Decision Log and the final report."
        ),
    )
    # V9 P0 Fix 3: thread_id for per-engagement finding isolation.
    # Previously findings were stored globally with no thread association,
    # so the API's GET /findings?thread_id=X returned ALL findings from
    # ALL engagements (cross-thread bleed). This field is set by
    # _persist_findings in pentest_worker.py (which has the thread_id
    # from the Celery task) before calling db.save_finding.
    thread_id: str | None = Field(
        default=None,
        description=(
            "V9 P0 Fix 3: The engagement thread_id this finding belongs "
            "to. None for findings persisted before the V9 migration "
            "(legacy findings) — Findings with thread_id=None are "
            "invisible to per-thread API queries (SQL NULL != value)."
        ),
    )

    # -- Validators ----------------------------------------------------------
    @field_validator("severity", mode="before")
    @classmethod
    def _normalise_severity(cls, v: str | Severity) -> Severity:
        if isinstance(v, Severity):
            return v
        return Severity(str(v).lower())

    @field_validator("confidence", mode="before")
    @classmethod
    def _normalise_confidence(cls, v: str | Confidence | None) -> Confidence:
        if v is None:
            return Confidence.TENTATIVE
        if isinstance(v, Confidence):
            return v
        return Confidence(str(v).lower())

    @field_validator("evidence_bundle", mode="before")
    @classmethod
    def _normalise_legacy_evidence_bundle(cls, v: Any) -> Any:
        """Load pre-proof relational evidence without dropping the finding.

        Older releases persisted relational evidence directly as a list,
        while the current contract is a structured dictionary.  Preserve the
        old items inside an explicit envelope; newly generated bundles pass
        through unchanged.
        """
        if isinstance(v, list):
            return {
                "type": "legacy_evidence_bundle",
                "legacy_format": True,
                "items": v,
            }
        return v

    @field_validator("vuln_class", mode="before")
    @classmethod
    def _normalise_vuln_class(cls, v: str | VulnClass | None) -> VulnClass:
        if v is None:
            return VulnClass.UNKNOWN
        if isinstance(v, VulnClass):
            return v
        return VulnClass(str(v).lower())

    @field_validator("confidence_level", mode="after")
    @classmethod
    def _validate_confidence_level(cls, v: str) -> str:
        """V5 Sprint 9: enforce the allowed confidence_level literals.

        Accepts: 'Tool-Confirmed', 'AI-Assessed', 'Needs Human Review',
        'Pending', 'Not Scanned', 'Clean'. Any other value raises
        ValueError so typos surface immediately at Finding construction
        time rather than silently propagating to the report.

        V10 P0-4 (RCA follow-up): 'Not Scanned' is a NEW explicit
        operator signal emitted when skip_recon=True and the seed URL
        path matches a known DVWA / generic surface keyword but no
        detector produced a real Finding. Previously such engagements
        returned findings=[] which looked identical to a "clean target"
        — operators had no way to distinguish "we scanned and found
        nothing" from "we have no detector for this class". 'Not
        Scanned' is never produced by an LLM; it is the deterministic
        fallback in hypothesis_analyzer._emit_not_scanned_finding.

        V10 RESIDUAL FIX (post-audit): 'Clean' is a NEW distinct signal
        for "the structural detector ran successfully and found NO
        issue" (e.g. CSP header present and not trivially weak, no
        dangerous JS sinks, captcha present). Previously structural
        validators conflated "could not check" (Not Scanned) with
        "checked, no issue" (also Not Scanned) — operators could not
        distinguish a detector that ran clean from one that failed to
        run. 'Clean' is never produced by an LLM; it is the deterministic
        success path of a structural validator that found no evidence
        of a vulnerability. Severity for Clean findings is INFO.

        TEAM-1 Phase 3 (refutation correctness): 'Refuted' is a NEW
        explicit terminal status emitted ONLY by the deterministic
        refutation path (DatabaseManager.mark_refuted with a sealed
        negative-control proof bundle and a causal observation). It
        records "an earlier CONFIRMED status was retracted by verified
        contradictory evidence". 'Refuted' is never produced by an LLM;
        LLM-only skepticism continues to downgrade to 'Needs Human
        Review'. REFUTED is terminal in the persistence layer: later
        graph-state saves and late OOB callbacks cannot resurrect the
        retracted confirmation (see memory/db.py, monotonic evidence law
        UNCONFIRMED -> CONFIRMED -> REFUTED).
        """
        allowed = {
            "Tool-Confirmed",
            "AI-Assessed",
            "Needs Human Review",
            "Pending",
            "Not Scanned",
            "Clean",
            "Refuted",
        }
        if v not in allowed:
            raise ValueError(
                f"confidence_level must be one of {sorted(allowed)}; "
                f"got {v!r}"
            )
        return v

    # M1-B (E-1, 2026-11-05): architectural proof requirement for
    # "Tool-Confirmed". Before this, ANY construction site could set the
    # literal — the writer set was an unenforced convention (~7 families),
    # and at least one ungated writer existed (service/cost_alerts.py
    # stamped it on lifecycle NOTIFICATION objects with no evidence at
    # all). The model now fail-closes: a Tool-Confirmed Finding must carry
    # either a sealed proof bundle (``evidence_bundle``) or an evidence
    # dict that names the deterministic gate which promoted it
    # (``tool_confirmed_by`` — the M1 canonical key — or one of the
    # legacy provenance keys emitted by the pre-M1 legitimate writers, so
    # persisted rows remain loadable). No provenance ⇒ ValueError at
    # construction, regardless of the writer.
    _TOOL_CONFIRMED_PROVENANCE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "tool_confirmed_by",  # M1+ canonical explicit writer provenance
            "validator_tool",  # validator agent tool-validated paths
            "promotion_guard",  # validator promotion gates (incl. sqli reauth)
            "oob_confirmed",  # OOB callback confirmation (db.mark_oob_confirmed)
            "avi_promoted",  # AVI merge in graph/builder.py
        }
    )

    @model_validator(mode="after")
    def _require_tool_confirmed_provenance(self) -> "Finding":
        if self.confidence_level != "Tool-Confirmed":
            return self
        if self.evidence_bundle:
            return self
        evidence = self.evidence if isinstance(self.evidence, dict) else {}
        if any(key in evidence for key in self._TOOL_CONFIRMED_PROVENANCE_KEYS):
            return self
        raise ValueError(
            "Finding(confidence_level='Tool-Confirmed') requires provenance: "
            "either evidence_bundle (sealed proof) or an evidence dict "
            "naming the confirming gate (tool_confirmed_by / validator_tool / "
            "promotion_guard / oob_confirmed / avi_promoted). Constructing a "
            "Tool-Confirmed finding with no proof is forbidden (M1-B/E-1)."
        )

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                f"Finding URL must be an absolute http(s) URL; got {v!r}"
            )
        return v

    # -- Convenience ---------------------------------------------------------
    def is_actionable(self) -> bool:
        """Return True if the finding is severe AND confidently confirmed.

        With ``use_enum_values=True`` set on the model, ``self.severity``
        and ``self.confidence`` are stored as their underlying string
        values, so we compare against ``*.value`` explicitly.
        """
        return (
            self.severity in (Severity.HIGH.value, Severity.CRITICAL.value)
            and self.confidence == Confidence.CONFIRMED.value
        )
