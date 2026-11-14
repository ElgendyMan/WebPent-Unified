"""webpent.production.chain_composer — TC-3 §2 V-1, The Chain Composer.

When >=2 promoted findings exist, a proposer pass reads them TOGETHER and
proposes CHAINS (e.g. info-disclosure + IDOR -> cross-account object
exfiltration).  A proposal creates a NEW HYPOTHESIS executed through the
NORMAL spine — full chain, full gates (validator, CausalGuard, ProofBundle,
replay, promotion).  A chain is only PROVEN by executing it; the impact
uplift lands via the EV scheduler's ChainPotential multiplier (the chain
hypothesis carries ``chain_potential`` > 1).

ANTI-FAKE (the FRP-1 discipline, applied to chains): an unproven chain
NEVER appears in reports.  The ONLY report-facing surface is
:meth:`ChainComposer.proven_chains` — a proposal reaches it exclusively by
executing both legs through the pipeline with the dependency digest
matching (the step-2 request parameter must be byte-identical to the
value the step-1 response supplied).  A guessed parameter, a refuted leg,
or an absent execution leaves the proposal in the register — visible to
the audit, invisible to the report.

PROPOSER AUTHORITY: the deterministic proposer carries
``llm_authority=False`` (the same discipline as the
AutonomousExperimentSelector — proposals are advisory inputs; the spine's
gates remain the only confirmation authority).  The LLM proposer plugs
into the same Protocol when an LLM client is configured; it proposes, it
never confirms.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

CHAIN_POTENTIAL_MULTIPLIER = 1.8

# Chain types the deterministic proposer knows.  A chain type is exercisable
# only when BOTH leg families have executed, promoted findings AND the
# dependency contract can be satisfied by the lane's observed outputs.
CHAIN_TYPE_CROSS_ACCOUNT_EXFIL = "cross_account_object_exfiltration"
CHAIN_TYPE_ACCOUNT_TAKEOVER = "stored_xss_session_takeover"
# UM-DR-25 (red-team window 2026-11-06): the third deterministic chain
# type — IDOR supplies the object ids (its response leaked the
# registry), MASS_ASSIGNMENT supplies the protected-field write leg;
# together they escalate privileges on the owner's non-enumerable
# objects. Tests shipped with the full contract
# (tests/test_v2_chain_composer.py) but the rule was never merged —
# 17 dead tests and a missing capability.
CHAIN_TYPE_IDOR_MASS_ASSIGNMENT = "idor_mass_assignment_escalation"

# The write leg's protected-field vocabulary: a value from this set
# appearing in the step-2 response body is the escalation marker the
# semantic gate requires (role/privilege fields only — never paths).
_PROTECTED_FIELD_MARKERS = ("admin", "administrator", "root")


@dataclass(frozen=True)
class ChainTypeSpec:
    """UM-DR-25 (red-team window 2026-11-06): the declarative chain-type
    registration seam.  A spec names its two leg families, the id-source
    template inside the step-1 observed body, the hypothesis class it
    builds, and its semantic gate.  Everything downstream (proposal,
    hypothesis construction, proof) flows through the SAME machinery —
    registering a spec requires zero edits to the proof path, and an
    unregistered type fails closed (UNBUILDABLE)."""

    chain_type: str
    step1_family: str
    step2_family: str
    id_source_template: str            # e.g. "registry.{resource_owner}.document_ids"
    hypothesis_vuln_class: str
    rationale_template: str
    step2_method: str = "GET"
    step2_body_template: dict[str, Any] | None = None
    semantic_gate: str = "owner_viewer"   # or "protected_field"
    protected_field_markers: tuple[str, ...] = ()


_CHAIN_TYPE_SPECS: dict[str, ChainTypeSpec] = {}


def register_chain_type_spec(spec: ChainTypeSpec) -> bool:
    """Fail-closed registration.  Rejected: duplicate chain_type, a
    family-pair collision with an existing spec, an empty id-source
    template, or a protected_field gate with no markers."""
    if not isinstance(spec, ChainTypeSpec):
        return False
    if not str(spec.chain_type or "").strip():
        return False
    if spec.chain_type in _CHAIN_TYPE_SPECS:
        return False
    pair = (str(spec.step1_family or "").upper(),
            str(spec.step2_family or "").upper())
    if any((s.step1_family.upper(), s.step2_family.upper()) == pair
           for s in _CHAIN_TYPE_SPECS.values()):
        return False
    if not str(spec.id_source_template or "").strip():
        return False
    if spec.semantic_gate == "protected_field" and not spec.protected_field_markers:
        return False
    _CHAIN_TYPE_SPECS[spec.chain_type] = spec
    return True


def get_chain_type_spec(chain_type: str) -> ChainTypeSpec | None:
    return _CHAIN_TYPE_SPECS.get(str(chain_type or ""))


def registered_chain_types() -> tuple[str, ...]:
    """The registered chain types in registration (deterministic) order."""
    return tuple(_CHAIN_TYPE_SPECS)


# -- the default registry (registration order IS the deterministic order) --
register_chain_type_spec(ChainTypeSpec(
    chain_type=CHAIN_TYPE_CROSS_ACCOUNT_EXFIL,
    step1_family="INFO_DISCLOSURE", step2_family="IDOR",
    id_source_template="registry.{resource_owner}.document_ids",
    hypothesis_vuln_class="IDOR",
    rationale_template=(
        "{s1_family} on {s1_path} supplies object ids; {s2_family} on "
        "{s2_path} reads objects without the ownership check -> "
        "exfiltration of non-enumerable objects (dependency: {extract})"),
))
register_chain_type_spec(ChainTypeSpec(
    chain_type=CHAIN_TYPE_IDOR_MASS_ASSIGNMENT,
    step1_family="IDOR", step2_family="MASS_ASSIGNMENT",
    id_source_template="registry.{resource_owner}.document_ids",
    hypothesis_vuln_class="MASS_ASSIGNMENT",
    rationale_template=(
        "{s1_family} on {s1_path} leaked the owner registry; {s2_family} "
        "on {s2_path} accepts protected-field writes -> privilege "
        "escalation on the owner's non-enumerable objects (dependency: "
        "{extract})"),
    step2_method="PUT",
    step2_body_template={"role": "admin"},
    semantic_gate="protected_field",
    protected_field_markers=_PROTECTED_FIELD_MARKERS,
))

_ACTING_PRINCIPAL = "User_A"   # the chain's acting (foreign) principal

_STATUS_PROPOSED = "PROPOSED"
_STATUS_PROVEN = "PROVEN"
_STATUS_REFUTED = "REFUTED"
_STATUS_UNBUILDABLE = "UNBUILDABLE"


def dependency_digest(*, extracted_value: str, used_value: str) -> str:
    """The chain's dependency proof: the step-2 parameter must be
    byte-identical to the value the step-1 response supplied."""
    return hashlib.sha256(
        f"{extracted_value}|{used_value}".encode()).hexdigest()[:32]


@dataclass
class ChainFinding:
    """The minimal promoted-finding profile a proposer reads TOGETHER."""
    finding_id: str
    family: str                      # e.g. INFO_DISCLOSURE / IDOR
    path: str
    engagement_id: str
    promoted_at: str
    evidence_ref: str                # ProofBundle / proof digest reference
    observed: dict[str, Any] = field(default_factory=dict)  # redacted body
    resource_owner: str = ""         # the IDOR family's target principal
    covered_object_ids: list[str] = field(default_factory=list)
    """Object ids the STANDALONE finding already demonstrably reaches —
    the chain must compose a capability BEYOND them (the non-enumerable
    object), or it is inflation, not a chain."""

    def to_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "family": self.family.upper()}


@dataclass
class ChainProposal:
    chain_id: str
    chain_type: str
    leg_finding_ids: list[str]
    rationale: str
    proposed_by: str
    llm_authority: bool
    dependency_contract: dict[str, Any]
    status: str = _STATUS_PROPOSED
    chain_hypothesis_id: str | None = None
    executed: dict[str, Any] | None = None
    dep_digest: str | None = None
    chain_potential: float = CHAIN_POTENTIAL_MULTIPLIER

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class ChainProposer(Protocol):
    """A proposer reads findings TOGETHER and proposes chains.  Proposals
    are advisory; execution through the spine is the only proof path."""

    def propose(self, findings: list[ChainFinding]) -> list[ChainProposal]: ...


class DeterministicChainProposer:
    """Rule-based proposer (llm_authority=False).

    Rules (the dispatch's examples, encoded):
      * {INFO_DISCLOSURE, IDOR} -> cross-account object exfiltration: the
        disclosure leg's observed body supplies the object ids the IDOR
        leg's candidate request needs (the dependency contract names the
        extraction path inside the step-1 response).
      * {XSS_STORED, CSRF_EXEMPT_STATE_CHANGE} -> account takeover
        (documented; requires lanes this environment does not ship — a
        proposal for it would stay PROPOSED and therefore never surface).

    SEMANTIC INFLATION GUARDS (zero false positives applies to chains):
      * two findings of the SAME family on the SAME path pattern are one
        root cause — rejected as chain material;
      * the dependency contract extracts from the RESOURCE OWNER's registry
        entry only — a chain whose step-2 object belongs to the acting
        principal is a self-access, not a cross-account chain;
      * the extracted id excludes the standalone finding's covered ids —
        the chain's value is the NON-ENUMERABLE object, and re-proving a
        covered object is double counting.
    """

    def __init__(self, *, chain_potential: float = CHAIN_POTENTIAL_MULTIPLIER,
                 resource_owner: str = "User_B"):
        self.chain_potential = chain_potential
        self.resource_owner = resource_owner

    def propose(self, findings: list[ChainFinding]) -> list[ChainProposal]:
        """UM-DR-25: spec-registry driven — every registered ChainTypeSpec
        pairs its step-1/step-2 families through the identical machinery.
        The two default specs never cross-pair (exfiltration requires
        INFO_DISCLOSURE as step-1; escalation requires IDOR)."""
        proposals: list[ChainProposal] = []
        by_family: dict[str, list[ChainFinding]] = {}
        for f in findings:
            by_family.setdefault(f.family.upper(), []).append(f)
        for spec in _CHAIN_TYPE_SPECS.values():
            step1_legs = by_family.get(spec.step1_family.upper(), [])
            step2_legs = by_family.get(spec.step2_family.upper(), [])
            for s1 in step1_legs:
                for s2 in step2_legs:
                    if self._same_root_cause(s1, s2):
                        continue
                    owner = (s2.resource_owner
                             or s1.resource_owner
                             or self.resource_owner).strip()
                    if not owner:
                        continue
                    extract_path = spec.id_source_template.format(
                        resource_owner=owner)
                    # ground the template in the step-1 leg's observed body
                    ids = _extract_path(s1.observed or {}, extract_path)
                    if not isinstance(ids, list) or not ids:
                        continue  # no id-bearing payload for the resource owner
                    contract: dict[str, Any] = {
                        "derive_from": s1.finding_id,
                        "extract": extract_path,
                        "inject_into": "candidate.path",
                        "chain_type": spec.chain_type,
                        "resource_owner": owner,
                        "hypothesis_vuln_class": spec.hypothesis_vuln_class,
                        "semantic_gate": spec.semantic_gate,
                        "acting_principal": _ACTING_PRINCIPAL,
                    }
                    if spec.step2_method != "GET" or spec.step2_body_template:
                        contract["step2_method"] = spec.step2_method
                        contract["step2_body_template"] = dict(
                            spec.step2_body_template or {})
                    if spec.semantic_gate == "protected_field":
                        contract["protected_field_markers"] = list(
                            spec.protected_field_markers)
                    proposals.append(ChainProposal(
                        chain_id=f"chain_{s1.finding_id}_{s2.finding_id}",
                        chain_type=spec.chain_type,
                        leg_finding_ids=[s1.finding_id, s2.finding_id],
                        rationale=spec.rationale_template.format(
                            s1_family=s1.family, s2_family=s2.family,
                            s1_path=s1.path, s2_path=s2.path,
                            extract=extract_path),
                        proposed_by="deterministic_chain_proposer_v1",
                        llm_authority=False,
                        dependency_contract=contract,
                        chain_potential=self.chain_potential,
                    ))
        return proposals

    @staticmethod
    def _same_root_cause(d: ChainFinding, i: ChainFinding) -> bool:
        return (d.family.upper() == i.family.upper()
                and d.path.rstrip("/") == i.path.rstrip("/"))

    def _locate_id_source(self, disclosure: ChainFinding,
                          idor_leg: ChainFinding) -> str | None:
        """Locate the RESOURCE OWNER's id list inside the disclosure body
        (registry.<resource_owner>.document_ids).  Extracting from the
        acting principal's own entry would build a self-access chain —
        a false chain."""
        owner = (idor_leg.resource_owner
                 or disclosure.resource_owner
                 or self.resource_owner).strip()
        if not owner:
            return None
        observed = disclosure.observed or {}
        registry = observed.get("registry")
        if not isinstance(registry, dict):
            return None
        profile = registry.get(owner)
        ids = profile.get("document_ids") if isinstance(profile, dict) else None
        if isinstance(ids, list) and ids:
            return f"registry.{owner}.document_ids"
        return None


class ChainComposer:
    """The proposal register + the ONLY chain proof path.

    Reports must read :meth:`proven_chains` and nothing else — an unproven
    chain NEVER appears (FRP-1 applied to chains)."""

    def __init__(self, proposer: ChainProposer | None = None):
        self.proposer: ChainProposer = proposer or DeterministicChainProposer()
        self._findings: dict[str, ChainFinding] = {}
        self._proposals: dict[str, ChainProposal] = {}
        self._proven: dict[str, ChainProposal] = {}

    # -- ingestion ----------------------------------------------------------
    def ingest(self, finding: ChainFinding) -> list[ChainProposal]:
        """Register a promoted finding; when >=2 compatible findings exist,
        propose chains.  Returns the NEW proposals (may be empty)."""
        self._findings[finding.finding_id] = finding
        new: list[ChainProposal] = []
        for proposal in self.proposer.propose(list(self._findings.values())):
            if proposal.chain_id not in self._proposals:
                self._proposals[proposal.chain_id] = proposal
                new.append(proposal)
        return new

    # -- hypothesis construction -------------------------------------------
    def build_chain_hypothesis(self, chain_id: str, *, engagement_id: str,
                               step1_observed: dict[str, Any],
                               idor_path_prefix: str = "/api/documents/"
                               ) -> dict[str, Any] | None:
        """Build the chain's NEW hypothesis through the normal spine: an
        IDOR-family hypothesis whose candidate path parameter is DERIVED
        from the step-1 response per the dependency contract.  Returns None
        (status -> UNBUILDABLE) when the extraction fails — a chain whose
        dependency cannot be grounded is not executed, not guessed."""
        proposal = self._proposals.get(chain_id)
        if proposal is None or proposal.status != _STATUS_PROPOSED:
            return None
        contract = proposal.dependency_contract
        # UM-DR-25: spec-registry dispatch — every REGISTERED chain type
        # has a spec naming its request shape; an unregistered type has
        # no proofable shape and fails closed (UNBUILDABLE, never
        # executed) — a foreign proposer can never smuggle a mystery
        # chain into the spine.
        chain_type = str(contract.get("chain_type") or proposal.chain_type)
        spec = get_chain_type_spec(chain_type)
        if spec is None:
            proposal.status = _STATUS_UNBUILDABLE
            return None
        write_leg = bool(spec.step2_body_template
                         or spec.step2_method != "GET")
        candidates = _extract_path(step1_observed, str(contract["extract"]))
        if not isinstance(candidates, list) or not candidates:
            proposal.status = _STATUS_UNBUILDABLE
            return None
        # Select the NON-ENUMERABLE, NON-SELF, UNCOVERED object: not the
        # acting principal's own, not already covered by a standalone
        # finding.  A chain over a covered or self-owned object is
        # inflation — it would be a false chain even with clean mechanics.
        legs = [self._findings[f] for f in proposal.leg_finding_ids
                if f in self._findings]
        excluded: set[str] = set()
        for leg in legs:
            excluded.update(leg.covered_object_ids)
        owner = str(contract.get("resource_owner", ""))
        for leg in legs:
            # UM-DR-25: read the self-owned exclusion from ANY leg's
            # observed registry (the disclosure leg carries it for
            # exfiltration chains; the IDOR leg carries it for
            # escalation chains).
            registry = (leg.observed or {}).get("registry") or {}
            self_owned = (registry.get(_ACTING_PRINCIPAL) or {}).get(
                "document_ids") or []
            excluded.update(self_owned)
        selected = next((str(c) for c in candidates
                         if str(c) not in excluded), None)
        if not selected:
            proposal.status = _STATUS_UNBUILDABLE
            return None
        extracted = selected

        def _spec(actor: str, doc_id: str, actor_role: str) -> dict[str, Any]:
            return {"method": "GET",
                    "path": f"{idor_path_prefix}{doc_id}",
                    "headers": {"X-User": actor},
                    "principal_alias": actor, "principal_role": actor_role}

        if write_leg:
            body = dict(contract.get("step2_body_template")
                        or spec.step2_body_template or {"role": "admin"})

            def _write_spec(actor: str, doc_id: str, actor_role: str) -> dict[str, Any]:
                return {"method": str(contract.get("step2_method")
                                      or spec.step2_method or "PUT"),
                        "path": f"{idor_path_prefix}{doc_id}",
                        "headers": {"X-User": actor},
                        "body": dict(body),
                        "principal_alias": actor, "principal_role": actor_role}

            requests = {
                "baseline": _write_spec(owner or "User_B", extracted, "owner"),
                "candidate": _write_spec(_ACTING_PRINCIPAL, extracted,
                                         "foreign-user"),
                "negative_control": _write_spec(_ACTING_PRINCIPAL,
                                                "DOC-NO-SUCH-999",
                                                "foreign-user"),
            }
            vulnerability_class = str(contract.get("hypothesis_vuln_class")
                                      or spec.hypothesis_vuln_class
                                      or "MASS_ASSIGNMENT")
        else:
            requests = {
                "baseline": _spec("User_B", extracted, "owner"),
                "candidate": _spec("User_A", extracted, "foreign-user"),
                "negative_control": _spec("User_A", "DOC-NO-SUCH-999",
                                          "foreign-user"),
            }
            vulnerability_class = str(contract.get("hypothesis_vuln_class")
                                      or spec.hypothesis_vuln_class
                                      or "IDOR")

        hyp = {
            "id": f"{chain_id}_hyp",
            "vulnerability_class": vulnerability_class,
            "api_type": "rest",
            "path": idor_path_prefix,
            "information_value": 0.9,
            "resource_owner": owner or "User_B",
            "engagement_id": engagement_id,
            "chain_potential": proposal.chain_potential,
            "chain_metadata": {
                "chain_id": chain_id,
                "chain_type": proposal.chain_type,
                "leg_finding_ids": list(proposal.leg_finding_ids),
                "dependency_contract": contract,
                "excluded_object_ids": sorted(excluded),
                "selected_object_id": selected,
                "llm_authority": proposal.llm_authority,
            },
            "requests": requests,
        }
        proposal.chain_hypothesis_id = hyp["id"]
        proposal.dep_digest = dependency_digest(extracted_value=extracted,
                                                used_value=extracted)
        return hyp

    # -- execution recording -------------------------------------------------
    def record_execution(self, chain_id: str, *, step1_promoted: bool,
                         step2_validator_outcome: str | None,
                         step2_promotion_decision: str | None,
                         step2_used_value: str | None,
                         step2_response_body: dict[str, Any] | None = None,
                         proof_ref: str | None = None) -> ChainProposal | None:
        """Record the chain execution.  PROVEN requires ALL of: the step-1
        finding promoted, the step-2 pipeline PROMOTED, the dependency
        digest match (the used parameter is byte-identical to the derived
        one), AND the semantic owner/viewer gate — the step-2 response must
        show the object owned by the RESOURCE OWNER and viewed by the
        ACTING principal (a self-access validates the mechanics but is a
        FALSE chain).  Anything less leaves the chain unproven (REFUTED on
        an explicit validator refutation, otherwise still PROPOSED)."""
        proposal = self._proposals.get(chain_id)
        if proposal is None:
            return None
        digest_ok = False
        if step2_used_value:
            # the derived value is recoverable from the recorded hypothesis
            digest_ok = (proposal.dep_digest is not None and
                         proposal.dep_digest == dependency_digest(
                             extracted_value=step2_used_value,
                             used_value=step2_used_value))
        owner = str(proposal.dependency_contract.get("resource_owner", ""))
        semantic_ok = False
        if isinstance(step2_response_body, dict) and owner:
            body_owner = str(step2_response_body.get("owner", ""))
            body_viewer = str(step2_response_body.get("viewer", ""))
            if (proposal.dependency_contract.get("semantic_gate")
                    == "protected_field"):
                # UM-DR-25 third-chain-type gate: the protected write must
                # hit the RESOURCE OWNER's object, be performed by the
                # ACTING principal specifically (not any third party), and
                # the response must carry an escalated protected-field
                # value (e.g. role=admin) — the mechanics plus the
                # semantic escalation, together.
                markers = set(proposal.dependency_contract.get(
                    "protected_field_markers") or _PROTECTED_FIELD_MARKERS)
                acting = str(proposal.dependency_contract.get(
                    "acting_principal") or _ACTING_PRINCIPAL)
                semantic_ok = (
                    body_owner == owner
                    and body_viewer == acting
                    and any(str(v) in markers
                            for v in step2_response_body.values())
                )
            else:
                semantic_ok = (body_owner == owner
                               and body_viewer
                               and body_viewer != owner)
        proposal.executed = {
            "step1_promoted": step1_promoted,
            "step2_validator_outcome": step2_validator_outcome,
            "step2_promotion_decision": step2_promotion_decision,
            "dependency_digest_match": digest_ok,
            "semantic_owner_viewer_gate": semantic_ok,
            "proof_ref": proof_ref,
        }
        if (step1_promoted
                and step2_validator_outcome == "CONFIRMED"
                and step2_promotion_decision == "PROMOTED"
                and digest_ok and semantic_ok):
            proposal.status = _STATUS_PROVEN
            self._proven[chain_id] = proposal
        elif step2_validator_outcome == "REFUTED":
            proposal.status = _STATUS_REFUTED
        return proposal

    # -- the report-facing surfaces ------------------------------------------
    def proven_chains(self) -> list[dict[str, Any]]:
        """THE ONLY chain surface reports may read.  Unproven proposals are
        structurally absent (anti-fake, FRP-1 for chains)."""
        return [p.to_dict() for p in self._proven.values()]

    def proposal_register(self) -> list[dict[str, Any]]:
        """The full audit register (proposals of every status)."""
        return [p.to_dict() for p in self._proposals.values()]


def _extract_path(obj: Any, path: str) -> Any:
    """Resolve a dotted/bracketed mini-path into the step-1 body
    (``registry.User_B.document_ids`` or ``...document_ids[0]``).
    Returns the RAW resolved value (dict/list/scalar) — the caller decides
    how to interpret it."""
    cur: Any = obj
    for token in path.replace("]", "").replace("[", ".").split("."):
        if token == "":
            continue
        if isinstance(cur, dict) and token in cur:
            cur = cur[token]
        elif isinstance(cur, list) and token.isdigit() and int(token) < len(cur):
            cur = cur[int(token)]
        else:
            return None
    return cur


def chain_ev_uplift_report(hypothesis_base: dict[str, Any]) -> dict[str, Any]:
    """The impact-uplift receipt: the SAME hypothesis scored by the REAL
    EVScheduler with chain_potential 1.0 (standalone basis) vs the chain
    multiplier.  The scheduler is untouched — the uplift is the multiplier
    the charter already defined."""
    from webpent.brain.ev_scheduler import EVScheduler

    standalone = dict(hypothesis_base, chain_potential=1.0)
    chained = dict(hypothesis_base,
                   chain_potential=CHAIN_POTENTIAL_MULTIPLIER)
    ev_standalone = EVScheduler().rank([standalone])[0]["ev"]
    ev_chained = EVScheduler().rank([chained])[0]["ev"]
    return {"ev_standalone_basis": round(ev_standalone, 6),
            "ev_chain_multiplier": CHAIN_POTENTIAL_MULTIPLIER,
            "ev_chained": round(ev_chained, 6),
            "uplift_ratio": round(ev_chained / ev_standalone, 6)
            if ev_standalone else 0.0}
