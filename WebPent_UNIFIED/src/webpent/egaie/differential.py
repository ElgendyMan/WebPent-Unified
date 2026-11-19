"""EGAIE differential discovery engine (L5).

A discovery capability that identifies security-relevant BEHAVIORAL
DIFFERENCES across identities, permissions, resources and application
states, and turns the differences into hypotheses about previously
unspecified vulnerability scenarios. Unlike the Logic Breaker port
(http-v3), nothing here starts from known case ids: scenarios are
derived from the target's own observable behavior.

Architecture fit (no second orchestrator, no duplicated pipeline):

- All active probes run through DifferentialExperimentPort, a subclass
  of HTTPExperimentPort: every request is a CampaignTask executed by
  the RuntimeFactory-built ActionAuthority with the G-02 smart_http
  adapter, so scope, capability, budget, idempotency and denial
  handling are the production path, unchanged.
- Scenario proposals feed InvestigationState.hypotheses and run in the
  same propose -> select -> execute -> validate -> seal loop of the
  single InvestigationOrchestrator.
- The verdict layer is DifferentialValidationPort: a deterministic,
  family-specific oracle that judges only recorded observations. A
  language-model explanation may motivate a hypothesis but is never
  evidence; nothing in this module or its evidence path is
  model-generated.
- Confirmed scenarios are sealed by DifferentialProofBundlePort under
  the same seal/replay contract as the Logic Breaker: replay re-runs
  the oracle on the recorded observations and compares verdict,
  evidence digests and deterministic seal. Replay never re-issues
  HTTP.

Hypothesis discipline:

- Every hypothesis carries motivating facts (grounded observation
  references), the invariant it may violate, the next MINIMAL
  discriminating experiment, the evidence that would confirm or
  falsify it, an estimated gain and action cost, and the identity /
  scope / state preconditions it needs.
- Unexpected responses are leads, not confirmations: a generic
  receipt or a surprising 200 only opens a follow-up experiment.
- Verdicts are fail-closed: missing, denied or contradictory evidence
  is INCONCLUSIVE or BLOCKED, never clean and never confirmed.
- Family labels describe what the evidence supports: a state-machine
  defect (workflow order) is never relabelled as an authorization
  bypass; cross-owner transitions and cross-identity reads are the
  only identity-boundary families.

Discovery surface assumption: the target may expose randomized
endpoint segments, resource ids and account ids (see
discovery_target.py). Nothing in this module hard-codes canonical
names: all paths, accounts and amounts are extracted from allowed
observations (the index document and response bodies). The only
engine-held values are its own probe credentials (the tester's own
synthetic accounts) and the observation-grounded external identities
correlated to them.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from webpent.autonomous.authorization import (
    EngagementAuthorization,
)
from webpent.config.settings import Settings
from webpent.egaie.http_port import (
    MAX_REVEALED_PATH_LENGTH,
    HTTPExperimentPort,
)
from webpent.egaie.http_target import ACTOR_A, ACTOR_B
# UNIFIED MERGE (2026-11-02): structured preconditions restored
# from the l10 lineage (DifferentialHypothesis.prerequisites,
# PrerequisiteLedger.from_hypotheses contract). No import cycle:
# prerequisites.py imports nothing from this module.
from webpent.egaie.prerequisites import (  # noqa: F401
    Precondition,
    PreconditionKind,
    PreconditionStatus,
    UnattainableEffect,
)
from webpent.egaie.schemas import (
    HypothesisRecord,
    HypothesisStatus,
    InvestigationState,
    ProposedExperiment,
)

# Families the differential engine can report. These are engine
# OUTPUT labels; the benchmark's ground truth is declared separately
# and is never importable by this module.
FAMILY_IDENTITY_BOUNDARY = "IDENTITY_BOUNDARY"
FAMILY_PRICE_INTEGRITY = "PRICE_INTEGRITY"
FAMILY_WORKFLOW_IDENTITY = "WORKFLOW_IDENTITY"
FAMILY_WORKFLOW_ORDER = "WORKFLOW_ORDER"
DIFFERENTIAL_FAMILIES = (
    FAMILY_IDENTITY_BOUNDARY,
    FAMILY_PRICE_INTEGRITY,
    FAMILY_WORKFLOW_IDENTITY,
    FAMILY_WORKFLOW_ORDER,
)
# The boundary-limit family is emitted only by generalized (L6)
# deployments whose index advertises an account surface with a
# balance-like field; the L5 fixture corpus never generates it, so the
# L5 benchmark metrics and ground truth stay exactly as shipped.
FAMILY_BOUNDARY_LIMIT = "BOUNDARY_LIMIT"
GENERALIZED_FAMILIES = DIFFERENTIAL_FAMILIES + (FAMILY_BOUNDARY_LIMIT,)
# UNIFIED MERGE (2026-11-02): family name restored from the l10 lineage
# so the l10-era benchmark strategy layer (egaie/benchmark/strategies.py)
# imports cleanly. The full GRANT_REPLAY execution path remains l10-only
# heritage: registration works, runtime dispatch of this family is not
# wired into the 0.34.0 differential engine (see MERGE_REPORT.md).
FAMILY_GRANT_REPLAY = "GRANT_REPLAY"
GENERALIZED_FAMILIES = GENERALIZED_FAMILIES + (FAMILY_GRANT_REPLAY,)

DEFAULT_TARGET_IDENTITY = "egaie:DIFFERENTIAL"

VERDICT_CONFIRMED = "confirmed"
VERDICT_CLEAN = "clean"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_BLOCKED = "blocked"

# Dispositions separate "no verdict because evidence is missing"
# from "no verdict because the action was denied by the authority".
DISPOSITION_EVIDENCE_MISSING = "evidence_missing"
DISPOSITION_ACTION_BLOCKED = "action_blocked"
DISPOSITION_NO_DIFFERENTIAL = "no_differential_available"
# UNIFIED MERGE (2026-11-02): restored from the l10 lineage with
# the workflow-identity judge it serves (see _judge_workflow_identity
# and RelationshipTracker._documented_open_wf_ids). A surface whose
# own published schema declares open access with any of these
# markers is intended behavior, never a differential finding.
_OPEN_ACCESS_MARKERS = (
    "any ",
    "anyone",
    "shared",
    "open to",
    "public",
    "unrestricted",
    "all ",
    "everyone",
)

_NUM_KEYS = ("price", "amount", "total", "value")

_NUMERIC_ROLES = (
    "total", "charged", "authoritative_total", "available", "paid",
    "price", "amount", "value",
)
_REVEALED_PATH_ROLES = ("order_path", "note_path", "resource_path")


@dataclass(frozen=True)
class SurfaceBindings:
    """The surface vocabulary one deployment answers with.

    L5's controlled fixture answers with the fixed vocabulary below;
    generalized (L6) deployments randomize every external name. The
    bindings are DERIVED FROM THE TARGET'S OWN INDEX DOCUMENT during
    reconnaissance: the engine reads them off the wire like any other
    observable, never from generator metadata, and every downstream
    component (tracker, generators, oracles) addresses the surface
    only through them. Field names here are semantic ROLES; the values
    are the external names.
    """

    actor_param: str = "actor"
    idem_param: str = "idem"
    amount_param: str = "price"
    code_param: str = "code"
    resource_param: str = "resource"
    account_param: str = "account"
    # Grant surface (L7 Step 6): the param names the grant/consume
    # endpoints take and the response fields the grant declares.
    # UNIFIED MERGE (2026-11-02): restored from the l10 lineage
    # with the pool-authority/grant strategies that read them.
    subject_param: str = "subject"
    token_param: str = "token"
    token_field: str = "token"
    uses_allowed_field: str = "uses_allowed"
    # the surface's own published grouping role (pool/desk/channel):
# restored from the l10 lineage with the tracker and planner logic
# that reads it (l10 Phase 10).
    pool_field: str = ""
    action_param: str = "action"
    submit_action: str = "submit"
    approve_action: str = "approve"
    owner_field: str = "owner"
    state_field: str = "state"
    applied_field: str = "applied"
    transitioned_by_field: str = "transitioned_by"
    workflow_id_field: str = "workflow_id"
    kind_field: str = "resource_type"
    discount_applied_by_field: str = "discount_applied_by"
    charged_field: str = "charged"
    authoritative_field: str = "authoritative_total"
    available_field: str = "available"
    owner_header: str = "x-resource-owner"
    # The L5 fixture signals denials only with status codes. A
    # generalized deployment publishes an outcome header on every
    # response; when set, oracles require it to corroborate a denial
    # before a CLEAN verdict may rest on it.
    outcome_header: str = ""
    outcome_denied: str = "denied"
    numeric_keys: tuple[str, ...] = _NUM_KEYS
    revealed_path_keys: tuple[str, ...] = (
        "order_path", "note_path", "resource_path")

    def to_mapping(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_mapping(cls, data: Any) -> SurfaceBindings:
        if not isinstance(data, dict):
            return DEFAULT_SURFACE_BINDINGS
        kwargs = {
            key: value for key, value in data.items()
            if key in {f.name for f in dataclasses.fields(cls)}
        }
        for key, value in kwargs.items():
            if key in ("numeric_keys", "revealed_path_keys"):
                kwargs[key] = tuple(value)
        try:
            return cls(**kwargs)
        except TypeError:
            return DEFAULT_SURFACE_BINDINGS

    @classmethod
    def from_schema(cls, schema: Any) -> SurfaceBindings | None:
        """Derive bindings from a deployment's published schema block.

        Returns None when the document carries no schema (the L5
        fixture surface), leaving the default vocabulary in place.
        """
        if not isinstance(schema, dict):
            return None
        fields = schema.get("fields")
        params = schema.get("params")
        actions = schema.get("actions")
        if not isinstance(fields, dict) or not isinstance(params, dict):
            return None
        actions = actions if isinstance(actions, dict) else {}

        def ext(mapping: dict, role: str, default: str) -> str:
            value = mapping.get(role)
            return value if isinstance(value, str) and value else default

        numerics = tuple(
            fields[role] for role in _NUMERIC_ROLES
            if isinstance(fields.get(role), str) and fields[role])
        revealed = tuple(
            fields[role] for role in _REVEALED_PATH_ROLES
            if isinstance(fields.get(role), str) and fields[role])
        outcome_header = schema.get("outcome_header")
        owner_header = schema.get("owner_header")
        return cls(
            actor_param=ext(params, "actor", "actor"),
            idem_param=ext(params, "idem", "idem"),
            amount_param=ext(params, "amount", "price"),
            code_param=ext(params, "code", "code"),
            resource_param=ext(params, "resource", "resource"),
            account_param=ext(params, "account", "account"),
            action_param=ext(params, "action", "action"),
            submit_action=ext(actions, "submit", "submit"),
            approve_action=ext(actions, "approve", "approve"),
            owner_field=ext(fields, "owner", "owner"),
            state_field=ext(fields, "state", "state"),
            applied_field=ext(fields, "applied", "applied"),
            transitioned_by_field=ext(fields, "transitioned_by",
                                      "transitioned_by"),
            workflow_id_field=ext(fields, "workflow_id", "workflow_id"),
            kind_field=ext(fields, "kind", "resource_type"),
            discount_applied_by_field=ext(
                fields, "discount_applied_by", "discount_applied_by"),
            charged_field=ext(fields, "charged", "charged"),
            authoritative_field=ext(
                fields, "authoritative_total", "authoritative_total"),
            available_field=ext(fields, "available", "available"),
            owner_header=(
                owner_header if isinstance(owner_header, str)
                and owner_header else "x-resource-owner"),
            subject_param=ext(params, "subject", "subject"),
            token_param=ext(params, "token", "token"),
            token_field=ext(fields, "token", "token"),
            uses_allowed_field=ext(
                fields, "uses_allowed", "uses_allowed"),
            pool_field=ext(fields, "pool", ""),
            outcome_header=(
                outcome_header if isinstance(outcome_header, str)
                and outcome_header else ""),
            numeric_keys=numerics or _NUM_KEYS,
            revealed_path_keys=revealed or (
                "order_path", "note_path", "resource_path"),
        )


DEFAULT_SURFACE_BINDINGS = SurfaceBindings()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(obj: Any) -> str:
    canonical = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _step_executed(step: dict[str, Any] | None) -> bool:
    return step is not None and step.get("execution") == "executed"


def _step_blocked(step: dict[str, Any] | None) -> bool:
    return step is not None and step.get("execution") in (
        "denied", "blocked")


def _group_is_operations(
    structured: dict[str, Any],
    group: str,
    paths: list[str],
) -> bool:
    """Decide whether an index group holds state-changing operations.

    Structural, never name-based on generated surfaces: an index that
    publishes a kinds map marks operation entries with the "mutate"
    kind, so the group is recognized by that mark. The canonical
    fixture (no kinds map) keeps the literal group name "operations".
    """
    kinds = structured.get("kinds")
    if isinstance(kinds, dict) and kinds and paths:
        return all(kinds.get(path) == "mutate" for path in paths)
    return group == "operations"


# --------------------------------------------------------------------------
# Observation ledger
# --------------------------------------------------------------------------

@dataclass
class ObservationRecord:
    """One allowed observation, stored in EXTERNAL (surface) space."""

    record_id: str
    actor: str                 # identity string used as the actor param
    method: str
    path: str
    params: dict[str, str]
    status_code: int | None
    headers: dict[str, str]
    structured: Any
    execution: str
    body_sha256: str = ""
    body_length: int = 0

    def to_step(self, label: str, purpose: str) -> dict[str, Any]:
        return {
            "label": label,
            "purpose": purpose,
            "record_id": self.record_id,
            "actor": self.actor,
            "method": self.method,
            "path": self.path,
            "params": dict(self.params),
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "structured": self.structured,
            "execution": self.execution,
            "body_sha256": self.body_sha256,
            "body_length": self.body_length,
        }


class ObservationLedger:
    """Append-only record of allowed observations.

    Every probe the engine executes lands here. Generators read ONLY
    from this ledger; nothing else (no fixtures, no ground truth, no
    model output) may motivate a hypothesis.
    """

    def __init__(self) -> None:
        self.records: list[ObservationRecord] = []
        self._counter = 0

    def append(
        self,
        actor: str,
        method: str,
        path: str,
        params: dict[str, str],
        observation: dict[str, Any],
    ) -> ObservationRecord:
        self._counter += 1
        record = ObservationRecord(
            record_id=f"obs-{self._counter:04d}",
            actor=actor,
            method=method,
            path=path,
            params=dict(params),
            status_code=observation.get("status_code"),
            headers=dict(observation.get("headers") or {}),
            structured=observation.get("structured"),
            execution=observation.get("execution", "executed"),
            body_sha256=observation.get("body_sha256", ""),
            body_length=observation.get("body_length", 0),
        )
        self.records.append(record)
        return record

    def __len__(self) -> int:
        return len(self.records)


# --------------------------------------------------------------------------
# Relationship tracker (grounded, observations only)
# --------------------------------------------------------------------------

@dataclass
class RelationshipView:
    """What the ledger says about the target, with corroboration."""

    accounts: tuple[str, ...] = ()
    resource_paths: tuple[str, ...] = ()
    operation_paths: tuple[str, ...] = ()
    workflow_paths: tuple[str, ...] = ()
    coupon_codes: tuple[str, ...] = ()
    # resource path -> owner account (external id, from the body)
    resource_owner: dict[str, str] = field(default_factory=dict)
    # resource path -> owner corroborated by the response header
    resource_owner_corroboration: dict[str, int] = field(
        default_factory=dict)
    # resource path -> resource_type observed in the body
    resource_type: dict[str, str] = field(default_factory=dict)
    # resource path -> identity strings granted a 200 read
    granted_reads: dict[str, set[str]] = field(default_factory=dict)
    # resource path -> identity strings denied (non-200)
    denied_reads: dict[str, set[str]] = field(default_factory=dict)
    # workflow path -> {owner, state} from GET observations
    workflow_owner: dict[str, str] = field(default_factory=dict)
    workflow_state: dict[str, str] = field(default_factory=dict)
    # resource path -> numeric fields observed in its body
    numeric_fields: dict[str, dict[str, float]] = field(
        default_factory=dict)
    observations_index: int = 0
    # probe credential -> external identity correlated from
    # grant/deny differentials on the same resource.
    identity_of: dict[str, str] = field(default_factory=dict)
    # credentials the ledger actually saw issuing reads (correlated
    # or not): the mutual-read discriminator works from this set
    # when no denial differential exists to correlate ownership.
    sweep_credentials: tuple[str, ...] = ()
    # operation path -> declared param names (generalized index
    # documents may describe each operation's parameter surface).
    operation_params: dict[str, tuple[str, ...]] = field(
        default_factory=dict)
    # operation path -> the operation's own documented role (charge,
    # discount, withdrawal, order): observable surface naming, not
    # enforcement metadata.
    operation_roles: dict[str, str] = field(default_factory=dict)
    # workflow path -> observed state chain (from the index schema).
    workflow_chains: dict[str, tuple[str, ...]] = field(
        default_factory=dict)
    # workflow path -> {action name -> target state}.
    workflow_action_targets: dict[str, dict[str, str]] = field(
        default_factory=dict)
    # workflow path -> the surface's own published checklist
    # requirements (from the index schema): requirements the
    # workflow documents must be satisfied before its final
    # transitions — a dependency the stage chain alone cannot
    # express. UNIFIED MERGE (2026-11-02): restored from the l10
    # lineage (planner setup derivation reads it).
    workflow_requirements: dict[str, tuple[str, ...]] = field(
        default_factory=dict)
    # the surface's own action-parameter name, carried from the
    # bindings the view was built with (schema-derived, never
    # assumed) so downstream planners address the surface through
    # its observed vocabulary.
    action_param: str = ""
    # workflow path -> the value of the published grouping field
    # (bindings.pool_field) on its body: the pool/desk/channel
    # record the surface itself publishes. Empty on surfaces that
    # publish no grouping role.
    workflow_pool: dict[str, str] = field(default_factory=dict)
    # workflow paths whose acceptance of any-identity transitions
    # is declared open access by the surface's own published schema
    # documentation (documented shared intake): intended behavior,
    # never a differential finding.
    documented_open: tuple[str, ...] = ()


@dataclass
class RelationshipTracker:
    """Extract relationships from ledger observations only.

    Every surface name the tracker matches on comes from
    ``bindings``; nothing here is hard-coded to one deployment's
    vocabulary.
    """

    ledger: ObservationLedger
    bindings: SurfaceBindings = DEFAULT_SURFACE_BINDINGS

    def view(self) -> RelationshipView:
        b = self.bindings
        view = RelationshipView()
        view.action_param = b.action_param
        resource_paths: set[str] = set()
        operation_paths: set[str] = set()
        workflow_paths: set[str] = set()
        accounts: set[str] = set()
        chains: dict[str, tuple[str, ...]] = {}
        action_targets: dict[str, dict[str, str]] = {}
        schema: dict[str, Any] | None = None
        for record in self.ledger.records:
            if record.execution != "executed":
                continue
            structured = record.structured
            if not isinstance(structured, dict):
                continue
            if "api" in structured and isinstance(
                    structured.get("api"), dict):
                view.observations_index += 1
                api = structured["api"]
                for group, entries in api.items():
                    if not isinstance(entries, list):
                        continue
                    parsed: list[tuple[str, tuple[str, ...], Any]] = []
                    for entry in entries:
                        if isinstance(entry, str):
                            parsed.append((entry, (), entry))
                        elif isinstance(entry, dict) and isinstance(
                                entry.get("path"), str):
                            entry_params = tuple(
                                key for key in entry
                                if key not in ("path", "role")
                                and isinstance(entry[key], str))
                            parsed.append(
                                (entry["path"], entry_params, entry))
                    if not parsed:
                        continue
                    if _group_is_operations(
                            structured, group,
                            [path for path, _, _ in parsed]):
                        for path, entry_params, entry in parsed:
                            operation_paths.add(path)
                            if entry_params:
                                view.operation_params.setdefault(
                                    path, entry_params)
                            if isinstance(entry, dict) and isinstance(
                                    entry.get("role"), str):
                                view.operation_roles.setdefault(
                                    path, entry["role"])
                    else:
                        resource_paths.update(
                            path for path, _, _ in parsed)
                codes = structured.get("promotions") or []
                if isinstance(codes, list):
                    codes = tuple(
                        c for c in codes if isinstance(c, str))
                    view.coupon_codes = tuple(sorted(
                        set(view.coupon_codes) | set(codes)))
                schema_block = structured.get("schema")
                if isinstance(schema_block, dict):
                    schema = schema_block
                    self._absorb_schema(
                        schema_block, chains, action_targets)
                continue
            # A revealed body: owner, resource_type, workflow fields,
            # numeric pricing fields.
            owner = structured.get(b.owner_field)
            if isinstance(owner, str) and owner:
                accounts.add(owner)
            path = record.path
            if b.workflow_id_field in structured:
                workflow_paths.add(path)
                workflow_owner = structured.get(b.owner_field)
                if isinstance(workflow_owner, str) and workflow_owner:
                    accounts.add(workflow_owner)
                    view.workflow_owner[path] = workflow_owner
                state = structured.get(b.state_field)
                if isinstance(state, str) and state:
                    # keep the FIRST observed state per workflow
                    view.workflow_state.setdefault(path, state)
                # L10 Phase 10: the workflow's own published grouping
                # value (pool/desk/channel record). First observed
                # value wins; grouping values are stable across
                # transitions.
                if b.pool_field:
                    pool_value = structured.get(b.pool_field)
                    if isinstance(pool_value, str) and pool_value:
                        view.workflow_pool.setdefault(
                            path, pool_value)
            elif owner and owner in record.headers.get(
                    b.owner_header, owner):
                resource_paths.add(path)
                view.resource_owner[path] = owner
                resource_type = structured.get(b.kind_field)
                if isinstance(resource_type, str) and resource_type:
                    view.resource_type[path] = resource_type
                if record.headers.get(b.owner_header) == owner:
                    view.resource_owner_corroboration[path] = (
                        view.resource_owner_corroboration.get(path, 0)
                        + 1)
            # numeric fields (pricing evidence)
            numerics: dict[str, float] = {}
            for key in b.numeric_keys:
                value = structured.get(key)
                if isinstance(value, (int, float)) and not isinstance(
                        value, bool):
                    numerics[key] = float(value)
            if numerics:
                merged = view.numeric_fields.setdefault(path, {})
                for key, value in numerics.items():
                    merged.setdefault(key, value)
            # grant/deny bookkeeping per identity used
            granted = record.status_code == 200
            if record.path in workflow_paths or b.workflow_id_field in (
                    structured):
                target_map = None
            else:
                target_map = view.granted_reads if granted else (
                    view.denied_reads)
            if target_map is not None and record.path:
                target_map.setdefault(record.path, set()).add(
                    record.actor)
        if schema is not None:
            view_workflow_paths = {
                path: path.rsplit("/", 1)[-1]
                for path in workflow_paths
            }
            for path, wf_id in view_workflow_paths.items():
                if wf_id in chains:
                    view.workflow_chains[path] = chains[wf_id]
                if wf_id in action_targets:
                    view.workflow_action_targets[path] = (
                        action_targets[wf_id])
                # the surface's own published checklist: its
                # requirements are part of the workflow's declared
                # dependency structure, absorbed as observed
                # surface vocabulary (never inferred fixture
                # knowledge)
                published = (schema.get("checklist") or {})
                if wf_id in published:
                    items = published[wf_id]
                    if isinstance(items, (list, tuple)):
                        view.workflow_requirements[path] = tuple(
                            str(item) for item in items)
        # Documentation-awareness: a workflow whose own published
        # schema declares open (any-identity) access is intended
        # behavior, and accepting a non-owner transition there is not
        # a differential. The declaration must name the workflow id
        # and assert open access; the scan reads only string values
        # the surface itself publishes.
        if schema is not None and chains:
            open_wf = self._documented_open_wf_ids(schema)
            if open_wf:
                view.documented_open = tuple(sorted(
                    path for path, wf_id in view_workflow_paths.items()
                    if wf_id in open_wf))
        # correlate probe credentials to external identities: a
        # credential C is the external identity O when C was granted a
        # read on a resource owned by O (external owner id recorded in
        # the body) AND the grant/deny record distinguishes C from a
        # broadly privileged identity: another used identity was denied
        # on that same resource, or C was denied on another resource.
        credentials = sorted({
            record.actor
            for record in self.ledger.records
            if record.execution == "executed" and record.actor
        })
        view.sweep_credentials = tuple(credentials)
        for credential in credentials:
            if credential in view.identity_of:
                continue
            # pass 1 (strong): a grant on a resource another used
            # identity was denied on the same path
            for path in sorted(view.granted_reads):
                if credential not in view.granted_reads[path]:
                    continue
                owner = view.resource_owner.get(path)
                if not owner:
                    continue
                if view.denied_reads.get(path, set()) - {credential}:
                    view.identity_of[credential] = owner
                    break
            if credential in view.identity_of:
                continue
            # pass 2 (fallback, single-credential recon): a grant plus
            # the credential's own denial somewhere else
            for path in sorted(view.granted_reads):
                if credential not in view.granted_reads[path]:
                    continue
                owner = view.resource_owner.get(path)
                if not owner:
                    continue
                denied_elsewhere = any(
                    credential in denied
                    for other_path, denied in view.denied_reads.items()
                    if other_path != path)
                if denied_elsewhere:
                    view.identity_of[credential] = owner
                    break
        view.accounts = tuple(sorted(accounts))
        view.resource_paths = tuple(sorted(resource_paths))
        view.operation_paths = tuple(sorted(operation_paths))
        view.workflow_paths = tuple(sorted(workflow_paths))
        return view

    @staticmethod
    def _absorb_schema(
        schema: dict[str, Any],
        chains: dict[str, tuple[str, ...]],
        action_targets: dict[str, dict[str, str]],
    ) -> None:
        """Pull state chains / action targets out of a schema block.

        These are the workflow's own published shape (state names and
        which action lands in which state): observable surface, not
        enforcement metadata. Which transitions are actually enforced
        is never in the document and is what the probes decide.
        """
        for wf_id, states in (schema.get("state_chains") or {}).items():
            if isinstance(states, list) and all(
                    isinstance(s, str) for s in states):
                chains[wf_id] = tuple(states)
        for wf_id, targets in (schema.get("action_targets")
                               or {}).items():
            if isinstance(targets, dict):
                action_targets[wf_id] = {
                    action: state
                    for action, state in targets.items()
                    if isinstance(action, str)
                    and isinstance(state, str)
                }

    @staticmethod
    def _documented_open_wf_ids(schema: dict[str, Any]) -> set[str]:
        """Workflow ids whose own published documentation declares
        open (any-identity) access.

        The surface's schema is its word about itself: when it
        states, in any of its string values, that a workflow accepts
        actions from any identity, that acceptance is documented
        intent, and the differential judge must not score it as a
        boundary violation. The scan matches published workflow ids
        (the keys the schema itself declares) against the surface's
        own strings with a small generic open-access vocabulary; it
        reads nothing but what the surface publishes and adds no
        names of its own.
        """
        wf_ids = {
            key for key in (schema.get("state_chains") or {})
            if isinstance(key, str)
        }
        wf_ids |= {
            key for key in (schema.get("action_targets") or {})
            if isinstance(key, str)
        }
        if not wf_ids:
            return set()
        found: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, str):
                lowered = node.lower()
                if any(marker in lowered
                       for marker in _OPEN_ACCESS_MARKERS):
                    for wf_id in wf_ids:
                        if wf_id in node:
                            found.add(wf_id)
            elif isinstance(node, dict):
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        for value in schema.values():
            if isinstance(value, (dict, list)) or isinstance(
                    value, str):
                walk(value)
        return found


# --------------------------------------------------------------------------
# Probe plans and hypotheses
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ProbeStep:
    """One step of a minimal discriminating experiment."""

    purpose: str            # baseline | candidate | control
    label: str
    method: str             # GET | POST
    path: str
    actor: str
    params: tuple[tuple[str, str], ...] = ()
    followup_of: str = ""   # label of the step revealing this path
    # Response-capture (L7 Step 6): a step whose params depend
    # on a VALUE the surface returned in an earlier step's
    # response (a minted authorization token, a confirmation
    # reference). The placeholder "{captured}" in params
    # resolves at execution from the named response field of the
    # named step; a step that cannot resolve its capture fails
    # closed with an unresolved-parameters observation, never
    # with a guessed value. UNIFIED MERGE (2026-11-02): restored
    # from the l10 lineage with the grant-replay generator.
    value_from: str = ""    # label of the step supplying the value
    value_key: str = ""     # response field carrying the value


@dataclass(frozen=True)
class ProbePlan:
    hypothesis_id: str
    steps: tuple[ProbeStep, ...]
    # Deployment-observable context the plan's discrimination relies
    # on (e.g. the workflow's initial state and the target state of
    # the probed action, read off the index schema). Carried through
    # to the oracle composites; generalized oracles use it in place
    # of any single deployment's literals.
    context: tuple[tuple[str, str], ...] = ()

    def by_purpose(self, purpose: str) -> tuple[ProbeStep, ...]:
        return tuple(s for s in self.steps if s.purpose == purpose)

    def context_dict(self) -> dict[str, str]:
        return dict(self.context)


@dataclass
class DifferentialHypothesis:
    """A discovery hypothesis with its full justification chain.

    motivating_facts reference recorded observations only; the model
    never appears in the evidence path.
    """

    hypothesis_id: str
    family: str
    statement: str
    motivating_facts: tuple[str, ...]
    invariant: str
    confirm_evidence: str
    falsify_evidence: str
    gain: float
    cost: float
    preconditions: tuple[str, ...]
    plan: ProbePlan
    # Scheduling precondition: the probe's discrimination depends on
    # the probed resource still being in its observed initial state.
    # Probes flagged True are executed before state-advancing probes
    # on the same resources; this is ordering of execution, not a
    # change to estimated value.
    pristine_state_required: bool = False
    # L9 §2: structured preconditions derived from the same wire
    # view as the plan itself (identity correlation, workflow
    # source state, pristine state, grant capability). They start
    # INFERRED or ESTABLISHABLE — never OBSERVED: only a recorded
    # observation can move them to OBSERVED, via
    # PrerequisiteLedger.verify. A hypothesis that declares none is
    # ungated (pre-planner behavior). UNIFIED MERGE (2026-11-02):
    # restored from the l10 lineage.
    prerequisites: tuple[Precondition, ...] = ()

    def to_experiment(self) -> ProposedExperiment:
        rationale = "; ".join(self.motivating_facts)
        if self.preconditions:
            rationale += " | preconditions: " + ", ".join(
                self.preconditions)
        return ProposedExperiment(
            experiment_id=f"e-{self.hypothesis_id}",
            family=self.family,
            signature=f"{self.hypothesis_id}/{self.family}",
            description=self.statement,
            cost=self.cost,
            risk=0.1,
            gain_estimate=self.gain,
            rationale=rationale,
            hypothesis_id=f"h-{self.hypothesis_id}",
        )


def _placeholder_observation(
    path: str,
    execution: str,
) -> dict[str, Any]:
    return {
        "path": path,
        "status_code": None,
        "headers": {},
        "body_sha256": "",
        "body_length": 0,
        "structured": None,
        "execution": execution,
    }


# --------------------------------------------------------------------------
# Hypothesis generators (bounded, type-aware, observation-grounded)
# --------------------------------------------------------------------------

class DifferentialGenerator:
    """Derive differential hypotheses from the relationship view.

    Bounded by design: each hypothesis set (the per-family probes and
    the cross-identity application probes) holds at most
    MAX_HYPOTHESES_PER_FAMILY hypotheses and every probe plan at most
    MAX_STEPS_PER_PROBE steps. Every variation is grounded in an
    observed value; there is no combinatorial exploration.
    """

    MAX_HYPOTHESES_PER_FAMILY = 8
    MAX_STEPS_PER_PROBE = 5
    # l10: distinct resource paths probed per operation during
    # the grant-replay family sweep.
    RESOURCE_PROBES_PER_OPERATION = 3

    # Families whose discrimination depends on the probed resource
    # still being in its pristine state. Single source of truth for
    # both the per-hypothesis pristine_state_required flag (set below)
    # and the proposer's staged emission schedule: the gain-based
    # selector re-scores pending experiments every round and would
    # otherwise interleave the bands.
    PRISTINE_FAMILIES = frozenset({FAMILY_WORKFLOW_ORDER})

    def __init__(self, bindings: SurfaceBindings | None = None) -> None:
        self._bindings = bindings or DEFAULT_SURFACE_BINDINGS
        self._counters: dict[str, int] = {}

    def _slug(self, family: str) -> str:
        self._counters[family] = self._counters.get(family, 0) + 1
        return f"{family.lower().replace('_', '-')}-{self._counters[family]:02d}"

    def generate(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        hypotheses: list[DifferentialHypothesis] = []
        hypotheses.extend(self._identity_hypotheses(view))
        hypotheses.extend(self._mutual_read_hypotheses(view))
        hypotheses.extend(self._price_hypotheses(view))
        hypotheses.extend(self._mutation_identity_hypotheses(view))
        hypotheses.extend(self._boundary_hypotheses(view))
        # Workflow-order probes MUST run before workflow-identity
        # probes on the same instance: the order probe's
        # discrimination needs the instance in its pristine state
        # (approve from draft is the out-of-order action; once any
        # probe has advanced the state, no out-of-order action exists
        # from "submitted"), while a successful cross-owner submit
        # advances it. The proposer stages the pristine band first
        # (see DifferentialProposer); generation order additionally
        # keeps the insertion-order ablation correct.
        hypotheses.extend(self._workflow_order_hypotheses(view))
        hypotheses.extend(self._workflow_identity_hypotheses(view))
        # L10 Phase 10: the cross-group authority survey runs after
        # workflow-identity so grouped surfaces' delegation question is
        # answered by group-level evidence rather than by the
        # single-workflow owner invariant.
        hypotheses.extend(self._pool_authority_hypotheses(view))
        # Grant-replay probes are stateless (each grant mints a fresh
        # token), so ordering against workflow state does not matter.
        hypotheses.extend(self._grant_replay_hypotheses(view))
        self._attach_preconditions(view, hypotheses)
        return hypotheses

    # -- L9 §2: structured preconditions -----------------------------

    def _identity_hypotheses(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        hypotheses: list[DifferentialHypothesis] = []
        credentials = sorted(view.identity_of)
        if not credentials:
            return hypotheses
        for path in view.resource_paths:
            if len(hypotheses) >= self.MAX_HYPOTHESES_PER_FAMILY:
                break
            owner = view.resource_owner.get(path)
            if not owner:
                continue
            candidate = next(
                (c for c in credentials if view.identity_of[c] != owner),
                None)
            if candidate is None:
                continue
            # probes act as the correlated EXTERNAL identity so the
            # recorded evidence and the oracle compare one identity
            # space (the target maps external ids at request time)
            identity = view.identity_of[candidate]
            # control: a resource this identity was already denied on
            control_path = next(
                (p for p in view.denied_reads
                 if candidate in view.denied_reads[p] and p != path),
                None)
            if control_path is None:
                continue
            slug = self._slug(FAMILY_IDENTITY_BOUNDARY)
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="GET", path=path, actor=owner),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="GET", path=path, actor=identity),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="GET", path=control_path, actor=identity),
            )
            hypotheses.append(DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_IDENTITY_BOUNDARY,
                statement=(
                    f"reading {path} may not require owning it: "
                    f"{identity} was granted what {owner} owns"),
                motivating_facts=(
                    f"recon granted a read of {path} (owner {owner})",
                    f"recon denied a read of {control_path} to "
                    f"{identity}"),
                invariant=(
                    "cross-identity reads are denied unless the "
                    "identity owns the resource"),
                confirm_evidence=(
                    f"candidate GET 200 with owner {owner} while the "
                    "control read stays denied for the same identity"),
                falsify_evidence=(
                    "candidate GET denied (403/404) like the control"),
                gain=0.6,
                cost=0.3,
                preconditions=(
                    "owner identity observed",
                    "candidate identity correlated from grant/deny "
                    "differentials",
                    "control resource known denied to the candidate"),
                plan=ProbePlan(hypothesis_id=slug, steps=steps),
            ))
        return hypotheses

    def _mutual_read_hypotheses(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        """Cross-identity read probes for surfaces with no denial.

        The correlated-identity generator above needs a denial
        differential to tie a credential to its external identity. An
        open-read surface produces none: every probed credential is
        granted every revealed read. That universality is itself the
        evidence, provided two DISTINCT credentials were each granted
        a read of a resource exposing a DIFFERENT owner: a single
        privileged identity cannot explain two credentials reading
        two different owners. Gated on the observed absence of any
        denied read, so enforced surfaces never emit it (their
        denials drive the correlated generator instead).
        """
        hypotheses: list[DifferentialHypothesis] = []
        if view.denied_reads:
            return hypotheses
        credentials = list(view.sweep_credentials)
        if len(credentials) < 2:
            return hypotheses
        owners: dict[str, str] = {}
        for path in view.resource_paths:
            owner = view.resource_owner.get(path)
            if owner and view.granted_reads.get(path):
                owners[path] = owner
        distinct = sorted(set(owners.values()))
        if len(distinct) < 2:
            return hypotheses
        first, second = credentials[0], credentials[1]
        path_a = next(p for p in sorted(owners) if owners[p] == distinct[0])
        path_b = next(p for p in sorted(owners) if owners[p] == distinct[1])
        slug = self._slug(FAMILY_IDENTITY_BOUNDARY)
        steps = (
            ProbeStep(
                purpose="baseline", label=f"{slug}-base",
                method="GET", path=path_a, actor=first),
            ProbeStep(
                purpose="candidate", label=f"{slug}-cand",
                method="GET", path=path_b, actor=first),
            ProbeStep(
                purpose="control", label=f"{slug}-ctrl",
                method="GET", path=path_a, actor=second),
        )
        hypotheses.append(DifferentialHypothesis(
            hypothesis_id=slug,
            family=FAMILY_IDENTITY_BOUNDARY,
            statement=(
                f"reading {path_b} may not require owning it: "
                f"{first} and {second} were each granted reads of "
                f"resources exposing different owners "
                f"({distinct[0]}, {distinct[1]})"),
            motivating_facts=(
                f"recon granted every revealed read to both {first} "
                f"and {second} with no denial observed",
                f"{path_a} and {path_b} expose distinct owners"),
            invariant=(
                "cross-identity reads are denied unless the "
                "identity owns the resource"),
            confirm_evidence=(
                "two distinct identities each granted reads of "
                "resources exposing different owners while no read "
                "was denied"),
            falsify_evidence=(
                "either cross-owner read is denied (403/404)"),
            gain=0.6,
            cost=0.3,
            preconditions=(
                "read surface swept with two distinct credentials",
                "no denied read observed anywhere in the sweep",
                "resources expose two different owner identities"),
            plan=ProbePlan(
                hypothesis_id=slug, steps=steps,
                context=(("probe", "mutual_read"),)),
        ))
        return hypotheses

    # -- identity boundary on state-changing operations ---------------

    def _mutation_identity_hypotheses(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        """Cross-identity application probes for bare mutation ops.

        Generalized surfaces only: the operation must declare a
        resource parameter on the index and take no amount parameter.
        The operation's own documented role decides the family the
        probe belongs to (charge-shaped use of a resource is an
        identity question; discount-shaped application is a price
        integrity question). Whether the operation actually grants
        cross-identity use is what the probe and its oracle decide.
        """
        hypotheses: list[DifferentialHypothesis] = []
        b = self._bindings
        credentials = sorted(view.identity_of)
        if credentials:
            identities = dict(view.identity_of)
        else:
            # Open-read surface: no denial differential exists to
            # correlate credentials to owners (L7 Step 6 failure
            # analysis, lab-104). The mutual-read evidence is the
            # fallback grounding: two distinct sweep credentials were
            # each granted reads of different-owner resources, so
            # their own strings are the external identities to use in
            # a cross-owner mutation probe. With denied reads present
            # the correlation should have worked, so no fallback.
            if view.denied_reads:
                return hypotheses
            # The external identities themselves: distinct owner
            # strings the surface exposed in resource bodies. On an
            # open-read surface these are the identities the probes
            # can legitimately act as, without any correlation step.
            owners = sorted(set(view.resource_owner.values()))
            if len(owners) < 2:
                return hypotheses
            credentials = owners
            identities = {o: o for o in owners}
        family_by_role = {
            "pay": FAMILY_IDENTITY_BOUNDARY,
            "coupon": FAMILY_PRICE_INTEGRITY,
        }
        mutation_ops = [
            op for op in view.operation_paths
            if op in view.operation_params
            and b.resource_param in view.operation_params[op]
            and b.amount_param not in view.operation_params[op]
            and view.operation_roles.get(op) in family_by_role
        ]
        if len(credentials) < 2 or not mutation_ops:
            return hypotheses

        def typed(predicate: Any) -> str | None:
            return next(
                (p for p in view.resource_paths
                 if view.resource_type.get(p)
                 and view.resource_owner.get(p)
                 and predicate(view.resource_owner[p])), None)

        for operation in mutation_ops:
            family = family_by_role[view.operation_roles[operation]]
            # One probe family per operation, repeated across distinct
            # resources (capped). A scoped defect (defective for one
            # collection or bucket only) sits behind a different
            # resource than the first probe happens to pick, so
            # single-resource probing reads clean and the run ends
            # with a false clean verdict. Evidence: the L8 dev
            # failure analysis — dv-104 and mk-114 were never
            # confirmed; the probe's single resource fell outside the
            # defective scope. Repetition costs extra denied probes
            # on secured surfaces but the finding-level dedup keeps
            # one defect one finding.
            probed: list[str] = []
            for resource in view.resource_paths:
                if len(hypotheses) >= (
                        self.MAX_HYPOTHESES_PER_FAMILY):
                    break
                if len(probed) >= (
                        self.RESOURCE_PROBES_PER_OPERATION):
                    break
                if not (view.resource_type.get(resource)
                        and view.resource_owner.get(resource)):
                    continue
                if resource in probed:
                    continue
                probed.append(resource)
                owner = view.resource_owner[resource]
                other = next(
                    (identities[c] for c in credentials
                     if identities[c] != owner), None)
                if other is None:
                    continue
                control_resource = typed(
                    lambda o, _other=other: o == _other)
                if control_resource is None:
                    continue
                slug = self._slug(family)
                params = ((b.resource_param,
                           resource.rsplit("/", 1)[-1]),)
                control_params = ((b.resource_param,
                                   control_resource.rsplit("/", 1)[-1]),)
                steps = (
                    ProbeStep(
                        purpose="baseline", label=f"{slug}-base",
                        method="POST", path=operation, actor=owner,
                        params=params),
                    ProbeStep(
                        purpose="candidate", label=f"{slug}-cand",
                        method="POST", path=operation, actor=other,
                        params=params),
                    ProbeStep(
                        purpose="control", label=f"{slug}-ctrl",
                        method="POST", path=operation, actor=other,
                        params=control_params),
                )
                if family == FAMILY_PRICE_INTEGRITY:
                    statement = (
                        f"{operation} may apply a discount for an identity "
                        f"that does not own the resource: {other} was "
                        f"granted what {owner} owns")
                    invariant = (
                        "discounts are denied unless the acting identity "
                        "owns the target resource")
                    confirm_evidence = (
                        f"candidate discount application accepted with the "
                        f"discount recorded as applied by {other}, while "
                        "the control application (same identity, own "
                        "resource) is accepted")
                else:
                    statement = (
                        f"{operation} may accept use by an identity that "
                        f"does not own the resource: {other} was granted "
                        f"what {owner} owns")
                    invariant = (
                        "state-changing operations are denied unless the "
                        "acting identity owns the target resource")
                    confirm_evidence = (
                        f"candidate application accepted with a receipt "
                        f"bound to a resource owned by {owner}, while the "
                        "control application (same identity, own "
                        "resource) is accepted")
                hypotheses.append(DifferentialHypothesis(
                    hypothesis_id=slug,
                    family=family,
                    statement=statement,
                    motivating_facts=(
                        f"{operation} is a revealed state-changing "
                        "operation binding a resource by parameter",
                        f"{other} is a correlated identity distinct "
                        f"from the owner {owner}"),
                    invariant=invariant,
                    confirm_evidence=confirm_evidence,
                    falsify_evidence=(
                        "candidate application denied like other "
                        "cross-identity use"),
                    gain=0.65,
                    cost=0.3,
                    preconditions=(
                        "operation and resource binding observed",
                        "candidate identity correlated from grant/deny "
                        "differentials",
                        "control resource owned by the candidate "
                        "identity"),
                    plan=ProbePlan(
                        hypothesis_id=slug, steps=steps,
                        # route the oracle to the cross-identity
                        # application judge (ownership + applier field),
                        # never the pricing judge
                        context=(("probe", "cross_identity_mutation"),)),
                ))
        return hypotheses

    # -- boundary limit (withdrawal ceilings) --------------------------

    def _boundary_hypotheses(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        """Over-limit withdrawal probes against account surfaces.

        Emitted only when the index advertises an operation binding
        an account parameter and an observed account exposes a
        balance-like numeric: the probe withdraws one more than the
        observed balance while the control withdraws exactly the
        balance. Whether the ceiling is real is the oracle's call.
        """
        hypotheses: list[DifferentialHypothesis] = []
        b = self._bindings
        withdrawal_ops = [
            op for op in view.operation_paths
            if op in view.operation_params
            and b.account_param in view.operation_params[op]
            and b.amount_param in view.operation_params[op]
        ]
        accounts = [
            path for path in view.resource_paths
            if b.available_field in (view.numeric_fields.get(path) or {})
        ]
        if not withdrawal_ops or not accounts:
            return hypotheses
        for operation in withdrawal_ops:
            if len(hypotheses) >= self.MAX_HYPOTHESES_PER_FAMILY:
                break
            account = accounts[0]
            owner = view.resource_owner.get(account)
            if not owner:
                continue
            slug = self._slug(FAMILY_BOUNDARY_LIMIT)
            account_id = account.rsplit("/", 1)[-1]
            binding = ((b.account_param, account_id),)
            server_token = "{server:" + account + "}"
            server_plus_token = "{server_plus_one:" + account + "}"
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="GET", path=account, actor=owner),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="POST", path=operation, actor=owner,
                    params=binding + ((b.amount_param,
                                       server_plus_token),)),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="POST", path=operation, actor=owner,
                    params=binding + ((b.amount_param,
                                       server_token),)),
            )
            observed = view.numeric_fields[account][b.available_field]
            hypotheses.append(DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_BOUNDARY_LIMIT,
                statement=(
                    f"{operation} may honor a withdrawal above the "
                    f"observed balance {observed:g}"),
                motivating_facts=(
                    f"{account} exposes a balance-like field "
                    f"({observed:g})",
                    f"{operation} is a revealed withdrawal-shaped "
                    "operation binding an account by parameter"),
                invariant=(
                    "withdrawals above the account's available "
                    "balance are rejected"),
                confirm_evidence=(
                    "candidate withdrawal accepted with a receipt "
                    "showing the balance driven below zero while the "
                    "control (at the observed balance) is accepted"),
                falsify_evidence=(
                    "candidate withdrawal denied as over-limit while "
                    "the control stays accepted"),
                gain=0.7,
                cost=0.3,
                preconditions=(
                    "account balance observed on a revealed path",
                    "withdrawal operation binds an account and an "
                    "amount by parameter",
                    "probe acts as the account owner"),
                plan=ProbePlan(hypothesis_id=slug, steps=steps),
            ))
        return hypotheses

    # -- price integrity (state-changing operations) -----------------

    def _price_hypotheses(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        hypotheses: list[DifferentialHypothesis] = []
        priced = [
            path for path in view.resource_paths
            if view.resource_type.get(path)
            and view.numeric_fields.get(path)
        ] or [
            path for path in view.resource_paths
            if view.numeric_fields.get(path)
        ]
        if not priced or not view.operation_paths:
            return hypotheses
        resource = priced[0]
        owner = view.resource_owner.get(resource)
        if not owner:
            return hypotheses
        for operation in view.operation_paths:
            if len(hypotheses) >= self.MAX_HYPOTHESES_PER_FAMILY:
                break
            # One probe family per operation, repeated across distinct
            # priced resources (capped): a scoped defect (honored for
            # one bucket or collection only) sits behind a different
            # resource than the first probe happens to pick. Evidence:
            # the L8 dev failure analysis — mk-114 was never confirmed
            # because the single priced resource fell outside the
            # honored scope.
            probed: list[str] = []
            for resource in priced:
                if len(hypotheses) >= (
                        self.MAX_HYPOTHESES_PER_FAMILY):
                    break
                if len(probed) >= (
                        self.RESOURCE_PROBES_PER_OPERATION):
                    break
                owner = view.resource_owner.get(resource)
                if not owner:
                    continue
                if resource in probed:
                    continue
                probed.append(resource)
                slug = self._slug(FAMILY_PRICE_INTEGRITY)
                b = self._bindings
                op_params = view.operation_params.get(operation, ())
                if op_params and b.resource_param in op_params and (
                        b.amount_param in op_params):
                    # generalized surface: the operation declares its
                    # parameter names on the index, so the probe binds
                    # the observed resource by parameter.
                    target = operation
                    resource_binding = ((b.resource_param,
                                         resource.rsplit("/", 1)[-1]),)
                    server_token = "{server:" + resource + "}"
                    server_plus_token = (
                        "{server_plus_one:" + resource + "}")
                else:
                    # fixture surface: the resource rides in the path.
                    target = (
                        f"{operation}/{resource.rsplit('/', 1)[-1]}")
                    resource_binding = ()
                    server_token = "{server}"
                    server_plus_token = "{server_plus_one}"
                steps = (
                    ProbeStep(
                        purpose="baseline", label=f"{slug}-base",
                        method="POST", path=target, actor=owner,
                        params=resource_binding + (
                            (b.amount_param, server_token),)),
                    ProbeStep(
                        purpose="candidate", label=f"{slug}-cand",
                        method="POST", path=target, actor=owner,
                        params=resource_binding + (
                            (b.amount_param, server_plus_token),)),
                    ProbeStep(
                        purpose="control", label=f"{slug}-ctrl",
                        method="POST", path=target, actor=owner,
                        params=resource_binding),
                )
                observed = ", ".join(
                    f"{key}={value:g}"
                    for key, value in sorted(
                        view.numeric_fields[resource].items()))
                hypotheses.append(DifferentialHypothesis(
                    hypothesis_id=slug,
                    family=FAMILY_PRICE_INTEGRITY,
                    statement=(
                        f"{operation} may honor a client-supplied price "
                        f"that differs from the authoritative {observed}"),
                    motivating_facts=(
                        f"{resource} exposes authoritative pricing "
                        f"({observed})",
                        f"{operation} is a revealed state-changing "
                        "operation"),
                    invariant=(
                        "the charged amount equals the server-side "
                        "authoritative total"),
                    confirm_evidence=(
                        "candidate receipt charged != authoritative_total "
                        "while the baseline (matching price) and the "
                        "control (no price) match"),
                    falsify_evidence=(
                        "candidate denied (403/409) or charged equals the "
                        "authoritative total"),
                    gain=0.7,
                    cost=0.3,
                    preconditions=(
                        "authoritative numeric field observed on a "
                        "resource",
                        "operation path revealed by the index",
                        "probe acts as the resource owner"),
                    plan=ProbePlan(hypothesis_id=slug, steps=steps),
                ))
        # cross-identity coupon application (published codes only).
        # Which operation accepts a code is not disclosed by the
        # surface: the index reveals bare operation segments, so each
        # published code is probed against every revealed operation
        # once and the fail-closed oracle sorts the leads out. This
        # second probe set is bounded by the number of published codes
        # and revealed operations - both observed counts - with no
        # value combinatorics explored.
        coupon_owner = view.resource_owner.get(priced[0])
        owner = coupon_owner
        other = next(
            (view.identity_of[c]
             for c in sorted(view.identity_of)
             if view.identity_of[c] != owner),
            None,
        )
        if owner is None or other is None:
            return hypotheses
        application_budget = self.MAX_HYPOTHESES_PER_FAMILY
        for code in view.coupon_codes:
            for operation in view.operation_paths:
                if application_budget <= 0:
                    break
                application_budget -= 1
                slug = self._slug(FAMILY_PRICE_INTEGRITY)
                coupon_resource = priced[0].rsplit("/", 1)[-1]
                target = f"{operation}/{coupon_resource}"
                # Multi-step shape: generic receipt, then follow-up reads of
                # the revealed order. The baseline read must precede the
                # candidate's application so it observes the owner-applied
                # state before the candidate overwrites the order; the
                # control applies an unpublished variation of the code to
                # prove the endpoint rejects codes it does not know.
                steps = (
                    ProbeStep(
                        purpose="baseline", label=f"{slug}-base",
                        method="POST", path=target, actor=owner,
                        params=(("code", code),)),
                    ProbeStep(
                        purpose="baseline", label=f"{slug}-base-order",
                        method="GET", path="{revealed}", actor=owner,
                        followup_of=f"{slug}-base"),
                    ProbeStep(
                        purpose="candidate", label=f"{slug}-cand",
                        method="POST", path=target, actor=other,
                        params=(("code", code),)),
                    ProbeStep(
                        purpose="candidate", label=f"{slug}-cand-order",
                        method="GET", path="{revealed}", actor=other,
                        followup_of=f"{slug}-cand"),
                    ProbeStep(
                        purpose="control", label=f"{slug}-ctrl",
                        method="POST", path=target, actor=other,
                        params=(("code", f"{code}-x"),)),
                )
                hypotheses.append(DifferentialHypothesis(
                    hypothesis_id=slug,
                    family=FAMILY_PRICE_INTEGRITY,
                    statement=(
                        f"published code {code} may be applied by a "
                        f"non-owner ({other}) to a resource owned by "
                        f"{owner}"),
                    motivating_facts=(
                        f"code {code} is published on the index surface",
                        f"{target} accepts a code parameter"),
                    invariant=(
                        "only the resource owner may apply a discount "
                        "code to it"),
                    confirm_evidence=(
                        "candidate application accepted and the revealed "
                        "order shows discount_applied_by != owner while "
                        "the owner-applied baseline records the owner"),
                    falsify_evidence=(
                        "candidate application denied like the "
                        "unpublished-code control"),
                    gain=0.7,
                    cost=0.4,
                    preconditions=(
                        "promotion code published on the index",
                        "two distinct observed identities"),
                    plan=ProbePlan(hypothesis_id=slug, steps=steps),
                ))
        return hypotheses

    # -- workflow identity (cross-owner transitions) -----------------

    def _workflow_identity_hypotheses(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        hypotheses: list[DifferentialHypothesis] = []
        b = self._bindings
        submit = (b.action_param, b.submit_action)
        # candidate probe identities: every external identity the
        # surface itself exposed (correlated values plus observed
        # owners). On an open-read surface only one credential may be
        # denial-correlated, but the surface still reveals both
        # identities through its own owner fields.
        candidates = sorted(
            set(view.identity_of.values())
            | set(view.resource_owner.values())
            | set(view.workflow_owner.values()))
        if not candidates or not view.workflow_paths:
            return hypotheses
        for path in view.workflow_paths:
            if len(hypotheses) >= self.MAX_HYPOTHESES_PER_FAMILY:
                break
            owner = view.workflow_owner.get(path)
            if not owner:
                continue
            # L10 Phase 10: the owner invariant covers EVERY gated
            # transition the workflow publishes, not only the entry
            # (submit-role) action. The surface's own action table
            # names the other transitions; each is probed with the
            # same candidate/control pairing and the same invariant.
            # The action values come from the published table — the
            # generator never assumes a fixed vocabulary.
            targets = view.workflow_action_targets.get(path) or {}
            actions: list[str] = sorted(targets)
            if b.submit_action in targets:
                actions = [b.submit_action] + [
                    a for a in actions if a != b.submit_action]
            if not actions:
                actions = [b.submit_action]
            pair = None
            for e in candidates:
                if e == owner:
                    continue
                control_path = next(
                    (w for w in view.workflow_paths
                     if view.workflow_owner.get(w)
                     and view.workflow_owner[w] != owner
                     and view.workflow_owner[w] != e),
                    None)
                control_kind = "third_party"
                if control_path is None:
                    # Two-identity surface: no workflow owned by a
                    # third party. The control becomes the candidate's
                    # OWN workflow, which must accept its owner's
                    # submission; the differential is candidate-denied
                    # vs. self-granted.
                    control_path = next(
                        (w for w in view.workflow_paths
                         if view.workflow_owner.get(w) == e
                         and w != path),
                        None)
                    control_kind = "own"
                if control_path is not None:
                    pair = (e, control_path, control_kind)
                    break
            if pair is None:
                continue
            candidate, control_path, control_kind = pair
            # probes act as the observed external identity (one
            # identity space for the recorded evidence and the oracle)
            identity = candidate
            # document which probed paths carry the surface's own
            # open-access declaration, so the judge can distinguish
            # documented shared intake from an undocumented
            # cross-owner acceptance
            base_context: list[tuple[str, str]] = [
                ("control_kind", control_kind)]
            for probed in (path, control_path):
                if probed in view.documented_open:
                    base_context.append(
                        (f"documented_open:{probed}", "1"))
            # L10 Phase 10: when the surface publishes a grouping
            # (pool) record and two or more distinct group values are
            # observed, a non-entry transition's authority is a GROUP
            # question, not a single-workflow owner question: the
            # surface may delegate that transition to a group-level
            # principal by design, so a cross-group one-workflow
            # differential cannot tell delegated acceptance from a
            # missing identity check. The probe keeps running, but its
            # control changes: it measures the SAME transition against
            # a THIRD-PARTY workflow from the SAME observed group, so
            # group-level delegation cancels out of the differential
            # and a within-group differential is evidence of
            # per-record authority resolution. Without a same-group
            # third-party control the one-workflow probe cannot
            # separate delegation from defect and is not generated;
            # the cross-group survey (_pool_authority_hypotheses)
            # remains the instrument for that shape.
            pool_governed = (
                b.pool_field
                and path in view.workflow_pool
                and len(set(view.workflow_pool.values())) >= 2)
            for action in actions:
                if len(hypotheses) >= self.MAX_HYPOTHESES_PER_FAMILY:
                    break
                context = list(base_context)
                control_for = control_path
                control_params = (submit,)
                if pool_governed and action != b.submit_action:
                    group_value = view.workflow_pool.get(path)
                    same_group = next(
                        (w for w in view.workflow_paths
                         if w != path
                         and view.workflow_pool.get(w) == group_value
                         and view.workflow_owner.get(w)
                         and view.workflow_owner[w] != owner
                         and view.workflow_owner[w] != identity),
                        None)
                    if same_group is None:
                        continue
                    control_for = same_group
                    control_params = ((b.action_param, action),)
                    if control_for in view.documented_open:
                        context.append(
                            (f"documented_open:{control_for}", "1"))
                slug = self._slug(FAMILY_WORKFLOW_IDENTITY)
                steps = (
                    ProbeStep(
                        purpose="baseline", label=f"{slug}-base",
                        method="GET", path=path, actor=identity),
                    ProbeStep(
                        purpose="candidate", label=f"{slug}-cand",
                        method="POST", path=path, actor=identity,
                        params=((b.action_param, action),)),
                    ProbeStep(
                        purpose="control", label=f"{slug}-ctrl",
                        method="POST", path=control_for,
                        actor=identity,
                        params=control_params),
                    # L10 Phase 10: the control transition may itself
                    # move the control workflow; the re-read after it
                    # is what keeps the planner's state belief (and
                    # later setups' hop counts) derived from what the
                    # investigation actually observed, not from a view
                    # that predates the probe.
                    ProbeStep(
                        purpose="control", label=f"{slug}-ctrl-read",
                        method="GET", path=control_for,
                        actor=identity),
                    ProbeStep(
                        purpose="candidate", label=f"{slug}-after",
                        method="GET", path=path, actor=identity),
                )
                hypotheses.append(DifferentialHypothesis(
                    hypothesis_id=slug,
                    family=FAMILY_WORKFLOW_IDENTITY,
                    statement=(
                        f"workflow {path} (owner {owner}) may accept "
                        f"the {action} transition from a non-owner "
                        f"({identity})"),
                    motivating_facts=(
                        f"workflow {path} exposes owner {owner}",
                        f"workflow {path} publishes the {action} "
                        "transition",
                        f"identity {identity} is distinct from {owner} "
                        "on this surface"),
                    invariant=(
                        "only the workflow owner may transition it"),
                    confirm_evidence=(
                        f"candidate {action} applied with "
                        f"transitioned_by = {identity} while the "
                        f"control workflow denies {identity}"),
                    falsify_evidence=(
                        f"candidate {action} denied (403) like the "
                        "control"),
                    gain=0.8,
                    cost=0.4,
                    preconditions=(
                        "workflow owner observed",
                        "candidate identity correlated",
                        "control workflow (third-party-owned, or the "
                        "candidate's own when the surface has two "
                        "identities)"),
                    plan=ProbePlan(
                        hypothesis_id=slug,
                        steps=steps,
                        context=tuple(context)),
                ))
        return hypotheses

    # -- cross-group authority survey (grouped delegation) -----------

    def _workflow_order_hypotheses(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        hypotheses: list[DifferentialHypothesis] = []
        b = self._bindings
        for path in view.workflow_paths:
            if len(hypotheses) >= self.MAX_HYPOTHESES_PER_FAMILY:
                break
            owner = view.workflow_owner.get(path)
            if not owner:
                continue
            # The discriminating action and its target state come from
            # the workflow's own published shape when the index
            # provides one (initial state, action -> state); the
            # fixture vocabulary applies otherwise. The probe skips a
            # state only when the chain actually has one to skip:
            # approve targeting the immediate next state is an
            # in-order action and cannot discriminate.
            chain = view.workflow_chains.get(path)
            targets = view.workflow_action_targets.get(path) or {}
            approve = b.approve_action
            context: tuple[tuple[str, str], ...] = ()
            if chain:
                if b.approve_action not in targets:
                    continue
                expected = targets[b.approve_action]
                if len(chain) < 3 or expected == chain[1]:
                    continue
                context = (
                    ("initial_state", chain[0]),
                    ("expected_state", expected))
            slug = self._slug(FAMILY_WORKFLOW_ORDER)
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="GET", path=path, actor=owner),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="POST", path=path, actor=owner,
                    params=((b.action_param, approve),)),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="POST", path=path, actor=owner,
                    params=((b.action_param, "unknown-action"),)),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-after",
                    method="GET", path=path, actor=owner),
            )
            initial_desc = chain[0] if chain else "draft"
            hypotheses.append(DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_WORKFLOW_ORDER,
                statement=(
                    f"workflow {path} may accept {approve} directly "
                    f"from {initial_desc} (skipping the next "
                    "state in the chain)"),
                motivating_facts=(
                    f"workflow {path} exposes state {initial_desc} "
                    f"and an action parameter"),
                invariant=(
                    "state transitions must follow the published "
                    "chain order"),
                confirm_evidence=(
                    f"{approve} applied from {initial_desc} to its "
                    "target state while an unknown action is "
                    "rejected by the same endpoint"),
                falsify_evidence=(
                    f"{approve} rejected (409 invalid transition) "
                    "while the control is rejected (400)"),
                gain=0.8,
                cost=0.4,
                preconditions=(
                    f"workflow state observed as {initial_desc}",
                    "probe acts as the workflow owner",
                    "instance still in its observed initial state"),
                plan=ProbePlan(hypothesis_id=slug, steps=steps,
                               context=context),
                # WORKFLOW_ORDER is in PRISTINE_FAMILIES: the flag and
                # the proposer's stage schedule must agree.
                pristine_state_required=(
                    FAMILY_WORKFLOW_ORDER
                    in DifferentialGenerator.PRISTINE_FAMILIES),
            ))
        return hypotheses


    def _attach_preconditions(
        self,
        view: RelationshipView,
        hypotheses: list[DifferentialHypothesis],
    ) -> None:
        """Attach structured preconditions to every hypothesis,
        derived from the same wire view the probes use (no new
        authority assumptions). Nothing is marked OBSERVED here: the
        surface exposed these facts on the wire, but only
        PrerequisiteLedger.verify — backed by a recorded observation
        id — may move a precondition to OBSERVED, so everything
        starts INFERRED or ESTABLISHABLE. Workflow-transition
        preconditions are ESTABLISHABLE only where the surface's own
        state description (the index schema chain) shows a way to
        reach the required source state; otherwise they stay
        INFERRED. Hypotheses with no preconditions stay ungated."""
        for hyp in hypotheses:
            preconds: list[Precondition] = []
            # Identity: every actor the plan acts as must be a
            # usable identity on this surface.
            for actor in sorted({s.actor for s in hyp.plan.steps
                                 if s.actor}):
                preconds.append(Precondition(
                    kind=PreconditionKind.IDENTITY,
                    target=f"identity:{actor}",
                    establish_via=(
                        "credential correlation on this surface")))
            if hyp.family in (FAMILY_WORKFLOW_IDENTITY,
                              FAMILY_WORKFLOW_ORDER):
                # Ownership: the workflow's owner is recorded (the
                # invariant under test is owner-scoped).
                for path in sorted({s.path for s in hyp.plan.steps
                                    if s.path in view.workflow_paths}):
                    preconds.append(Precondition(
                        kind=PreconditionKind.OWNERSHIP,
                        target=f"workflow-owner:{path}",
                        establish_via=(
                            "owner field observed on the workflow")))
                # Transition source state: a POST on a workflow path
                # requires the path to sit in the source state its
                # own transition table demands.
                for path in sorted({s.path for s in hyp.plan.steps
                                    if s.method == "POST"
                                    and s.path in view.workflow_paths}):
                    chain = view.workflow_chains.get(path)
                    preconds.append(Precondition(
                        kind=PreconditionKind.WORKFLOW_TRANSITION,
                        target=f"transition:{path}:source-state",
                        status=(PreconditionStatus.ESTABLISHABLE
                                if chain
                                else PreconditionStatus.INFERRED),
                        establish_via=(
                            "authorized setup transition as the "
                            "workflow owner"),
                    ))
            if hyp.pristine_state_required:
                # Ordering precondition: the probed resource must
                # still sit in its observed initial state; the plan's
                # baseline GET re-read verifies it at execution time.
                for path in sorted({s.path for s in hyp.plan.steps}):
                    preconds.append(Precondition(
                        kind=PreconditionKind.APP_STATE,
                        target=f"pristine:{path}",
                        establish_via="baseline GET re-read"))
            if hyp.family == FAMILY_GRANT_REPLAY:
                # Capability: the plan itself mints the token (a
                # setup action inside the probe); the use-count
                # evidence is read from the grant response at
                # judgment time.
                preconds.append(Precondition(
                    kind=PreconditionKind.CAPABILITY,
                    target="capability:grant-token",
                    establish_via=(
                        "authorized grant as the observed subject")))
                preconds.append(Precondition(
                    kind=PreconditionKind.EVIDENCE,
                    target="evidence:grant-use-count",
                    establish_via=(
                        "grant response read at judgment time")))
            hyp.prerequisites = tuple(
                sorted(preconds, key=lambda p: p.target))

    # -- identity boundary (resource reads) -------------------------



    def _pool_authority_hypotheses(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        """Survey a grouped surface's gated transitions across two of
        its own published groups (L10 Phase 10).

        On a surface whose workflows carry a published grouping field
        (bindings.pool_field), a gated transition's authority may be
        delegated to a group-level principal by design. A
        single-workflow differential cannot tell delegated acceptance
        from a missing identity check, so this family surveys the SAME
        transition across TWO distinct groups: one principal per
        probed workflow, every probe cross-owner, so each group's
        observed authority set is built purely from transitions the
        surface itself accepted and refused.

        Two distinct groups that accept identical non-open authority
        sets mean the probed group's transition authority is resolved
        from another group's record (a cross-resource ownership
        boundary failure). Distinct sets mean each group resolves its
        own authority and the observed acceptance is the surface's
        intended delegation: no finding, no false positive.
        """
        hypotheses: list[DifferentialHypothesis] = []
        b = self._bindings
        if not b.pool_field or not view.workflow_pool:
            return hypotheses
        pools: dict[str, list[str]] = {}
        for path in sorted(view.workflow_pool):
            if path in view.workflow_paths:
                pools.setdefault(
                    view.workflow_pool[path], []).append(path)
        if len(pools) < 2:
            return hypotheses
        candidates = sorted(
            set(view.identity_of.values())
            | set(view.resource_owner.values())
            | set(view.workflow_owner.values()))
        if len(candidates) < 2:
            return hypotheses
        pool_names = sorted(pools)[:2]
        group_paths = [pools[name] for name in pool_names]
        shared_actions: set[str] | None = None
        for paths in group_paths:
            acts = {
                action
                for path in paths
                for action in (
                    view.workflow_action_targets.get(path) or {})
                if action != b.submit_action
            }
            shared_actions = acts if shared_actions is None else (
                shared_actions & acts)
        if not shared_actions:
            return hypotheses
        action = sorted(shared_actions)[0]
        # Assign one cross-owner probe per probed workflow: candidate
        # c (sorted) takes the first still-unprobed workflow in the
        # group whose owner is not c, so every probe measures group
        # authority rather than owner self-access.
        assignments: list[list[tuple[str, str]]] = []
        for paths in group_paths:
            taken: list[tuple[str, str]] = []
            used: set[str] = set()
            for cand in candidates:
                if len(taken) >= len(paths):
                    break
                path = next(
                    (p for p in paths if p not in used
                     and view.workflow_owner.get(p)
                     and view.workflow_owner[p] != cand), None)
                if path is not None:
                    used.add(path)
                    taken.append((path, cand))
            if len(taken) < 2:
                return hypotheses
            assignments.append(taken)
        slug = self._slug(FAMILY_IDENTITY_BOUNDARY)
        steps: list[ProbeStep] = []
        context: list[tuple[str, str]] = [
            ("probe", "pool_authority_survey"),
            ("action", action),
        ]
        for pool_idx, (pool_name, taken) in enumerate(
                zip(pool_names, assignments)):
            purpose = "baseline" if pool_idx == 0 else "candidate"
            for n, (path, cand) in enumerate(taken):
                context.append((f"pool:{path}", pool_name))
                context.append((f"owner:{path}",
                                view.workflow_owner[path]))
                if path in view.documented_open:
                    context.append((f"documented_open:{path}", "1"))
                steps.append(ProbeStep(
                    purpose=purpose,
                    label=f"{slug}-g{pool_idx}-base-{n}",
                    method="GET", path=path, actor=cand))
                steps.append(ProbeStep(
                    purpose=purpose,
                    label=f"{slug}-g{pool_idx}-probe-{n}",
                    method="POST", path=path, actor=cand,
                    params=((b.action_param, action),)))
                steps.append(ProbeStep(
                    purpose=purpose,
                    label=f"{slug}-g{pool_idx}-after-{n}",
                    method="GET", path=path, actor=cand))
        statement = (
            f"distinct published groups {pool_names[0]!r} and "
            f"{pool_names[1]!r} accept identical non-open authority "
            f"sets for the {action} transition: the probed group's "
            "transition authority is resolved from another group's "
            "record rather than its own (cross-resource ownership "
            "resolution)")
        hypotheses.append(DifferentialHypothesis(
            hypothesis_id=slug,
            family=FAMILY_IDENTITY_BOUNDARY,
            statement=statement,
            motivating_facts=(
                f"surface publishes grouping field {b.pool_field!r}",
                f"group {pool_names[0]!r} observed on workflows "
                f"{', '.join(group_paths[0])}",
                f"group {pool_names[1]!r} observed on workflows "
                f"{', '.join(group_paths[1])}",
                f"the {action} transition is published on both "
                "groups' workflows"),
            invariant=(
                "a grouped workflow's transition authority resolves "
                "from its own group's record, not from another "
                "group's"),
            confirm_evidence=(
                f"both groups accept {action} from the same principal "
                "set while refusing the remaining principals: "
                "identical non-open authority across distinct groups"),
            falsify_evidence=(
                "the two groups accept distinct principal sets (each "
                "group resolves its own authority: the observed "
                "acceptance is intended delegation)"),
            gain=0.9,
            cost=0.5,
            preconditions=(
                "two distinct published group values observed",
                "one probed workflow per principal per group, each "
                "probe cross-owner",
                "probed workflows reach the transition's source state "
                "through authorized setup hops"),
            plan=ProbePlan(
                hypothesis_id=slug,
                steps=tuple(steps),
                context=tuple(context)),
        ))
        return hypotheses

    # -- grant replay (token consumed beyond its declared uses) ------



    def _grant_replay_hypotheses(
        self, view: RelationshipView,
    ) -> list[DifferentialHypothesis]:
        """Token-authorization invariant: a grant declares how many
        times its token may be consumed; consumption beyond that
        count must be denied.

        Mechanism note (the L7 Step 6 gap this closes): the probe
        needs the minted token VALUE in later steps' params, which the
        response-capture fields on ProbeStep provide. The declared
        use count is read from the grant response at judgment time,
        so deployments that legitimately allow more than one use do
        not trip the oracle.
        """
        hypotheses: list[DifferentialHypothesis] = []
        b = self._bindings
        grant_op = next(
            (op for op in view.operation_paths
             if view.operation_roles.get(op) == "grant"), None)
        consume_op = next(
            (op for op in view.operation_paths
             if view.operation_roles.get(op) == "consume"), None)
        if not grant_op or not consume_op:
            return hypotheses
        grant_params = set(view.operation_params.get(grant_op, ()))
        consume_params = set(view.operation_params.get(consume_op, ()))
        if b.subject_param not in grant_params or (
                b.action_param not in grant_params):
            return hypotheses
        if b.token_param not in consume_params:
            return hypotheses
        # Subject: an identity the surface itself exposed. The grant
        # itself is not the invariant under test, so any observed
        # identity works; the oracle never rests on who minted.
        subject = next(iter(view.resource_owner.values()), None)
        if not subject:
            return hypotheses
        # Action: a transition name the surface publishes. Skipped
        # when none is observable: guessing one is not
        # observation-grounded and would make the grant step itself
        # inconclusive.
        action = next(iter({
            action
            for targets in view.workflow_action_targets.values()
            for action in targets
        }), None)
        if not action:
            return hypotheses
        slug = self._slug(FAMILY_GRANT_REPLAY)
        base_label = f"{slug}-base"
        capture = (
            b.token_param, "{captured}")
        grant_params_tuple = (
            (b.subject_param, subject), (b.action_param, action))
        # One declared use is the tightest published bound, so the
        # probe consumes up to three times: two legitimate uses on a
        # two-use deployment, a third for the replay beyond both.
        consume_steps = tuple(
            ProbeStep(
                purpose="candidate", label=label,
                method="POST", path=consume_op, actor=subject,
                params=(capture,),
                value_from=base_label, value_key=b.token_field)
            for label in (
                f"{slug}-cand", f"{slug}-replay", f"{slug}-third"))
        steps = (
            ProbeStep(
                purpose="baseline", label=base_label,
                method="POST", path=grant_op, actor=subject,
                params=grant_params_tuple),
            *consume_steps,
            ProbeStep(
                purpose="control", label=f"{slug}-ctrl",
                method="POST", path=consume_op, actor=subject,
                # A value the probe never minted: if the endpoint
                # grants it, token validation is absent and the
                # oracle must report no differential instead of a
                # finding.
                params=((b.token_param, subject),)),
        )
        hypotheses.append(DifferentialHypothesis(
            hypothesis_id=slug,
            family=FAMILY_GRANT_REPLAY,
            statement=(
                f"{consume_op} may accept the token issued by "
                f"{grant_op} after the grant's declared use count "
                f"is spent (token minted for {subject})"),
            motivating_facts=(
                f"{grant_op} issues a token carrying a declared use "
                "count",
                f"{consume_op} takes a token parameter and tracks "
                "consumption"),
            invariant=(
                "consumption beyond the declared use count is denied"),
            confirm_evidence=(
                "the minted token was accepted on consumption "
                "beyond its declared use count while an unknown "
                "token is denied"),
            falsify_evidence=(
                "consumption beyond the declared count is denied "
                "(unknown_token or token_exhausted)"),
            gain=0.8,
            cost=0.3,
            preconditions=(
                "grant and consume operations observed",
                "grant declares its use count in its response",
                "an action name is published on the surface"),
            plan=ProbePlan(hypothesis_id=slug, steps=steps),
        ))
        return hypotheses



class DifferentialPrioritizer:
    """Rank hypotheses by estimated gain over action cost."""

    def rank(
        self,
        hypotheses: list[DifferentialHypothesis],
    ) -> list[DifferentialHypothesis]:
        # Two-band stable sort: probes whose discrimination depends on
        # the resource's pristine state (pristine_state_required, e.g.
        # approve-from-draft order probes) run in the first band,
        # before any probe that may advance shared state (e.g.
        # cross-owner submit). Within a band, gain over cost decides;
        # ties keep generation order. This is an execution-ordering
        # precondition carried by the hypothesis, not a change to
        # estimated value.
        return sorted(
            hypotheses,
            key=lambda h: (
                0 if h.pristine_state_required else 1,
                -(h.gain / max(h.cost, 0.1))))


# --------------------------------------------------------------------------
# Experiment port (production path: ActionExecutor + G-02 adapter)
# --------------------------------------------------------------------------

class _SetupTask:
    """Minimal stand-in for planner setup executions: only the id
    participates in the port's task keys (idempotency, ledger).

    UNIFIED MERGE (2026-11-02): restored from the l10 lineage with
    run_setup_steps (L9 §5 invariant: setup actions execute through
    the production action path).
    """

    __slots__ = ("experiment_id",)

    def __init__(self, experiment_id: str) -> None:
        self.experiment_id = experiment_id


class DifferentialExperimentPort(HTTPExperimentPort):
    """Runs differential probe plans through the production path.

    Every step is a CampaignTask executed by the ActionAuthority with
    the G-02 smart_http adapter; scope, capability, budget,
    idempotency and denial handling are inherited unchanged.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ledger = ObservationLedger()
        self._plans: dict[str, ProbePlan] = {}
        self._step_records: dict[str, dict[str, ObservationRecord]] = {}
        self._bindings = DEFAULT_SURFACE_BINDINGS
        # per-experiment remediation ordinal (l10): the planner's
        # post-remediation re-run is a DISTINCT investigation step,
        # so its idempotency tokens derive from the ordinal instead
        # of replaying the first pass (G-02 replay guard).
        self._remediation_ord: dict[str, int] = {}

    # Surface-binding hooks. The L5 controlled fixture answers with
    # the fixed vocabulary below; generalized deployments DERIVE the
    # bindings from the target's own index/schema document during
    # reconnaissance (see _absorb_surface), so every downstream
    # component addresses the surface only through them.
    ACTOR_PARAM = "actor"
    IDEM_PARAM = "idem"
    REVEALED_PATH_KEYS = ("order_path", "note_path", "resource_path")

    @property
    def bindings(self) -> SurfaceBindings:
        return self._bindings

    def _numeric_keys(self) -> tuple[str, ...]:
        return self._bindings.numeric_keys

    def _absorb_surface(self, structured: Any) -> None:
        """Read the deployment's vocabulary off its own index.

        Only the observed index document is consulted: no generator
        metadata, no deployment internals. A surface without a schema
        block keeps the default (fixture) vocabulary.
        """
        schema = (
            structured.get("schema")
            if isinstance(structured, dict) else None)
        derived = SurfaceBindings.from_schema(schema)
        if derived is not None:
            self._bindings = derived

    # -- plan registry ------------------------------------------------

    def register_plan(self, plan: ProbePlan) -> None:
        self._plans[plan.hypothesis_id] = plan

    def plan_for(self, signature: str) -> ProbePlan:
        hypothesis_id = signature.rsplit("/", 1)[0]
        plan = self._plans.get(hypothesis_id)
        if plan is None:
            raise ValueError(
                f"no registered differential plan for {signature!r}")
        return plan

    # -- reconnaissance (read-only) -----------------------------------

    def reconnaissance(
        self,
        bootstrap_actor: str,
        index_path: str = "/",
        second_actor: str | None = None,
    ) -> list[dict[str, Any]]:
        observations: list[dict[str, Any]] = []
        index_obs = self._observe(
            index_path, {}, "differential-recon-index")
        observations.append(index_obs)
        self.ledger.append("", "GET", index_path, {}, index_obs)
        structured = index_obs.get("structured")
        # Bind the surface vocabulary from the observed index BEFORE
        # any probe: the actor parameter the sweep uses comes from
        # the target's own schema, not from a hard-coded name.
        self._absorb_surface(structured)
        actor_param = self._bindings.actor_param
        paths: list[str] = []
        if isinstance(structured, dict):
            api = structured.get("api") or {}
            if isinstance(api, dict):
                for group in sorted(api):
                    entries = api[group]
                    if not isinstance(entries, list):
                        continue
                    group_paths: list[str] = []
                    for entry in entries:
                        if isinstance(entry, str):
                            group_paths.append(entry)
                        elif isinstance(entry, dict) and isinstance(
                                entry.get("path"), str):
                            group_paths.append(entry["path"])
                    if not _group_is_operations(
                            structured, group, group_paths):
                        paths.extend(group_paths)
        # Both engine-held synthetic credentials sweep the revealed
        # read surface: the grant/deny differential between them is
        # what correlates each credential to its external identity.
        sweep_actors = (
            (bootstrap_actor, second_actor)
            if second_actor else (bootstrap_actor,))
        for actor in sweep_actors:
            for path in paths:
                observation = self._observe(
                    path, {actor_param: actor},
                    f"differential-recon-{actor}-{path}")
                observations.append(observation)
                self.ledger.append(
                    actor, "GET", path, {actor_param: actor},
                    observation)
        return observations

    # -- setup execution and remediation ordinals (L9/L10) -------------

    def mark_remediated(self, experiment_id: str) -> None:
        """Record that the planner's remediation re-runs this
        experiment: the next execute() derives the re-run's
        idempotency tokens from the remediation ordinal instead of
        the original ones.
        """
        self._remediation_ord[experiment_id] = (
            self._remediation_ord.get(experiment_id, 0) + 1)

    def run_setup_steps(
        self,
        steps: tuple[ProbeStep, ...],
        experiment_id: str,
    ) -> dict[str, ObservationRecord]:
        """Execute planner setup steps through the SAME action path
        as every probe: the authority, the G-02 wrappers, the
        idempotency key and the observation ledger. The planner
        proposes; this port executes — nothing here bypasses scope,
        capability or authorization checks (L9 §5). Returns each
        step's ObservationRecord by label so the caller can verify
        the re-read (HTTP success alone never proves a transition).
        """
        executed: dict[str, ObservationRecord] = {}
        task = _SetupTask(f"{experiment_id}-setup")
        ordinal = self._remediation_ord.get(experiment_id, 0)
        for step in steps:
            executed[step.label] = self._run_step(
                step, task, executed, attempt=ordinal)
        return executed

    def _stamp_documented_open(
        self, context: dict[str, Any]
    ) -> None:
        """Carry the surface's own documented-open vocabulary into
        the composite context at execution time (L9 §2
        prior_observation). Restored from the l10 lineage.
        """
        view = RelationshipTracker(
            self.ledger, bindings=self._bindings).view()
        documented = set(view.documented_open)
        if not documented:
            return
        for path in documented:
            context.setdefault(f"documented_open:{path}", "1")

    # -- execution ------------------------------------------------------

    def execute(
        self, experiment: ProposedExperiment,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        plan = self.plan_for(experiment.signature)
        attempt = self._remediation_ord.get(
            experiment.experiment_id, 0)
        executed: dict[str, ObservationRecord] = {}
        for step in plan.steps:
            executed[step.label] = self._run_step(step, experiment,
                                                  executed,
                                                  attempt=attempt)
        self._step_records[experiment.experiment_id] = executed
        surface = self._bindings.to_mapping()
        context = plan.context_dict()
        self._stamp_documented_open(context)
        composites = []
        for purpose in ("baseline", "candidate", "control"):
            steps = [
                record.to_step(step.label, step.purpose)
                for step in plan.steps
                if step.purpose == purpose
                and (record := executed.get(step.label)) is not None
            ]
            composites.append({
                "purpose": purpose,
                "family": experiment.family,
                "hypothesis_id": plan.hypothesis_id,
                "experiment_id": experiment.experiment_id,
                # The oracle judges against the surface vocabulary the
                # evidence was produced under, never against a fixed
                # one.
                "surface": surface,
                "context": context,
                "steps": steps,
            })
        baseline, candidate, control = composites
        return baseline, candidate, control

    def _run_step(
        self,
        step: ProbeStep,
        experiment: ProposedExperiment,
        executed: dict[str, ObservationRecord],
        attempt: int = 1,
    ) -> ObservationRecord:
        task_key = f"{experiment.experiment_id}-{step.label}"
        if attempt:
            # The planner's post-remediation re-run is a distinct
            # investigation step: its deterministic idempotency
            # token derives from the remediation ordinal, so the
            # executor's replay guard treats it as new work. Plain
            # repetitions of the experiment (blind replay, resume,
            # selector re-selection) keep the original token and
            # deduplicate against it.
            task_key = f"{task_key}-m{attempt}"
        path = step.path
        if step.followup_of:
            parent = executed.get(step.followup_of)
            revealed = self._revealed_path(parent) if parent else None
            if not revealed:
                observation = _placeholder_observation(
                    path, "path_unrevealed")
                return self.ledger.append(
                    step.actor, step.method, path,
                    dict(step.params), observation)
            path = revealed
        params = self._resolve_step_params(dict(step.params))
        # Response-capture: "{captured}" resolves from an earlier
        # step's response. Missing parent, missing field or a
        # non-string value fails closed: the step records an
        # unresolved-parameters observation rather than executing
        # with a guessed value.
        if any(value == "{captured}" for value in params.values()):
            parent = executed.get(step.value_from) if step.value_from \
                else None
            captured = self._captured_value(parent, step.value_key)
            if captured is None:
                observation = _placeholder_observation(
                    path, "unresolved_parameters")
                return self.ledger.append(
                    step.actor, step.method, path,
                    dict(step.params), observation)
            params = {
                key: captured if value == "{captured}" else value
                for key, value in params.items()
            }
        # The step's declared actor IS the request identity: it must
        # travel on the wire, not only in the ledger record. Without
        # this the target sees an unauthenticated actor and every
        # identity-dependent observation is meaningless.
        if step.actor and self._bindings.actor_param not in params:
            params[self._bindings.actor_param] = step.actor
        unresolved = any(
            "{server" in value for value in params.values())
        if unresolved:
            observation = _placeholder_observation(
                path, "unresolved_parameters")
            return self.ledger.append(
                step.actor, step.method, path, params, observation)
        if step.method == "POST":
            params.setdefault(
                self._bindings.idem_param, _sha256(task_key)[:16])
            observation = self._observe_post(path, params, task_key)
        else:
            observation = self._observe(path, params, task_key)
        return self.ledger.append(
            step.actor, step.method, path, params, observation)

    def _revealed_path(
        self, record: ObservationRecord | None,
    ) -> str | None:
        if record is None:
            return None
        structured = record.structured
        if not isinstance(structured, dict):
            return None
        for key in self._bindings.revealed_path_keys:
            value = structured.get(key)
            if isinstance(value, str) and value.startswith("/"):
                return value[:MAX_REVEALED_PATH_LENGTH]
        return None


    @staticmethod
    def _captured_value(
        record: ObservationRecord | None, key: str,
    ) -> str | None:
        """The captured response value from an earlier step.

        Only non-empty string fields count: a value the surface did
        not return stays unresolved and the dependent step fails
        closed."""
        if record is None or not key:
            return None
        structured = record.structured
        if not isinstance(structured, dict):
            return None
        value = structured.get(key)
        if not isinstance(value, str) or not value:
            return None
        return value

    def _resolve_step_params(
        self, params: dict[str, str],
    ) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for key, value in params.items():
            if value.startswith("{server") and value.endswith("}"):
                token = value[1:-1]
                scope = token.split(":", 1)[1] if ":" in token else None
                server = self._server_value(scope)
                if server is not None:
                    if token.startswith("server_plus_one"):
                        value = self._format_number(server + 1)
                    else:
                        value = self._format_number(server)
            resolved[key] = value
        return resolved

    @staticmethod
    def _format_number(value: float) -> str:
        return str(int(value)) if float(value).is_integer() else (
            f"{value:g}")

    def _server_value(self, scope: str | None = None) -> float | None:
        """First observed numeric, optionally scoped to one path.

        Scoping keeps a probe's baseline value tied to the exact
        resource the probe varies (an account's balance, an item's
        authoritative total) instead of whichever numeric the
        ledger happened to record first.
        """
        for record in self.ledger.records:
            if scope is not None and record.path != scope:
                continue
            structured = record.structured
            if not isinstance(structured, dict):
                continue
            for key in self._numeric_keys():
                value = structured.get(key)
                if isinstance(value, (int, float)) and not isinstance(
                        value, bool):
                    return float(value)
        return None


# --------------------------------------------------------------------------
# Validation (fail-closed family oracles)
# --------------------------------------------------------------------------

def _inconclusive(
    reason: str, disposition: str = DISPOSITION_EVIDENCE_MISSING,
) -> dict[str, Any]:
    return {
        "verdict": VERDICT_INCONCLUSIVE,
        "reason": reason,
        "disposition": disposition,
    }


def _clean(reason: str) -> dict[str, Any]:
    return {"verdict": VERDICT_CLEAN, "reason": reason}


def _confirmed(
    predicate: str, reason: str,
) -> dict[str, Any]:
    return {
        "verdict": VERDICT_CONFIRMED,
        "reason": reason,
        "violated_predicate": predicate,
    }


def _blocked(
    reason: str,
    disposition: str = DISPOSITION_ACTION_BLOCKED,
) -> dict[str, Any]:
    return {
        "verdict": VERDICT_BLOCKED,
        "reason": reason,
        "disposition": disposition,
    }


class DifferentialValidationPort:
    """Deterministic family oracles over recorded observations.

    Fail-closed: no executed observation is BLOCKED; a missing or
    contradictory differential is INCONCLUSIVE; an acceptance
    without the discriminating evidence is never CONFIRMED. Every
    surface name an oracle matches on comes from the composite's own
    surface bindings (carried on the evidence itself), and every
    denial is read off the target's declared outcome when the
    surface publishes one: a bare status code never establishes a
    denial on a surface that corroborates outcomes.
    """

    @staticmethod
    def _bindings(
        composite: dict[str, Any],
    ) -> SurfaceBindings:
        return SurfaceBindings.from_mapping(composite.get("surface"))

    @staticmethod
    def _context(composite: dict[str, Any]) -> dict[str, str]:
        context = composite.get("context")
        return dict(context) if isinstance(context, dict) else {}

    @staticmethod
    def _first(
        composite: dict[str, Any], suffix: str,
    ) -> dict[str, Any] | None:
        for step in composite.get("steps", []):
            if step.get("label", "").endswith(suffix):
                return step
        return None

    @staticmethod
    def _outcome(
        step: dict[str, Any] | None, bindings: SurfaceBindings,
    ) -> str:
        """Classify a step: granted / denied / no_evidence /
        contradictory. When the surface publishes an authorization
        outcome header, the header and the status code must agree;
        either alone is not evidence on such a surface."""
        if not _step_executed(step):
            return "no_evidence"
        headers = step.get("headers") or {}
        status = step.get("status_code")
        header = (
            headers.get(bindings.outcome_header)
            if bindings.outcome_header else None)
        if status == 200:
            if header and header == bindings.outcome_denied:
                return "contradictory"
            return "granted"
        if header and header != bindings.outcome_denied:
            return "contradictory"
        return "denied"

    @staticmethod
    def _state_refused(
        step: dict[str, Any] | None, bindings: SurfaceBindings,
    ) -> bool:
        """True when the executed step was refused by the workflow's
        own state machine: the response body names the state field
        (the surface's declared vocabulary for a transition refusal
        that reports the current state). An identity refusal carries
        no state field on such a surface, so the two are
        distinguishable by the surface's own response shape alone.

        UNIFIED MERGE (2026-11-02): restored from the l10 lineage
        with the workflow-identity judge that reads it.
        """
        if not _step_executed(step):
            return False
        structured = (step or {}).get("structured") or {}
        return isinstance(structured, dict) and (
            bindings.state_field in structured)

    def validate(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        family = baseline.get("family", "")
        steps = (
            baseline.get("steps", [])
            + candidate.get("steps", [])
            + control.get("steps", []))
        if not any(_step_executed(step) for step in steps):
            return _blocked("no observations were executed")
        if family == FAMILY_IDENTITY_BOUNDARY:
            probe = self._context(baseline).get("probe")
            if probe == "cross_identity_mutation":
                judge = self._judge_mutation
            elif probe == "mutual_read":
                judge = self._judge_mutual_read
            elif probe == "pool_authority_survey":
                judge = self._judge_pool_authority
            else:
                judge = self._judge_identity
        elif family == FAMILY_PRICE_INTEGRITY:
            if self._context(baseline).get("probe") == (
                    "cross_identity_mutation"):
                judge = self._judge_mutation
            else:
                judge = self._judge_price
        elif family == FAMILY_GRANT_REPLAY:
            judge = self._judge_grant_replay
        elif family == FAMILY_WORKFLOW_IDENTITY:
            judge = self._judge_workflow_identity
        elif family == FAMILY_WORKFLOW_ORDER:
            judge = self._judge_workflow_order
        elif family == FAMILY_BOUNDARY_LIMIT:
            judge = self._judge_boundary
        else:
            return _blocked("unrecognized family")
        return judge(baseline, candidate, control)

    # -- identity boundary (resource reads) -------------------------

    def _judge_identity(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        bindings = self._bindings(baseline)
        cand_step = self._first(candidate, "-cand")
        ctrl_step = self._first(control, "-ctrl")
        if not _step_executed(cand_step) or not _step_executed(
                ctrl_step):
            if _step_blocked(cand_step) or _step_blocked(ctrl_step):
                return _blocked(
                    "candidate or control observation was blocked by "
                    "the authority")
            return _inconclusive(
                "candidate or control observation missing")
        cand_outcome = self._outcome(cand_step, bindings)
        if cand_outcome == "contradictory":
            return _inconclusive(
                "candidate read outcome contradicts its status "
                "evidence")
        if cand_outcome == "denied":
            return _clean(
                "candidate cross-identity read was denied like the "
                "control")
        structured = cand_step.get("structured") or {}
        owner = structured.get(bindings.owner_field)
        if not owner:
            header = (cand_step.get("headers") or {}).get(
                bindings.owner_header)
            owner = header
        if not owner:
            return _inconclusive(
                "granted read without ownership evidence")
        if owner == cand_step.get("actor"):
            return _clean("candidate read its own resource")
        ctrl_outcome = self._outcome(ctrl_step, bindings)
        if ctrl_outcome == "contradictory":
            return _inconclusive(
                "control read outcome contradicts its status "
                "evidence")
        if ctrl_outcome == "granted":
            return _inconclusive(
                "control read also granted: candidate identity may "
                "be broadly privileged",
                DISPOSITION_NO_DIFFERENTIAL)
        return _confirmed(
            "cross_identity_read_allowed",
            f"identity {cand_step.get('actor')} was granted a read "
            f"of a resource owned by {owner} while its control read "
            "of a foreign resource was denied")

    def _judge_mutual_read(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        """Two distinct credentials, two distinct exposed owners.

        Reaching this judge means the recon sweep observed no denied
        read at all. The verdict rests on the probe itself: the
        candidate and control reads were each granted on a resource
        exposing a different owner, so two distinct identities were
        granted what at least one of them cannot own."""
        bindings = self._bindings(baseline)
        cand_step = self._first(candidate, "-cand")
        ctrl_step = self._first(control, "-ctrl")
        if not _step_executed(cand_step) or not _step_executed(
                ctrl_step):
            if _step_blocked(cand_step) or _step_blocked(ctrl_step):
                return _blocked(
                    "candidate or control observation was blocked by "
                    "the authority")
            return _inconclusive(
                "candidate or control observation missing")
        base_step = self._first(baseline, "-base")
        base_outcome = self._outcome(base_step, bindings)
        if base_outcome == "denied":
            return _inconclusive(
                "baseline read was denied: ownership is enforced "
                "somewhere, so the mutual grant is not interpretable",
                DISPOSITION_NO_DIFFERENTIAL)
        if base_outcome == "contradictory":
            return _inconclusive(
                "baseline read outcome contradicts its status "
                "evidence")
        cand_outcome = self._outcome(cand_step, bindings)
        if cand_outcome == "contradictory":
            return _inconclusive(
                "candidate read outcome contradicts its status "
                "evidence")
        if cand_outcome == "denied":
            return _clean(
                "one cross-owner read was denied: the boundary is "
                "enforced")
        ctrl_outcome = self._outcome(ctrl_step, bindings)
        if ctrl_outcome == "contradictory":
            return _inconclusive(
                "control read outcome contradicts its status "
                "evidence")
        if ctrl_outcome == "denied":
            return _clean(
                "one cross-owner read was denied: the boundary is "
                "enforced")
        cand_owner = (cand_step.get("structured") or {}).get(
            bindings.owner_field)
        ctrl_owner = (ctrl_step.get("structured") or {}).get(
            bindings.owner_field)
        if not isinstance(cand_owner, str) or not isinstance(
                ctrl_owner, str):
            return _inconclusive(
                "granted reads without ownership evidence")
        if cand_owner == ctrl_owner:
            return _inconclusive(
                "both granted reads expose the same owner: "
                "cross-owner exposure not established",
                DISPOSITION_NO_DIFFERENTIAL)
        if cand_step.get("actor") == ctrl_step.get("actor"):
            return _inconclusive(
                "candidate and control ran as the same identity",
                DISPOSITION_NO_DIFFERENTIAL)
        return _confirmed(
            "cross_identity_read_allowed",
            f"identities {cand_step.get('actor')} and "
            f"{ctrl_step.get('actor')} were each granted reads of "
            f"resources owned by different identities "
            f"({cand_owner}, {ctrl_owner}) while no read was "
            "denied")

    # -- cross-identity applications (charge / discount shaped) ------

    def _judge_mutation(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        bindings = self._bindings(baseline)
        base_step = self._first(baseline, "-base")
        cand_step = self._first(candidate, "-cand")
        ctrl_step = self._first(control, "-ctrl")
        if not _step_executed(cand_step) or not _step_executed(
                ctrl_step):
            if _step_blocked(cand_step) or _step_blocked(ctrl_step):
                return _blocked(
                    "candidate or control observation was blocked by "
                    "the authority")
            return _inconclusive(
                "candidate or control observation missing")
        cand_outcome = self._outcome(cand_step, bindings)
        if cand_outcome == "contradictory":
            return _inconclusive(
                "candidate application outcome contradicts its "
                "status evidence")
        if cand_outcome == "denied":
            return _clean(
                "candidate cross-identity application was denied")
        structured = cand_step.get("structured") or {}
        if not isinstance(structured, dict):
            return _inconclusive(
                "accepted application without structured evidence")
        owner = structured.get(bindings.owner_field)
        if not owner:
            return _inconclusive(
                "accepted application without ownership evidence")
        base_outcome = self._outcome(base_step, bindings)
        if base_outcome == "contradictory":
            return _inconclusive(
                "baseline application outcome contradicts its "
                "status evidence")
        if base_outcome == "denied":
            return _inconclusive(
                "baseline (owner) application was also denied: the "
                "endpoint may not process applications at all",
                DISPOSITION_NO_DIFFERENTIAL)
        ctrl_outcome = self._outcome(ctrl_step, bindings)
        if ctrl_outcome == "contradictory":
            return _inconclusive(
                "control application outcome contradicts its "
                "status evidence")
        if ctrl_outcome != "granted":
            return _inconclusive(
                "control application (same identity, own resource) "
                "was not granted: the candidate identity may lack "
                "operation access",
                DISPOSITION_NO_DIFFERENTIAL)
        if owner == cand_step.get("actor"):
            return _clean(
                "candidate application targeted a resource it owns")
        applied_by = structured.get(bindings.discount_applied_by_field)
        if isinstance(applied_by, str) and applied_by == (
                cand_step.get("actor")):
            return _confirmed(
                "cross_owner_discount_applied",
                f"discount recorded as applied by {applied_by} on a "
                f"resource owned by {owner} while the same "
                "identity's control application (own resource) was "
                "granted")
        return _confirmed(
            "cross_identity_application_allowed",
            f"identity {cand_step.get('actor')} was granted an "
            f"application bound to a resource owned by {owner} "
            "while its control application (own resource) was "
            "granted")

    # -- price integrity (state-changing operations) -----------------

    def _judge_price(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        bindings = self._bindings(baseline)
        # Multi-step coupon shape: the plan carries follow-up reads of
        # the revealed order ("-cand-order"), so the discriminating
        # evidence is the order's applier field, not the receipt.
        for composite in (baseline, candidate, control):
            for step in composite.get("steps", []):
                if step.get("label", "").endswith("-cand-order"):
                    return self._judge_multi_step_discount(
                        baseline, candidate, control)

        def pricing(step: dict[str, Any] | None) -> tuple[Any, Any]:
            structured = (step or {}).get("structured") or {}
            charged = structured.get(bindings.charged_field)
            authoritative = structured.get(bindings.authoritative_field)
            return charged, authoritative

        base_step = self._first(baseline, "-base")
        cand_step = self._first(candidate, "-cand")
        ctrl_step = self._first(control, "-ctrl")
        if not _step_executed(cand_step):
            return _blocked(
                "candidate observation missing",
                DISPOSITION_EVIDENCE_MISSING)
        cand_outcome = self._outcome(cand_step, bindings)
        if cand_outcome == "contradictory":
            return _inconclusive(
                "candidate application outcome contradicts its "
                "status evidence")
        if cand_outcome == "denied":
            return _clean(
                "overriding amount was denied")
        cand_charged, cand_authoritative = pricing(cand_step)
        if cand_charged is None or cand_authoritative is None:
            return _inconclusive(
                "accepted operation without pricing evidence")
        if cand_charged != cand_authoritative:
            ctrl_charged, ctrl_authoritative = pricing(ctrl_step)
            if _step_executed(ctrl_step) and ctrl_charged is not None:
                if ctrl_charged == ctrl_authoritative:
                    return _confirmed(
                        "client_amount_honored_over_authoritative",
                        f"accepted amount {cand_charged} differs from "
                        f"the authoritative total "
                        f"{cand_authoritative} while the control "
                        f"charged {ctrl_charged} equal to its "
                        "authoritative total")
                return _inconclusive(
                    "control also charged an amount differing from "
                    "its authoritative total",
                    DISPOSITION_NO_DIFFERENTIAL)
            return _inconclusive(
                "accepted amount differs from the authoritative "
                "total without control pricing evidence")
        base_charged, base_authoritative = pricing(base_step)
        if _step_executed(base_step) and base_charged is not None and (
                base_charged != base_authoritative):
            return _inconclusive(
                "baseline (matching amount) also diverged from the "
                "authoritative total",
                DISPOSITION_NO_DIFFERENTIAL)
        return _clean(
            "accepted amount equals the authoritative total")

    def _judge_multi_step_discount(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        """Multi-step price shape: a generic acceptance receipt plus a
        follow-up read of the revealed order. The receipt carries no
        pricing or ownership context, so the discriminating evidence is
        the order's applier field, corroborated by the owner-applied
        baseline read."""
        bindings = self._bindings(baseline)
        base_order = self._first(baseline, "-base-order")
        cand_step = self._first(candidate, "-cand")
        cand_order = self._first(candidate, "-cand-order")
        ctrl_step = self._first(control, "-ctrl")
        if not _step_executed(cand_step):
            return _blocked(
                "candidate application observation missing",
                DISPOSITION_EVIDENCE_MISSING)
        cand_outcome = self._outcome(cand_step, bindings)
        if cand_outcome == "contradictory":
            return _inconclusive(
                "candidate application outcome contradicts its "
                "status evidence")
        if cand_outcome == "denied":
            return _clean("candidate application was denied")
        if not _step_executed(ctrl_step):
            return _blocked(
                "control application observation missing",
                DISPOSITION_EVIDENCE_MISSING)
        ctrl_outcome = self._outcome(ctrl_step, bindings)
        if ctrl_outcome == "contradictory":
            return _inconclusive(
                "control application outcome contradicts its status "
                "evidence")
        if ctrl_outcome == "granted":
            return _inconclusive(
                "control (unpublished code) was also accepted; the "
                "endpoint does not validate codes",
                DISPOSITION_NO_DIFFERENTIAL)
        if not _step_executed(cand_order) or cand_order.get(
                "status_code") != 200:
            return _inconclusive(
                "accepted application without a readable revealed "
                "order")
        structured = cand_order.get("structured") or {}
        if not isinstance(structured, dict):
            return _inconclusive(
                "revealed order returned no structured state")
        owner = structured.get(bindings.owner_field)
        applied_by = structured.get(bindings.discount_applied_by_field)
        if not owner or not applied_by:
            return _inconclusive(
                "revealed order without ownership or applier evidence")
        if not _step_executed(base_order) or base_order.get(
                "status_code") != 200:
            return _inconclusive(
                "no executed baseline read of the revealed order")
        base_struct = base_order.get("structured") or {}
        if not isinstance(base_struct, dict):
            return _inconclusive(
                "baseline order returned no structured state")
        if (base_struct.get(bindings.owner_field) != owner
                or base_struct.get(
                    bindings.discount_applied_by_field) != owner):
            return _inconclusive(
                "baseline (owner-applied) order does not record the "
                "owner as the applier",
                DISPOSITION_NO_DIFFERENTIAL)
        actor = cand_step.get("actor")
        if applied_by == owner:
            return _clean(
                "discount was applied by the resource owner")
        if applied_by != actor:
            return _inconclusive(
                "order records an applier that is neither the owner "
                "nor the candidate identity")
        return _confirmed(
            "cross_owner_discount_applied",
            f"non-owner {applied_by} applied a discount to a resource "
            f"owned by {owner} while the unpublished-code control was "
            "rejected")

    # -- boundary limit (withdrawal ceilings) -------------------------

    def _judge_boundary(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        bindings = self._bindings(baseline)
        base_step = self._first(baseline, "-base")
        cand_step = self._first(candidate, "-cand")
        ctrl_step = self._first(control, "-ctrl")
        if not _step_executed(cand_step) or not _step_executed(
                ctrl_step):
            if _step_blocked(cand_step) or _step_blocked(ctrl_step):
                return _blocked(
                    "candidate or control observation was blocked by "
                    "the authority")
            return _inconclusive(
                "candidate or control observation missing")
        base_outcome = self._outcome(base_step, bindings)
        if base_outcome != "granted":
            return _inconclusive(
                "no pre-withdrawal balance evidence: the account "
                "read did not succeed",
                DISPOSITION_EVIDENCE_MISSING)
        ctrl_outcome = self._outcome(ctrl_step, bindings)
        if ctrl_outcome == "contradictory":
            return _inconclusive(
                "control withdrawal outcome contradicts its status "
                "evidence")
        if ctrl_outcome != "granted":
            return _inconclusive(
                "control withdrawal (within balance) was not "
                "accepted: the endpoint may not process withdrawals "
                "at all",
                DISPOSITION_NO_DIFFERENTIAL)
        cand_outcome = self._outcome(cand_step, bindings)
        if cand_outcome == "contradictory":
            return _inconclusive(
                "candidate withdrawal outcome contradicts its "
                "status evidence")
        if cand_outcome == "denied":
            return _clean(
                "over-limit withdrawal was denied while the "
                "within-balance control was accepted")
        structured = cand_step.get("structured") or {}
        if not isinstance(structured, dict):
            return _inconclusive(
                "accepted withdrawal without structured evidence")
        available = structured.get(bindings.available_field)
        if not isinstance(available, (int, float)) or isinstance(
                available, bool):
            return _inconclusive(
                "accepted withdrawal without balance evidence")
        if available >= 0:
            return _inconclusive(
                "accepted withdrawal did not drive the balance below "
                "zero; the withdrawn amount may not exceed the "
                "balance")
        return _confirmed(
            "over_limit_withdrawal_accepted",
            f"withdrawal accepted with balance driven to {available:g} "
            "while the within-balance control was accepted")

    # -- workflow identity (state transitions) ------------------------

    def _judge_workflow_identity(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        bindings = self._bindings(baseline)

        def applied(step: dict[str, Any] | None) -> bool:
            structured = (step or {}).get("structured") or {}
            if not isinstance(structured, dict):
                return False
            value = structured.get(bindings.applied_field)
            return value is True

        base_step = self._first(baseline, "-base")
        cand_step = self._first(candidate, "-cand")
        ctrl_step = self._first(control, "-ctrl")
        context = self._context(baseline)
        control_kind = context.get("control_kind", "third_party")
        if not _step_executed(cand_step) or not _step_executed(
                ctrl_step):
            if _step_blocked(cand_step) or _step_blocked(ctrl_step):
                return _blocked(
                    "candidate or control observation was blocked by "
                    "the authority")
            return _inconclusive(
                "candidate or control observation missing")
        cand_outcome = self._outcome(cand_step, bindings)
        if cand_outcome == "contradictory":
            return _inconclusive(
                "candidate submission outcome contradicts its "
                "status evidence")
        if cand_outcome == "denied":
            # Classify the refusal by the surface's own response
            # vocabulary before treating it as an identity decision
            # (L9 §4): a body that names the workflow's state field is
            # a state-machine refusal (the transition is not legal
            # from the observed state), not an identity decision. A
            # state-machine refusal leaves the identity question
            # unresolved: the experiment never reached the invariant,
            # so this is inconclusive evidence that a precondition was
            # not established — never a clean verdict and never a
            # finding.
            cand_structured = cand_step.get("structured") or {}
            if isinstance(cand_structured, dict) and (
                    bindings.state_field in cand_structured):
                return _inconclusive(
                    "candidate transition was refused by the "
                    "workflow's own state machine before any identity "
                    "decision: the required source state was not "
                    "established",
                    DISPOSITION_ACTION_BLOCKED)
            # Identity-shaped refusal: consult the control before
            # emitting clean. A granted-and-applied third-party control
            # means the same identity that was refused here WAS
            # accepted on another owner's workflow: ownership is
            # checked on one path and not on the other, which is the
            # defect under test — unless the surface's own
            # documentation declares that path open to any identity
            # (documented shared intake is intended behavior, not a
            # differential).
            ctrl_outcome = self._outcome(ctrl_step, bindings)
            if ctrl_outcome == "contradictory":
                return _inconclusive(
                    "control submission outcome contradicts its "
                    "status evidence")
            if (ctrl_outcome == "granted" and applied(ctrl_step)
                    and control_kind == "third_party"):
                ctrl_path = ctrl_step.get("path")
                if context.get(f"documented_open:{ctrl_path}") == "1":
                    return _clean(
                        "the control workflow accepts non-owner "
                        "submissions as the surface's own documented "
                        "shared-intake behavior; the probed workflow "
                        "refused the cross-owner submission")
                return _confirmed(
                    "cross_owner_transition_accepted",
                    f"identity {cand_step.get('actor')} was refused on "
                    f"{cand_step.get('path')} but its submission was "
                    f"applied on {ctrl_path}, a workflow owned by "
                    "another identity (ownership is not checked "
                    "there)")
            if ctrl_outcome == "denied" and self._state_refused(
                    ctrl_step, bindings):
                # The control never made an identity decision: it was
                # refused by the workflow's own state machine because
                # its source state no longer holds. A clean resting on
                # that refusal would be a false negative machine, so
                # the outcome is a blocked precondition — the planner
                # (or a re-planned probe) must re-establish the state
                # before this comparison can mean anything.
                return _inconclusive(
                    "control submission was refused by the workflow's "
                    "own state machine before any identity decision: "
                    "the required source state was not established",
                    DISPOSITION_ACTION_BLOCKED)
            return _clean(
                "candidate cross-owner submission was denied like "
                "the control")
        if applied(cand_step):
            # A path whose acceptance of any-identity transitions is
            # the surface's own documented behavior is not a
            # differential: the acceptance is intended, whoever it is
            # attributed to.
            if context.get(
                    f"documented_open:{cand_step.get('path')}") == "1":
                return _clean(
                    "the workflow accepts non-owner submissions as "
                    "the surface's own documented shared-intake "
                    "behavior")
            structured = cand_step.get("structured") or {}
            transitioned_by = structured.get(
                bindings.transitioned_by_field)
            if isinstance(transitioned_by, str) and (
                    transitioned_by != cand_step.get("actor")):
                return _inconclusive(
                    "submission applied by a third identity; cannot "
                    "attribute the transition to the candidate")
            base_outcome = self._outcome(base_step, bindings)
            if base_outcome != "granted":
                return _inconclusive(
                    "baseline (owner) submission was not granted: "
                    "the workflow may not process submissions at all",
                    DISPOSITION_NO_DIFFERENTIAL)
            # The differential's premise is a CROSS-owner transition:
            # verify from the surface's own body that the recorded
            # owner is a different identity than the candidate.
            base_structured = base_step.get("structured") or {}
            owner_value = base_structured.get(bindings.owner_field)
            if isinstance(owner_value, str) and (
                    owner_value == cand_step.get("actor")):
                return _clean(
                    "the accepted submission came from the workflow's "
                    "recorded owner; no cross-owner transition was "
                    "probed")
            # §5: an HTTP success never proves a transition. When the
            # surface's own re-read (the plan's post-submission GET)
            # exposes the state field, a confirmation requires the
            # re-read to show the workflow moved off the state the
            # baseline observed; a reported-applied transition that
            # leaves the state unchanged is not evidenced.
            after_step = self._first(candidate, "-after")
            after_structured = (after_step or {}).get("structured") or {}
            state_field = bindings.state_field
            if (isinstance(base_structured, dict)
                    and isinstance(after_structured, dict)
                    and state_field in base_structured
                    and state_field in after_structured
                    and after_structured[state_field]
                    == base_structured[state_field]):
                return _inconclusive(
                    "the candidate submission reported an applied "
                    "transition, but the post-submission re-read shows "
                    "the workflow in its pre-submission state: the "
                    "transition succeeded without state evidence",
                    DISPOSITION_EVIDENCE_MISSING)
            ctrl_outcome = self._outcome(ctrl_step, bindings)
            if ctrl_outcome == "contradictory":
                return _inconclusive(
                    "control submission outcome contradicts its "
                    "status evidence")
            if ctrl_outcome == "granted" and applied(ctrl_step):
                if control_kind == "third_party":
                    return _inconclusive(
                        "control submission also applied: candidate "
                        "identity may be broadly privileged",
                        DISPOSITION_NO_DIFFERENTIAL)
                # own-workflow control: the candidate must succeed on
                # its own workflow; the differential is that the same
                # submission on ANOTHER owner's workflow also applied
                return _confirmed(
                    "cross_owner_transition_accepted",
                    f"identity {cand_step.get('actor')} was granted a "
                    "transition on a workflow owned by "
                    f"{base_step.get('actor') if base_step else 'another'} "
                    "while its own workflow accepts it as the owner "
                    "(ownership is not checked)")
            ctrl_state_refused = ctrl_outcome == "denied" and (
                self._state_refused(ctrl_step, bindings))
            if control_kind == "own" and ctrl_outcome != "granted":
                if ctrl_state_refused:
                    # The control was refused by its own state machine
                    # before any identity decision (typically because
                    # an earlier probe consumed its source state; on a
                    # forward-only workflow that state is
                    # unattainable). This cannot discount the
                    # candidate's acceptance: an own-workflow control
                    # that DID reach an identity decision confirms
                    # whether granted or denied, so the comparison
                    # rests on the directly evidenced cross-owner
                    # transition (applied flag, owner attribution and
                    # the re-read), not on the control. Parking this
                    # outcome inconclusive was the §4 false-negative
                    # shape.
                    return _confirmed(
                        "cross_owner_transition_accepted",
                        f"identity {cand_step.get('actor')} was granted "
                        "a transition on a workflow owned by "
                        f"{base_step.get('actor') if base_step else 'another'} "
                        "while the control workflow's own state machine "
                        "refused its submission before any identity "
                        "decision (ownership is not checked)")
                return _inconclusive(
                    "the candidate's own workflow did not accept its "
                    "submission; the surface is not comparable",
                    DISPOSITION_NO_DIFFERENTIAL)
            if ctrl_state_refused:
                # A third-party control refused by its own state
                # machine: whether it would have accepted or refused
                # the candidate identity is unknown, so the
                # broad-privilege alternative cannot be ruled out.
                # Blocked precondition, never a verdict.
                return _inconclusive(
                    "the control submission was refused by its "
                    "workflow's own state machine before any identity "
                    "decision: the required source state was not "
                    "established",
                    DISPOSITION_ACTION_BLOCKED)
            return _confirmed(
                "cross_owner_transition_accepted",
                f"identity {cand_step.get('actor')} was granted a "
                f"transition on a workflow owned by "
                f"{base_step.get('actor') if base_step else 'another'} "
                "while its control transition was denied "
                "(ownership is not checked)")
        return _clean(
            "candidate cross-owner submission was not applied")

    # -- pool authority survey (cross-group delegation, L10) ---------

    @staticmethod
    def _pool_triples(
        composite: dict[str, Any],
    ) -> list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
        """Group a survey composite's steps into per-workflow
        (base, probe, after) triples by the labels the survey
        published (``<slug>-g<N>-{base|probe|after}-<k>``). A
        composite whose survey steps do not parse into complete
        triples yields no evidence rather than a partial verdict."""
        roles: dict[str, dict[str, dict[str, Any]]] = {}
        order: list[str] = []
        for step in composite.get("steps", []):
            parts = (step.get("label") or "").rsplit("-", 2)
            if len(parts) != 3 or parts[1] not in (
                    "base", "probe", "after"):
                continue
            key = parts[2]
            bucket = roles.setdefault(key, {})
            if parts[1] in bucket:
                return []
            bucket[parts[1]] = step
            if key not in order:
                order.append(key)
        triples: list[tuple[dict[str, Any], dict[str, Any],
                            dict[str, Any]]] = []
        for key in order:
            bucket = roles[key]
            if set(bucket) != {"base", "probe", "after"}:
                return []
            triples.append((
                bucket["base"], bucket["probe"], bucket["after"]))
        return triples

    def _judge_pool_authority(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        """Cross-group transition-authority survey (L10 Phase 10).

        Each group's composite is compared as a whole: every probed
        workflow contributes a base GET, a cross-owner transition
        POST and an after GET, and the group's observed authority set
        is the set of principals whose transition the surface itself
        accepted (applied plus re-read state evidence, never a bare
        status code). CONFIRMED requires BOTH groups to accept the
        SAME non-empty principal set while refusing the SAME non-empty
        remainder: identical non-open authority across two distinct
        published groups means the probed group's transition authority
        resolves from another group's record. Distinct sets mean each
        group resolves its own authority and the observed acceptance
        is intended delegation: clean. Acceptance open to every probed
        principal is the surface's own designed-open behavior and
        confirms nothing. Any state-machine refusal means a
        precondition was never established: ACTION_BLOCKED, so the
        planner re-plans the setup instead of the verdict resting on
        it.
        """
        bindings = self._bindings(baseline)
        accepted: list[set[str]] = []
        refused: list[set[str]] = []
        for composite in (baseline, candidate):
            acc: set[str] = set()
            ref: set[str] = set()
            triples = self._pool_triples(composite)
            if not triples:
                return _inconclusive(
                    "no complete group observations were recorded")
            for base, probe, after in triples:
                if not _step_executed(probe):
                    if _step_blocked(probe):
                        return _blocked(
                            "a group probe was blocked by the "
                            "authority")
                    return _inconclusive(
                        "a group probe did not execute")
                outcome = self._outcome(probe, bindings)
                if outcome == "contradictory":
                    return _inconclusive(
                        "a group probe outcome contradicts its status "
                        "evidence")
                actor = probe.get("actor")
                if outcome == "denied":
                    structured = probe.get("structured") or {}
                    if isinstance(structured, dict) and (
                            bindings.state_field in structured):
                        return _inconclusive(
                            "a group transition was refused by the "
                            "workflow's own state machine before any "
                            "identity decision: the required source "
                            "state was not established",
                            DISPOSITION_ACTION_BLOCKED)
                    ref.add(actor)
                    continue
                structured = probe.get("structured") or {}
                if structured.get(bindings.applied_field) is not True:
                    return _inconclusive(
                        "a group transition was granted without "
                        "applied evidence")
                # §5: an HTTP success never proves a transition. When
                # both re-reads expose the state field, acceptance
                # requires the after re-read to move off the base
                # state; a reported-applied transition that leaves the
                # state unchanged is not evidenced.
                base_structured = (base or {}).get("structured") or {}
                after_structured = (
                    (after or {}).get("structured") or {})
                state_field = bindings.state_field
                if (isinstance(base_structured, dict)
                        and isinstance(after_structured, dict)
                        and state_field in base_structured
                        and state_field in after_structured
                        and after_structured[state_field]
                        == base_structured[state_field]):
                    return _inconclusive(
                        "a group transition reported applied, but the "
                        "post-transition re-read shows the workflow "
                        "in its pre-transition state",
                        DISPOSITION_EVIDENCE_MISSING)
                acc.add(actor)
            accepted.append(acc)
            refused.append(ref)
        if accepted[0] != accepted[1] or refused[0] != refused[1]:
            return _clean(
                "the two published groups accept or refuse distinct "
                "principal sets for the same transition: each group "
                "resolves its own authority, so the observed "
                "acceptance is the surface's intended delegation")
        if not accepted[0]:
            return _clean(
                "neither group accepted any cross-owner transition: "
                "no cross-group authority resolution was demonstrated")
        if not refused[0]:
            return _clean(
                "both groups accept every probed principal: the "
                "transition is open by the surface's own behavior, "
                "not resolved from another group's record")
        return _confirmed(
            "cross_resource_authority_resolution",
            f"distinct published groups accept the identical non-open "
            f"principal set {sorted(accepted[0])!r} and refuse the "
            f"identical remainder {sorted(refused[0])!r} for the same "
            "transition: the probed group's transition authority "
            "resolves from another group's record rather than its own")

    # -- grant replay (token beyond declared uses) -------------------

    def _judge_grant_replay(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        bindings = self._bindings(baseline)
        base_step = self._first(baseline, "-base")
        cand_step = self._first(candidate, "-cand")
        replay_step = self._first(candidate, "-replay")
        third_step = self._first(candidate, "-third")
        ctrl_step = self._first(control, "-ctrl")
        consume_steps = (cand_step, replay_step, third_step)
        if not _step_executed(base_step):
            if _step_blocked(base_step):
                return _blocked(
                    "grant baseline was blocked by the authority")
            return _inconclusive("grant baseline missing")
        base_struct = base_step.get("structured") or {}
        declared = base_struct.get(bindings.uses_allowed_field)
        if isinstance(declared, bool) or not isinstance(declared, int):
            return _inconclusive(
                "the grant response did not declare a use count",
                DISPOSITION_EVIDENCE_MISSING)
        token_value = base_struct.get(bindings.token_field)
        if not isinstance(token_value, str) or not token_value:
            return _inconclusive(
                "the grant response did not carry a minted token",
                DISPOSITION_EVIDENCE_MISSING)
        if not _step_executed(ctrl_step):
            if _step_blocked(ctrl_step):
                return _blocked(
                    "control observation was blocked by the "
                    "authority")
            return _inconclusive(
                "control observation missing")
        if any(_step_blocked(step) for step in consume_steps):
            return _blocked(
                "a consume observation was blocked by the authority")
        ctrl_outcome = self._outcome(ctrl_step, bindings)
        if ctrl_outcome == "contradictory":
            return _inconclusive(
                "control outcome contradicts its status evidence")
        if ctrl_outcome == "granted":
            return _inconclusive(
                "the consume endpoint accepted a token that was "
                "never minted; it may not validate tokens at all",
                DISPOSITION_NO_DIFFERENTIAL)
        outcomes = {
            step.get("label", ""): self._outcome(step, bindings)
            for step in consume_steps if _step_executed(step)
        }
        if any(value == "contradictory" for value in outcomes.values()):
            return _inconclusive(
                "a consume outcome contradicts its status evidence")
        granted = sum(value == "granted" for value in outcomes.values())
        if granted > declared:
            return _confirmed(
                "token_accepted_beyond_declared_uses",
                f"the minted token was accepted {granted} times "
                f"while the grant declared {declared} use(s), and "
                "an unknown token was denied by the same endpoint")
        if len(outcomes) == len(consume_steps):
            return _clean(
                f"consumption was limited to the grant's declared "
                f"use count ({declared})")
        return _inconclusive(
            "fewer consume observations than planned; the declared "
            "use count is not exhausted by the evidence",
            DISPOSITION_EVIDENCE_MISSING)

    # -- workflow order (transition sequence) -------------------------

    def _judge_workflow_order(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        bindings = self._bindings(baseline)
        context = self._context(baseline)
        initial_state = context.get("initial_state", "draft")
        expected_state = context.get("expected_state", "approved")
        base_step = self._first(baseline, "-base")
        cand_step = self._first(candidate, "-cand")
        ctrl_step = self._first(control, "-ctrl")
        after_step = self._first(candidate, "-after")
        if not _step_executed(cand_step) or not _step_executed(
                ctrl_step):
            if _step_blocked(cand_step) or _step_blocked(ctrl_step):
                return _blocked(
                    "candidate or control observation was blocked by "
                    "the authority")
            return _inconclusive(
                "candidate or control observation missing")
        base_state = (base_step.get("structured") or {}).get(
            bindings.state_field)
        if not isinstance(base_state, str):
            return _inconclusive(
                "workflow state not observed before the probe",
                DISPOSITION_EVIDENCE_MISSING)
        if base_state != initial_state:
            return _inconclusive(
                f"workflow already in {base_state}; the probe needs "
                f"the pristine {initial_state} state",
                DISPOSITION_EVIDENCE_MISSING)
        ctrl_outcome = self._outcome(ctrl_step, bindings)
        if ctrl_outcome == "contradictory":
            return _inconclusive(
                "control outcome contradicts its status evidence")
        if ctrl_outcome == "granted":
            return _inconclusive(
                "control accepted an unknown action; the endpoint "
                "may not validate actions at all",
                DISPOSITION_NO_DIFFERENTIAL)
        cand_outcome = self._outcome(cand_step, bindings)
        if cand_outcome == "contradictory":
            return _inconclusive(
                "candidate outcome contradicts its status evidence")
        if cand_outcome == "denied":
            return _clean(
                f"{initial_state}->{expected_state} was rejected as "
                "an invalid transition while the control was "
                "rejected (400)")
        structured = cand_step.get("structured") or {}
        if not isinstance(structured, dict) or structured.get(
                bindings.applied_field) is not True:
            return _inconclusive(
                "accepted request without applied evidence")
        after_state = structured.get(bindings.state_field)
        if not isinstance(after_state, str) and _step_executed(
                after_step):
            after_struct = after_step.get("structured") or {}
            if isinstance(after_struct, dict):
                after_state = after_struct.get(bindings.state_field)
        if after_state == expected_state:
            return _confirmed(
                "out_of_order_transition_accepted",
                f"{context.get('probe_action', 'approve')} was "
                f"applied directly from {initial_state} to "
                f"{expected_state}, skipping the next state, while "
                "an unknown action was rejected by the same "
                "endpoint")
        return _inconclusive(
            "applied request without state evidence of the skipped "
            "transition")




# --------------------------------------------------------------------------
# Sealed proof bundles (same seal/replay contract as the Logic Breaker)
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Sealed proof bundles (same seal/replay contract as the Logic Breaker)
# --------------------------------------------------------------------------

@dataclass
class DifferentialProofBundle:
    """Sealed evidence bundle for a differential verdict.

    The seal covers the target identity, the hypothesis identity, the
    raw evidence digests and the oracle verdict, and is recomputed
    from raw observations at verification time.
    """

    target_identity: str
    case_identity: str
    baseline: dict[str, Any]
    candidate: dict[str, Any]
    control: dict[str, Any]
    causal_result: dict[str, Any]
    semantic_evidence: dict[str, Any]
    source_provenance: dict[str, Any]
    runtime_provenance: dict[str, Any]
    evidence_digests: dict[str, str] = field(default_factory=dict)
    deterministic_seal: str = ""
    is_sealed: bool = False

    def __post_init__(self) -> None:
        if not self.evidence_digests:
            self.evidence_digests = {
                "baseline_sha256": _digest(self.baseline),
                "candidate_sha256": _digest(self.candidate),
                "control_sha256": _digest(self.control),
            }
        if not self.deterministic_seal:
            self.deterministic_seal = self._compute_seal()
            self.is_sealed = True

    def _compute_seal(self) -> str:
        return _digest({
            "bundle_kind": "egaie_differential_proof_v1",
            "target_identity": self.target_identity,
            "case_identity": self.case_identity,
            "baseline_digest": _digest(self.baseline),
            "candidate_digest": _digest(self.candidate),
            "control_digest": _digest(self.control),
            "oracle_verdict": self.causal_result.get("verdict", ""),
        })

    def verify_seal(self) -> bool:
        return self._compute_seal() == self.deterministic_seal


class DifferentialProofBundlePort:
    """Build and replay-verify sealed differential proof bundles.

    Replay re-runs the differential oracle on the recorded
    observations and compares verdict, digests, seal and target
    identity. No HTTP request is ever re-issued.
    """

    def __init__(
        self,
        expected_target_identity: str = DEFAULT_TARGET_IDENTITY,
    ) -> None:
        self._expected_target_identity = expected_target_identity
        self._oracle = DifferentialValidationPort()
        self._runtime_provenance = {
            "mode": "controlled_local_http_target",
            "offline": False,
            "transport": "action_executor",
        }

    def build(
        self,
        experiment: ProposedExperiment,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
        causal_result: dict[str, Any],
    ) -> DifferentialProofBundle:
        return DifferentialProofBundle(
            target_identity=DEFAULT_TARGET_IDENTITY,
            case_identity=experiment.experiment_id,
            baseline=dict(baseline),
            candidate=dict(candidate),
            control=dict(control),
            causal_result=dict(causal_result),
            semantic_evidence={
                "precondition": (
                    "active_probe_idempotent_per_token_on_"
                    "controlled_target"),
                "vulnerability_class": experiment.family,
                "experiment_id": experiment.experiment_id,
                "statement": experiment.description,
                "oracle": "differential_behavioral",
            },
            source_provenance={
                "source": "egaie",
                "component": "DifferentialProofBundlePort",
                "validation": "egaie.differential_oracle",
            },
            runtime_provenance=dict(self._runtime_provenance),
        )

    def verify(self, bundle: DifferentialProofBundle) -> dict[str, Any]:
        identity_match = (
            bundle.target_identity == self._expected_target_identity)
        recomputed = {
            "baseline_sha256": _digest(bundle.baseline),
            "candidate_sha256": _digest(bundle.candidate),
            "control_sha256": _digest(bundle.control),
        }
        digest_match = all(
            recomputed[name] == bundle.evidence_digests.get(name)
            for name in recomputed
        )
        seal_valid = bundle.verify_seal()
        replayed = self._oracle.validate(
            bundle.baseline, bundle.candidate, bundle.control)
        verdict_match = (
            replayed.get("verdict")
            == bundle.causal_result.get("verdict"))
        return {
            "replay_valid": bool(
                identity_match and digest_match and seal_valid
                and verdict_match),
            "seal_valid": seal_valid,
            "verdict_match": verdict_match,
            "digest_match": digest_match,
            "identity_match": identity_match,
        }


# --------------------------------------------------------------------------
# Proposer (single orchestrator, propose phase)
# --------------------------------------------------------------------------

_RECON_ORIGIN_PREFIX = "differential:recon:"
class DifferentialProposer:
    """Advisory proposer: discovery hypotheses for the orchestrator.

    On the first propose() call it runs read-only reconnaissance,
    derives bounded hypotheses from the observations, registers their
    probe plans with the experiment port and adds the hypothesis
    records to the investigation state. Every emitted experiment still
    runs through the full differential-oracle + sealed-bundle + replay
    pipeline and can never confirm anything by itself.

    Emission is staged by scheduling precondition. Hypotheses whose
    discrimination requires a resource in its pristine state
    (pristine_state_required) are proposed first; the remaining
    hypotheses go on the table only once every pristine-state
    experiment has a recorded outcome. The selector scores pending
    experiments by information gain every round and would otherwise
    interleave the bands, letting state-advancing probes destroy the
    precondition later probes depend on. The stage boundary is derived
    from the investigation state alone, so a resumed run continues the
    schedule instead of replaying it.
    """

    def __init__(
        self,
        port: DifferentialExperimentPort,
        bootstrap_actor: str = ACTOR_A,
        second_actor: str | None = ACTOR_B,
        generator: DifferentialGenerator | None = None,
        prioritizer: DifferentialPrioritizer | None = None,
    ) -> None:
        self._port = port
        self._bootstrap_actor = bootstrap_actor
        self._second_actor = second_actor
        self._generator = generator or DifferentialGenerator()
        self._prioritizer = prioritizer or DifferentialPrioritizer()
        self._deferred: list[DifferentialHypothesis] | None = None

    def _bound_generator(self) -> DifferentialGenerator:
        """The generator addressing the surface only through the
        vocabulary the target itself published during reconnaissance.
        A caller-supplied custom generator is honored as-is."""
        if isinstance(self._generator, DifferentialGenerator):
            return DifferentialGenerator(self._port.bindings)
        return self._generator

    def propose(
        self, state: InvestigationState,
    ) -> list[ProposedExperiment]:
        pristine = DifferentialGenerator.PRISTINE_FAMILIES
        recon_origins = [
            record.origin[len(_RECON_ORIGIN_PREFIX):]
            for record in state.hypotheses
            if record.origin.startswith(_RECON_ORIGIN_PREFIX)
        ]
        if not recon_origins:
            self._port.reconnaissance(
                self._bootstrap_actor, second_actor=self._second_actor)
            view = RelationshipTracker(
                self._port.ledger, bindings=self._port.bindings).view()
            ranked = self._prioritizer.rank(
                self._bound_generator().generate(view))
            first = [
                h for h in ranked if h.pristine_state_required]
            self._deferred = [
                h for h in ranked if not h.pristine_state_required]
            if not first:
                # No pristine-state family exists on this surface:
                # the stage boundary has nothing to wait for, so
                # the deferred band is emitted at once. Without
                # this, a boundary-only or price-only surface
                # stalls — the orchestrator ends as
                # objectives_complete on the empty first band and
                # stage 2 never runs.
                first, self._deferred = self._deferred, None
            return self._emit(state, first)
        # Stage 2 already emitted: a non-pristine-family recon
        # hypothesis can only exist after the deferred band went out.
        if any(
            record.family not in pristine
            for record in state.hypotheses
            if record.origin.startswith(_RECON_ORIGIN_PREFIX)
        ):
            return []
        # Stage 2 waits: every pristine-state experiment must have a
        # recorded outcome before state-advancing probes are proposed.
        recon_experiment_ids = {
            f"e-{slug}" for slug in recon_origins}
        if any(
            experiment.experiment_id in recon_experiment_ids
            and experiment.family in pristine
            and experiment.experiment_id not in state.experiment_outcomes
            for experiment in state.experiments
        ):
            return []
        if self._deferred is not None:
            deferred, self._deferred = self._deferred, None
            return self._emit(state, deferred)
        # Resumed mid-schedule: rebuild the deferred band from the
        # ledger view. Only non-pristine families can be missing here,
        # so slug counters cannot collide with emitted hypotheses.
        view = RelationshipTracker(
            self._port.ledger, bindings=self._port.bindings).view()
        ranked = self._prioritizer.rank(
            self._bound_generator().generate(view))
        return self._emit(
            state, [h for h in ranked if not h.pristine_state_required])

    def _emit(
        self,
        state: InvestigationState,
        hypotheses: list[DifferentialHypothesis],
    ) -> list[ProposedExperiment]:
        experiments: list[ProposedExperiment] = []
        for hypothesis in hypotheses:
            self._port.register_plan(hypothesis.plan)
            state.add_hypothesis(HypothesisRecord(
                hypothesis_id=f"h-{hypothesis.hypothesis_id}",
                family=hypothesis.family,
                statement=hypothesis.statement,
                # origin doubles as the confirmed-case identity: the
                # slug, prefixed differential:recon: to mark provenance.
                origin=(
                    f"{_RECON_ORIGIN_PREFIX}"
                    f"{hypothesis.hypothesis_id}"),
                status=HypothesisStatus.PROPOSED,
            ))
            experiments.append(hypothesis.to_experiment())
        return experiments


def build_differential_experiment_port(
    *,
    target: Any,
    engagement_id: str,
    campaign_id: str,
    authorization: EngagementAuthorization,
    settings: Settings,
) -> DifferentialExperimentPort:
    """Build the differential port on a full production runtime (the
    real path), mirroring build_logic_experiment_port."""
    from webpent.egaie.http_port import _manifest
    from webpent.shared.g02_contract import (
        G02_HTTP_APPROVAL_EXPIRY,
        G02_HTTP_CANONICAL_WRAPPER,
        G02_HTTP_INVENTORY_REF,
        G02_HTTP_PROOF_CONTRACT,
        G02_HTTP_SCOPE_POLICY,
    )
    from webpent.shared.runtime import (
        AdapterRegistry,
        RegisteredAdapter,
        RuntimeFactory,
    )

    registry = AdapterRegistry()
    runtime = RuntimeFactory.create(
        engagement_id=engagement_id,
        campaign_id=campaign_id,
        target_origin=authorization.target_origin,
        settings=settings,
        manifest=_manifest(settings),
        use_default_ledger=False,
        adapters=registry,
    )
    port = DifferentialExperimentPort(
        target=target,
        engagement_id=engagement_id,
        campaign_id=campaign_id,
        authorization=authorization,
        settings=settings,
        runtime=runtime,
    )
    # Registration must precede the first execution (the authority
    # resolves the adapter at execute time, not at construction).
    registry.register(RegisteredAdapter(
        name="smart_http",
        capability="smart_http_execution",
        transport="http",
        handler=port._transport_handler,
        policy_checked=True,
        canonical_wrapper=G02_HTTP_CANONICAL_WRAPPER,
        scope_policy=G02_HTTP_SCOPE_POLICY,
        static_inventory_ref=G02_HTTP_INVENTORY_REF,
        proof_contract=G02_HTTP_PROOF_CONTRACT,
        expires_at=G02_HTTP_APPROVAL_EXPIRY,
    ))
    return port
