"""L7 Step 4: the four benchmark configurations as one orchestrator API.

Mission section 4 demands four fair configurations on the same lab
surface, all of which generate AND execute candidate experiments:

  adaptive: the L6 engine unchanged (gain-ranked proposer,
      information-gain selector);
  independent-fixed: an independently written candidate generator with
      deterministic (insertion-order) scheduling;
  adaptive-no-selector: the adaptive proposer WITHOUT the gain
      selector (pure insertion order), isolating the selector's
      contribution;
  observation-baseline: a simple observation-driven baseline that
      tests explicit security invariants with no access to hidden
      labels.

Shared between configurations, by design and documented here: the
observation contract (reconnaissance through the production path),
the validation oracle, the sealed ProofBundle port, and the request
budgets. NOT shared: candidate generation logic and scheduling. The
independent-fixed and observation-baseline generators observe the
SAME published surface as the adaptive engine but write their own
templates, pick their own candidates, and schedule deterministically
through the same _NoopSelector.

What this module must NOT do: let any strategy see lab labels, and
let a zero-candidate configuration masquerade as a valid baseline.
Every strategy here proposes executable ProbePlans through the same
port machinery; if a strategy proposes nothing, the benchmark harness
records zero requests, not zero defects.

Documented limitation: the GRANT_REPLAY family (lab-102) needs a
consume-then-replay probe whose replay step must carry the token the
consume step just received. The shared step schema cannot carry a
response value into a later step's parameters, so NO strategy emits
an executable grant probe in step 4; section 6 addresses the family
only with a mechanism change justified by the measured failure, not
by relabeling.
"""
from __future__ import annotations

from typing import Any

from webpent.egaie.differential import (
    FAMILY_BOUNDARY_LIMIT,
    FAMILY_GRANT_REPLAY,
    FAMILY_IDENTITY_BOUNDARY,
    FAMILY_PRICE_INTEGRITY,
    FAMILY_WORKFLOW_IDENTITY,
    FAMILY_WORKFLOW_ORDER,
    DifferentialGenerator,
    DifferentialHypothesis,
    DifferentialProofBundlePort,
    DifferentialProposer,
    DifferentialValidationPort,
    ProbePlan,
    ProbeStep,
    RelationshipTracker,
)
from webpent.egaie.discovery_runner import (
    _build_orchestrator,
    _LedgerModelPort,
    _NoopSelector,
)
from webpent.egaie.orchestrator import InvestigationOrchestrator
from webpent.egaie.planner import PlannerConfig, StatefulPlanner
from webpent.egaie.schemas import HypothesisRecord, HypothesisStatus

STRATEGY_NAMES = (
    "adaptive",
    "independent-fixed",
    "adaptive-no-selector",
    "observation-baseline",
)

# Origin prefixes. The observation-baseline and the independent-fixed
# strategies record their own namespaces so per-strategy request and
# hypothesis metrics are separable from the adaptive engine's raw logs
# (mission section 2 instrumentation carries through unchanged).
INDEPENDENT_ORIGIN = "independent:recon:"
BASELINE_ORIGIN = "baseline:rule:"

_FAMILY_SLUG = {
    FAMILY_IDENTITY_BOUNDARY: "ident",
    FAMILY_PRICE_INTEGRITY: "price",
    FAMILY_WORKFLOW_IDENTITY: "wfid",
    FAMILY_WORKFLOW_ORDER: "wforder",
    FAMILY_BOUNDARY_LIMIT: "spend",
    FAMILY_GRANT_REPLAY: "grant",
}


class _SlugCounter:
    """Deterministic per-family hypothesis ids (stable across runs)."""

    def __init__(self, prefix: str) -> None:
        self._prefix = prefix
        self._counts: dict[str, int] = {}

    def next(self, family: str) -> str:
        n = self._counts.get(family, 0) + 1
        self._counts[family] = n
        return f"{self._prefix}{n}-{_FAMILY_SLUG[family]}"


# --------------------------------------------------------------------------
# Shared reconnaissance mixin
# --------------------------------------------------------------------------


class _ReconMixin:
    """Build a relationship view from the production recon path.

    The port's reconnaissance runs through the same ActionAuthority
    and G-02 adapter as every probe and appends its observations to
    the port's ledger; the view is then derived from that ledger. No
    strategy touches labels, and none bypasses the production path.
    """

    _bootstrap_actor: str = "actor-a"
    _second_actor: str = "actor-b"

    port: Any
    _view: Any | None = None

    def _recon(self) -> Any:
        if self._view is not None:
            return self._view
        self.port.reconnaissance(
            self._bootstrap_actor, second_actor=self._second_actor)
        # reconnaissance already appended to the ledger; derive the
        # view from the ledger (never from fixture data).
        self._view = RelationshipTracker(
            self.port.ledger,
            bindings=self.port.bindings,
        ).view()
        return self._view


# --------------------------------------------------------------------------
# Shared view helpers (observation-derived, independent of labels)
# --------------------------------------------------------------------------


def _external_identities(view: Any) -> list[str]:
    """Every external identity the surface itself exposed."""
    return sorted(
        set(view.identity_of.values())
        | set(view.resource_owner.values())
        | set(view.workflow_owner.values()))


def _typed_owned_resource(view: Any, owner: str | None) -> str | None:
    """A resource path with a type and (optionally) this owner."""
    return next(
        (p for p in view.resource_paths
         if view.resource_type.get(p)
         and (owner is None or view.resource_owner.get(p) == owner)),
        None)


def _identity_control_pair(
    view: Any, path: str, owner: str, identities: list[str],
) -> tuple[str, str, str] | None:
    """Pick (identity, control workflow, control kind) for a
    non-owner-transition probe. A third-party-owned control confirms
    cleanly (the control must deny); with only two identities, the
    candidate's own workflow is the control (the control must
    accept)."""
    for identity in identities:
        if identity == owner:
            continue
        control = next(
            (w for w in view.workflow_paths
             if view.workflow_owner.get(w)
             and view.workflow_owner[w] != owner
             and view.workflow_owner[w] != identity),
            None)
        if control is not None:
            return identity, control, "third_party"
        own = next(
            (w for w in view.workflow_paths
             if view.workflow_owner.get(w) == identity
             and w != path),
            None)
        if own is not None:
            return identity, own, "own"
    return None


# --------------------------------------------------------------------------
# Config B: independent-fixed
# --------------------------------------------------------------------------


class IndependentProposer(_ReconMixin):
    """Independently written candidate generator, deterministic order.

    Own templates and own hypothesis ids (namespace ``bx``), staged
    emission: pristine workflow-order probes first, then everything
    else once the pristine probes have recorded outcomes (or
    immediately when no pristine probe applies). Insertion order is
    the schedule (the _NoopSelector enforces nothing else).
    """

    _MAX_PER_FAMILY = 3

    def __init__(self, port: Any) -> None:
        self.port = port
        self._view = None
        self._slugs = _SlugCounter("bx")
        self._deferred: list[DifferentialHypothesis] | None = None

    # -- orchestration API -------------------------------------------

    def propose(self, state: Any) -> list[Any]:
        view = self._recon()
        if not view.workflow_paths and not view.operation_paths:
            return []
        if self._deferred is None and not self._own_hypotheses(state):
            pristine = self._pristine_hypotheses(view)
            if pristine:
                return self._emit(state, pristine)
            # nothing pristine applies: one round, all families
            deferred, self._deferred = self._deferred, None
            return self._emit(state, deferred or [])
        if self._own_hypotheses(state):
            if self._deferred is None or self._pristine_pending(state):
                return []
            deferred, self._deferred = self._deferred, None
            return self._emit(state, deferred)
        return []

    def _own_hypotheses(self, state: Any) -> bool:
        return any(
            r.origin.startswith(INDEPENDENT_ORIGIN)
            for r in state.hypotheses)

    def _pristine_pending(self, state: Any) -> bool:
        ids = {
            f"e-{r.origin[len(INDEPENDENT_ORIGIN):]}"
            for r in state.hypotheses
            if r.origin.startswith(INDEPENDENT_ORIGIN)}
        for exp in state.experiments:
            if (exp.experiment_id in ids
                    and exp.family in DifferentialGenerator.PRISTINE_FAMILIES
                    and exp.experiment_id not in
                    state.experiment_outcomes):
                return True
        return False

    def _emit(
        self, state: Any, hypotheses: list[DifferentialHypothesis],
    ) -> list[Any]:
        for h in hypotheses:
            # Record id carries the engine's "h-" prefix so it matches
            # the experiment's hypothesis_id exactly (the engine's own
            # emission convention); the origin keeps the bare slug.
            state.add_hypothesis(HypothesisRecord(
                hypothesis_id=f"h-{h.hypothesis_id}",
                family=h.family,
                statement=h.statement,
                origin=f"{INDEPENDENT_ORIGIN}{h.hypothesis_id}",
                status=HypothesisStatus.PROPOSED))
            self.port.register_plan(h.plan)
        return [h.to_experiment() for h in hypotheses]

    # -- candidate generation ----------------------------------------

    def _pristine_hypotheses(
        self, view: Any,
    ) -> list[DifferentialHypothesis]:
        out = self._order_hypotheses(view)
        self._deferred = [
            *self._read_hypotheses(view),
            *self._mutation_hypotheses(view),
            *self._price_hypotheses(view),
            *self._workflow_identity_hypotheses(view),
            *self._spend_hypotheses(view),
            *self._grant_hypotheses(view),
        ]
        return out

    def _order_hypotheses(
        self, view: Any,
    ) -> list[DifferentialHypothesis]:
        """Skip-a-state probe: approve directly from the chain start."""
        b = self.port.bindings
        out: list[DifferentialHypothesis] = []
        for path in view.workflow_paths:
            if len(out) >= self._MAX_PER_FAMILY:
                break
            owner = view.workflow_owner.get(path)
            chain = view.workflow_chains.get(path)
            targets = view.workflow_action_targets.get(path) or {}
            approve = b.approve_action
            if not owner or not chain or approve not in targets:
                continue
            expected = targets[approve]
            # skip only when a state actually exists to skip
            if len(chain) < 3 or expected == chain[1]:
                continue
            slug = self._slugs.next(FAMILY_WORKFLOW_ORDER)
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
                    params=((b.action_param, "no-such-action"),)),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-after",
                    method="GET", path=path, actor=owner),
            )
            out.append(DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_WORKFLOW_ORDER,
                statement=(
                    f"skipping a state may be possible on {path}: "
                    f"{approve} taken straight from {chain[0]}"),
                motivating_facts=(
                    f"workflow {path} publishes chain {chain}"),
                invariant="transitions follow the published order",
                confirm_evidence=(
                    f"{approve} applied from {chain[0]} to "
                    f"{expected} while an unknown action is refused"),
                falsify_evidence=(
                    f"{approve} refused from {chain[0]}"),
                gain=0.7,
                cost=0.5,
                preconditions=(
                    f"chain starts at {chain[0]}",
                    "probe acts as the workflow owner",
                    "resource still in its observed initial state"),
                pristine_state_required=True,
                plan=ProbePlan(
                    hypothesis_id=slug,
                    steps=steps,
                    context=(
                        ("initial_state", chain[0]),
                        ("expected_state", expected)),
                ),
            ))
        return out

    def _read_hypotheses(
        self, view: Any,
    ) -> list[DifferentialHypothesis]:
        out: list[DifferentialHypothesis] = []
        credentials = sorted(view.identity_of)
        # rule 1: denial-correlated reads. A credential granted on
        # some resources and denied on others ties the credential to
        # an external identity; the control is another resource the
        # same identity was already denied on. With no correlated
        # identity (open-read surfaces correlate none) this loop
        # yields nothing and the mutual-read rule below still runs.
        for path in view.resource_paths:
            if len(out) >= self._MAX_PER_FAMILY:
                break
            owner = view.resource_owner.get(path)
            if not owner:
                continue
            candidate = next(
                (c for c in credentials
                 if view.identity_of[c] != owner),
                None)
            if candidate is None:
                continue
            identity = view.identity_of[candidate]
            control_path = next(
                (p for p in view.denied_reads
                 if candidate in view.denied_reads[p] and p != path),
                None)
            if control_path is None:
                continue
            slug = self._slugs.next(FAMILY_IDENTITY_BOUNDARY)
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="GET", path=path, actor=owner),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="GET", path=path, actor=identity),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="GET", path=control_path,
                    actor=identity),
            )
            out.append(DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_IDENTITY_BOUNDARY,
                statement=(
                    f"reading {path} may not require owning it: "
                    f"{identity} was granted what {owner} owns"),
                motivating_facts=(
                    f"the surface granted a read of {path} "
                    f"(owner {owner})",
                    f"the surface denied a read of {control_path} "
                    f"to {identity}"),
                invariant=(
                    "cross-identity reads are denied unless the "
                    "identity owns the resource"),
                confirm_evidence=(
                    f"{path} served to {identity} while "
                    f"{control_path} stays denied for it"),
                falsify_evidence=(
                    f"{path} denied to {identity} like its control"),
                gain=0.6,
                cost=0.3,
                preconditions=(
                    "owner identity observed",
                    "candidate identity correlated from grant/deny "
                    "differentials",
                    "control resource known denied to the candidate"),
                plan=ProbePlan(hypothesis_id=slug, steps=steps),
            ))
        if out:
            return out
        # rule 2: mutual-read differential on an open surface. Two
        # DISTINCT credentials were each granted reads of resources
        # exposing DIFFERENT owners: a single privileged identity
        # cannot explain both.
        if view.denied_reads:
            return out
        sweep = list(view.sweep_credentials)
        if len(sweep) < 2:
            return out
        owned = {
            p: view.resource_owner[p]
            for p in view.resource_paths
            if view.resource_owner.get(p)
            and view.granted_reads.get(p)}
        distinct = sorted(set(owned.values()))
        if len(distinct) < 2:
            return out
        first, second = sweep[0], sweep[1]
        path_a = next(p for p in sorted(owned)
                      if owned[p] == distinct[0])
        path_b = next(p for p in sorted(owned)
                      if owned[p] == distinct[1])
        slug = self._slugs.next(FAMILY_IDENTITY_BOUNDARY)
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
        out.append(DifferentialHypothesis(
            hypothesis_id=slug,
            family=FAMILY_IDENTITY_BOUNDARY,
            statement=(
                f"reading {path_b} may not require owning it: "
                f"{first} and {second} were each granted reads of "
                f"resources exposing different owners "
                f"({distinct[0]}, {distinct[1]})"),
            motivating_facts=(
                f"every revealed read was granted to both {first} "
                f"and {second} with no denial observed",
                f"{path_a} and {path_b} expose distinct owners"),
            invariant=(
                "cross-identity reads are denied unless the "
                "identity owns the resource"),
            confirm_evidence=(
                "two distinct identities each granted reads of "
                "resources exposing different owners while no read "
                "was denied"),
            falsify_evidence="either cross-owner read is denied",
            gain=0.6,
            cost=0.3,
            preconditions=(
                "read surface swept with two distinct credentials",
                "no denied read observed anywhere in the sweep",
                "resources expose two different owner identities"),
            plan=ProbePlan(
                hypothesis_id=slug,
                steps=steps,
                context=(("probe", "mutual_read"),),
            ),
        ))
        return out

    def _mutation_hypotheses(
        self, view: Any,
    ) -> list[DifferentialHypothesis]:
        b = self.port.bindings
        out: list[DifferentialHypothesis] = []
        credentials = sorted(view.identity_of)
        if credentials:
            identities = dict(view.identity_of)
        else:
            # Open-read surface: no denial differential exists to
            # correlate credentials to owners. The distinct owner
            # strings the surface exposed in resource bodies are the
            # fallback identities (two owners minimum). With denied
            # reads present the correlation should have worked, so no
            # fallback. Mirrors the engine's Step 6 fix, implemented
            # against this proposer's own view API.
            if view.denied_reads:
                return out
            owners = sorted(set(view.resource_owner.values()))
            if len(owners) < 2:
                return out
            credentials = owners
            identities = {o: o for o in owners}
        family_by_role = {
            "pay": FAMILY_IDENTITY_BOUNDARY,
            "coupon": FAMILY_PRICE_INTEGRITY,
        }
        for operation in view.operation_paths:
            if len(out) >= self._MAX_PER_FAMILY:
                break
            op_params = view.operation_params.get(operation, ())
            if (b.resource_param not in op_params
                    or b.amount_param in op_params):
                continue
            role = view.operation_roles.get(operation)
            if role not in family_by_role:
                continue
            family = family_by_role[role]
            resource = _typed_owned_resource(view, None)
            if resource is None:
                continue
            owner = view.resource_owner[resource]
            other = next(
                (identities[c] for c in credentials
                 if identities[c] != owner),
                None)
            if other is None:
                continue
            control_resource = _typed_owned_resource(view, other)
            if control_resource is None:
                continue
            slug = self._slugs.next(family)
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
            out.append(DifferentialHypothesis(
                hypothesis_id=slug,
                family=family,
                statement=(
                    f"{operation} may accept use by an identity "
                    f"that does not own the resource: {other} was "
                    f"granted what {owner} owns"),
                motivating_facts=(
                    f"{operation} is a revealed state-changing "
                    "operation binding a resource by parameter",
                    f"{other} is a correlated identity distinct "
                    f"from the owner {owner}"),
                invariant=(
                    "state-changing operations are denied unless "
                    "the acting identity owns the target resource"),
                confirm_evidence=(
                    f"candidate application accepted bound to a "
                    f"resource owned by {owner}, while the control "
                    "application (same identity, own resource) is "
                    "accepted"),
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
                    hypothesis_id=slug,
                    steps=steps,
                    context=(("probe", "cross_identity_mutation"),),
                ),
            ))
        return out

    def _grant_hypotheses(
        self, view: Any,
    ) -> list[DifferentialHypothesis]:
        """Token-authorization invariant, this proposer's own rule.

        A grant declares how many times its token may be consumed;
        consumption beyond that count must be denied. The minted token
        value rides into the consume steps through ProbeStep's response
        capture (the same fail-closed mechanism the engine uses); the
        declared count is read from the grant response at judgment
        time, so multi-use deployments never trip the oracle.
        """
        out: list[DifferentialHypothesis] = []
        b = self.port.bindings
        grant_op = next(
            (op for op in view.operation_paths
             if view.operation_roles.get(op) == "grant"), None)
        consume_op = next(
            (op for op in view.operation_paths
             if view.operation_roles.get(op) == "consume"), None)
        if not grant_op or not consume_op:
            return out
        grant_params = set(view.operation_params.get(grant_op, ()))
        consume_params = set(view.operation_params.get(consume_op, ()))
        if b.subject_param not in grant_params or (
                b.action_param not in grant_params):
            return out
        if b.token_param not in consume_params:
            return out
        subject = next(iter(view.resource_owner.values()), None)
        if not subject:
            return out
        action = next(iter({
            action
            for targets in view.workflow_action_targets.values()
            for action in targets
        }), None)
        if not action:
            return out
        slug = self._slugs.next(FAMILY_GRANT_REPLAY)
        base_label = f"{slug}-base"
        capture = (b.token_param, "{captured}")
        grant_params_tuple = (
            (b.subject_param, subject), (b.action_param, action))
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
                # A value never minted: acceptance means the endpoint
                # does not validate tokens at all, so the oracle must
                # report no differential instead of a finding.
                params=((b.token_param, subject),)),
        )
        out.append(DifferentialHypothesis(
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
                "the minted token was accepted on consumption beyond "
                "its declared use count while an unknown token is "
                "denied"),
            falsify_evidence=(
                "consumption beyond the declared count is denied "
                "(unknown_token or token_exhausted)"),
            gain=0.7,
            cost=0.3,
            preconditions=(
                "grant and consume operations observed",
                "grant declares its use count in its response",
                "an action name is published on the surface"),
            plan=ProbePlan(hypothesis_id=slug, steps=steps),
        ))
        return out

    def _price_hypotheses(
        self, view: Any,
    ) -> list[DifferentialHypothesis]:
        b = self.port.bindings
        out: list[DifferentialHypothesis] = []
        priced = [
            p for p in view.resource_paths
            if view.resource_type.get(p)
            and view.numeric_fields.get(p)
        ] or [
            p for p in view.resource_paths
            if view.numeric_fields.get(p)
        ]
        if not priced or not view.operation_paths:
            return out
        resource = priced[0]
        owner = view.resource_owner.get(resource)
        if not owner:
            return out
        for operation in view.operation_paths:
            if len(out) >= self._MAX_PER_FAMILY:
                break
            op_params = view.operation_params.get(operation, ())
            if op_params and b.resource_param in op_params and (
                    b.amount_param in op_params):
                # generalized surface: the operation declares its
                # parameter names, so the probe binds the observed
                # resource by parameter.
                target = operation
                binding = ((b.resource_param,
                            resource.rsplit("/", 1)[-1]),)
                server_token = "{server:" + resource + "}"
                server_plus_token = (
                    "{server_plus_one:" + resource + "}")
            else:
                # fixture surface: the resource rides in the path.
                target = f"{operation}/{resource.rsplit('/', 1)[-1]}"
                binding = ()
                server_token = "{server}"
                server_plus_token = "{server_plus_one}"
            slug = self._slugs.next(FAMILY_PRICE_INTEGRITY)
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="POST", path=target, actor=owner,
                    params=(*binding,
                        (b.amount_param, server_token))),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="POST", path=target, actor=owner,
                    params=(*binding,
                        (b.amount_param, server_plus_token))),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="POST", path=target, actor=owner,
                    params=binding),
            )
            observed = ", ".join(
                f"{key}={value:g}" for key, value in sorted(
                    view.numeric_fields[resource].items()))
            out.append(DifferentialHypothesis(
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
                    "candidate receipt charged != authoritative "
                    "total while the baseline (matching price) and "
                    "the control (no price) match"),
                falsify_evidence=(
                    "candidate denied or charged equals the "
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
        return out

    def _workflow_identity_hypotheses(
        self, view: Any,
    ) -> list[DifferentialHypothesis]:
        b = self.port.bindings
        out: list[DifferentialHypothesis] = []
        submit = (b.action_param, b.submit_action)
        identities = _external_identities(view)
        if not identities or not view.workflow_paths:
            return out
        for path in view.workflow_paths:
            if len(out) >= self._MAX_PER_FAMILY:
                break
            owner = view.workflow_owner.get(path)
            if not owner:
                continue
            pair = _identity_control_pair(view, path, owner,
                                          identities)
            if pair is None:
                continue
            identity, control_path, control_kind = pair
            slug = self._slugs.next(FAMILY_WORKFLOW_IDENTITY)
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="GET", path=path, actor=identity),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="POST", path=path, actor=identity,
                    params=(submit,)),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="POST", path=control_path,
                    actor=identity, params=(submit,)),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-after",
                    method="GET", path=path, actor=identity),
            )
            out.append(DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_WORKFLOW_IDENTITY,
                statement=(
                    f"non-owner {identity} may transition {path} "
                    f"(owner {owner})"),
                motivating_facts=(
                    f"workflow {path} exposes owner {owner}",
                    f"{identity} differs from {owner}"),
                invariant="only the owner transitions a workflow",
                confirm_evidence=(
                    f"submit applied with transitioned_by={identity} "
                    f"while the control workflow denies {identity}"),
                falsify_evidence=(
                    f"submit denied to {identity} like the control"),
                gain=0.6,
                cost=0.3,
                preconditions=(
                    "workflow owner observed",
                    "control workflow third-party-owned, or the "
                    "candidate's own when the surface has two "
                    "identities"),
                plan=ProbePlan(
                    hypothesis_id=slug,
                    steps=steps,
                    context=(("control_kind", control_kind),),
                ),
            ))
        return out

    def _spend_hypotheses(
        self, view: Any,
    ) -> list[DifferentialHypothesis]:
        b = self.port.bindings
        out: list[DifferentialHypothesis] = []
        withdrawal_ops = [
            op for op in view.operation_paths
            if op in view.operation_params
            and b.account_param in view.operation_params[op]
            and b.amount_param in view.operation_params[op]
        ]
        accounts = [
            p for p in view.resource_paths
            if b.available_field
            in (view.numeric_fields.get(p) or {})]
        if not withdrawal_ops or not accounts:
            return out
        account = accounts[0]
        owner = view.resource_owner.get(account)
        if not owner:
            return out
        operation = withdrawal_ops[0]
        account_id = account.rsplit("/", 1)[-1]
        binding = ((b.account_param, account_id),)
        server_token = "{server:" + account + "}"
        server_plus_token = "{server_plus_one:" + account + "}"
        observed = view.numeric_fields[account][b.available_field]
        slug = self._slugs.next(FAMILY_BOUNDARY_LIMIT)
        steps = (
            ProbeStep(
                purpose="baseline", label=f"{slug}-base",
                method="GET", path=account, actor=owner),
            ProbeStep(
                purpose="candidate", label=f"{slug}-cand",
                method="POST", path=operation, actor=owner,
                params=(*binding,
                    (b.amount_param, server_plus_token))),
            ProbeStep(
                purpose="control", label=f"{slug}-ctrl",
                method="POST", path=operation, actor=owner,
                params=(*binding,
                    (b.amount_param, server_token))),
        )
        out.append(DifferentialHypothesis(
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
                "withdrawals above the account's available balance "
                "are rejected"),
            confirm_evidence=(
                "candidate withdrawal accepted with the balance "
                "driven below zero while the control (at the "
                "observed balance) is accepted"),
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
        return out


# --------------------------------------------------------------------------
# Config D: observation-baseline
# --------------------------------------------------------------------------


class ObservationDrivenProposer(_ReconMixin):
    """Fixed rule probes: one explicit security invariant per family.

    Deterministic rules over the same observed view; no ranking, no
    gain model, no hidden labels, one probe per family, emitted once.
    Hypothesis ids live in the ``bl`` namespace.
    """

    def __init__(self, port: Any) -> None:
        self.port = port
        self._view = None
        self._slugs = _SlugCounter("bl")

    def propose(self, state: Any) -> list[Any]:
        if any(
            r.origin.startswith(BASELINE_ORIGIN)
            for r in state.hypotheses):
            return []
        view = self._recon()
        if not view.workflow_paths and not view.operation_paths:
            return []
        rules = (
            self._rule_order(view),
            self._rule_workflow_identity(view),
            self._rule_read(view),
            self._rule_mutation(view),
            self._rule_price(view),
            self._rule_spend(view),
            self._rule_grant(view),
        )
        hypotheses = [h for h in rules if h is not None]
        for h in hypotheses:
            # Record id carries the engine's "h-" prefix so it matches
            # the experiment's hypothesis_id exactly; origin keeps the
            # bare slug.
            state.add_hypothesis(HypothesisRecord(
                hypothesis_id=f"h-{h.hypothesis_id}",
                family=h.family,
                statement=h.statement,
                origin=f"{BASELINE_ORIGIN}{h.hypothesis_id}",
                status=HypothesisStatus.PROPOSED))
            self.port.register_plan(h.plan)
        return [h.to_experiment() for h in hypotheses]

    # -- one rule per family -----------------------------------------

    def _rule_order(self, view: Any) -> Any:
        b = self.port.bindings
        for path in view.workflow_paths:
            owner = view.workflow_owner.get(path)
            chain = view.workflow_chains.get(path)
            targets = view.workflow_action_targets.get(path) or {}
            approve = b.approve_action
            if not owner or not chain or approve not in targets:
                continue
            expected = targets[approve]
            if len(chain) < 3 or expected == chain[1]:
                continue
            slug = self._slugs.next(FAMILY_WORKFLOW_ORDER)
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
                    params=((b.action_param, "no-such-action"),)),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-after",
                    method="GET", path=path, actor=owner),
            )
            return DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_WORKFLOW_ORDER,
                statement=(
                    f"rule: an approve from the chain start must be "
                    f"refused on {path}"),
                motivating_facts=(f"chain {chain} published",),
                invariant="transitions follow the published order",
                confirm_evidence=(
                    f"{approve} applied from {chain[0]} to "
                    f"{expected}"),
                falsify_evidence=(
                    f"{approve} refused from {chain[0]}"),
                gain=1.0,
                cost=0.5,
                preconditions=(
                    f"chain starts at {chain[0]}",
                    "resource in its observed initial state"),
                pristine_state_required=True,
                plan=ProbePlan(
                    hypothesis_id=slug,
                    steps=steps,
                    context=(
                        ("initial_state", chain[0]),
                        ("expected_state", expected)),
                ),
            )
        return None

    def _rule_workflow_identity(self, view: Any) -> Any:
        b = self.port.bindings
        submit = (b.action_param, b.submit_action)
        identities = _external_identities(view)
        for path in view.workflow_paths:
            owner = view.workflow_owner.get(path)
            if not owner:
                continue
            pair = _identity_control_pair(view, path, owner,
                                          identities)
            if pair is None:
                continue
            identity, control_path, control_kind = pair
            slug = self._slugs.next(FAMILY_WORKFLOW_IDENTITY)
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="GET", path=path, actor=identity),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="POST", path=path, actor=identity,
                    params=(submit,)),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="POST", path=control_path,
                    actor=identity, params=(submit,)),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-after",
                    method="GET", path=path, actor=identity),
            )
            return DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_WORKFLOW_IDENTITY,
                statement=(
                    f"rule: a non-owner submit on {path} must be "
                    "refused"),
                motivating_facts=(f"owner {owner} observed",),
                invariant="only the owner transitions a workflow",
                confirm_evidence=(
                    f"non-owner submit applied (transitioned_by="
                    f"{identity})"),
                falsify_evidence=f"submit denied to {identity}",
                gain=1.0,
                cost=0.5,
                preconditions=(
                    "workflow owner observed",
                    "control workflow available"),
                plan=ProbePlan(
                    hypothesis_id=slug,
                    steps=steps,
                    context=(("control_kind", control_kind),),
                ),
            )
        return None

    def _rule_read(self, view: Any) -> Any:
        credentials = sorted(view.identity_of)
        for path in view.resource_paths:
            owner = view.resource_owner.get(path)
            if not owner:
                continue
            candidate = next(
                (c for c in credentials
                 if view.identity_of[c] != owner),
                None)
            if candidate is None:
                continue
            identity = view.identity_of[candidate]
            control_path = next(
                (p for p in view.denied_reads
                 if candidate in view.denied_reads[p] and p != path),
                None)
            if control_path is None:
                continue
            slug = self._slugs.next(FAMILY_IDENTITY_BOUNDARY)
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="GET", path=path, actor=owner),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="GET", path=path, actor=identity),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="GET", path=control_path,
                    actor=identity),
            )
            return DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_IDENTITY_BOUNDARY,
                statement=(
                    f"rule: {path} must refuse {identity} just like "
                    f"{control_path} does"),
                motivating_facts=(
                    "denial correlation observed for the identity"),
                invariant=(
                    "cross-identity reads are denied unless the "
                    "identity owns the resource"),
                confirm_evidence=(
                    f"{path} served to {identity} while "
                    f"{control_path} stays denied"),
                falsify_evidence=(
                    f"{path} denied to {identity} like its control"),
                gain=1.0,
                cost=0.3,
                preconditions=(
                    "denial correlation exists",
                    "probe acts as the correlated identity"),
                plan=ProbePlan(hypothesis_id=slug, steps=steps),
            )
        if view.denied_reads:
            return None
        sweep = list(view.sweep_credentials)
        if len(sweep) < 2:
            return None
        owned = {
            p: view.resource_owner[p]
            for p in view.resource_paths
            if view.resource_owner.get(p)
            and view.granted_reads.get(p)}
        distinct = sorted(set(owned.values()))
        if len(distinct) < 2:
            return None
        first, second = sweep[0], sweep[1]
        path_a = next(p for p in sorted(owned)
                      if owned[p] == distinct[0])
        path_b = next(p for p in sorted(owned)
                      if owned[p] == distinct[1])
        slug = self._slugs.next(FAMILY_IDENTITY_BOUNDARY)
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
        return DifferentialHypothesis(
            hypothesis_id=slug,
            family=FAMILY_IDENTITY_BOUNDARY,
            statement=(
                f"rule: {path_b} must refuse {first} exactly as a "
                "cross-owner read is refused everywhere else"),
            motivating_facts=(
                f"{path_a} and {path_b} expose distinct owners "
                f"({distinct[0]}, {distinct[1]})"),
            invariant=(
                "cross-identity reads are denied unless the "
                "identity owns the resource"),
            confirm_evidence=(
                f"{first} read {path_b} (owner {distinct[1]}) "
                f"while {second} reading {path_a} saw its own "
                "owner"),
            falsify_evidence="either cross-owner read is denied",
            gain=1.0,
            cost=0.3,
            preconditions=(
                "two sweep credentials on the surface",
                "no denied read observed anywhere in the sweep",
                "resources expose two different owner identities"),
            plan=ProbePlan(
                hypothesis_id=slug,
                steps=steps,
                context=(("probe", "mutual_read"),),
            ),
        )

    def _rule_mutation(self, view: Any) -> Any:
        b = self.port.bindings
        credentials = sorted(view.identity_of)
        if credentials:
            identities = dict(view.identity_of)
        else:
            # Open-read surface: the distinct owner strings the surface
            # exposed in resource bodies are the fallback identities
            # (two owners minimum). Mirrors the read rule's fallback and
            # the engine's Step 6 fix, against this proposer's own view
            # API.
            if view.denied_reads:
                credentials, identities = [], {}
            else:
                owners = sorted(set(view.resource_owner.values()))
                credentials = owners
                identities = {o: o for o in owners}
        family_by_role = {
            "pay": FAMILY_IDENTITY_BOUNDARY,
            "coupon": FAMILY_PRICE_INTEGRITY,
        }
        for operation in view.operation_paths:
            op_params = view.operation_params.get(operation, ())
            if (b.resource_param not in op_params
                    or b.amount_param in op_params):
                continue
            role = view.operation_roles.get(operation)
            if role not in family_by_role:
                continue
            family = family_by_role[role]
            resource = _typed_owned_resource(view, None)
            if resource is None:
                continue
            owner = view.resource_owner[resource]
            other = next(
                (identities[c] for c in credentials
                 if identities[c] != owner),
                None)
            if other is None:
                continue
            control_resource = _typed_owned_resource(view, other)
            if control_resource is None:
                continue
            slug = self._slugs.next(family)
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
            return DifferentialHypothesis(
                hypothesis_id=slug,
                family=family,
                statement=(
                    f"rule: {operation} must refuse use by {other} "
                    f"of a resource owned by {owner}"),
                motivating_facts=(
                    f"resource parameter {b.resource_param} "
                    "published on a state-changing operation"),
                invariant=(
                    "state-changing operations are denied unless "
                    "the acting identity owns the target resource"),
                confirm_evidence=(
                    f"application accepted for {other} bound to a "
                    f"resource owned by {owner}"),
                falsify_evidence=(
                    "application denied like other cross-identity "
                    "use"),
                gain=1.0,
                cost=0.3,
                preconditions=(
                    "operation and resource binding observed",
                    "control resource owned by the candidate "
                    "identity"),
                plan=ProbePlan(
                    hypothesis_id=slug,
                    steps=steps,
                    context=(("probe", "cross_identity_mutation"),),
                ),
            )
        return None

    def _rule_price(self, view: Any) -> Any:
        b = self.port.bindings
        priced = [
            p for p in view.resource_paths
            if view.resource_type.get(p)
            and view.numeric_fields.get(p)
        ] or [
            p for p in view.resource_paths
            if view.numeric_fields.get(p)
        ]
        if not priced:
            return None
        resource = priced[0]
        owner = view.resource_owner.get(resource)
        if not owner:
            return None
        for operation in view.operation_paths:
            op_params = view.operation_params.get(operation, ())
            if not op_params or b.amount_param not in op_params:
                continue
            if b.resource_param in op_params:
                target = operation
                binding = ((b.resource_param,
                            resource.rsplit("/", 1)[-1]),)
                server_token = "{server:" + resource + "}"
                server_plus_token = (
                    "{server_plus_one:" + resource + "}")
            else:
                target = f"{operation}/{resource.rsplit('/', 1)[-1]}"
                binding = ()
                server_token = "{server}"
                server_plus_token = "{server_plus_one}"
            slug = self._slugs.next(FAMILY_PRICE_INTEGRITY)
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="POST", path=target, actor=owner,
                    params=(*binding,
                        (b.amount_param, server_token))),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="POST", path=target, actor=owner,
                    params=(*binding,
                        (b.amount_param, server_plus_token))),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="POST", path=target, actor=owner,
                    params=binding),
            )
            return DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_PRICE_INTEGRITY,
                statement=(
                    f"rule: {operation} must refuse a client price "
                    "above the authoritative total"),
                motivating_facts=(
                    f"{resource} exposes authoritative pricing"),
                invariant=(
                    "the charged amount equals the server-side "
                    "authoritative total"),
                confirm_evidence=(
                    "over-balance charge executed while the "
                    "at-balance charge succeeded"),
                falsify_evidence=(
                    "the over-balance charge was rejected"),
                gain=1.0,
                cost=0.3,
                preconditions=(
                    "authoritative numeric field observed",
                    "probe acts as the resource owner"),
                plan=ProbePlan(hypothesis_id=slug, steps=steps),
            )
        return None

    def _rule_spend(self, view: Any) -> Any:
        b = self.port.bindings
        for operation in view.operation_paths:
            op_params = view.operation_params.get(operation, ())
            if (b.account_param not in op_params
                    or b.amount_param not in op_params):
                continue
            account = next(
                (p for p in view.resource_paths
                 if b.available_field
                 in (view.numeric_fields.get(p) or {})),
                None)
            if account is None:
                continue
            owner = view.resource_owner.get(account)
            if not owner:
                continue
            account_id = account.rsplit("/", 1)[-1]
            binding = ((b.account_param, account_id),)
            server_token = "{server:" + account + "}"
            server_plus_token = "{server_plus_one:" + account + "}"
            slug = self._slugs.next(FAMILY_BOUNDARY_LIMIT)
            steps = (
                ProbeStep(
                    purpose="baseline", label=f"{slug}-base",
                    method="GET", path=account, actor=owner),
                ProbeStep(
                    purpose="candidate", label=f"{slug}-cand",
                    method="POST", path=operation, actor=owner,
                    params=(*binding,
                        (b.amount_param, server_plus_token))),
                ProbeStep(
                    purpose="control", label=f"{slug}-ctrl",
                    method="POST", path=operation, actor=owner,
                    params=(*binding,
                        (b.amount_param, server_token))),
            )
            return DifferentialHypothesis(
                hypothesis_id=slug,
                family=FAMILY_BOUNDARY_LIMIT,
                statement=(
                    f"rule: a debit above the published balance on "
                    f"{account_id} must be refused"),
                motivating_facts=(
                    f"balance published on {b.available_field}"),
                invariant=(
                    "withdrawals above the account's available "
                    "balance are rejected"),
                confirm_evidence=(
                    "a debit above the published balance succeeded"),
                falsify_evidence=(
                    "the above-balance debit was refused"),
                gain=1.0,
                cost=0.3,
                preconditions=(
                    "an account with a published balance observed",
                    "probe acts as the account owner"),
                plan=ProbePlan(hypothesis_id=slug, steps=steps),
            )
        return None


    def _rule_grant(self, view: Any) -> Any:
        """Rule for the token-authorization invariant: one grant, then
        consume up to three times against the declared use count. The
        minted token rides into the consume steps through ProbeStep's
        response capture; the declared count is read from the grant
        response at judgment time."""
        b = self.port.bindings
        grant_op = next(
            (op for op in view.operation_paths
             if view.operation_roles.get(op) == "grant"), None)
        consume_op = next(
            (op for op in view.operation_paths
             if view.operation_roles.get(op) == "consume"), None)
        if not grant_op or not consume_op:
            return None
        grant_params = set(view.operation_params.get(grant_op, ()))
        consume_params = set(view.operation_params.get(consume_op, ()))
        if b.subject_param not in grant_params or (
                b.action_param not in grant_params):
            return None
        if b.token_param not in consume_params:
            return None
        subject = next(iter(view.resource_owner.values()), None)
        if not subject:
            return None
        action = next(iter({
            action
            for targets in view.workflow_action_targets.values()
            for action in targets
        }), None)
        if not action:
            return None
        slug = self._slugs.next(FAMILY_GRANT_REPLAY)
        base_label = f"{slug}-base"
        capture = (b.token_param, "{captured}")
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
                params=((b.subject_param, subject),
                        (b.action_param, action))),
            *consume_steps,
            ProbeStep(
                purpose="control", label=f"{slug}-ctrl",
                method="POST", path=consume_op, actor=subject,
                # A value never minted: acceptance means no token
                # validation, so the oracle reports no differential.
                params=((b.token_param, subject),)),
        )
        return DifferentialHypothesis(
            hypothesis_id=slug,
            family=FAMILY_GRANT_REPLAY,
            statement=(
                f"rule: a token issued by {grant_op} must stop being "
                f"accepted by {consume_op} once its declared use "
                "count is spent"),
            motivating_facts=(
                f"{grant_op} issues a token carrying a declared use "
                "count",
                f"{consume_op} takes a token parameter and tracks "
                "consumption"),
            invariant=(
                "consumption beyond the declared use count is denied"),
            confirm_evidence=(
                "the minted token was accepted on consumption beyond "
                "its declared use count while an unknown token is "
                "denied"),
            falsify_evidence=(
                "consumption beyond the declared count is denied "
                "(unknown_token or token_exhausted)"),
            gain=1.0,
            cost=0.3,
            preconditions=(
                "grant and consume operations observed",
                "grant declares its use count in its response",
                "an action name is published on the surface"),
            plan=ProbePlan(hypothesis_id=slug, steps=steps),
        )


# --------------------------------------------------------------------------
# Factory
# --------------------------------------------------------------------------


def _planner_for(port: Any) -> StatefulPlanner:
    """The L9 stateful planner for one investigation. Its action
    vocabulary is DERIVED FROM THE SURFACE at derivation time (the
    planner reads the schema-derived bindings off the observed
    view), because reconnaissance happens inside the run — after
    this wiring — so nothing about any application is assumed
    (L9 §3)."""
    return StatefulPlanner(PlannerConfig())


def build_strategy_orchestrator(
    port: Any, strategy: str,
) -> InvestigationOrchestrator:
    """The one entry point the benchmark harness uses.

    adaptive delegates to the L6 benchmark builder so the flagship
    configuration is byte-identical to the L6 measurement; the other
    three share the oracle, proof and model ports with it but carry
    their own proposer and a scheduling-neutral selector. All four
    carry the L9 stateful planner: a blocked-precondition outcome
    (a probe's required source state was not established) triggers
    one bounded remediation cycle — authorized setup transitions
    through the ordinary action path, then a re-run — instead of
    leaving a comparison that cannot mean anything unexplored.
    """
    if strategy == "adaptive":
        orch = _build_orchestrator(port, "adaptive")
        orch.planner = _planner_for(port)
        return orch
    if strategy == "adaptive-no-selector":
        return InvestigationOrchestrator(
            experiment_port=port,
            validation_port=DifferentialValidationPort(),
            proof_port=DifferentialProofBundlePort(),
            model_port=_LedgerModelPort(),
            selector=_NoopSelector(),
            proposer=DifferentialProposer(port),
            planner=_planner_for(port),
        )
    if strategy == "independent-fixed":
        return InvestigationOrchestrator(
            experiment_port=port,
            validation_port=DifferentialValidationPort(),
            proof_port=DifferentialProofBundlePort(),
            model_port=_LedgerModelPort(),
            selector=_NoopSelector(),
            proposer=IndependentProposer(port),
            planner=_planner_for(port),
        )
    if strategy == "observation-baseline":
        return InvestigationOrchestrator(
            experiment_port=port,
            validation_port=DifferentialValidationPort(),
            proof_port=DifferentialProofBundlePort(),
            model_port=_LedgerModelPort(),
            selector=_NoopSelector(),
            proposer=ObservationDrivenProposer(port),
            planner=_planner_for(port),
        )
    raise ValueError(f"unknown benchmark strategy: {strategy}")
