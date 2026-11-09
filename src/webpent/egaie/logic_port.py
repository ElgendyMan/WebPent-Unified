"""EGAIE Logic Breaker port: evidence-grounded price-integrity hunting.

First Logic Breaker capability on EGAIE (http-v3, family
PRICE_INTEGRITY). The experiment port reuses the existing contracts
and the production ActionExecutor path unchanged: every mutating
request is a CampaignTask executed by the RuntimeFactory-built
ActionAuthority with the G-02 smart_http adapter, exactly like
HTTPExperimentPort. What is new here is only the logic layer:

- LogicExperimentPort maps http-v3 case ids to their probe structure
  (paths and the documented per-case probe parameters) and executes
  through the inherited production path. Probe parameters are fixture
  setup, never detection input.
- InvariantValidationPort is an independent invariant oracle with
  documented predicates. It judges only what the observations say:
  the amount accepted must match the authoritative amount (including
  legitimate owner-applied discounts), a client-controlled price must
  never override the server price, and a discount must be applied by
  the order's own owner. Missing data is never interpreted as
  success: unexecuted or partial evidence is inconclusive or blocked,
  never clean and never confirmed.
- LogicProofBundlePort seals the oracle's evidence into a bundle and
  verifies it by reloading the recorded observations, independently
  re-running the same invariant oracle, and comparing the verdict,
  the evidence digests and the deterministic seal. Replay here means
  re-deriving the verdict from recorded evidence; it never re-issues
  HTTP requests. Bundles from a different engagement identity are
  rejected.

This is a logic verdict, not an authorization verdict: it says the
pricing invariant was violated, and it is produced and verified
inside this port's own contract rather than relabelled through
CausalGuard.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from webpent.autonomous.authorization import (
    EngagementAuthorization,
)
from webpent.config.settings import Settings
from webpent.egaie.benchmark.http_ground_truth import (
    HTTP_CASE_V3_INDEX,
    HTTP_GROUND_TRUTH_V3,
    HTTPCase,
)
from webpent.egaie.http_port import (
    MAX_REVEALED_PATH_LENGTH,
    HTTPExperimentPort,
)
from webpent.egaie.http_target import ACTOR_A
from webpent.egaie.schemas import (
    InvestigationState,
    ProposedExperiment,
)

EXECUTION_TIMEOUT_S = 10.0

# Documented probe parameters per http-v3 case id. These define what
# the probe sends (fixture setup); the invariant oracle never sees
# them and judges only the target's own responses.
PRICE_OVERRIDE_PROBE = "1337"
COUPON_PROBE_CODE = "SAFE10"
_PROBE_PARAMS: dict[str, dict[str, str]] = {
    "pos-price-1": {"price": PRICE_OVERRIDE_PROBE},
    "pos-coupon-1": {"code": COUPON_PROBE_CODE},
    "neg-till-1": {"price": PRICE_OVERRIDE_PROBE},
    "neg-coupon-1": {"code": COUPON_PROBE_CODE},
}

DEFAULT_TARGET_IDENTITY = "egaie:PRICE_INTEGRITY"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(obj: Any) -> str:
    canonical = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class LogicExperimentPort(HTTPExperimentPort):
    """Executes http-v3 price-integrity experiments through the
    production ActionExecutor path inherited from HTTPExperimentPort.

    Only the case mapping and the probe parameters are family-
    specific; execution, denial handling and observation normalization
    are the production path, unchanged.
    """

    # -- probe-structure mapping (fixture setup, not detection) ----
    @staticmethod
    def _case_from_id(case_id: str) -> HTTPCase:
        # Fail closed on the V3 registry only: the Logic Breaker port
        # resolves cases exclusively through the declared http-v3
        # ground truth. An unknown id, or an id belonging to another
        # version, raises BEFORE any HTTP request is issued; the
        # read-only HTTP port keeps its own broader resolution for its
        # legacy callers.
        try:
            return HTTP_CASE_V3_INDEX[case_id]
        except KeyError as exc:
            raise ValueError(
                f"unknown http-v3 case id: {case_id!r} "
                "(the Logic Breaker port resolves http-v3 cases only)"
            ) from exc

    @classmethod
    def _case_of(cls, experiment: ProposedExperiment) -> HTTPCase:
        return cls._case_from_id(experiment.signature.split("/", 1)[0])

    def _stage2_baseline_path(self, stage1_signature: str) -> str:
        case = self._case_from_id(stage1_signature.split("/", 1)[0])
        return case.stage2_baseline_path or case.baseline_path

    def _params(self, task_key: str, extra: dict[str, str] | None = None,
                ) -> dict[str, str]:
        # Deterministic per-task idempotency token, carried as a query
        # parameter so the target's application-level once-per-token
        # application can never double-apply a mutation on resume.
        params = {"actor": ACTOR_A, "idem": _sha256(task_key)[:16]}
        if extra:
            params.update(extra)
        return params

    # -- stage 1, state-changing (POST) variant --------------------
    def _execute_stage1_post(
        self, experiment: ProposedExperiment,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        case = self._case_of(experiment)
        attack_params = dict(_PROBE_PARAMS.get(case.case_id, {}))
        baseline = self._observe_post(
            case.baseline_path,
            self._params(f"{experiment.experiment_id}-baseline"),
            f"{experiment.experiment_id}-baseline",
        )
        candidate = self._observe_post(
            case.path,
            self._params(
                f"{experiment.experiment_id}-candidate", attack_params),
            f"{experiment.experiment_id}-candidate",
        )
        control = self._observe_post(
            "/control" + case.path,
            self._params(f"{experiment.experiment_id}-control"),
            f"{experiment.experiment_id}-control",
        )
        # Multi-step POST cases: the generic receipt reveals the
        # resource path whose state is only observable through a
        # follow-up GET (stage 2).
        structured = candidate.get("structured", {})
        revealed = (
            structured.get("resource_path") or structured.get("note_path"))
        if isinstance(revealed, str) and revealed.startswith("/api/"):
            self.revealed_paths[experiment.signature] = revealed[
                :MAX_REVEALED_PATH_LENGTH]
        return baseline, candidate, control


class InvariantValidationPort:
    """Independent pricing-invariant oracle (the Logic Breaker judge).

    Documented predicates, evaluated on the candidate observation
    only, from the target's own response data:

    - amount_mismatch: the charged amount differs from the
      authoritative total the server itself reported. A legitimate
      discount keeps them equal (the discounted total is the
      authoritative one on the order), so this predicate fires only
      when a client-controlled price overrode the server price.
    - unauthorized_discount: a pricing discount was applied by an
      actor that is not the order's owner.

    Verdict discipline (fail-closed):
    - no observation executed -> blocked
    - any observation missing (denied or placeholder) while others
      executed -> inconclusive; missing data is never interpreted as
      success
    - candidate accepted (200) but carries no pricing evidence
      (generic receipt) -> inconclusive
    - candidate rejected (non-200) -> clean (nothing was accepted)
    - candidate accepted with pricing evidence -> confirmed when a
      predicate is violated, clean otherwise

    Ground-truth labels are never available to this port at runtime.
    """

    def validate(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        executed_flags = [
            self._executed(obs) for obs in (baseline, candidate, control)
        ]
        result: dict[str, Any] = {
            "verdict": "inconclusive",
            "causal_signal": False,
            "confidence": 0.0,
            "violated_predicates": [],
            "block_reason": None,
            "raw_decision": {"oracle": "invariant_price_integrity"},
        }
        if not any(executed_flags):
            result["verdict"] = "blocked"
            result["block_reason"] = "no_observation_executed"
            return result
        if not all(executed_flags):
            result["verdict"] = "inconclusive"
            result["block_reason"] = "incomplete_evidence_missing_data"
            return result
        verdict, violated = self._judge(candidate)
        result["verdict"] = verdict
        result["violated_predicates"] = violated
        result["causal_signal"] = verdict == "confirmed"
        if verdict == "confirmed":
            result["confidence"] = 0.9
        elif verdict == "clean":
            result["confidence"] = 0.8
        else:
            result["confidence"] = 0.3
        return result

    @staticmethod
    def _executed(observation: dict[str, Any]) -> bool:
        return (
            observation.get("execution") == "executed"
            and observation.get("_placeholder") is not True
            and observation.get("status_code") is not None
        )

    def _judge(
        self, candidate: dict[str, Any],
    ) -> tuple[str, list[str]]:
        structured = candidate.get("structured")
        status = candidate.get("status_code")
        if status != 200:
            # The request was rejected: nothing was accepted, so no
            # pricing invariant was violated by this probe.
            return "clean", []
        if not isinstance(structured, dict):
            return "inconclusive", []
        charged = structured.get("charged")
        authoritative = structured.get("authoritative_total")
        if charged is None or authoritative is None:
            # Accepted but with no pricing evidence (generic
            # receipt): inconclusive, never clean.
            return "inconclusive", []
        if not isinstance(charged, (int, float)) or not isinstance(
                authoritative, (int, float)):
            return "inconclusive", []
        violated: list[str] = []
        if charged != authoritative:
            violated.append("amount_mismatch")
        discount_by = structured.get("discount_applied_by")
        owner = structured.get("owner")
        if discount_by is not None and owner is not None and (
                discount_by != owner):
            violated.append("unauthorized_discount")
        if violated:
            return "confirmed", violated
        return "clean", []


@dataclass
class LogicProofBundle:
    """Sealed evidence bundle for a logic verdict.

    Field names mirror the evidence roles (baseline/candidate/
    control) so the bundle is directly reloadable: verification
    re-runs the invariant oracle on these recorded observations. The
    seal covers the target identity, the case identity, the raw
    evidence digests and the oracle verdict, and is recomputed from
    raw observations at verification time (cached digests are never
    trusted).
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
            "bundle_kind": "egaie_logic_proof_v1",
            "target_identity": self.target_identity,
            "case_identity": self.case_identity,
            "baseline_digest": _digest(self.baseline),
            "candidate_digest": _digest(self.candidate),
            "control_digest": _digest(self.control),
            "oracle_verdict": self.causal_result.get("verdict", ""),
        })

    def verify_seal(self) -> bool:
        return self._compute_seal() == self.deterministic_seal


class LogicProofBundlePort:
    """Build and replay-verify sealed logic proof bundles.

    Replay is an independent re-derivation: the recorded observations
    are reloaded from the bundle and the same invariant oracle is
    re-run on them, then verdict, evidence digests, seal and target
    identity are all compared. No HTTP request is ever re-issued, and
    a bundle whose recorded evidence disagrees with its own verdict,
    digests, seal or engagement identity fails closed.
    """

    def __init__(
        self,
        expected_target_identity: str = DEFAULT_TARGET_IDENTITY,
    ) -> None:
        self._expected_target_identity = expected_target_identity
        self._oracle = InvariantValidationPort()
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
    ) -> LogicProofBundle:
        return LogicProofBundle(
            target_identity=f"egaie:{experiment.family}",
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
                "oracle": "invariant_price_integrity",
            },
            source_provenance={
                "source": "egaie",
                "component": "LogicProofBundlePort",
                "validation": "egaie.invariant_oracle",
            },
            runtime_provenance=dict(self._runtime_provenance),
        )

    def verify(self, bundle: LogicProofBundle) -> dict[str, Any]:
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


class LogicFollowUpProposer:
    """Advisory proposer for http-v3 multi-step price-integrity cases.

    Proposal only: the proposed stage2 experiment still runs through
    the full invariant-oracle + sealed-bundle + replay pipeline and
    can never confirm anything by itself. Polarity-blind: any
    multi-step case whose stage-1 probe is inconclusive deserves a
    follow-up, positive or negative alike.
    """

    def propose(
        self, state: InvestigationState,
    ) -> list[ProposedExperiment]:
        proposals: list[ProposedExperiment] = []
        known_ids = {e.experiment_id for e in state.experiments}
        for case in HTTP_GROUND_TRUTH_V3:
            if not case.multi_step:
                continue
            stage1_id = f"e-{case.case_id}"
            stage2_id = f"e-{case.case_id}-stage2"
            if state.experiment_outcome(stage1_id) != "inconclusive":
                continue
            if stage2_id in known_ids:
                continue
            proposals.append(ProposedExperiment(
                experiment_id=stage2_id,
                family=case.family,
                signature=f"{case.case_id}/{case.family}:stage2",
                description=f"stage2 follow-up probe for {case.case_id}",
                cost=0.2,
                risk=0.2,
                gain_estimate=0.5,
                rationale=(
                    "advisory follow-up after inconclusive stage1"),
                hypothesis_id=f"h-{case.case_id}",
            ))
        return proposals


def build_logic_experiment_port(
    *,
    target: Any,
    engagement_id: str,
    campaign_id: str,
    authorization: EngagementAuthorization,
    settings: Settings,
) -> LogicExperimentPort:
    """Build the logic port on a full production runtime (the real
    path), mirroring build_http_experiment_port."""
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
    port = LogicExperimentPort(
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
        handler=port._transport_handler,  # noqa: SLF001
        policy_checked=True,
        canonical_wrapper=G02_HTTP_CANONICAL_WRAPPER,
        scope_policy=G02_HTTP_SCOPE_POLICY,
        static_inventory_ref=G02_HTTP_INVENTORY_REF,
        proof_contract=G02_HTTP_PROOF_CONTRACT,
        expires_at=G02_HTTP_APPROVAL_EXPIRY,
    ))
    return port
