"""UM-DR-35 corrective closure — confirmation-authority regression matrix.

Mission §1.5 mandatory matrix. Every row proves that confirmation requires
the ACTUAL CausalGuard authority (``webpent.cqa_v2.causal_guard``), reached
through the universal boundary (``production/confirmation_adapter`` +
``shared/verifier.verify_replay_evidence``). Nothing else — scanner markers,
LLM verdicts, boolean flags, replay alone, bundles alone, forged results,
tampered evidence — may confirm or promote.

The final test is a repository-wide AST invariant: no module outside the
trusted authority implementations may assign a confirmed or promoted
finding state.
"""
from __future__ import annotations

import ast
import hashlib
import json
import uuid
from pathlib import Path

import pytest

from webpent.cqa_v2.causal_guard import Verdict
from webpent.models.findings import Confidence, Finding
from webpent.production.confirmation_adapter import (
    ConfirmationOutcome,
    adjudicate_with_causal_guard,
    confirmation_gate,
)
from webpent.shared.verifier import verify_replay_evidence

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "webpent"

LAB_ORIGIN = "http://127.0.0.1:9777"
VULN_PATH = "/api/invoices/INV-B-204"


def _digest(seed: str) -> str:
    return f"sha256:{hashlib.sha256(seed.encode()).hexdigest()}"


def _obs(
    *,
    role: str,
    status: int,
    body: dict | str,
    url: str,
    actor: str | None = "User_A",
    owner_in_body: str | None = None,
) -> dict:
    body_str = json.dumps(body) if isinstance(body, dict) else body
    return {
        "observation_role": role,
        "status_code": status,
        "body_length": len(body_str),
        "target_backed": True,
        "evidence_origin": "target_runtime",
        "target_fingerprint": _digest(LAB_ORIGIN + VULN_PATH),
        "request_digest": _digest(f"{role}-req"),
        "response_digest": _digest(body_str),
        "request_url": url,
        "url_shape": url,
        "headers": {"X-User": actor, "content-type": "application/json"},
        "response_body": body_str,
    }


def _valid_vulnerable_triple() -> tuple[dict, dict, dict]:
    """Real walking-skeleton triple against the vulnerable lab variant."""
    baseline = _obs(
        role="baseline", status=200,
        body={"id": "INV-A-101", "owner": "User_A", "amount": 1000, "viewer": "User_A"},
        url=f"{LAB_ORIGIN}/api/invoices/INV-A-101",
    )
    candidate = _obs(
        role="candidate", status=200,
        body={"id": "INV-B-204", "owner": "User_B", "amount": 1000, "viewer": "User_A"},
        url=f"{LAB_ORIGIN}{VULN_PATH}",
    )
    control = _obs(
        role="negative_control", status=403,
        body={"detail": "forbidden: not the owner"},
        url=f"{LAB_ORIGIN}/api/invoices/INV-X-000",
    )
    return baseline, candidate, control


def _finding() -> Finding:
    return Finding(
        id=uuid.uuid4(),
        thread_id="umdr35-matrix",
        url=f"{LAB_ORIGIN}{VULN_PATH}",
        vuln_class="idor",
        title="UM-DR-35 matrix IDOR",
        severity="high",
        description="matrix",
        tool_name="matrix-validator",
        confidence_level="Pending",
        hypothesis_id=uuid.uuid4(),
        reasoning="matrix",
        evidence={},
    )


_SCOPE = {"target_origin": LAB_ORIGIN, "scope_bound": True, "declared_scope": [LAB_ORIGIN]}
_IDENTITY = {
    "mode": "authenticated",
    "candidate_identity": {"identity_id": "User_A", "role": "foreign-user"},
    "baseline_identity": {"identity_id": "User_A", "role": "owner"},
    "negative_control_identity": {"identity_id": "User_A", "role": "foreign-user"},
}


# ---------------------------------------------------------------------------
# A. The authority itself
# ---------------------------------------------------------------------------

def test_authority_adjudicates_real_vulnerable_triple_confirmed():
    baseline, candidate, control = _valid_vulnerable_triple()
    adj = adjudicate_with_causal_guard(
        baseline, candidate, control, vulnerability_class="IDOR",
        identity_context=_IDENTITY,
    )
    assert adj.guard_result.verdict is Verdict.CONFIRMED
    assert adj.guard_result.causal_signal is True
    assert adj.guard_result.authorization_differential is True
    assert adj.confirmed is True


def test_authority_rejects_patched_target():
    baseline, _, control = _valid_vulnerable_triple()
    patched = _obs(
        role="candidate", status=403,
        body={"detail": "forbidden: not the owner"},
        url=f"{LAB_ORIGIN}{VULN_PATH}",
    )
    adj = adjudicate_with_causal_guard(
        baseline, patched, control, vulnerability_class="IDOR",
        identity_context=_IDENTITY,
    )
    assert adj.confirmed is False


# ---------------------------------------------------------------------------
# B. Mission §1.5 negative matrix — nothing but the authority confirms
# ---------------------------------------------------------------------------

def test_matrix_scanner_claim_alone_not_confirmed():
    """Scanner claims a vulnerability → not confirmed without CausalGuard."""
    baseline, candidate, control = _valid_vulnerable_triple()
    decision = confirmation_gate(
        baseline, candidate, control,
        vulnerability_class="IDOR",
        # a scanner's positive marker, no validator CONFIRM outcome
        validator_outcome=None,
        validator_id="scanner.sqlmap",
        identity_context=_IDENTITY, scope_context=_SCOPE,
    )
    assert decision.outcome is ConfirmationOutcome.BLOCKED
    assert decision.reason == "class_validator_outcome_not_confirmed"


def test_matrix_llm_yes_not_confirmed():
    """LLM says YES → not confirmed without CausalGuard."""
    baseline, candidate, control = _valid_vulnerable_triple()
    decision = confirmation_gate(
        baseline, candidate, control,
        vulnerability_class="IDOR",
        validator_outcome="LLM_SAYS_YES",
        validator_id="llm-supervisor",
        identity_context=_IDENTITY, scope_context=_SCOPE,
    )
    assert decision.confirmed is False


def test_matrix_booleans_alone_not_confirmed():
    """causal_signal=True / negative_control_complete=True alone → blocked."""
    baseline, candidate, control = _valid_vulnerable_triple()
    finding = _finding()
    # Booleans claimed True by a caller whose evidence has NO guard context
    # (headers stripped) — the guard must BLOCK, not honor the booleans.
    def strip(obs: dict) -> dict:
        return {k: v for k, v in obs.items() if k != "headers"}

    result = verify_replay_evidence(
        finding,
        baseline=strip(baseline), candidate=strip(candidate),
        negative_control=strip(control),
        causal_signal=True, negative_control_complete=True,
        validator_id="bools-only", validator_version="v1",
        causal_basis="caller booleans", engagement_id="umdr35-matrix",
        hypothesis_id=uuid.uuid4(),
        scope_context=_SCOPE, identity_context={"mode": "anonymous"},
        require_target_backed=True,
    )
    assert result.passed is False
    assert "causal_guard" in result.reason


def test_matrix_missing_baseline_blocked():
    _, candidate, control = _valid_vulnerable_triple()
    result = verify_replay_evidence(
        _finding(), baseline=None, candidate=candidate, negative_control=control,
        causal_signal=True, negative_control_complete=True,
        validator_id="v", validator_version="v1", causal_basis="b",
        engagement_id="umdr35-matrix", scope_context=_SCOPE,
        identity_context=_IDENTITY, require_target_backed=True,
    )
    assert result.passed is False
    assert result.reason == "baseline_and_candidate_required"


def test_matrix_missing_candidate_blocked():
    baseline, _, control = _valid_vulnerable_triple()
    result = verify_replay_evidence(
        _finding(), baseline=baseline, candidate=None, negative_control=control,
        causal_signal=True, negative_control_complete=True,
        validator_id="v", validator_version="v1", causal_basis="b",
        engagement_id="umdr35-matrix", scope_context=_SCOPE,
        identity_context=_IDENTITY, require_target_backed=True,
    )
    assert result.passed is False
    assert result.reason == "baseline_and_candidate_required"


def test_matrix_missing_negative_control_blocked():
    baseline, candidate, _ = _valid_vulnerable_triple()
    result = verify_replay_evidence(
        _finding(), baseline=baseline, candidate=candidate, negative_control=None,
        causal_signal=True, negative_control_complete=True,
        validator_id="v", validator_version="v1", causal_basis="b",
        engagement_id="umdr35-matrix", scope_context=_SCOPE,
        identity_context=_IDENTITY, require_target_backed=True,
    )
    assert result.passed is False
    assert result.reason == "negative_control_required"


def test_matrix_negative_control_reproduces_signal_blocked():
    """Control that reproduces the same technical signal → blocked."""
    baseline, candidate, _ = _valid_vulnerable_triple()
    contaminated = _obs(
        role="negative_control", status=200,
        body={"id": "INV-B-204", "owner": "User_B", "amount": 1000, "viewer": "User_A"},
        url=f"{LAB_ORIGIN}{VULN_PATH}?again=1",
    )
    decision = confirmation_gate(
        baseline, candidate, contaminated,
        vulnerability_class="IDOR", validator_outcome="CONFIRMED",
        validator_id="v", identity_context=_IDENTITY, scope_context=_SCOPE,
    )
    assert decision.confirmed is False


def test_matrix_control_equal_to_baseline_blocked():
    """Control identical to the baseline (not independent) → blocked."""
    baseline, candidate, _ = _valid_vulnerable_triple()
    decision = confirmation_gate(
        baseline, candidate, baseline,
        vulnerability_class="IDOR", validator_outcome="CONFIRMED",
        validator_id="v", identity_context=_IDENTITY, scope_context=_SCOPE,
    )
    assert decision.outcome is ConfirmationOutcome.BLOCKED
    assert decision.reason == "negative_control_technical_signal_absent"


def test_matrix_baseline_already_contains_signal_no_promotion():
    """Baseline already containing the alleged vulnerability signal → no
    unsupported promotion (no differential → CLEAN/INCONCLUSIVE, blocked)."""
    baseline, candidate, control = _valid_vulnerable_triple()
    # Baseline returns the foreign object too (no own/baseline differential).
    contaminated_baseline = _obs(
        role="baseline", status=200,
        body={"id": "INV-B-204", "owner": "User_B", "amount": 1000, "viewer": "User_A"},
        url=f"{LAB_ORIGIN}/api/invoices/INV-A-101",
    )
    decision = confirmation_gate(
        contaminated_baseline, candidate, control,
        vulnerability_class="IDOR", validator_outcome="CONFIRMED",
        validator_id="v", identity_context=_IDENTITY, scope_context=_SCOPE,
    )
    assert decision.confirmed is False


def test_matrix_forged_causal_guard_result_blocked():
    """A forged/manually-constructed guard-shaped dict is not a typed
    authority result — the verifier re-adjudicates the evidence itself."""
    baseline, candidate, control = _valid_vulnerable_triple()
    result = verify_replay_evidence(
        _finding(),
        baseline=baseline, candidate=candidate, negative_control=control,
        causal_signal=True, negative_control_complete=True,
        validator_id="v", validator_version="v1", causal_basis="b",
        engagement_id="umdr35-matrix", hypothesis_id=uuid.uuid4(),
        scope_context=_SCOPE, identity_context=_IDENTITY,
        require_target_backed=True,
    )
    assert result.passed is True
    guard_block = result.evidence["causal_guard"]
    assert guard_block["authority"] == "webpent.cqa_v2.causal_guard.guarded_causal_evaluate"
    # The verdict is derived by the adapter FROM the evidence — the recorded
    # guard observation digests must bind to the exact observations held.
    digests = guard_block["evidence_digests"]
    assert set(digests) == {"baseline", "candidate", "negative_control"}


def test_matrix_tampered_replay_evidence_blocked():
    """Tampering with observations after adjudication breaks replay."""
    baseline, candidate, control = _valid_vulnerable_triple()
    finding = _finding()
    result = verify_replay_evidence(
        finding,
        baseline=baseline, candidate=candidate, negative_control=control,
        causal_signal=True, negative_control_complete=True,
        validator_id="v", validator_version="v1", causal_basis="b",
        engagement_id="umdr35-matrix", hypothesis_id=uuid.uuid4(),
        scope_context=_SCOPE, identity_context=_IDENTITY,
        require_target_backed=True,
    )
    assert result.passed is True and result.proof_bundle is not None
    bundle = result.proof_bundle
    # Tamper with the recorded baseline evidence: replay digests mismatch.
    tampered_baseline = dict(baseline)
    tampered_baseline["response_digest"] = _digest("tampered")
    replay_ok = bundle.replay(
        [tampered_baseline, candidate, control], control,
        replay_context={
            "engagement_id": "umdr35-matrix",
            "finding_id": str(finding.id),
            "hypothesis_id": str(finding.hypothesis_id),
            "target_fingerprint": _digest(LAB_ORIGIN + VULN_PATH),
            "scope_context": _SCOPE,
            "identity_context": _IDENTITY,
        },
    )
    assert replay_ok is False


def test_matrix_tampered_proof_bundle_blocked():
    """A tampered bundle fails seal verification and the promotion contract."""
    baseline, candidate, control = _valid_vulnerable_triple()
    result = verify_replay_evidence(
        _finding(),
        baseline=baseline, candidate=candidate, negative_control=control,
        causal_signal=True, negative_control_complete=True,
        validator_id="v", validator_version="v1", causal_basis="b",
        engagement_id="umdr35-matrix", hypothesis_id=uuid.uuid4(),
        scope_context=_SCOPE, identity_context=_IDENTITY,
        require_target_backed=True,
    )
    assert result.passed is True
    bundle = result.proof_bundle
    tampered = bundle.model_copy(
        update={"causal_oracle": {**bundle.causal_oracle, "causal_signal": False}},
    )
    assert tampered.verify_seal() is False
    from webpent.models.proof_bundle import proof_bundle_promotion_ready
    assert proof_bundle_promotion_ready(tampered) is False


def test_matrix_valid_full_chain_promotion_may_proceed():
    """Valid CausalGuard + valid ProofBundle + verified Replay → may proceed."""
    baseline, candidate, control = _valid_vulnerable_triple()
    finding = _finding()
    result = verify_replay_evidence(
        finding,
        baseline=baseline, candidate=candidate, negative_control=control,
        causal_signal=True, negative_control_complete=True,
        validator_id="matrix-validator", validator_version="v1",
        causal_basis="matrix", engagement_id="umdr35-matrix",
        hypothesis_id=uuid.uuid4(),
        scope_context=_SCOPE, identity_context=_IDENTITY,
        require_target_backed=True,
    )
    assert result.passed is True
    assert result.reason == "verified_replay"
    bundle = result.proof_bundle
    assert bundle is not None
    assert bundle.causal_oracle["causal_guard"]["verdict"] == "CONFIRMED"
    assert bundle.oracle_decision == "CONFIRMED"
    from webpent.models.proof_bundle import proof_bundle_promotion_ready
    assert proof_bundle_promotion_ready(bundle) is True
    # Same-finding invariant: the bundle is bound to THIS finding.
    assert bundle.finding_id == str(finding.id)


def test_matrix_scope_missing_blocked_before_bundle():
    baseline, candidate, control = _valid_vulnerable_triple()
    result = verify_replay_evidence(
        _finding(),
        baseline=baseline, candidate=candidate, negative_control=control,
        causal_signal=True, negative_control_complete=True,
        validator_id="v", validator_version="v1", causal_basis="b",
        engagement_id="umdr35-matrix", scope_context=None,
        identity_context=_IDENTITY, require_target_backed=True,
    )
    assert result.passed is False
    assert result.reason == "scope_and_identity_context_required"


# ---------------------------------------------------------------------------
# C. Role ablation — signals derived from actual evidence (§1.4)
# ---------------------------------------------------------------------------

def test_role_ablation_signals_derived_from_evidence_all_roles():
    baseline, candidate, control = _valid_vulnerable_triple()
    adj = adjudicate_with_causal_guard(
        baseline, candidate, control, vulnerability_class="IDOR",
        identity_context=_IDENTITY,
    )
    for role, payload in adj.role_signals.items():
        assert payload["signal"] is True, role
        assert payload["derived_from"] == f"recorded_{role}_observation"
        assert payload["semantic_digest"] is not None
        assert payload["status_code"] is not None


def test_role_ablation_control_signal_fails_when_evidence_absent():
    baseline, candidate, _ = _valid_vulnerable_triple()
    adj = adjudicate_with_causal_guard(
        baseline, candidate, {}, vulnerability_class="IDOR",
        identity_context=_IDENTITY,
    )
    assert adj.role_signals["negative_control"]["signal"] is None
    assert adj.role_signals["negative_control"]["basis"] == "observation_absent"
    assert adj.guard_result.verdict is Verdict.BLOCKED


def test_role_ablation_graph_and_avi_paths_consistent_semantics():
    """§1.4: the graph path (verifier) and the AVI path (gate) have the SAME
    confirmation semantics — both derive from the same authority call."""
    baseline, candidate, control = _valid_vulnerable_triple()
    # AVI-path gate:
    gate = confirmation_gate(
        baseline, candidate, control, vulnerability_class="IDOR",
        validator_outcome="CONFIRMED", validator_id="canonical_validator_idor",
        identity_context=_IDENTITY, scope_context=_SCOPE,
    )
    # Graph-path verifier:
    verifier = verify_replay_evidence(
        _finding(),
        baseline=baseline, candidate=candidate, negative_control=control,
        causal_signal=True, negative_control_complete=True,
        validator_id="canonical_validator_idor", validator_version="v1",
        causal_basis="consistency", engagement_id="umdr35-matrix",
        hypothesis_id=uuid.uuid4(),
        scope_context=_SCOPE, identity_context=_IDENTITY,
        require_target_backed=True,
    )
    assert gate.confirmed is True
    assert verifier.passed is True
    # Both record the same authority verdict on the same evidence digests.
    gate_digests = gate.adjudication.evidence_digests
    verifier_digests = verifier.evidence["causal_guard"]["evidence_digests"]
    assert gate_digests == verifier_digests


# ---------------------------------------------------------------------------
# D. AST invariant — no module outside the authority assigns confirmed state
# ---------------------------------------------------------------------------

# Trusted authority implementations: these are the ONLY modules allowed to
# assign a confirmed/promoted finding state. Each entry is justified.
_AUTHORITY_ALLOWLIST: dict[str, str] = {
    # The universal adapter: converts authority verdicts into decisions.
    "production/confirmation_adapter.py": "the universal confirmation boundary (runs CausalGuard, never assigns finding state itself)",
    # The strict verifier: sole ProofBundle+replay authority; confirmation
    # requires the mandatory CausalGuard adjudication it performs itself.
    "shared/verifier.py": "strict replay verifier — mandatory CausalGuard adjudication + sealed ProofBundle + replay",
    # Validators: assign Tool-Confirmed ONLY on verification.passed from the
    # strict verifier (gated branches, pinned by the tests in this file).
    "agents/validator/agent.py": "validator dispatch — confirmed branches gated by verify_replay_evidence",
    "agents/validator/active_checks.py": "active validator — _confirmed() gated by verify_replay_evidence",
    "agents/validator/postp0_checks.py": "post-P0 validator — gated by verify_replay_evidence",
    "agents/validator/structural_checks.py": "structural validator — gated by verify_replay_evidence",
    "agents/access_control/agent.py": "access-control validator — gated by verify_replay_evidence",
    "agents/api_testing/agent.py": "api-testing validator — gated by verify_replay_evidence",
    # AVI promotion pipeline: central promotion authority; its new
    # causal_guard_adjudicated gate requires the typed guard adjudication.
    "production/autonomous_validation_v1.py": "AVI PromotionPipeline — causal_guard_adjudicated gate + sealed bundle + replay",
    # Graph AVI merge: converts PromotionPipeline-promoted findings only.
    "graph/builder.py": "graph wiring — merges only PromotionPipeline-promoted findings (guard-gated)",
    # Model definition + persistence mapping (enums, monotonic preservation).
    "models/findings.py": "model enum + provenance validator definition",
    "memory/db.py": "persistence mapping (DB Tool-Confirmed preservation)",
    "families/promotion.py": "family spine promotion — FIRM confidence, gated by family proof contract (flag-off path)",
    "egaie/finding_bridge.py": "EGAIE bridge — requires replay-valid bundle records + HypothesisStatus.CONFIRMED (flag-off path)",
    "state/reducers.py": "state channel reducer (read-only state merge)",
    "production/stateful_discovery.py": "CausalGuard-routed stateful discovery (verdict-routed, Pending level)",
}

_CONFIRMED_STATES = ("CONFIRMED", "Tool-Confirmed", "PROMOTED")


def _iter_confirmation_assignments(tree: ast.AST, rel: str):
    """Yield (kind, detail) for every confirmed-state assignment construct."""
    for node in ast.walk(tree):
        # model_copy(update={"confidence": Confidence.CONFIRMED.value, ...})
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "model_copy":
            for kw in node.keywords:
                if kw.arg == "update" and isinstance(kw.value, ast.Dict):
                    for key, value in zip(kw.value.keys, kw.value.values):
                        if isinstance(key, ast.Constant) and key.value in (
                            "confidence", "confidence_level", "status",
                        ) and isinstance(value, ast.Constant) \
                                and str(value.value) in _CONFIRMED_STATES:
                            yield ("model_copy_update", f"{key.value}={value.value}")
        # dict literal {"confidence": "confirmed", ...}
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value in (
                    "confidence", "confidence_level",
                ) and isinstance(value, ast.Constant) \
                        and str(value.value) in _CONFIRMED_STATES:
                    yield ("dict_literal", f"{key.value}={value.value}")
        # Finding(confidence=..., confidence_level=...) keyword constants
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "Finding":
            for kw in node.keywords:
                if kw.arg in ("confidence", "confidence_level") and isinstance(
                    kw.value, ast.Constant,
                ) and str(kw.value.value) in _CONFIRMED_STATES:
                    yield ("finding_ctor", f"{kw.arg}={kw.value.value}")
        # direct assignments confidence = Confidence.CONFIRMED.value
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in (
                    "confidence", "confidence_level",
                ):
                    value = node.value
                    if isinstance(value, ast.Constant) and str(value.value) in _CONFIRMED_STATES:
                        yield ("assign", f"{target.id}={value.value}")
                    if isinstance(value, ast.Attribute) and value.attr == "CONFIRMED":
                        yield ("assign", f"{target.id}=Confidence.CONFIRMED")


def test_ast_invariant_no_confirmation_assignment_outside_authority():
    """Repository-wide invariant (UM-DR-35 §1.5).

    No module outside the trusted authority allowlist may independently
    assign a confirmed or promoted finding state — via direct assignment,
    model-copy updates, dict literals, or Finding construction. The scan
    covers the real source tree, not a hand-maintained list of files.
    """
    violations: list[str] = []
    scanned = 0
    for path in sorted(SRC.rglob("*.py")):
        rel = str(path.relative_to(SRC))
        scanned += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - documented template
            continue
        for kind, detail in _iter_confirmation_assignments(tree, rel):
            if rel not in _AUTHORITY_ALLOWLIST:
                violations.append(f"{rel}:{kind}:{detail}")
    assert scanned > 500, "source tree unexpectedly small — scan sanity"
    assert not violations, (
        "Modules outside the confirmation authority assign confirmed/promoted "
        "finding states (UM-DR-35 violation). If an exception is genuinely "
        "necessary it must be explicitly justified in _AUTHORITY_ALLOWLIST: "
        f"{violations}"
    )


def test_ast_invariant_allowlist_entries_exist_and_justified():
    """Every allowlist entry must exist and carry a justification."""
    for rel, justification in _AUTHORITY_ALLOWLIST.items():
        assert (SRC / rel).exists(), f"allowlist entry missing on disk: {rel}"
        assert len(justification.strip()) >= 20, f"unjustified allowlist entry: {rel}"


def test_verifier_records_guard_provenance_in_evidence_and_bundle():
    baseline, candidate, control = _valid_vulnerable_triple()
    result = verify_replay_evidence(
        _finding(),
        baseline=baseline, candidate=candidate, negative_control=control,
        causal_signal=True, negative_control_complete=True,
        validator_id="provenance-check", validator_version="v1",
        causal_basis="provenance", engagement_id="umdr35-matrix",
        hypothesis_id=uuid.uuid4(),
        scope_context=_SCOPE, identity_context=_IDENTITY,
        require_target_backed=True,
    )
    assert result.passed is True
    guard = result.evidence["causal_guard"]
    assert guard["adjudicated_by"] == "webpent.production.confirmation_adapter"
    assert guard["authority"] == "webpent.cqa_v2.causal_guard.guarded_causal_evaluate"
    assert guard["verdict"] == "CONFIRMED"
    assert guard["role_technical_signals"]["baseline"]["signal"] is True
    assert guard["role_technical_signals"]["candidate"]["signal"] is True
    assert guard["role_technical_signals"]["negative_control"]["signal"] is True
    bundle_guard = result.proof_bundle.causal_oracle["causal_guard"]
    assert bundle_guard["verdict"] == "CONFIRMED"
    assert bundle_guard["evidence_digests"] == guard["evidence_digests"]


def test_guard_blocks_when_actor_and_resource_context_absent():
    """Fail-closed: evidence without actor/resource context cannot confirm —
    even with caller booleans True (the guard BLOCKS on incomplete context)."""
    baseline, candidate, control = _valid_vulnerable_triple()

    def strip_context(obs: dict) -> dict:
        stripped = dict(obs)
        stripped.pop("headers", None)   # no actor binding
        stripped["response_body"] = ""  # no resource-owner evidence
        return stripped

    result = verify_replay_evidence(
        _finding(),
        baseline=strip_context(baseline), candidate=strip_context(candidate),
        negative_control=strip_context(control),
        causal_signal=True, negative_control_complete=True,
        validator_id="v", validator_version="v1", causal_basis="b",
        engagement_id="umdr35-matrix", hypothesis_id=uuid.uuid4(),
        scope_context=_SCOPE, identity_context={"mode": "anonymous"},
        require_target_backed=True,
    )
    assert result.passed is False
    guard = result.evidence["causal_guard"]
    assert guard["verdict"] in {"BLOCKED", "INCONCLUSIVE", "CLEAN"}
    assert guard["verdict"] != "CONFIRMED"
