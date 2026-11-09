"""FINAL VERIFICATION runtime proof — part 2: authority spine probes.

  P1C-refute : CONFIRMED -> REFUTED with deterministic evidence; terminal;
               survives reload; re-save cannot resurrect; LLM-text-only
               refutation refused fail-closed.
  P5-forgery : forged "Tool-Confirmed"/target_backed/promotion without a
               sealed bundle carries no authority.
  P1F-scope  : sqlmap/dalfox fail-closed out-of-scope denial BEFORE network;
               poisoned scope input cannot widen scope.
  P3-iso     : multi-principal workspace isolation (A vs B vs admin).
"""
from __future__ import annotations

import json
import logging
import os
import sys

TREE = "/home/z/my-project/verify/tree/webpent-goed"
sys.path.insert(0, os.path.join(TREE, "src"))
os.chdir(TREE)

os.environ["WEBPENT_DATABASE_URL"] = "sqlite:////home/z/my-project/verify/results/fv_webpent.db"
os.environ.pop("DATABASE_URL", None)
os.environ["WEBPENT_LLM_ENABLED"] = "false"
os.environ["WEBPENT_CELERY_PAYLOAD_KEY"] = "fv-verify-crypto-key-0123456789abcdef"
os.environ["ADMIN_PASSWORD"] = "fv-operator-password-1"
os.environ["WEBPENT_AUTH_ENABLED"] = "true"
os.environ["JWT_SECRET_KEY"] = "fv-verify-jwt-secret-0123456789abcdef0123456789"
os.environ["AUDIT_SECRET_KEY"] = "fv-verify-audit-secret-0123456789abcdef012345"
os.environ["WEBPENT_ALLOW_PLAINTEXT_REDIS"] = "true"

logging.basicConfig(level=logging.INFO)
logging.getLogger("alembic").setLevel(logging.WARNING)

EVIDENCE: dict = {"probes": {}, "defects_found": [], "fixes_applied": []}


def ev(probe: str, **kw):
    EVIDENCE["probes"].setdefault(probe, {}).update(kw)
    print(f"[EVIDENCE] {probe}: {json.dumps(kw, default=str, sort_keys=True)[:700]}")


import uuid  # noqa: E402

from webpent.memory.db import STATUS_CONFIRMED, get_db_manager  # noqa: E402
from webpent.models.findings import Finding  # noqa: E402

# ================================================================ P1C-refute
db = get_db_manager()
db.init_db()

fid = uuid.uuid4()
base_finding = Finding(
    id=fid,
    thread_id="fv-refute-001",
    url="http://127.0.0.1:9/lab",
    vuln_class="sqli",
    title="FV probe: union-based SQLi (to be refuted)",
    severity="high",
    description="FV verification probe finding",
    tool_name="fv_probe",
    confidence_level="Tool-Confirmed",
    hypothesis_id=None,
    reasoning="sealed bundle from validator (probe fixture)",
    evidence={"kind": "probe"},
)
db.save_finding(base_finding)
# bring the row into CONFIRMED through the real persistence path
db.save_finding(
    base_finding.model_copy(
        update={"confidence_level": "Tool-Confirmed", "reasoning": "probe: tool-confirmed"}
    )
)
st = db.get_latest_finding_status(fid)
ev("P1C-setup", finding_id=str(fid), persisted_status=st, confirmed=(st == STATUS_CONFIRMED))

# --- (a) LLM-text-only refutation attempt must be REFUSED ---
refused = db.mark_refuted(
    fid,
    reasoning_appendix="LLM says: I believe this is a false positive.",
    causal_observation=None,
    proof_bundle=None,
    evidence_hash=None,
)
st_after_llm = db.get_latest_finding_status(fid)
ev(
    "P1C-llm-only-refusal",
    status_after=st_after_llm,
    refused_ok=(st_after_llm == STATUS_CONFIRMED),
)
if st_after_llm != STATUS_CONFIRMED:
    EVIDENCE["defects_found"].append("P1C: LLM-text-only refutation was NOT refused")

# --- (b) deterministic refutation with valid causal observation + sealed bundle ---
from webpent.models.proof_bundle import build_proof_bundle  # noqa: E402
from webpent.validators.causal_validator import validate_causal_observation  # noqa: E402

observation = {
    "evidence_refs": [
        f"differential-contradiction:{fid}",
        "baseline_request:sha256:fv-baseline-req",
        "baseline_response:sha256:fv-baseline-resp",
        "candidate_request:sha256:fv-candidate-req",
        "candidate_response:sha256:fv-candidate-resp",
        "negative_control_request:sha256:fv-nc-req",
        "negative_control_response:sha256:fv-nc-resp",
    ],
    "causal_signal": True,
    "negative_control_complete": True,
    "oracle_decision": "REFUTED",
    "contradiction_basis": "baseline_candidate_indistinguishable",
    "baseline": {
        "status_code": 200,
        "body_length": 512,
        "request_digest": "sha256:fv-baseline-req",
        "response_digest": "sha256:fv-baseline-resp",
        "observation_role": "baseline",
    },
    "candidate": {
        "body_length": 512,
        "body_delta": 0,
        "status_delta": 0,
        "request_digest": "sha256:fv-candidate-req",
        "response_digest": "sha256:fv-candidate-resp",
        "observation_role": "candidate",
    },
    "negative_control": {
        "status_code": 200,
        "body_length": 512,
        "request_digest": "sha256:fv-nc-req",
        "response_digest": "sha256:fv-nc-resp",
        "control": "independent_clean_baseline_request",
        "observation_role": "negative_control",
    },
    "target_fingerprint": "sha256:fv-target-fingerprint",
}
gate_ok = validate_causal_observation(observation)
ev("P1C-causal-gate", observation_valid=gate_ok)
bundle = build_proof_bundle(
    engagement_id="fv-refute-001",
    finding_id=str(fid),
    hypothesis_id=None,
    evidence=(observation,),
    evidence_refs=(f"differential-contradiction:{fid}",),
    negative_control=observation["negative_control"],
    baseline=observation["baseline"],
    causal_oracle={
        "decision": "REFUTED",
        "basis": "differential_baseline_candidate_indistinguishable",
        "reason": "fv probe differential contradiction",
    },
    target_backed=True,
    negative_control_independent=True,
    validator_id="fv.verification.refutation",
    validator_version="fv.v1",
    evidence_origin="target_runtime",
).seal(actor="fv.verification.refutation")
updated = db.mark_refuted(
    fid,
    reasoning_appendix="FV probe: deterministic differential contradiction.",
    causal_observation=observation,
    proof_bundle=bundle,
    evidence_hash="sha256:fv-evidence",
)
st_after = db.get_latest_finding_status(fid)
ev(
    "P1C-refuted",
    result_conf=(getattr(updated, "confidence_level", "") if updated else None),
    persisted_status=st_after,
    refuted=(st_after == "REFUTED"),
)

# --- (c) terminal: re-save CONFIRMED must NOT resurrect ---
db.save_finding(
    base_finding.model_copy(
        update={"confidence_level": "Tool-Confirmed", "reasoning": "probe: resurrection attempt"}
    )
)
st_res = db.get_latest_finding_status(fid)
ev("P1C-terminal-no-resurrect", status_after_resave=st_res, terminal=(st_res == "REFUTED"))
if st_res != "REFUTED":
    EVIDENCE["defects_found"].append("P1C: REFUTED finding was resurrected by re-save")

# --- (d) reload survival: brand-new manager instance, fresh connection ---
db2 = get_db_manager()
reloaded = db2.get_finding(fid)
ev(
    "P1C-reload-survival",
    reloaded_conf=(getattr(reloaded, "confidence_level", None) if reloaded else None),
    survives_reload=(
        reloaded is not None and getattr(reloaded, "confidence_level", "") == "Refuted"
    ),
)

# ================================================================ P5-forgery
from webpent.validators.proof_validator import validate_bundle_structure  # noqa: E402

# forged bundle: no negative control -> structure validation must fail
# forged bundle: no negative control -> structure validation must fail
# (note: evidence_origin='llm_generated' is rejected at model construction —
#  recorded as evidence; the forge attempt therefore uses a valid literal but
#  omits the negative control).
forged_bundle = build_proof_bundle(
    engagement_id="fv-forge",
    finding_id="00000000-0000-0000-0000-0000000000f1",
    hypothesis_id=None,
    evidence=(observation["baseline"],),
    evidence_refs=("forged",),
    causal_oracle={"decision": "CONFIRMED", "basis": "llm-only", "reason": "forged"},
    target_backed=True,
    negative_control_independent=False,
    validator_id="fv.forge",
    validator_version="0",
    evidence_origin="target_runtime",
)
ev(
    "P5-forged-bundle-no-negative-control",
    structure_rejected=(not validate_bundle_structure(forged_bundle, require_negative_control=True)),
)
if validate_bundle_structure(forged_bundle, require_negative_control=True):
    EVIDENCE["defects_found"].append("P5: forged bundle without negative control passed structure validation")
# forgery with tampered evidence digest -> seal must fail / verification must fail
try:
    tampered = build_proof_bundle(
        engagement_id="fv-forge",
        finding_id="00000000-0000-0000-0000-0000000000f2",
        hypothesis_id=None,
        evidence=(observation,),
        evidence_refs=(f"differential-contradiction:{fid}",),
        negative_control=observation["negative_control"],
        baseline=observation["baseline"],
        causal_oracle={"decision": "CONFIRMED", "basis": "tampered", "reason": "forge-confirm"},
        target_backed=True,
        negative_control_independent=True,
        validator_id="fv.forge2",
        validator_version="0",
        evidence_origin="target_runtime",
    ).seal(actor="fv.forge2")
    # tamper AFTER sealing
    from webpent.models.proof_bundle import ProofBundle  # noqa: E402

    d = tampered.model_dump()
    d["evidence_digests"] = ["sha256:totally-forged"]
    t2 = ProofBundle(**d)
    verdict = t2.verify()
    ev("P5-tampered-bundle-verify", verify_result=str(verdict)[:200])
    if getattr(verdict, "valid", verdict) is True or str(verdict).lower().find("invalid") < 0:
        EVIDENCE["defects_found"].append(f"P5: tampered bundle verify did not clearly reject: {verdict}")
except Exception as exc:  # seal/verify refusal counts as rejection
    ev("P5-tampered-bundle-verify", exception=type(exc).__name__)

# ================================================================ P1F-scope
from webpent.shared.engagement_scope import (  # noqa: E402
    get_engagement_target_hosts,
    is_engagement_target_host,
)

ev(
    "P1F-scope-baseline",
    engagement_hosts=sorted(get_engagement_target_hosts()),
    in_scope_127=bool(is_engagement_target_host("127.0.0.1")),
    out_of_scope_evil=bool(is_engagement_target_host("evil.example.com")),
)
if is_engagement_target_host("evil.example.com"):
    EVIDENCE["defects_found"].append("P1F: out-of-scope host accepted by scope law")

from webpent.tools.exploitation import dalfox, sqlmap  # noqa: E402

OUT = "http://evil.example.com/x?u=1"
for name, mod in (("dalfox", dalfox), ("sqlmap", sqlmap)):
    fn = mod.run_dalfox if name == "dalfox" else mod.run_sqlmap
    try:
        r = fn(OUT)
        # any string return here is a FAILURE of fail-closed denial
        ev(f"P1F-{name}-out-of-scope", blocked=False, returned=str(r)[:160])
        EVIDENCE["defects_found"].append(f"P1F: {name} returned output for out-of-scope target")
    except Exception as exc:
        msg = str(exc)
        scope_word = ("scope" in msg.lower()) or ("refus" in msg.lower())
        ev(
            f"P1F-{name}-out-of-scope",
            exception=type(exc).__name__,
            scope_denial_msg=scope_word,
            detail=msg[:200],
        )
        if not scope_word:
            EVIDENCE["defects_found"].append(
                f"P1F: {name} refused out-of-scope target but denial message lacks scope semantics: {msg[:120]}"
            )

# in-scope attempt: preflight admits the loopback host; the run fails honestly
# on the missing dalfox binary (infrastructure refusal, not a scope refusal).
try:
    IN = "http://127.0.0.1:9/x?u=1"
    r_in = dalfox.run_dalfox(IN)
    ev("P1F-dalfox-in-scope", returned=str(r_in)[:160])
except Exception as exc:
    msg = str(exc)
    is_infra = ("binary" in msg.lower() or "not found" in msg.lower()
                or "filenotfound" in type(exc).__name__.lower() or "executable" in msg.lower())
    ev(
        "P1F-dalfox-in-scope",
        exception=type(exc).__name__,
        scope_related=("scope" in msg.lower()),
        infrastructure_failure=is_infra or "scope" not in msg.lower(),
        detail=msg[:200],
    )

# poisoned scope: ScopeLaw must reject poisoned arguments/URLs for a
# registered tool, and must refuse unregistered tools outright.
from webpent.live_hunter.profile import AuthorizedLabProfile  # noqa: E402
from webpent.live_hunter.tool_scope import REGISTERED_TOOLS, ScopeLaw  # noqa: E402

prof = AuthorizedLabProfile(
    authorized_targets=("127.0.0.1",),
    engagement_id="fv-scope-poison",
    operator_approval_at="2026-09-15T00:00:00+00:00",
    knowledge_ready=True,
)
law = ScopeLaw(profile=prof, engagement_id="fv-scope-poison")
# Contract poison patterns are infrastructure vectors (metadata SSRF, OS shell
# flags, exotic schemes) — probe THOSE, plus an out-of-scope host in args.
d_meta = law.authorize_invocation(
    tool_name="sqlmap",
    target_url="http://127.0.0.1:9/x",
    arguments=("--data=1 --url=http://169.254.169.254/latest/meta-data",),
)
d_osshell = law.authorize_invocation(
    tool_name="sqlmap",
    target_url="http://127.0.0.1:9/x",
    arguments=("--os-shell",),
)
d_unreg = law.authorize_invocation(tool_name="skynet", target_url="http://127.0.0.1:9/x")
ev(
    "P1F-scopelaw-poison",
    registered_tools=sorted(REGISTERED_TOOLS)[:8],
    metadata_ip_detected=d_meta.poison_detected,
    metadata_ip_allowed=d_meta.in_scope,
    metadata_details=list(d_meta.poison_details)[:2],
    osshell_detected=d_osshell.poison_detected,
    osshell_allowed=d_osshell.in_scope,
    unregistered_allowed=d_unreg.in_scope,
)
if d_meta.in_scope:
    EVIDENCE["defects_found"].append("P1F: ScopeLaw allowed metadata-SSRF poisoned arguments")
if d_osshell.in_scope:
    EVIDENCE["defects_found"].append("P1F: ScopeLaw allowed --os-shell poisoned arguments")
if d_unreg.in_scope:
    EVIDENCE["defects_found"].append("P1F: unregistered tool allowed by ScopeLaw")

# ================================================================ P3-iso
import glob as _glob  # noqa: E402

wss = sorted(_glob.glob("/home/z/.webpent/workspaces/fv-client-*"), key=os.path.getmtime)
paths = sorted({os.path.join(ws, "databases", "webpent.sqlite3") for ws in wss if os.path.exists(os.path.join(ws, "databases", "webpent.sqlite3"))})
distinct = len(set(paths))
ev("P3-workspace-isolation", workspace_count=len(paths), distinct_dbs=distinct, paths=[p.split("/")[-3] for p in paths][:6])
if len(paths) >= 2 and distinct == 1:
    EVIDENCE["defects_found"].append("P3: multiple engagements share ONE database file")

out = "/home/z/my-project/verify/results/fv_authority_evidence.json"
with open(out, "w") as f:
    json.dump(EVIDENCE, f, indent=2, default=str)
print(f"[done] evidence -> {out}")
print("DEFECTS:", json.dumps(EVIDENCE["defects_found"], indent=2))
