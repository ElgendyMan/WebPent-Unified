"""R2 addendum repros — families/forge red-team round (2026-11-02).

Verifies each Critical/High finding by direct execution against the real
code paths. Each section prints PROVEN or NOT-REPRODUCED with evidence.
"""
import subprocess
import sys

sys.path.insert(0, "/home/z/my-project/webpent/webpent/src")


def hdr(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


# ---------------------------------------------------------------------------
hdr("R2-fam-01 (High): build_plan_for multi_step_auth_bypass -> TypeError")

from webpent.families.base import FamilyCandidate, FamilyId
from webpent.families.execution_plans import build_plan_for

c = FamilyCandidate(candidate_id="MS-1", family=FamilyId.MULTI_STEP_AUTH_BYPASS,
                    vuln_class="multi_step_auth_bypass", scenario_id="MSAUTH-x",
                    affected_endpoint="POST /api/finalize", hypothesis="h")
try:
    build_plan_for(c, base_url="https://target.example")
    print("NOT-REPRODUCED: plan built")
except TypeError as exc:
    print(f"PROVEN: TypeError: {exc}")
# and the node swallows it -> zero plans for the whole family
from webpent.families.execution_node import family_execution_node
state = {"target_id": "t", "engagement_id": "e",
         "auth_flows": [{"step": 1}, {"step": 2}]}
out = family_execution_node(state)
plans = out["family_execution_plans"]
msauth = [p for p in out["family_candidates"]
          if p.get("family") == "multi_step_auth_bypass"]
print(f"node with auth_flows: candidates={len(out['family_candidates'])} "
      f"(msauth={len(msauth)}), plans_built={len(plans)} "
      f"status={out['family_execution_status']}")

# ---------------------------------------------------------------------------
hdr("R2-fam-02 (Critical): oauth CONFIRMED from attacker-host-200 only")

from webpent.families.execution_node import _execute_plan
from webpent.families.execution_plans import build_oauth_plan
from webpent.agents.validator.family_checks import dispatch_family_validator

c = FamilyCandidate(candidate_id="OA-1", family=FamilyId.OAUTH,
                    vuln_class="oauth", scenario_id="OAUTH-x",
                    affected_endpoint="GET /oauth/authorize", hypothesis="h")
plan = build_oauth_plan(c, authorize_url="https://target.example/oauth/authorize",
                        client_id="web", attacker_redirect_uri="https://attacker.example/cb")

class _Resp:  # attacker landing page: 200, no code anywhere
    def __init__(self, status, text=""):
        self.status_code, self.text, self.url = status, text, "https://attacker.example/cb"

pack = _execute_plan(plan, lambda rp: _Resp(200, "<html>welcome</html>"))
res = dispatch_family_validator("oauth", pack)
print(f"attacker page = plain 200 (no 'code=' delivered anywhere)")
print(f"verdict = {res.verdict.value} | rationale = {res.rationale}")
print("PROVEN" if res.verdict.value == "CONFIRMED" else "NOT-REPRODUCED")

# ---------------------------------------------------------------------------
hdr("R2-fam-03 (High): race post-state oracle is tautological")

from webpent.families.execution_plans import build_race_plan

c = FamilyCandidate(candidate_id="RC-1", family=FamilyId.RACE_CONDITION,
                    vuln_class="race_condition", scenario_id="RACE-x",
                    affected_endpoint="POST /api/transfer", hypothesis="h")
plan = build_race_plan(c, burst_size=3)
def exec_race(rp):
    # burst-* -> 200 (race won), seq-* -> 403 (negative held),
    # post-state -> 200 whose body explicitly says NO side effects
    if rp.label.startswith("seq-"):
        return _Resp(403, "forbidden")
    return _Resp(200, "STATE UNCHANGED — no side effects happened")
pack = _execute_plan(plan, exec_race)
res = dispatch_family_validator("race_condition", pack)
print(f"burst 3x200, seq 403; post-state body explicitly says NO side effects")
print(f"verdict = {res.verdict.value} | causal_oracle = "
      f"{res.proof_bundle_spec.get('causal_oracle')}")
print("PROVEN (post-state never inspected; label written by node itself)"
      if res.verdict.value == "CONFIRMED" else "NOT-REPRODUCED")

# ---------------------------------------------------------------------------
hdr("R2-fam-04 (High): tenant/chain/biz-logic can never CONFIRM via node")

from webpent.families.execution_plans import build_tenant_plan

c = FamilyCandidate(candidate_id="TN-1", family=FamilyId.TENANT_ISOLATION,
                    vuln_class="tenant_isolation", scenario_id="TEN-x",
                    affected_endpoint="GET /api/items/1", hypothesis="h")
plan = build_tenant_plan(c, actor_a_session="tok-a", foreign_resource_ref="/2")
def exec_tenant(rp):
    # actor A gets 2xx with FULL foreign-tenant data; same-tenant negative 403
    if rp.label == "same-tenant-different-user-negative":
        return _Resp(403, "forbidden")
    return _Resp(200, '{"owner":"tenant-B","data":"secret"}')
pack = _execute_plan(plan, exec_tenant)
res = dispatch_family_validator("tenant_isolation", pack)
print(f"actor A 2xx with foreign tenant body -> verdict = {res.verdict.value} "
      f"({res.rationale[:70]})")
t1 = "PROVEN (needs literal marker 'foreign-tenant-observed' echoed by target)" \
     if res.verdict.value != "CONFIRMED" else "NOT-REPRODUCED"
print(t1)
# exploit_chain: node hardcodes 1 feeder -> len<2 forever
pack2 = {"feeder_findings": [{"vuln_class": "feeder"}],
         "composed_replay": _Resp(200, "ok"), "chain_scenario_id": "CH-x",
         "feeder_artifacts_used": ["artifact-1", "artifact-2"]}
res2 = dispatch_family_validator("exploit_chain", pack2)
print(f"exploit_chain with node's hardcoded pack -> {res2.verdict.value} "
      f"({res2.rationale[:60]})")

# ---------------------------------------------------------------------------
hdr("R2-fam-05 (High): replay_evidence keyed by family overwrites evidence")

from webpent.families.execution_node import _execute_plan  # noqa: E402

packs = {}
for i in range(3):
    p = build_race_plan(
        FamilyCandidate(candidate_id=f"RC-{i}", family=FamilyId.RACE_CONDITION,
                        vuln_class="race_condition", scenario_id=f"RACE-{i}",
                        affected_endpoint=f"POST /api/transfer{i}", hypothesis="h"),
        burst_size=2)
    pk = _execute_plan(p, lambda rp: _Resp(200, "x"))
    packs[p.family] = pk  # node's exact assignment: replay_evidence[plan.family]
print(f"3 distinct race plans executed -> evidence packs kept: {len(packs)} "
      f"(keys={list(packs)})")
print("PROVEN (2 of 3 executed bursts' evidence silently discarded)"
      if len(packs) == 1 else "NOT-REPRODUCED")

# ---------------------------------------------------------------------------
hdr("R2-fam-06 (Medium): hash()-based digests/ids are non-deterministic")

code = (
    "import sys; sys.path.insert(0, '/home/z/my-project/webpent/webpent/src');"
    "from webpent.families.execution_node import _execute_plan, _seal_proof_bundle;"
    "from webpent.families.execution_plans import build_race_plan;"
    "from webpent.families.base import FamilyCandidate, FamilyId;"
    "from webpent.agents.validator.family_checks import FamilyValidationResult, FamilyVerdict;"
    "p = build_race_plan(FamilyCandidate(candidate_id='B',"
    "     family=FamilyId.RACE_CONDITION, vuln_class='race_condition',"
    "     scenario_id='S', hypothesis='h', affected_endpoint='POST /x'), burst_size=1);"
    "R = type('R',(),{'status_code':200,'text':'same body'});"
    "pack = _execute_plan(p, lambda rp: R());"
    "r = pack['burst_replays'][0];"
    "res = FamilyValidationResult('business_logic','S',FamilyVerdict.CONFIRMED,'why');"
    "st = {'engagement_id':'e'};"
    "print(r.body_digest, _seal_proof_bundle(res, st))"
)
runs = [subprocess.run([sys.executable, "-c", code], capture_output=True,
                       text=True) for _ in range(2)]
outs = [r.stdout.strip() for r in runs]
if not all(outs):
    for r in runs:
        print("stderr:", r.stderr.strip()[:300])
print(f"run1: {outs[0][:120]}")
print(f"run2: {outs[1][:120]}")
print("PROVEN (same body / same result -> different digests+ids across runs)"
      if outs[0] != outs[1] and all(outs) else "NOT-REPRODUCED")

# ---------------------------------------------------------------------------
hdr("R2-forge-01 (High): synthesizer emits VulnClass; one stored row poisons reads")

from webpent.forge import synthesizer
from webpent.forge.indexer import PayloadIndexer
from webpent.forge.schemas import Family

gen = synthesizer.generate(limit=1)
p = gen["valid_payloads"][0]
print(f"synthesized payload family = {type(p.family).__name__} "
      f"(value={p.family.value!r}); forge.Family expected")
idx = PayloadIndexer(":memory:")
try:
    idx.store_payload(p)
    print("stored; now reading corpus...")
    try:
        idx.list_all()
        print("NOT-REPRODUCED: list_all survived")
    except ValueError as exc:
        print(f"PROVEN: list_all() raises ValueError: {exc} "
              f"(corpus reads bricked by one synthesized row)")
except Exception as exc:
    print(f"store rejected ({type(exc).__name__}: {exc}) — checking CLI bandage...")

print("\nDone.")
