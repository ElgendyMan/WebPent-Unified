# UM-DR-37 Root Cause Report — the zero-findings production run

Generated 2026-11-16T05:24:44.894368+00:00. This is the mission's core diagnostic deliverable.

## Reproduction (before the fix)

`artifacts/umdr37_graph_trace_before.json`: through the REAL
`run_unified_hunt` against the authorized IDOR lab, the unfixed tree
produced `endpoints=1` (origin only), 0 candidate records, 0 findings,
0 CausalGuard invocations. Drop-off reason codes recorded:
RESOURCE_NOT_DISCOVERED, CANDIDATE_EXTRACTION_FAILED,
NO_FINDINGS_PRODUCED.

## The four root causes (each reproduced, fixed, regression-pinned)

1. **RC-1 JSON-blind crawler** (`shared/http_discovery.py`): link
   extraction ran only for HTML; the lab's JSON manifest (`"links"`)
   was invisible. Fix: bounded JSON link extraction before the HTML
   gate.
2. **RC-2 identifier gate** (`access_control/agent.py` `_ID_PATTERN`):
   the 10-char minimum dropped structured short ids (INV-A-101, 9
   chars). Fix: ids with >=5 chars containing a digit; plain words
   still never match.
3. **RC-3 identity_profiles drop** (`cli/unified_hunt.py`): the
   no-checkpointer branch silently dropped the operator's secondary
   identities. Fix: both branches forward the same kwargs.
4. **RC-4 missing guard context** (`access_control/agent.py`): BAC
   probe rows lacked `actor_id`/`resource_owner`/
   `authorization_outcome`, so complete owner/foreign/denied triples
   were adjudicated INCONCLUSIVE. Fix: the node stamps the context it
   already possesses into the baseline/candidate/control rows.

## Verification (after the fix)

`umdr37_graph_trace_after.json`: endpoints=7, candidate records=4,
CausalGuard invoked twice, verdicts CONFIRMED, 2 Tool-Confirmed IDOR
findings with sealed ProofBundles (`verified_replay`). Reproduced
three times (see the E2E report). Regression tests:
`tests/test_umdr37_root_cause_fixes.py` 10/10, including a REAL
`run_unified_hunt` campaign asserting confirmation while the 403
enforced boundary and the 404 missing resource stay unconfirmed.

## Why the compiled campaign succeeded while production starved

The compiled campaign hand-built observations with full authorization
context and bypassed discovery/strategist lanes — it proved the
confirmation AUTHORITY worked, not that the production DISCOVERY path
could reach it. The four fixes close that gap; no gate was weakened.
