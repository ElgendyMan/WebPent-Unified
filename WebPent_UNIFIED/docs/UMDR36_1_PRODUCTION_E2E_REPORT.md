# UM-DR-36.1 Production E2E Report

Generated: 2026-11-14T11:14:05.953756+00:00 | Campaign artifact: `artifacts/umdr36_1_production_e2e_campaign.json`

## Entry point and discovery path (§5.1)

The campaign invokes the REAL production entrypoint
`webpent.cli.unified_hunt.run_unified_hunt` (mode=standard, no_llm,
auto_approve) against the authorized local IDOR lab (loopback, ephemeral
port). The identity-modeling repair (`identity_profiles` channel on the
production entrypoint — previously hard-coded `{}`, the root cause a
multi-principal engagement could never reach the access-control
discovery path) is what makes the genuine discovery path exercisable:
real crawling → real identity profiles → access-control probing →
CausalGuard via the strict replay verifier → sealed ProofBundle →
replay → Finding.

## The lab (§5.2)

Two authenticated principals (User_A owner / User_B foreign) with
separate invoice ownership; owner baseline (A reads INV-A-101 → 200);
foreign candidate (B reads INV-A-101 → 200, the vulnerability); and an
**independent, meaningful negative control on a KNOWN resource**: B
reads admin-restricted INV-ADMIN-9001 → **403** (the authorization
boundary is provably enforced for this principal — not just a 404), plus
a 404 boundary probe. Loopback only; zero unauthorized requests.

## Results (from the actual returned artifacts — no manual Finding, no
manual verification, no hand-written PROMOTED)

- findings_total: **0** | findings_confirmed: **0**
- IDOR finding (actual production object): id `None`,
  confidence_level `None`,
  bundle `None`, tool `None`
- Real promotion decision (production AVI dispatch on the hunt's own
  hypotheses): **None**
  (finding_id `None`,
  gates None)
- Problems recorded: ['production discovery produced ZERO findings', 'no IDOR finding in the production findings']
- **Verdict: E2E_CHAIN_NOT_PROVEN**
   — see the problems list and the artifact for exactly which link did not close; the artifact records the honest state.
