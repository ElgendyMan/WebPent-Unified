# WebPent-Unified v0.44.0 — UM-DR-45 Convergence & Ascension

Aggregate release notes for the UM-DR-33 → UM-DR-45 arc. Numbers derive
from the saved evidence files cited inline.

## One trunk (M1/M2)
The parallel branches were classified by patch-id equivalence and archived
as tags (never deleted): security/umdr42-closure (18 unique patches),
security/umdr34-origin-scope-hardening (5), features/v0.39.0-umdr33 (3).
`patch_id_equivalence.json` records every commit's classification.

## Green CI (R1)
The red SBOM step (bare pip-audit exit on allowlisted advisories) was
replaced by an allowlist-adjudicating generator (`scripts/generate_sbom.py`,
18 tests) — generation failure and un-waived advisories still fail.

## Security & identity closure (K-track)
- **K3**: the shadow→state converter is now reflectable under
  `typing.get_type_hints` (module-level Hypothesis binding).
- **K4**: authenticated deployments with no provisionable operator now
  REFUSE TO BOOT (fail-fast on top of fail-closed); the development bypass
  is announced at WARNING on every boot.
- **K5**: cross-process scope authority verified (opt-in durable SQLite
  store; 503 fail-closed without it).
- **K6**: `h2` declared as the direct dependency it always was — the http2
  smuggling capability was silently dead in every uv-synced environment.

## The measured ultimate (X-track)
12 campaigns across 4 authorised lab targets, LLM disabled, CausalGuard and
ProofBundle the sole confirmation authority:

* labsuite engine (battery B): **precision 1.0 / recall 1.0** on every
  defective target (9/18/15 defects), **zero** confirmations on the secured
  control;
* CLI hunt surface (battery A): recall 0.0 on the same targets — the
  credential-channel wiring gap is reported as a finding (UMDR45-F05), not
  hidden.

## Governance (H-track, R2/R3)
MIT LICENSE; GOVERNANCE_INDEX maps every standing gate to its enforcement
point; accounting_v3 ruled the single suite-accounting schema (old reports
superseded, never edited); all 46 G-08/G-02 transport approvals reviewed
per-record — **zero bulk renewal**.

## Findings: 4 FIXED / 4 OPEN
See FINDINGS_REGISTER.json. OPEN items are owner decisions by design
(credential-channel wiring, allowlist unification, base-image pin, orphan
retirement, RC-8/9/10 continuation).

## Honest ceiling
An Advanced Autonomous Security Research / Engineering Platform — not yet
an independently validated Autonomous Bug Hunter Ultimate. The claim moved
exactly as far as the evidence moved it.
