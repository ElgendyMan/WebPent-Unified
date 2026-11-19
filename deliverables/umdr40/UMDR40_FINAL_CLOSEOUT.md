# UM-DR-40 — Final Closeout Report

Generated 2026-11-18T13:10:01.800487+00:00 — final chain head `bafe618ee6f7` (mission branch, from published main `ca4ae448`).

## Decision: **COMPLETE_LOCAL (RC-4 + RC-5 + RC-6 + RC-7) — REMOTE_CI_BLOCKED — RC-8..10 ASSESSED**

The binding green suite: **9365 collected / 9354 passed / 0 failed / 0 errors** at `ccb4aea` (the 9,330 baseline + the windows' 24 new contract tests), with BUILD_INFO honesty and evidence gates PASS and the frozen gate green against BOTH declared refreezes (builder.py 95efa271, strategist 887c4c0f).

## What the windows delivered

* **RC-4 (identity-aware research activation) — PROVEN**: router bypass fixed; per-campaign activation with recorded budget impact; the production-entrypoint proof reproduced across FOUR independent builds: enabled principals_observed=3 vs baseline 0, guard verdicts unchanged, zero request-budget delta.
* **RC-5 (generation-time semantic dedup) — IMPLEMENTED**: deterministic uuid5 ids at the builder registration boundary; the two-pass acceptance green; the enabler for RC-6.
* **RC-6 (measured information gain) — IMPLEMENTED**: the strategist's decision batch records its measured before/after gain (distinguished ids) in the decision log — adapted INTO the strategist, exactly per the 39 register.
* **RC-7 (ranked runner-up slice) — IMPLEMENTED**: every coverage entry carries its bounded alternatives slice with scores.

## The window's chain

``
ca4ae448 (published main, tree = delivered UMDR39 package)
  baabbe5 provenance re-baseline / bed2af9 prism time-bomb / ce5c76c cleanup
  fe091f6+29cfee2 RC-4 wiring+contracts+RC-5 / 07d2a9a RC-4 activation
  ba0d294 generators+refreeze+regen / 65988e2 campaign proof
  a972cef RC-6/7 / ccb4aea BINDING SUITE 9,365/9,354/0/0
  8e5dafc evidence / bafe618 accounting / bafe618 matrix+closeout
```

## Honest limits

* RC-8 remains open; RC-9/RC-10 assessed (no coverage claimed).
* resolved_preconditions in the gain record stays empty by design (no precondition channel in this pass) — recorded, not invented.
* Remote CI/publication remain blocked on push credentials; the branch carries the complete verified chain.
* The environment recycled the build tree twice; the current chain is the deterministic rebuild #3 (byte-identical builder hash across builds: 95efa271), and every proof reproduced identically.
