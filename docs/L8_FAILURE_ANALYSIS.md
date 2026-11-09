# L8 §5 — Failure analysis and the smallest evidence-backed improvement

Sequencing discipline: every analysis and engine change in this
document used only DEV-block runs (docvault, market). The HELD-OUT
block (ticketflow, slots) was measured afterwards, once, and its
outcomes could not and did not influence any engine change; the
held-out gaps reported at the end are documented as measured limits,
not fixed.

## 1. The failure the first DEV measurement exposed

`docs/l8_discovery_dev.json` (generation 1, before the §5 change) at
budget 32, adaptive strategy:

| instance | variant | tp | fn | note |
|---|---|---|---|---|
| dv-101 | defective | 1 | 0 | confirmed |
| dv-104 | multi_observation | 0 | 1 | **never confirmed** |
| mk-111 | defective | 1 | 0 | confirmed |
| mk-114 | multi_observation | 0 | 1 | **never confirmed** |

Both multi-observation variants were missed at every budget by every
strategy. The apps' implementations are the diagnosis: a
multi-observation defect is scoped to ONE collection (docvault skips
the write-bit check in `collections[1]` only) or ONE bucket (market
honors a client amount for one quote bucket only), while the probe
generators picked exactly one resource each — `priced[0]` for price
probes, a single typed owner for identity mutation probes. The
chosen resource sat in the enforced scope, the probe observed clean
behavior, and the run correctly concluded clean on what it actually
tested. The engine was not wrong about the resource it probed; it
never probed the defective one.

## 2. The smallest fix

One new constant, `RESOURCE_PROBES_PER_OPERATION = 3`, and the two
probe loops (`_mutation_identity_hypotheses`, `_price_hypotheses`)
emit one probe per distinct resource per operation, capped by the
existing `MAX_HYPOTHESES_PER_FAMILY = 8`. Nothing else changed: the
oracle, the dedup, the sealing and the strategy orchestration are
untouched.

Red-first evidence: `tests/appsuite/test_discovery.py` gained two
tests asserting the scoped price and ownership defects are confirmed
on the multi-observation variants. Both failed before the change;
both pass after. Post-fix DEV re-measurement (generation 2):

- adaptive at b=32: tp=4, fp=1 (the documented dv-103 guest read, a
  designed false positive), fn=0 — recall 1.0, requests/tp 57.8
  (was 97.5).
- The scoped defects are now confirmed: dv-104 first-confirmation
  budget 4, mk-114 first-confirmation budget 2, by adaptive and
  adaptive-no-selector. Both fixed baselines (independent-fixed,
  observation-baseline) still miss them: the advantage is measured,
  not asserted.

## 3. Benchmark correction forced by the fix (discovery-v2)

Multi-resource probing on the L6 tuning fixture produced
confirmations of the checkout price defect on sibling invoices
(`/chk-0001/r-000101`, `r-000102`) that discovery-v1 did not declare,
and its path-exact scoring counted them as false positives. The
target's own implementation (`http_target._checkout_response`)
honors a client price for every priced invoice: the defect is
operation-scoped, and the benchmark under-declared it. discovery-v2
declares `price-override-checkout-2/3`, mirroring the identity
family's existing per-resource convention, and bumps the version.
One defect is one finding; v1 was counting genuine re-confirmations
of the same real defect as errors.

## 4. Held-out measured gaps (documented, deliberately not fixed)

`docs/l8_discovery_heldout.json` (160 runs, measured once after the
DEV analysis was frozen):

- WORKFLOW_ORDER on ticketflow: confirmed on tf-121 and tf-124 at
  first-confirmation budget 2 by every strategy, fp=0 everywhere,
  and the ambiguous variant correctly produces nothing.
- WORKFLOW_IDENTITY on ticketflow: 40 hypotheses generated across
  strategies, none confirmed — both defective variants carry one
  unconfirmed identity defect (fn). Diagnosis (analysis only, no
  change made): ticketflow checks identity BEFORE order, so a
  non-owner transition on the identity-target ticket succeeds only
  from the candidate action's required source state; the
  WORKFLOW_IDENTITY probe plan does not drive the workflow into
  that state first, the transition is rejected 409 for edge-table
  reasons, and the fail-closed oracle reads that as enforcement.
  The failure is a false negative, never a false positive.
- slots: its only defect family (idempotent_mutation) is the
  deliberately untuned family required by §2; it maps to no engine
  family and is correctly never confirmed. This is a design
  boundary, not an engine failure.
- observation-baseline matches adaptive on unique tp at lower
  request cost on held-out (54 vs 98 requests/tp): no adaptive
  advantage over the simple baseline on this block. Reported as
  measured.
