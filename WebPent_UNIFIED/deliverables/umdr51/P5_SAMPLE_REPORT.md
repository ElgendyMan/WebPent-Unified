# UM-DR-51 P5 — عينة تقرير finding حقيقية

_مولّدة من حملة حقيقية بتاريخ 2026-11-26T16:20:03Z — الحقول غير المسجلة معلنة صريحة، لا مخترعة._

## Finding: [auth_bypass] confirmed differential

- **Class**: auth_bypass | **Severity**: critical | **Tool**: n/a
- **URL**: `http://127.0.0.1:39941/api/invoices/INV-A-101`
- **Resource**: not recorded by the earning campaign
- **Identity/authz context**: not recorded by the earning campaign
- **App state context**: not recorded by the earning campaign
- **Fix recommendation**: not recorded by the earning campaign
- **Retest status**: not retested (first report)
- **Confidence**: Tool-Confirmed — Tool-Confirmed = CausalGuard adjudicated differential + ProofBundle evidence + sealed replay verification

### Why this is real (expected vs observed)

- **Expected**: both surfaces/legs enforce the same authorization requirement
- **Observed**: CausalGuard-adjudicated differential (sealed ProofBundle, replayed); promoted through families/promotion.py with a passed verification
- **Engine reasoning**: CausalGuard-adjudicated differential (sealed ProofBundle, replayed); promoted through families/promotion.py with a passed verification

### The original request (scrubbed) and the response

- `GET http://127.0.0.1:39941/api/invoices/INV-A-101`
- proof bundle: `proof_bundle_55e337553e8e4376905526a3c8b5a1b5`

### Impact

- not recorded by the earning campaign (CVSS not recorded by the earning campaign (the CVSS engine node has not enriched this finding))

### How to re-prove it, step by step

Step 1: replay GET http://127.0.0.1:39941/api/invoices/INV-A-101 as the resource's legitimate owner — it must succeed
Step 2: replay the identical request as a foreign principal (the differential leg) — the differential must reproduce
Step 3: verify the replay through the CausalGuard adjudication (sealed replay, ProofBundle evidence intact)

---
