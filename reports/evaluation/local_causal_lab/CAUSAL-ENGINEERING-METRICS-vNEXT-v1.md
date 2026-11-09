# Causal Engineering Metrics vNext

**Author:** Manus AI

هذه المقاييس تشغيلية فقط. هي تسجل عدد تقييمات الـfixture، توزيع قرارات الـoracle، عدد scoring ProofBundles، ونجاح replay. لا تُستخدم لحساب precision أو recall أو false negatives، ولا تُحوّل الحالات blocked أو inconclusive إلى clean أو failure.

| Metric | Value | Scope |
|---|---:|---|
| Target-backed experiments executed | 0 | لم تُنفذ تجربة WebGoat target-backed؛ الـflow القديم لم يُعاد تشغيله. |
| Offline fixture experiments executed | 1 | تقييم crAPI ownership fixture صناعي داخل الذاكرة فقط. |
| CONFIRMED decisions | 1 | fixture-only؛ ليست target-backed ولا scoring evidence. |
| CLEAN decisions | 0 | لا يوجد target experiment clean في هذه المرحلة. |
| INCONCLUSIVE decisions | 0 | لا يوجد target oracle evaluated. |
| BLOCKED decisions | 0 | WebGoat blocker موثق design-only وليس oracle execution. |
| Scoring ProofBundles created | 0 | القرار fixture-only و`target_backed=false`، لذلك لا bundle scoring. |
| Replay successes | 0 | لم تُنشأ scoring bundle أو target replay. |

> **القراءة الصحيحة:** وجود قرار `CONFIRMED` واحد يعكس نجاح typed oracle على نموذج crAPI offline synthetic فقط. لا يثبت وجود ثغرة في crAPI، ولا يثبت detection quality، ولا يفتح P10 أو VIP.

The implementation is `build_causal_engineering_metrics()` in `src/webpent/shared/proof_engine.py`; its output schema is intentionally limited to the four operational counters above and the decision distribution.

Governance remains unchanged: `official_isolated_p10_runs_authorized=false`, P10/P9/VIP are `NOT_QUALIFIED`, Bug Bounty is `BLOCKED`, and scoring promotion is `false`.

## References

[1] [Engineering metrics implementation](../../src/webpent/shared/proof_engine.py)

[2] [Machine-readable metrics artifact](./CAUSAL-ENGINEERING-METRICS-vNEXT-v1.json)
