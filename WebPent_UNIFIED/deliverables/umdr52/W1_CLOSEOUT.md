# W1_CLOSEOUT — UM-DR-52 Week 1: Behavioral & Business Logic Reasoning

**الحكم: PARTIALLY_COMPLETE — بوابة G5 (العقل) VERIFIED بالقياس على مختبرين؛ الاختبار الآلي للطبقة كاملة أخضر؛ بنود W3 الميدانية التفصيلية تُحال إلى إغلاق النافذة (الأسبوع الثالث).**

الحكم بالأرقام من سجلات خام داخل الشجرة، كل رقم بملفه:

## 1) الأدلة المبنية

| المكوّن | الملف | الاختبار |
|---|---|---|
| A1+A2+A3 الطبقة السلوكية | `src/webpent/researcher/behavioral_layer.py` (789 سطرًا) | `tests/test_umdr52_w1_behavioral.py` |
| ربط المحرك (استهلاك الطبقة) | `src/webpent/production/brain_engine.py` (`build_brain_context` يبني `ctx.behavioral`؛ `estimate_priority_inputs` يستهلك `backing_for`؛ انبعاث `invariant_specs` إلى المسبح) | نفس الملف |
| ربط القرار (الخريطة) | `src/webpent/shared/prioritization.py` (`_brain_decision_map_k`، `p/(p+k)`) | `tests/test_umdr52_w1_behavioral.py` |
| ربط الاستراتيجي | `src/webpent/agents/strategist/agent.py:516` (`priority_score=score if _brain_decides else None`) | نفس الملف |

## 2) قياس G5 — دلتا OFF/ON (النصفان)

### 2أ) الميداني — Juice Shop (3 runs/sذرع، حملة/عملية منفصلة)
- **الملف الخام:** `deliverables/umdr52/run_files/brain_{off,on}_run{1..3}.json`؛ **الحكم:** `deliverables/umdr52/W1_FIELD_BRAIN_DELTA.json`
- `rank_order_changed = TRUE` — بصمة ترتيب OFF `2ad59ee5456d3eeb` مقابل ON `383288d57538dd88`، الأذرع حتمية (3/3 متطابقة داخل كل ذرع).
- `hypothesis_pool_changed = TRUE` — +2 فرضيات حتمية (30→32، انبعاث InvariantHypothesis من specs المعدَّنة).
- `outcome_counts_changed = FALSE` على شكل هذا الهدف — لم ينقلب قرار promoted على Juice Shop.
- `rate_ceiling_clean = TRUE`؛ `arms_deterministic = TRUE`؛ السقف مرفوع بعلم مُعلن (10000/د، مختبر محلي مصرّح به) مع snapshot للـgovernor في كل run.

### 2ب) الـfixture المعتمد — SKG lab (حتمي، بلا شبكة)
- **الملف:** `deliverables/umdr52/W1_FIXTURE_DECISION_DELTA.json` (مولّد من `scripts/umdr52_w1_fixture_delta.py` عبر الواجهات الحقيقية: `rank_with_brain` + `estimate_priority_inputs` + `recommend_action`).
- `order_changed = TRUE`.
- **انقلابا قرار مقاسان، مصدرهما الطبقة السلوكية:**
  - `/api/transfer`: OFF `defer` (0.2114) → ON `abandon` (brain_priority 0.0216 → decision 0.1259، تحت عتبة الإهمال 0.15 عبر الخريطة).
  - `/api/profile`: OFF `defer` (0.1860) → ON `abandon` (brain_priority 0.0084 → decision 0.0533).
- **حكم G5 على المختبرين معًا:** `VERIFIED` — ORDER تغيّر في الميداني والfixture، و≥1 OUTCOME انقلب في الfixture بصيغة القرار الحرفية (الأولوية تقرر، لا ترتّب فقط). دلتا pool-only لم تُعلن نجاحًا في أي سجل.

## 3) اختبارات الانحدار (العزل والسلطة)
19/19 أخضر (`pytest tests/test_umdr52_w1_behavioral.py`):
- عزل Inference عن Evidence: كل قاعدة مستنتجة تبقى فرضية بشرائط مسبقة وتجربة مميِّزة؛ لا مسار جانبي للتنفيذ.
- fail-open ممنوع: غياب الشرائط المسبقة ⇒ لا spec.
- سلطة CausalGuard غير المماسة: الطبقة لا تُصدر Findings ولا تؤكد.
- OFF متوافق بايت-ببايت: `ctx.behavioral=None` يجعل كل حد سلوكي no-op.

## 4) الحدود المعلنة (بصدق)
1. انقلاب OUTCOME قيس على الـfixture المعتمد؛ على Juice Shop قرارات promoted لم تنقلب في هذا الشكل الهدف — مسجل مقاسًا لا مخفيًا.
2. W6-chain على الميداني: `decisions_changed=false` في هذه الدفعة (`W1_FIELD_BRAIN_DELTA.json → w6_chain.status = INCONCLUSIVE`) — التعلم عابر-الحملات يُعاد قياسه في W2/W3 بعد محرك W2.
3. WebGoat/DVWA بنود الميدان ليست W1 — تُقفل في إغلاق W3 أو تعلن BLOCKED بمحاولة موثقة.
