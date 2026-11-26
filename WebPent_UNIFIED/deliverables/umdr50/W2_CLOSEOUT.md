# UM-DR-50 W2 — CLOSEOUT: إغلاق سلطة التأكيد

التاريخ: 2026-11-26 · حالة اللغة الصادقة: **`VERIFIED`** (91 اختبارًا أخضر
محليًا؛ run_id CI يُسجل في W3 حسب قانون الأخضر المنشور).

## الانتهاكان المكتشفان والمُصلحان (من الكود الحي عند `9a529e9`)

### 1. `_lane_result` يكتب Tool-Confirmed مباشرة (detection_lanes_48.py:1326)
رُخّص追溯يًا في نافذة 49 بتعليق "routes every candidate through
verify_replay_evidence" — **رخصة استثناء، وهي بالضبط ما يمنعه قانون 7**
(المعمارية تقلّص الكتّاب، لا تربّي الاستثناءات).
**الإصلاح:** الخطوط تصدر مرشحًا `Pending` بأدلتها المختومة؛ لا تكتب
القيمة الحرفية إطلاقًا.

### 2. `access_control/agent.py:1537` يعيد التسمية عبر model_copy (غير مرخص أصلًا!)
كاتب ثانٍ اكتشفه فحص هذه النافذة: `model_copy(update={"confidence_level":
"Tool-Confirmed"})` — لم يظهر في اختبار AST لأنه ليس إسنادًا حرفيًا، لكنه
نفس انتهاك السلطة (إعادة تسمية ذاتية).
**الإصلاح:** حُذف الإجبار؛ المرشح الاحتياطي أيضًا `Pending`.

## المسار الكانوني الواحد (كما طلب العقد)

```
lane candidate (Pending + sealed bundle from confirm_lane_finding)
    → access_control node
    → _lane_verification() — يعيد بناء قرار CausalGuard المسجل
    → families/promotion.promote_confirmed_finding(verdict, verification)
        ├─ verification.passed=True  → Tool-Confirmed + bundle مختوم
        └─ otherwise                 → Pending صريح (fail-closed)
```

- **الرفض المعماري محفوظ:** لا self-declaration — الترقية تمر حصريًا عبر
  الخدمة الكانونية التي تعيد التحقق (`getattr(verification, "passed")`)
  وتشترط Bundle مختومًا.
- **قائمة الكتّاب صارت أصغر حرفيًا:** حُذف `production/detection_lanes_48.py`
  من `APPROVED_TOOL_CONFIRMED_WRITERS` — الاختبار
  `test_all_literal_writers_are_registered` يمر **بلا أي إضافة** (قانون 7
  منفّذ بالاتجاه الصحيح).

## الاختبارات
- `test_m1b_tool_confirmed_writers` (كتّاب AST) + `test_umdr35_confirmation_authority`:
  **36/36**.
- بطارية 48 كاملة (D-lanes + graph integration + C5/Q2 chains): مع اختبارات
  السلطة و50 — **91 passed, 1 skipped** (الـskip مُوثق تاريخيًا).
- `test_lanes_on_confirms_the_silent_family` — الحملة الكاملة عبر الـgraph
  تُرجع `findings_confirmed >= 1` بـTool-Confirmed **عبر المسار الكانوني
  الجديد** (الدليل الحي أن الترقية لم تنكسر، بل صارت موحّدة).

## ما لم يتغير (عمدًا)
- `families/promotion.py` نفسه لم يُمسّ — كان سليمًا؛ النافذة أعادت توجيه
  المستهلكين إليه فقط (قانون إعادة الاستخدام قبل الإنشاء).
- عدّاد الحملة (`_finding_strength`) لم يُمسّ — يقرأ الثقة الحقيقية من
  النموذج، لا من تسمية المسار.
