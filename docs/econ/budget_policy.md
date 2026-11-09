# BudgetMapper — سياسة توزيع الوقت (NC-ECON-1, U-ECON-6)

## الخوارزمية (L-3: حتمية، بلا عشوائية ولا LLM)

1. لكل target: `EV_per_hour = expected_EV ÷ estimated_hours`
2. ترتيب تنازلي بحسب `EV_per_hour` (التعادل يُحسم بـ `target_id` حتى لا يعتمد
   الترتيب على ترتيب الإدخال أبدًا)
3. أعلى 20% → `INTENSIVE`
4. الوسط 30% → `ROUTINE`
5. الأسفل 50% → `DORMANT` (مراقبة CEM فقط)

## جدول العتبات

| العتبة | القيمة الافتراضية | المصدر |
|---|---|---|
| حصة INTENSIVE من الأهداف | 20% (تقرَّب لعُقل هدف واحد) | `budget.intensive_share_targets` |
| حصة ROUTINE من الأهداف | 30% | `budget.routine_share_targets` |
| حصة DORMANT من الأهداف | الباقي (50%) | محسوبة |
| حصة INTENSIVE من الساعات | 60% | `budget.intensive_share_hours` |
| حصة ROUTINE من الساعات | 30% | `budget.routine_share_hours` |
| حصة DORMANT من الساعات | 10% | `budget.dormant_share_hours` |
| `ev_scale_usd` | 10000 USD | `budget.ev_scale_usd` |
| `total_hours` | يجب أن يكون > 0، وإلا `ValueError` | مدخل مُحقن |

كل العتبات تُحمَّل من `config/econ/roi_params.yaml` تحت قسم `budget:`؛
ملف فاسد/غائب → الافتراضيات (fail-soft).

## القواعد الثابتة

- `expected_EV` يأتي من `TargetScorer` (U-ECON-2) مضروبًا في `ev_scale_usd/100`:
  درجة 100 ≈ المرجع 10000 USD. لا يُحسب أي EV من الشبكة (L-2).
- داخل كل طبقة تُقسَّم الساعات بالتساوي؛ مجموع الساعات = `total_hours` بالضبط.
- عدد الأهداف محدود بـ 256؛ الإدخال يُمرر عبر `sanitized()` و `redact()`.
- كل allocation يحمل {target_id, tier, hours_per_week, ev_per_hour,
  justification, timestamp} والعلم `advisory: True` (L-4). لا شيء يُرسَل من
  هنا إطلاقًا (L-1, L-8).
- `total_hours <= 0` يرفع `ValueError`: توزيع صفر ليس ميزانية.
