# PortfolioManager — آلة الحالات (NC-ECON-1, U-ECON-10)

محفظة من 5-50 target، أربع حالات وخمس حواف قانونية فقط (L-3).

## الحالات

| الحالة | المعنى |
|---|---|
| `ACTIVE` | شغل مكثف (Top 20% من خريطة الميزانية) |
| `WATCHING` | CEM فقط (Middle 30%) |
| `DORMANT` | مراقبة دورية نادرة (Bottom) |
| `ARCHIVED` | مُنسحب (فشل متكرر)؛ إعادة تفعيله يدوية فقط (L-8) |

## الحواف القانونية (أي حافة أخرى ترفع ValueError)

| From | To | Trigger | نوعه |
|---|---|---|---|
| WATCHING | ACTIVE | signal-high من CEM | تلقائي |
| ACTIVE | WATCHING | EV_per_hour نزل 50%+ لمدة أسبوع | تلقائي |
| WATCHING | DORMANT | لا تغيير لمدة 60 يوم | تلقائي |
| DORMANT | ARCHIVED | فشل 3 حملات متتالية | تلقائي |
| ARCHIVED | WATCHING | المشغّل يعيد التفعيل يدويًا | يدوي فقط |

## القواعد

- كل transition لابه reason (DoD) — رفض reason فارغ رفض نفسه.
- كل انتقال يُسجَّل سطر JSONL في `download/econ/portfolio_transitions.jsonl`
  مع {target_id, from_state, to_state, reason, timestamp, advisory:true}
  (L-4)؛ فشل الكتابة → تحذير فقط (fail-soft).
- `auto_transition` يستقبل الملاحظات كلها مُحقنة (L-2): إشارات CEM،
  EV/hour الآن وأسبوعًا مضى، عدّاد إخفاقات الحملات. لا شيء يُقاس من الشبكة.
- `last_transition` يأتي من `now` المحقون، لا من ساعة الحائط.
- portfolio.yaml فاسد/غائب → محفظة فارغة (fail-soft)؛ الحد الأقصى 50 target.
- `daily_plan(total_hours)` يقسم الساعات 60/30/10 على ACTIVE/WATCHING/DORMANT
  وARCHIVED لا يأخذ شيئًا؛ المجموع = total_hours بالضبط.
