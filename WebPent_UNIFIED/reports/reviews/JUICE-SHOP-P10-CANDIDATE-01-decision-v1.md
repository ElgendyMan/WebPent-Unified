# JUICE-SHOP-P10-CANDIDATE-01 — Decision Record

## القرار

المرشح: **Static dependency/component surface — Vulnerable Components**.

القرار الحالي: **`blocked` / `needs_profile_source_proof`**.

هذا القرار هندسي مؤقت قابل لإعادة الفحص، وليس رفضًا نهائيًا من reviewer مستقل، ولا يضيف الحالة إلى `approved scoring set`. يظل `official_isolated_p10_runs_authorized=false`.

## سبب الإغلاق

المراجعة المصدرية والـcandidate triage حددا سطحًا static محتملًا، لكن لم يثبتا بعد موردًا exact يمكن ربطه بصورة حتمية بتحدي Vulnerable Components، ولم يتوفر semantic causal predicate يثبت vulnerability exposure بدل مجرد وجود asset أو ظهور version string أو قابلية الوصول إلى route.

لذلك لا توجد حاليًا الشروط اللازمة لترقية المرشح إلى contract قابل للتنفيذ:

| المتطلب | الحالة |
|---|---|
| Source-to-runtime mapping exact | غير مثبت بما يكفي |
| Safe precondition | غير معتمدة لهذا المرشح |
| Semantic causal predicate | غير متوفر |
| Baseline/candidate separation | غير متوفر بعقد معتمد |
| Independent negative control | غير متوفر |
| Central verification | غير متوفر لهذا المرشح |
| Sealed/replayable ProofBundle | غير متوفر |
| Independent governance approval | غير متوفر |

## حدود التنفيذ

لم تتم إضافة adapter أو oracle أو case جديدة، ولم يتم تعديل Generic Core أو frozen P10 artifacts أو evaluator. لم يتم استخدام payload أو authentication bypass أو state mutation أو external callback. لم يتم تحويل route reachability أو source presence إلى finding أو TP.

الفحص بقي محليًا ومحدودًا على مصدر Juice Shop وWebPent artifacts. خدمة Juice Shop الحالية loopback-only على `127.0.0.1:3000`، ولم يتم تشغيل Official P10 أو أي run رسمي.

## شروط إعادة الفتح

يمكن إعادة فتح المرشح فقط إذا أثبتت مراجعة جديدة، دون تغيير ground truth لإخفاء drift، ما يلي:

1. موردًا exact في source وruntime مع provenance واضح بين Juice Shop source commit وWebPent source-manifest commit.
2. predicate دلاليًا يثبت exposure أمنيًا قابلًا للتفسير، وليس مجرد public reachability أو version disclosure.
3. safe precondition قابلة لإعادة التنفيذ على loopback دون mutation أو credentials أو payload غير ضروري.
4. baseline وcandidate وindependent negative control منفصلين، مع تمرير النتيجة إلى central verifier.
5. ProofBundle redacted قابلًا للـsealing و`verify_seal()` وreplay.
6. regression tests وbefore/after comparison وindependent governance signoff.

## أثر القرار على P10

المجموعة oracle-approved تظل **3 cases و3 classes**. هذا المرشح لا يزيد العدد أو التغطية. الفجوة تظل **7 cases و3 classes** للوصول إلى الحد الأدنى الرسمي **10 cases و6 classes**. لا تُحسب هذه الحالة FN، ولا تُضاف إلى precision/recall، ولا تستخدم لرفع الأرقام إداريًا.

## المراجع الداخلية

- `docs/juice_shop_p10_expansion_plan_v1.json`
- `reports/improvements/JUICE-SHOP-P10-CASE-EXPANSION-001_proposal.md`
- `reports/evaluation/JUICE-SHOP-P10-expansion-feasibility-v1.md`
- `src/webpent/profiles/juice_shop/cases.py`
- `src/webpent/adapters/juice_shop/oracles.py`

## حالة الحوكمة

هذا السجل جاهز للمراجعة البشرية المستقلة، لكنه لا يمثل توقيعًا مستقلًا أو اعتمادًا نهائيًا. تظل الحالات السبع/الثماني غير المعتمدة خارج scoring حسب قراراتها السابقة، وتظل P10 وP9 وVIP `NOT_QUALIFIED`.
