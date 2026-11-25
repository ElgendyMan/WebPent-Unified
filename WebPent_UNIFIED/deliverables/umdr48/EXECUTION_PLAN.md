# UM-DR-48 — EXECUTION PLAN (P0.4)

> البوابة الرسمية: أهداف §0 وقوانين §0.5 في برومبت المهمة. هذه الخطة
> تُترجمها لأوامر وأبواب قابلة للتنفيذ الآلي. كل باب يُغلق برقم أو
> بتشخيص قانون-1 كامل — لا وسط.

## الأوامر (كل مرحلة بأمر واحد قابل للإعادة)

| المرحلة | الأمر | باب الإقفال |
|---|---|---|
| P0 (تشخيص) | MISS_MAP.md (مكتمل) + هذه الخطة | الخريطة تفتح D وC5 |
| D1–D5 (خطوط الكشف) | `uv run --extra dev python -m pytest tests/test_umdr48_d_lanes.py -q` (RED→GREEN لكل lane) | TP≥1 لكل عائلة + سلبية على الآمن |
| بوابة D | `uv run --extra dev python scripts/umdr48_measurement_battery_v2.py` | recall ≥ 0.75، FP=0، 3 runs متطابقة |
| C5 (السلاسل) | `uv run --extra dev python -m pytest tests/test_umdr48_c5_chains.py -q` ثم البطارية v2 | ≥2 سلسلة مؤكدة end-to-end |
| Q (الميزانية والمقاومة) | `uv run --extra dev python scripts/umdr48_waste_ledger.py` + negative suite ضمن البطارية v2 | ≤300 req/finding، FP=0 تحت ≥12 near-miss |
| S (المتانة) | `uv run --extra dev python scripts/umdr48_stress_battery.py` | 4 توازي + استئناف 0 تكرار + safe-stop + حتمية |
| R | بانتظار هدف المالك (لا تُختلق أهداف) | توثيق |
| الختام | MEASUREMENT_V2 + DELTA_V2 + ULTIMATE_ACCEPTANCE v2 + v0.47.0 | روابط raw تعمل |

## ترتيب التنفيذ وأبوابه الحرفية

1. **D1 workflow-skip lane** (عقد: state-before/after): من
   `workflow_observations`/SKG استخرج مرشحي التخطي (action على مورد له
   حالة معلنة، والمسار المصرح يمر بحالة وسيطة). نفّذ POST التسلسل
   (skip مباشر + control: approve ثم ship)، قارن الحالة النهائية،
   ارفع differential إلى CausalGuard. RED: بطارية 47 (TP=0). GREEN:
   TP≥1 على المتأثر. سلبية: 409 على الآمن، صفر تأكيد.
2. **D2 framing-differential lane** (عقد: تفسيران موثقان): زوج CL/TE
   على endpoint بـPOST. الدليل = الرد نفسه يفصّل framing_used +
   bytes_beyond_content_length (مصدر مزدوج: طلب مختوم + رد موثق).
3. **D3 graphql-cross-identity lane** (عقد: differential بيانات على
   نفس operation): من operations (F2.3 داخل SKG) نفّذ الـquery
   بالهوية الأدنى (User_B) وقارن برد الهوية المالكة. يستهلك
   `identity_profiles` — الناقص في 47.
4. **D4 tenant-context-override lane** (عقد: تبديل مُحدِّد النطاق
   مع تثبيت الهوية): أزواج (identity ثابتة × tenant-context متغير)
   على مورد أجنبي؛ التوقيع 403→200 + tenant_source=client_header.
5. **D5 redirect-policy-walk lane** (عقد: الوجهة الفعلية مقابل
   النطاق): walker بقفزات ≤5 يقرأ Location لكل قفزة ويحكم بالنطاق
   المصرح + قناة raw-path (إرسال حرفي بلا تطبيع) لعيوب traversal.
6. **بوابة D** — بطارية v2 (نفس الـ46/47: عائلاتها الثمانية بعد
   التوسعة، 3 runs، نفس آلية القياس والـattribution).
7. **C5** — قسما السلاسل: chain_compose_lab (workflow-skip → IDOR
   reveal) و oauth_gql_chain_lab (OAuth grant → GraphQL mutation) —
   ground truth معلن قبل التشغيل؛ السلسلة تؤكد عبر الخطوات
   (إثبات منفرد لكل خطوة + تركيب نهائي تحت CausalGuard).
8. **Q** — مخصص ميزانية بالمعادلة الحرفية: كل طلب مرشّح يحمل
   info-expectation معلنة؛ الطلبات صفر-التوقع تُحسب في WASTE_LEDGER.
   negative suite: ≥12 near-miss (كل عائلة × 2: دورة محمية تُدار
   بشكل سليم، operation GraphQL معزول، tenant عازل للترويسة،
   redirect داخل النطاق، framing صحيح مرفوض بـ400...) — باب: FP=0.
9. **S** — أمر stress واحد يثبت: 4 حملات متوازية معزولة، قتل واستئناف
   (صفر طلب مكرر بالتوقيع)، safe-stop منتصف سلسلة (snapshot نظيف)،
   تشغيلتان متطابقتان حرفيًا.
10. **الختام** — الأرقام والروابط، push واحد لكل مرحلة كبرى، عدد
    pushes موثق بـrun IDs.

## قوانين الحماية أثناء التنفيذ

- كل lane جديد تحت flag `ENABLE_UMDR48_LANES` (default OFF) مع اختبار
  OFF/ON — نفس انضباط الدمج السلوكي في 47.
- لا تعديل على الـlabs الست الأصلية (الحقيقة الأرضية ثابتة) — التوسعة
  ملفات جديدة معلنة فقط.
- كل طلب جديد يمر من نفس scoped sender (النطاق + الترخيص + rate
  limits) — لا استثناءات "للاختبار".
