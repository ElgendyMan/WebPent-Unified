# W3_SESSION_CUT_STATE — UM-DR-52 (قصّ الجلسة الختامي)

**حالة النافذة عند القص: partial within measured bounds — بلا ادعاء Ultimate.**

## المقفل بالقياس
- **G5 (العقل): VERIFIED** — ORDER تغيّر ميدانيًا (Juice Shop، أذرع حتمية) و≥1 OUTCOME انقلب على الfixture المعتمد (انقلابا `defer→abandon`)؛ pool-only لم يُعلن نجاحًا في أي سجل.
- **تكامل W1→W2: VERIFIED** — الدعم السلوكي عبر صيغة W3 يقلب الترتيب الكامل وعضوية الاختيار k=3.
- **W6 صفر الدروس: مات** — 6 دروس عامة قابلة للاستخدام بفصل صارم عن بيانات الهدف (`LESSONS_LEDGER.json`).
- **الاختبارات:** 19 (W1) + 24 (W2) = 43/43 أخضر على الوحدتين الجديدتين.
- **الدفاتر الآلية:** FINDINGS_REGISTER (Confirmed=0 صادق) + METER_INSTRUMENTATION + EXPERIMENT_ECONOMICS (نطاق معلن) + FIELD_CAMPAIGN_RECORDS.

## المفتوح المعلن (بالأسماء — يُحمل للنافذة التالية)
1. **G6 Tool-Confirmed على Juice Shop:** NOT_VERIFIED — `findings_confirmed_mean=0` في الوضع القياسي؛ مسار bundle المختوم لم يُ reach. السبب الجذري المرشح: الوضع القياسي لا يدخل مسار التأكيد التفاضلي على مرشحات الأعمال؛ يحتاج ربط خطط `plan_experiments` بمسار ProofBundle.
2. **WebGoat خلف الجدار:** BLOCKED — اعتماد المالك على POST login/بيانات الدروس غير موجود؛ الشكل المصرح GET وحده قيس (تمييز صفري مسجل بصدق).
3. **redirect_scope_bypass 2/2:** NOT_RUN — بنية إعادة التشغيل من النوافذ 48/49 لم تُستأجر هذه الجلسة.
4. **DVWA:** BLOCKED بيئيًا (لا docker/php — محاولة مسجلة).
5. **سلسلة Tool-Confirmed:** NOT_VERIFIED — تركيب السلاسل مقاس في SKG، بلا تأكيد ميداني.
6. **G7 compute isolation + اقتصاد الميدان:** PARTIAL — الشبكة مقاسة per-run، عزل validator/replay غير معزول.
7. **قفل البقعة العمياء في CI + الفلاك الحتمي:** NOT_RUN هذه الجلسة (لا انحدار promotion-origin عابرًا جديدًا سُجل).
8. **بنود النظافة (README/تكرار UMDR42/توفيق 9aa79d1):** تُنفذ في commit الإغلاق الدفاتري المباشر بعدها.

## الكود النهائي
- الشجرة نظيفة عند قصّ الجلسة (بطارية ختامية تسجل في السجل v3 — أرقامها الفعلية هي الحكم لا الذاكرة).
- الوحدات الجديدة: `researcher/behavioral_layer.py`، `researcher/adaptive_engine.py`؛ الربط: `brain_engine.py`، `shared/prioritization.py`، `agents/strategist/agent.py`.
- القياس: `scripts/umdr52_w1_field_delta.py`، `umdr52_w1_fixture_delta.py`، `umdr52_w2_integration_delta.py`، `umdr52_w3_field_probe.py`، `umdr52_ledgers.py`.
