# FINDINGS_REGISTER — UM-DR-52 (النسخة البشرية للسجل الآلي)

السجل الآلي: `FINDINGS_REGISTER.json` (كل بند بحقوله المقررة). هذا الملخص:

- **Confirmed: 0.** لا يوجد Tool-Confirmed finding من حملات هذه النافذة في الوضع القياسي — السجل يسجل ما هو موجود، لا يصنع بندًا.
- **Candidates:** C1 — Juice Shop (مختبر محلي): حملات الوضع القياسي أنتجت مرشحين بلا تأكيد؛ `findings_confirmed_mean=0` في الذرعين (`run_files/*.json`). الحالة: NOT_VERIFIED.
- **Probes:** P1 — WebGoat path_traversal (الشكل المصرح به GET فقط): استجابات متطابقة بايت-ببايت للمرشح والضابط السلبي والأساس — لا دليل تمييز؛ مسجل بلا ادعاء. الحالة: NOT_VERIFIED.
- **BLOCKED:** WebGoat خلف جدار المصادقة (`WEBGOAT_LESSON_SESSION_OWNER_FIXTURE_UNAVAILABLE` — اعتماد المالك على POST login غير موجود)؛ DVWA (لا docker/php في البيئة — محاولة مسجلة).
- **NOT_RUN:** redirect_scope_bypass anchor 2/2 (تتطلب بنية إعادة التشغيل من النوافذ 48/49)؛ سلسلة Tool-Confirmed متعددة الخطوات.
