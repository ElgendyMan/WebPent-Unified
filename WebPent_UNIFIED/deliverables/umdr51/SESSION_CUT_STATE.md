# UM-DR-51 — حالة قطع الجلسة (2026-11-26، قبل اكتمال دورة النشر v0.49.0)

## المكتمل والمركّب (سلسلة أخضر متوقعة — لم يُتحقق من CI بعد)
- `b9b7601` P1 + `3f5ea05` P2 + `8db809b` P3 + `761f68e` P4 + `c5bf5b7` P5 + `50b40ed` P6
- ست إصلاحات إنتاجية موثقة (علم البيئة، entrypoint الـconsole، أصل الترقية، severity،
  علامات التقرير الصريحة، دفاع GT-integrity) + اختبارات جديدة (5+4) — الاختبارات
  المستهدفة كلها خضراء (962/415/280/15/5/4)؛ البطارية الكاملة النهائية انقطعت بقطع
  الجلسة (worklogs/umdr51_battery_final.log).

## المتبقي الموثق (نمط قانون 4 — الجلسة القادمة من هنا)
1. بطارية كاملة على شجرة نظيفة عند الطرف → re-bind BUILD_INFO (provenance + evidence)
   برفعة "Update project to v0.49.0 UM-DR-51 window: BUILD_INFO re-freeze (...)".
2. رفع → CI أخضر بـrun_id على رأس الإصدار بالضبط.
3. وسم v0.49.0 → e7c5e3a-pattern Release بنص الحكم الصادق (من FINAL_ACCEPTANCE_MATRIX)
   + PUBLICATION.json (schema webpent.publication.v1) + إدخال DRIFT_REGISTER
   (settings.py/modern_spine_integration.py في وضع delta معلن — تسوية عند re-freeze).
4. إعادة بناء حزمة download/umdr51 النهائية (الـPACK الحالي أساس).

## تحذير لمن يكمل: لا تعتمد أن CI أخضر — لم يُتحقق. الحكم المعلن في
FINAL_ACCEPTANCE_MATRIX.json هو الوحيد الملزم.
