# UM-DR-50 P0.1 — PUBLICATION AUDIT (clean-clone SHA resolution)

التاريخ: 2026-11-26 · القانون المنفَّذ: قانون الاستنساخ النظيف (قانون البعثة 2)

## المنهجية
استنساخ نظيف كامل من `ElgendyMan/WebPent-Unified` (main) → استخراج كل SHA
طوله 40-ست-عشري من كل ملفات الأدلة المنشورة (كلا طبقتي التخطيط) وBUILD_INFO →
`git cat-file -e <SHA>` لكل واحد داخل الاستنساخ النظيف. الخرج الحرفي الكامل
في `PUBLICATION_AUDIT_RAW.txt` (نفس المجلد) — أُنتج بـ
`scripts/umdr50_p01_audit.sh` (السندبوكس، خارج الشجرة).

## نتيجة الاستنساخ النظيف (الطقس الحرفي)
```
$ git fetch origin && git rev-parse HEAD origin/main
901f192a301c6729db802aab5ddbea6d243ace20
901f192a301c6729db802aab5ddbea6d243ace20
```
أول استنساخ نظيف في التاريخ يرى رأس main = `901f192` (سلسلة النشر كاملة).

## النتيجة: 7 قابلة للحل / 2 يتيمة

| SHA | المصدر | الحالة |
|---|---|---|
| `901f192a…` | رأس الاستنساخ | OK — رأس main المستعاد |
| `1968f63c…` | BUILD_INFO recovery_baseline | OK — `Update project to v0.40.1 UMDR35-36` |
| `989c49ba…` | BUILD_INFO release_history[0] | OK — `Update to v0.38.0 UMDR32` |
| `4795f023…` | أدلة 45 | OK — `Start feature development with v0.39.0 UMDR33` |
| `42736397…` | أدلة 45 | OK — `Update project to v0.44.0 UMDR45 release` |
| `85943a70…` | أدلة 45/47 | OK — `Update project to v0.46.0 UMDR47 window` |
| `adf9056e…` | أدلة 45/49 | OK — `fix(tests): UM-DR-45 unreadable-approval sentinel` |
| **`66fec2d1…`** | **BUILD_INFO provenance كاملًا (source/tested/evidence) + أدلة 49** | **MISSING — `git cat-file -e` فشل** |
| `fe92f178…` | أدلة umdr38 التاريخية | MISSING — سلف من مستودع سابق (تاريخي، معلَن) |

## الحكم
1. **تأكد تنبؤ الخطة الرئيسية حرفيًا:** `66fec2d` commit يتيم — الدليل الملزم
   لنافذة 49 (`deliverables/umdr49_closure/FULL_SUITE_EVIDENCE.json`)
   يربط `source_commit=66fec2d` غير الموجود في استنساخ نظيف. **هذا بالضبط
   ما كسر provenance نافذة 49** — البطارية ركضت على شجرة مُعاد كتابتها
   (force-push لاحق) فصار الـcommit المُختبر غير موجود.
2. `fe92f178` يتيم تاريخي مقبول: أدلة umdr38 أُنتجت في المستودع السابق
   قبل النقل، والبوابة تتعامل معه كتاريخ معلن لا كادعاء حالي.
3. **الأثر المباشر على المرحلة 3 (P3.2/P3.5):** البطارية النهائية
   الإلزامية يجب أن تركض على شجرة نظيفة `tree_clean=true` عند `901f192`
   (أو الطرف الجديد وقتها) — والأدلة تُربط بهذا الـSHA القابل للحل —
   وإلا تتكرر كارثة 49 بعينها.

## حالة اللغة الصادقة
`P0.1 = VERIFIED` (الخرج الحرفي ملصق أعلاه وفي الملف الخام).
