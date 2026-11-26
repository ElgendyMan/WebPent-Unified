# UM-DR-51 — Phase 2 closeout: الحلقة الموحدة عبر الـentrypoint الرسمي

**التاريخ:** 2026-11-26 · **الأساس:** `b9b7601` (ما بعد المرحلة 1)
**الميدان:** OWASP Juice Shop 20.4.0 محلي

## الحلقة عبر الـentrypoint الرسمي — VERIFIED

حملتان رسميتان عبر الـCLI الرسمي نفسه (لا نداء داخلي):

```
uv run --extra dev webpent hunt \
  --url http://127.0.0.1:3000 --mode standard \
  --authorization umdr51-owner-approved-local-lab \
  --engagement-id umdr51-loop-cli-run2 \
  --auto-approve --no-llm --no-progress
```

- **run2 (بعد الإصلاح): exit 0** — الحلقة الكاملة: اكتشاف (crawl+recon) → SKG →
  تغطية → فرضيات (30+) → مسارات الاختبار (11 ممرًا: access_control، api_testing،
  business_logic_fuzzer، request_smuggling، graphql_testing، cache_poisoning،
  prototype_pollution، oauth_misconfig...) → strategist → تنفيذ مُحكوم → validator →
  تقرير (`output/report.html` ~54KB) → استخلاص دروس → ذاكرة بحث.
- نتائج صادقة: **6 findings مرشّحة / 0 مؤكدة** — سلطة التأكيد (CausalGuard) لم تُؤكد
  شيئًا في وضع standard؛ لا replay مفبرك ولا تنفيذ test-only منفصل.

## عيب إنتاج حقيقي اكتُشف وأُصلح: الـentrypoint الرسمي لم يكن يستنتج هويته

**الظاهرة:** `webpent hunt` (الـconsole script من pyproject `[project.scripts]
webpent = "webpent.cli:main"`) كان ينهار بـ`ProductionSpineError: entrypoint
underivable in this process` — إلا إذا ضُبط `WEBPENT_ENTRYPOINT=cli` خارجيًا. سلم
الاشتقاق في `_derive_entrypoint` يغطي `python -m webpent.cli` و`worker.py`/`server.py`
لكنه لم يغطِّ الـconsole script الرسمي.

**الإصلاح:** حالة اشتقاق جديدة — basename لملف `__main__` == `webpent` (سطح
الإطلاق الموثق في pyproject). الوضع fail-closed محفوظ: أي basename آخر يبقى يرفع
الخطأ الصريح (لا label خاطئ صامت أبدًا).

**التحقق:** حملة CLI نظيفة بعد الإصلاح (exit 0 بلا أي env خارجي) + **962 passed /
3 skipped / 1 xfailed(strict)** على كل اختبارات spine/M2/R3/entrypoint + بوابة
التجميد وبوابة الصدق خضراوان.

## حالة بوابة الحلقة

**مغلقة بهذه الحدود الصادقة:** الحلقة الكاملة تعمل من الاكتشاف إلى الإبلاغ عبر
الـentrypoint الرسمي، بحملات مصرّحة، بلا بِرَك موازية (مسار كانوني واحد)، والتأكيد
حصريًا عبر CausalGuard. الملاحظة الصادقة: findings المرشحة تحتاج أدلة تفاضلية
مختومة (ProofBundle) لتتحول إلى مؤكدة — هذا عمل العائلات في المرحلة 3 (الأدلة
التفاضلية الحقيقية لكل عائلة على الميدان).
