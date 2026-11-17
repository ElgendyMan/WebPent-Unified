# WebPent-Unified — منصة اختبار أمني ذاتية لتطبيقات الويب

> **مستودع النشر (publication repo).** كود المشروع الفعلي يعيش داخل
> [`WebPent_UNIFIED/`](WebPent_UNIFIED/) — هذا هو الجذر القانوني للمشروع ولا يوجد
> مشروع آخر بجانبه. أوامر التشغيل كلها تُنفَّذ من داخل هذا الدليل.

وجّهه إلى هدف **مُصرَّح لك** باختباره، وهو يخطط، ويستكشف، ويولّد فرضيات، ويتحقق منها
بأدوات حقيقية، ويُخرج تقرير bug-bounty جاهزًا للتسليم — كل خطوة مبنية على evidence
حقيقي لا تخمين: طبقات agents فوق LangGraph، آلاف الاختبارات، redaction فوري لكل
قيمة حساسة، وصفر تعامل مع بيانات خارجية كتعليمات تنفيذ.

> ⚠️ **تنبيه قانوني — اقرأه قبل أي تشغيل:** استخدم WebPent فقط على أنظمة تملكها أو
> لديك تصريح كتابي لاختبارها. التشغيل الفعلي يتطلب تمرير `--authorization`، ولا يُنفَّذ
> أي طلب نشط خارج ملف الـscope المصرَّح به. لا تستخدمه ضد أهداف عامة أو أنظمة طرف
> ثالث دون تفويض صريح. سياسة الأمان والإفصاح:
> [`WebPent_UNIFIED/SECURITY.md`](WebPent_UNIFIED/SECURITY.md).

## النسخة الحالية

**0.40.1** — راجع [`WebPent_UNIFIED/CHANGELOG.md`](WebPent_UNIFIED/CHANGELOG.md)
و[`WebPent_UNIFIED/BUILD_INFO.json`](WebPent_UNIFIED/BUILD_INFO.json).

## التثبيت (من clone نظيف)

```bash
git clone https://github.com/ElgendyMan/WebPent-Unified.git
cd WebPent-Unified/WebPent_UNIFIED

# Python 3.12 (المطلوب في CI؛ الحد الأدنى 3.11) + uv
uv python install 3.12
uv sync --locked --extra dev          # التبعيات المقفلة (uv.lock)
uv run playwright install chromium    # متصفح اختبارات التكامل
```

## تشغيل الاختبارات

```bash
# من داخل WebPent_UNIFIED/
uv run --extra dev python scripts/run_tests_with_evidence.py
uv run --extra dev python scripts/check_test_evidence.py
```

الجناح الكامل يُنتج أدلة مرتبطة بالـcommit المختبر بالضبط في
`.webpent-evidence/` (دليل مُهمل من git — لا يلوث الشجرة) ويُرفع كـartifact
في سير عمل CI.

## البدء السريع

```bash
# من داخل WebPent_UNIFIED/ — فحص سريع لهدف مصرَّح لك (التفويض إلزامي)
uv run webpent hunt --url <target> --mode quick --authorization <ref>

# تجربة أولى آمنة على مختبر محلي (بدون أي هدف خارجي)
docker compose --profile quickstart up
```

دليل الاستخدام الكامل وأوامر الفحص كلها في
[`WebPent_UNIFIED/README.md`](WebPent_UNIFIED/README.md).

## CI — البوابات

سير العمل القانوني على **جذر المستودع** (GitHub لا يكتشف سير العمل إلا هناك):
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) — التبعيات المقفلة،
بوابات العقود الثابتة، سلطة بناء الـorchestrator، عزل الـdenylist، أرضية عدد
الاختبارات، أمانة BUILD_INFO، ruff/bandit/pip-audit/secret-scan، تغطية بأرضية
ملزمة، SBOM، والجناح الانحداري الكامل مع أدلة مرتبطة بالـcommit المنشور بالضبط.
إضافة إلى [`nightly.yml`](.github/workflows/nightly.yml) (canary ليلي)
و[`weekly-benchmarks.yml`](.github/workflows/weekly-benchmarks.yml).

## التقارير والأدلة

| المدخل | المحتوى |
|---|---|
| [`deliverables/umdr38/`](deliverables/umdr38/) | تقارير إغلاق UM-DR-38 ومصفوفة القبول وأدلة الحزم |
| [`deliverables/umdr37/evidence/`](deliverables/umdr37/evidence/) | الأدلة الدائمة لحملات الإنتاج (سجلات خام + هاشات + manifest) |
| [`WebPent_UNIFIED/docs/`](WebPent_UNIFIED/docs/) | التقارير الهندسية التاريخية وأدلة التحقق |
