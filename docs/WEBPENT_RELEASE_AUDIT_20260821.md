# WebPent — Release Audit

**التاريخ:** 21 أغسطس 2026

**المستودع:** [ElgendyMan/webpent-v61](https://github.com/ElgendyMan/webpent-v61)

## نطاق المراجعة

تمت مراجعة الخطط والتغييرات المتراكمة قبل بناء الإصدار الجديد، مع مقارنة الملفات المتتبعة في Git بالـZIP السابق، وفحص سجل الحذف التاريخي، والتحقق من وجود المكونات التي طُلبت في الخطط السابقة.

## النتيجة

لم يظهر أي حذف غير مقصود من المستودع نفسه. ظهر نقص واحد في ZIP السابق/المحاولة السابقة: `uv.lock` لم يكن مضمّنًا بسبب نمط تنظيف عام طابق امتداد `.lock`، وتم تصحيح ذلك بإعادة بناء الأرشيف من `git archive`. أما ملفات source وtest وdocs الأخرى فموجودة ومطابقة للمستودع الحالي.

| المجال المراجع | النتيجة |
|---|---|
| Payload ingestion | موجود، و`payload` مدعوم كنوع metadata |
| Git repository ingestion | موجود عبر Git source checkout محدود العمق مع التحقق من المسار داخل checkout |
| Engagement/client isolation | موجود عبر metadata filters وstable engagement handling في مسارات الذاكرة والتجميع |
| Findings aggregation | موجود مع deduplication والحفاظ على confirmation الأقوى |
| Credentials وcookies | موجود دعم profiles متعددة ومسارات auth/session مع عدم عرض القيم السرية |
| Reports | موجود JSON وHTML وPDF وMarkdown عبر واجهات CLI/reporter |
| LLM و`--no-llm` وfallbacks | موجودة مع مسارات bounded fallback وfail-closed عند فشل الأدوات |
| Stealth | موجود كخيار تشغيل ضمن العقود الحالية، دون تفعيل destructive behavior |
| Smart campaigns | موجود inventory عام وWAPTLab، cap محدود، hypothesis adapter، وJS routes projection |
| JavaScript/HTTP discovery | موجود handoff للـscript assets، Angular HttpClient extraction، وquery hypothesis projection |
| Dalfox | موجود headless fallback، JSON clean output، وعدم ترقية empty output إلى confirmation |
| Nuclei | موجود احترام للمسار المخصص وfallback للـbinary المحلي عند غيابه من PATH |
| IDOR validation | موجود differential replay وnegative control وevidence/proof bundle قبل التوكيد |
| Destructive actions | تظل مرفوضة fail-closed حتى في authorized-active |

## ما استُبعد من ZIP عمدًا

يُبنى الإصدار النهائي من `git archive` للـcommit المختبر، ولذلك يحتوي كل الملفات المتتبعة في Git، بما فيها `uv.lock` وsource وtests وdocs وملفات التحقق المتتبعة. يُستبعد فقط ما لا ينتمي إلى Git release مثل `.git` و`.venv` والكاش وقواعد البيانات المحلية وملفات `__pycache__` وأي runtime artifacts غير متتبعة. أما `webpent.db.migration.lock` وملفات التحقق المتتبعة فتظل موجودة في archive لأنها جزء من الشجرة المتتبعة ولا تحتوي بيانات سرية.

تقارير التشغيل الحية المرتبطة بدورات معينة لا تُضاف تلقائيًا إذا كانت خارج الشجرة المتتبعة؛ التقرير النهائي المنقح يثبت نتائج WAPTLab v3 وJuice Shop v14 والقيود المعروفة، بينما source وtests وdocs الأساسية و`uv.lock` مضمّنة في الإصدار.

## التحقق النهائي المطلوب قبل التسليم

يجب إعادة تشغيل `pytest -q --tb=short`، ثم `ruff check .`، ثم `python -m compileall -q src scripts tests`. بعد ذلك يُعاد بناء ZIP من Git tree مع استبعاد runtime artifacts، ويُحسب SHA-256، ويُراجع `git status` للتأكد من نظافة working tree.

## الخلاصة

لا توجد حاليًا إصلاحات source ناقصة اكتشفها هذا التدقيق. الإضافة المطلوبة هي توثيق المراجعة وتحديث تقرير التسليم ليعكس commit النهائي ومقارنة ZIP. لا يوجد دليل على حذف مكوّن وظيفي دون قصد.
