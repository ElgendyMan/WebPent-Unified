# Web Application Testing Methodology

## الغرض

هذا الملف يلخّص منهجية اختبار تطبيقات الويب التي يحتاجها WebPent عند التخطيط والـtriage وكتابة التقرير. الملخص مستند إلى [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) و[NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) و[OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/). المصادر الأصلية هي المرجع الكامل؛ هذا الملف لا يستبدلها.

## دورة العمل

| المرحلة | سؤال العمل | المخرج القابل للتتبع |
|---|---|---|
| التخطيط والنطاق | ما الهدف المصرّح به وما حدود الاختبار ومعدل الطلبات؟ | target scope، engagement id، قواعد السلامة |
| الاستطلاع | ما السطح المرصود فعليًا من endpoints وparameters وroles؟ | observed endpoints وtechnology facts |
| بناء الفرضيات | ما فئة السلوك المشبوه ولماذا تنطبق على السطح المرصود؟ | hypothesis مع origin detail وconfidence |
| الاختبار الموجّه | ما probe المحدود الذي يختبر الفرضية؟ | request/response evidence وnegative control |
| التحقق | هل سبّب التغيير سلوكًا سببيًا قابلًا لإعادة الإنتاج؟ | causal signal، replay، owner/control comparison |
| التقييم | ما الأثر ونطاق الصلاحيات والـpreconditions؟ | severity/CVSS context bounded by observed role |
| التقرير | هل يستطيع مراجع مستقل إعادة إنتاج النتيجة؟ | finding record، evidence، remediation، references |
| التعلم | ما الذي فشل أو نجح بدون تسريب بين العملاء؟ | client-scoped lesson، لا تُستخدم كإثبات مستقل |

## قواعد WebPent غير القابلة للتخفيف

المعرفة المسترجعة من corpus قد تقترح فئة اختبار أو مسار تحقق، لكنها لا تُنشئ finding. لا يجوز ترقية candidate بدون سلوك فعلي، causal signal، negative control، وevidence كافٍ. لا يجوز استخدام write-up أو repository لإثبات أن الهدف الحالي vulnerable. عند غياب evidence أو عند فشل الـvalidator، تكون النتيجة candidate أو no-result بدل تخمين إيجابي.

## BAC وIDOR

اختبار access control يجب أن يقارن بين سياقين مصرحين ومختلفين في الملكية أو الدور، مع تثبيت الطريقة والمسار والـobject identifier. تغيير ID مجاور وحده ليس إثباتًا. الدليل الأقوى هو أن الطلب المغير ينجح في قراءة أو تعديل مورد مملوك لسياق آخر، مع negative control يثبت أن الطلب الصحيح يفشل أو لا يعرض المورد. enumeration المجاور يظل bounded ومغلقًا افتراضيًا.

## provenance

كل سياق يخرج من هذا الملف يجب أن يظل advisory ويُسجل معه نوع المعرفة والمصدر. يُفضّل استخدام commit pinned للـrepositories، وتبقى الروابط العامة قابلة للمراجعة. لا تُحفظ credentials أو responses حقيقية داخل corpus.

## مراجع

1. OWASP WSTG: <https://owasp.org/www-project-web-security-testing-guide/>
2. NIST SP 800-115: <https://csrc.nist.gov/pubs/sp/800/115/final>
3. OWASP ASVS: <https://owasp.org/www-project-application-security-verification-standard/>
