# Finding Report Contract

## الهدف

التقرير الجيد يشرح سلوكًا مرصودًا ويمكن لمراجع مستقل إعادة إنتاجه. هذا الملف يحوّل مبادئ NIST SP 800-115 وOWASP WSTG إلى حقول عملية داخل WebPent، مع الحفاظ على الفصل بين المعرفة الإرشادية وevidence الخاصة بالهدف.

## الحد الأدنى للـfinding المؤكد

| الحقل | ما يجب أن يحتويه |
|---|---|
| العنوان والفئة | اسم واضح مثل Broken Access Control أو Reflected XSS |
| النطاق | target وengagement وendpoint المرصود |
| precondition | الحساب أو الدور أو حالة الجلسة اللازمة |
| baseline | الطلب الصحيح والرد قبل التغيير |
| probe | التغيير الوحيد المقصود في parameter/header/body/method |
| causal signal | فرق سلوكي مرتبط مباشرة بالتغيير |
| negative control | حالة ضابطة تفشل أو لا تظهر فيها النتيجة |
| impact | ما الذي أمكن قراءته أو تعديله فعليًا، بدون مبالغة |
| reproducibility | خطوات replay آمنة ومحدودة |
| remediation | إصلاح مرتبط بالسبب، وليس نصيحة عامة فقط |
| confidence/severity | مبني على evidence وrole context لا على corpus وحده |
| references | روابط المنهجية أو write-up المستخدمة كخلفية |

## قاعدة عدم الترقية

المحتوى المسترجع من methodology أو report أو write-up يحدد ماذا نتحقق منه، لكنه لا يثبت أن الهدف vulnerable. عند غياب causal signal أو negative control، يجب إبقاء الحالة hypothesis أو candidate. يجب عدم دمج نتائج target مختلفة أو lessons من عميل آخر، ويجب أن يبقى `client_id` إلزاميًا عند استعمال lessons.

## مثال وصفي محايد

`Observed endpoint /api/items/{id}` مع owner context A. Baseline request for item 41 returns the owner's item. The only changed input is the object identifier 42 under context A. The response returns item 42, which was independently established as owned by context B. The same request with an invalid identifier returns 404, and the owner-control request under context B succeeds. This is evidence for an authorization failure only if the ownership facts and replay are recorded; a neighboring ID by itself is not sufficient.

## مراجع

- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
