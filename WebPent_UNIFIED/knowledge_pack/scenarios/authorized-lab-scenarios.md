# Authorized Lab Scenarios

هذه السيناريوهات مصممة للتشغيل على WAPTLab أو Juice Shop أو targets يملك المستخدم تصريحًا مكتوبًا لاختبارها. لا تُستخدم ضد خدمات عامة عشوائية. كل scenario يحدد observation وprobe وcontrol، ولا يساوي finding حتى يثبت السلوك.

## BAC / IDOR

ابدأ بحسابين أو دورين أنشأهما المشغّل داخل lab. اجمع object ownership من responses المرصودة، ثم أعد نفس الطلب مع تغيير identifier واحد فقط. النجاح يتطلب وصولًا فعليًا إلى object مملوك للسياق الآخر أو تنفيذ تعديل غير مصرح به، مع control يثبت أن object غير موجود أو أن الدور الصحيح يتصرف كما هو متوقع. لا يكفي أن يكون الرقم متجاورًا أو أن status code مختلفًا.

## SQL injection

اختر parameter ظهر فعليًا في endpoint مرصود، وابدأ baseline ثم probe واحد محدود. قارن body/status/headers/timing مع negative control، ولا تستخدم destructive statements. يجب أن يكون الفرق قابلًا لإعادة الإنتاج ومرتبطًا بالـparameter، وإلا تسجل hypothesis فقط.

## XSS

حدد reflection أو DOM sink من response أو browser observation. استخدم marker غير تنفيذي أولًا، ثم تحقق من context وencoding داخل lab فقط. يجب توثيق المكان الذي يصل إليه input والـsink، مع control encoded أو context لا يصل إلى sink. لا تعتبر مجرد انعكاس نصي finding تنفيذية.

## SSRF

استخدم controlled callback يملكه المشغّل أو fixture داخل lab، ولا تستخدم cloud metadata أو خدمات طرف ثالث. يجب إثبات أن الخادم هو الذي بدأ الاتصال، مع control يثبت اختلاف server-side behavior عن client-side redirect. إذا لم توجد interaction قابلة للإسناد، لا ترفع النتيجة.

## GraphQL authorization

اكتشف schema وoperations من traffic المصرح به فقط. قارن field أو node access بين roles/owners، واحتفظ بنفس query قدر الإمكان مع تغيير authorization context. النجاح يتطلب data exposure أو mutation أثره مثبت، مع public-field وunauthorized controls.

## Report replay

لكل scenario احفظ baseline وprobe وcontrol ووقت الاختبار وengagement id، مع redaction للـtokens وPII. يظل كل سياق مسترجع من RAG خلف boundary منفصل، ولا يُخلط مع target evidence.
