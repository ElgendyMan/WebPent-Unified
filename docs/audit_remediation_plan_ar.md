# خطة معالجة تقرير تدقيق WebPent v60

**التاريخ:** 17 أغسطس 2026  
**المرجع:** `WebPent_v60_Audit_Report.docx`  
**الهدف:** رفع الأمان والموثوقية دون كسر backward compatibility أو تخفيف fail-closed وscope وHITL وEvidence Contract.

## 1. baseline قبل التنفيذ

تم تثبيت baseline في `audit-remediation-baseline.log`:

| القياس | النتيجة |
|---|---:|
| pytest | 465 passed، 80 warnings |
| test functions | 431 مقابل floor 429 |
| compileall | ناجح |
| `uv lock --check` | ناجح |
| `pip check` | ناجح |
| Ruff المحدد على `src` و`tests` بالقواعد `E,F,I,RUF` | فاشل بسبب 659 مخالفة على كامل السطح، وليس بسبب مجموعة v63 فقط |
| Ruff الافتراضي | فاشل بسبب 562 مخالفة، منها 288 E501 و109 I001 |

لن نستخدم رقم الاختبارات وحده كدليل جودة؛ كل إصلاح أمني جديد سيحصل على regression test سلوكي قدر الإمكان، وليس `inspect.getsource()` فقط.

## 2. مبادئ عدم كسر المشروع

يجب أن تظل الموارد القديمة قابلة للقراءة، لكن أي resource قديم بلا `owner/tenant/engagement` سيُعامل deny-by-default في المسارات الحساسة. لن نغير شكل state أو checkpoint بلا migration/version gate. لن نسمح بترقية LLM hypothesis إلى `Tool-Confirmed` دون evidence contract. وكل تعديل على network أو subprocess سيحافظ على scope enforcement وHITL وrate/concurrency budgets.

بعد كل مجموعة تغييرات سنشغل compileall، الاختبارات المتخصصة، full pytest، وRuff على الملفات المعدلة. عند فشل اختبار أو تغير غير متوقع في state serialization سنوقف المجموعة ونرجع آخر commit/نسخة احتياطية بدل متابعة تغييرات متراكمة.

## 3. نطاق التنفيذ المرحلي

### المرحلة A — P0 stop-the-bleed

| البند | الإجراء | اختبار القبول |
|---|---|---|
| TLS raw smuggling | إبقاء certificate validation مفعلة، ورفض أي `CERT_NONE` أو `check_hostname=False` في production path؛ السماح بـcustom CA فقط من policy صريحة | fixture بشهادة غير موثوقة يفشل، وfixture موثوقة ينجح |
| SQLite checkpoint busy timeout | تطبيق `PRAGMA busy_timeout=30000` على كل connection path، وتسجيل الفشل بدل إخفائه | اختبار اتصالين متوازيين وقراءة pragma من المسار الموصى به |
| ysoserial/phpggc | تحويل command إلى allowlisted executable + arguments typed، طول محدود، no-shell، approval/policy gate، وعدم تمرير LLM string كـcommand | أوامر صحيحة تمر، metacharacters/unknown executable/overlength تُرفض قبل التنفيذ |
| ground-truth tests | إضافة contract suite قابلة للتشغيل محليًا على FastAPI ground-truth، مع marker واضح، وعدم جعل غياب Docker يخفي unit contracts | collection ناجح، fixtures الأساسية تمر، وCI يميز integration skipped عن passed |

### المرحلة B — P1 evidence والهوية والتنفيذ

| البند | الإجراء | اختبار القبول |
|---|---|---|
| report hash | canonicalize payload دون `master_report_hash` السابق، ثم hash مرة واحدة؛ تحقق مستقل يعيد نفس القيمة | export ثم verify يعيدان نفس hash، والتلاعب يفشل |
| cross reasoning | تحويل LLM chains إلى `chains_to_test` أو `Needs Human Review`؛ لا finding confirmed بلا validator evidence | chain بلا tool proof لا يرفع confidence |
| JWT alg=none | baseline أصلي ثم probe، مع عدم اعتبار 200 وحده bypass | public 200 لا ينتج critical، وفرق auth حقيقي فقط ينتج candidate |
| safe HTTP invariant | إزالة fallback إلى raw `httpx.Client` ورفع خطأ واضح إذا غاب factory الآمن | monkeypatch لغياب factory يفشل closed |
| crawler curation | حصر endpoints المختارة داخل crawled surface وscope، ورفض raw LLM URLs | URL غير موجودة في surface لا تصل إلى queue |
| strategist/scope/rabbit-hole | استخدام accessors موحدة للـdict/model، وتطبيق scope على artifact وrelative URL بعد canonicalization | artifact خارج النطاق يُرفض قبل traversal |
| reference lookup | parse URL ومقارنة hostname/scheme/port حسب السياسة بدل `startswith` | `trusted.example.attacker.com` وuserinfo bypass يفشلان |
| exception redaction | redaction مركزي لـBearer/Cookie/Set-Cookie/password قبل `str()` وlogging | secret sentinel لا يظهر في ToolExecutionError أو logs |
| API ownership | authorization service واحد لكل status/findings/risk/approve/resume/export/OOB | cross-user وcross-tenant يحصلان على 403/404 دون metadata leak |
| reauth vault | opaque encrypted record مع key من runtime secret، TTL، one-time retrieval، وعدم وضع plaintext في checkpoint | restart/expiry/replay يفشل، وcheckpoint لا يحتوي secret |
| secure deployment | auth enabled افتراضيًا وloopback bind للتطوير؛ production يرفض weak defaults وRedis غير الآمن | compose contract tests تفحص القيم الفعلية |
| subprocess lifecycle | process group حقيقي، kill group عند timeout، distinction صريح بين timeout وstderr، no-shell invariant | child/grandchild يُنهى، وstderr العادي لا يُصنف timeout |
| Alembic | رفع migration exception وعدم `stamp head` عند الفشل | migration fault يفشل startup ولا يعلن schema سليمة |
| hypothesis patterns | إضافة API/GraphQL/OAuth/webhook/v2 patterns كـdiscovery hints فقط، دون رفع evidence | modern endpoint ينتج candidate ولا ينتج confirmed تلقائيًا |

### المرحلة C — P2 الأعلى عائدًا

سننفذ فقط التحسينات ذات أثر واضح وقابل للاختبار: grounding minimum length وoverlap ratio، body cap streaming، rate governor في recon/access control، bounded OOB polling، POST-body OOB injection، copy-on-write state updates، وتشفير session cookies مع KDF قياسي. أما GraphQL/WebSocket/OAuth/SAML/Kubernetes validators الكاملة فستُبنى كـinterfaces وsafe discovery contracts أولًا، ولا سنضيف probes intrusive بلا fixtures وpolicy gates.

أي feature حديثة ستبقى advisory/candidate حتى تملك evidence contract وnegative control. لن نضيف blind fuzzing أو exploit behavior إلى production defaults.

### المرحلة D — P3 hygiene والاتساق

سننظف dead imports، نوحد version/test metadata في README وbaseline وdelivery notes، نصلح template labels وknowledge source identifiers و`doctor-offline.json`، ونحوّل `verify_all.py` إلى check حقيقي أو نحذفه. سنضع Ruff configuration صريحة: بوابة merge محددة ومعلنة، مع فصل legacy violations عن الملفات التي تم لمسها، بدل الادعاء أن المشروع كله نظيف بينما يوجد مئات المخالفات.

## 4. ما لن نعد به في هذه الجولة

لن ندّعي أن إضافة patterns أو GraphQL discovery تعني دعم GraphQL end-to-end. ولن نرقّي المشروع إلى production-ready طالما dependency audit يحتوي advisories أو Redis/secrets/checkpoint controls غير مكتملة. ترقية LangChain/LangGraph major versions ستكون branch منفصلة مع migration tests للحفاظ على checkpoints القديمة.

## 5. Definition of Done

تعتبر كل مجموعة مكتملة فقط إذا تحقق الآتي: الكود يمر compileall، الاختبارات الجديدة والقديمة تمر، test count لا ينخفض عن 429، لا يوجد cross-tenant read/write مثبت في tests، لا يوجد secret sentinel في checkpoint/log/error fixtures، كل network/subprocess path يمر policy أو يرفض fail-closed، artifacts قابلة لإعادة التحقق، والتوثيق يذكر بوضوح ما تم إغلاقه وما بقي known risk.

## 6. ناتج التسليم

في النهاية سنسلم source ZIP منقحًا، SHA256، تقرير تنفيذ عربي، مصفوفة findings قبل/بعد، full pytest log، targeted/default Ruff logs، dependency audit، وقرار release واضح: production-ready أو staging-only مع أسباب قابلة للتدقيق.
