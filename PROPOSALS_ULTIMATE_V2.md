# PROPOSALS_ULTIMATE_V2 — الطبقة التالية: من إطار كامل إلى صياد bug bounty حقيقي

التاريخ: 2026-10-29
الفرع: `donorC-side`
الأساس: كل اقتراحات `PROPOSALS_ULTIMATE_20261025.md` العشرة منفذة ومجمّدة (HEAD `9064e89` + الـ 21 defect-fix).
هذا الملف هو **الجولة الثانية**: مش تكرار للجولة الأولى، بل الفجوات المتبقية بعد تدقيق المشروع الحالي.

---

## §0. قراءة صادقة للجاهزية الحالية (قبل الاقتراحات)

اللي المشروع عنده **فعليًا** ولازم ما نقترحش فيه تكرار:

- اكتشاف JS: `js_discovery`, `javascript_intelligence`
- هجمات HTTP متقدمة جزئيًا: `request_smuggling` (CL.TE/TE.CL), `advanced_web_vulns` فيها validator لتسميم الكاش
- GraphQL: `graphql_testing`
- المصادقة: `oauth_hunter`, `multi_step_auth`, `access_control`, `bac_identity_tester`, `authorization_matrix`
- النطاق: `scope_enforcer` (إجباري) — لكن مفيش **اختيار** هدف
- الذاكرة: `attack_memory`, `reflection`, `payload_optimizer`, `waf_detector`
- الدليل: `proof_engine`, `proof_bundle_store`, `browser_proof_runner` (موجود!), `bounty_report`, `cvss_engine`, `executive_summary`
- القياس: `vabhfil_v8/benchmark.py` — لكنه يقيّم **artifacts مسجلة فقط ولا يلمس هدفًا أبدًا**
- الحوكمة: التجميد المجمد + `spend_governor` + `kill_switch` + `request_ledger` + `resume`

الفجوات الحقيقية بعد التدقيق (وهي موضوع هذا الملف):

1. لا يوجد **أي** سيرفر OOB — أي ثغرة عمياء (blind SSRF/XXE/cmdi/SQLi) لا يمكن تأكيدها أصلًا.
2. لا يوجد تحليل **taint ساكن للـ JS** (source→sink) ولا إعادة بناء **source maps** — عمياء على ثغرات العميل الثقيلة.
3. الـ race عندنا threads فقط — لا يوجد **single-packet attack عبر HTTP/2** (حالة الفن).
4. لا يوجد **ingest لبرامج bug bounty** ولا اختيار هدف (المشغّل هو اللي يختار).
5. التعلم محصور بالحملة الواحدة — لا مكتبة تقنيات عبر الحملات ولا dedupe ضد تقارير معلنة.
6. الـ benchmark لا يلمس هدفًا حيًا — لا ground truth حقيقي ولا scoreboard.
7. مفيش **حكم حي** يظهر للشخص كل ساعة الإرسال والتكلفة والفرضيات.

قاعدة عمل لكل اقتراح: قبل أي سطر كود، `grep` سريع للتأكد إن الموديول مش موجود فعلًا (المشروع فيه 148 موديول في `shared/` وحده) — وتُسجل نتيجة الفحص في أول commit للاقتراح.

---

## §1. سيرفر OOB ذاتي الاستضافة (oast) — أساس كل شيء

**الفجوة:** blind SSRF/XXE/OS command/SQLi بدون تأكيد callback = صفر تقارير عالية القيمة من هذه الفئات. الاعتماد على interactsh.fun طرف ثالث يتناقض مع مبادئ الخصوصية.

**التصميم:**

- موديول جديد `src/webpent/oast/`: `server.py` (HTTP/HTTPS listener + DNS wildcard guidance في doc النشر), `client.py` (توليد marker فريد لكل probe: `probe-{campaign}-{finding}`, استعلام `/poll` عن callbacks المطابقة), `correlate.py` (ربط callback بـ probe بالـ marker وربط النتيجة بـ ART_* artifacts في الـ chain v3).
- **فشل مغلق:** بدون `OAST_DOMAIN` مضبوط، الـ blind probes لا تُبث أصلًا وتُسجل `inconclusive: no_oast_configured`. لا يوجد fallback لطرف ثالث.
- التكامل: `ssrf/xxe/cmdi/sqli` validators تستدعي `client.expect(marker)` قبل الإرسال و`correlate.wait(marker, timeout)` بعده.
- تخضع للـ `request_ledger` والـ `spend_governor` مثل بقية الإرسال، ولـ `kill_switch`.

**الملفات الجديدة:** `src/webpent/oast/{__init__,server,client,correlate}.py`، `src/webpent/config/settings.py` (ثلاثة حقول جديدة)، `docs/oast-deployment.md`، `tests/test_oast.py`.

**الـ flag:** `enable_oast` (افتراضي False) + `oast_domain` + `oast_poll_endpoint`.

**الاختبارات:** دورة كاملة ضد سيرفر محلي على المنفذ الحر (probe → callback → correlate)، فشل مغلق بلا ضبط، تشفير marker فريد لكل probe، توقف النظيف مع kill_switch.

**المخاطر:** نشر الـ DNS wildcard مسؤولية المشغّل — يُوثق حرفيًا مع تحذير ألا يُوجَّه النطاق لهدف الحملات.

**معيار النجاح:** blind SSRF ضد fixture محلي (مطبع على 169.254-style URL داخلي) تُأكَّد تلقائيًا بالـ callback وتدخل الـ chain v3 كـ artifact.

---

## §2. DOM XSS: تحليل taint ساكن للـ JS + تأكيد بمتصفح

**الفجوة:** `javascript_intelligence` يعمل على مستوى الأنماط. الصيادون الحقيقيون يفوزون هنا: تتبع data من source إلى sink داخل كود مضغوط.

**التصميم:**

- موديول `src/webpent/agents/dom_xss/`:
  - `parser.py` — استخراج AST عبر `esprima` (محفوظة على PyPI، نقية) بعد إزالة الضغط (استخدام `jsbeautifier`).
  - `taint.py` — جداول sources (`location.hash/search/name`, `postMessage.data`, `document.referrer`, `localStorage`) و sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `location=`, jQuery `.html()`), والمسار: أولوية التدفق داخل نفس الدالة ثم عبر وسيطات الدوال (تحليل ترتيبي محدود العمق = 3).
  - `payloads.py` — صياغة payload حسب نوع الـ sink مع تجاوز الترميز الأساسي.
- تأكيد: إعادة استخدام/مط `shared/browser_proof_runner` (موجود) للتأكد: payload مرئي في DOM أو `window.onhashchange` أُثبت — لقطة شاشة + console log كدليل.

**الـ flag:** `enable_dom_xss` (افتراضي False) + `dom_xss_max_ast_nodes` (سقف 50k عقدة، فشل مغلق فوقه).

**الملفات:** `src/webpent/agents/dom_xss/{parser,taint,payloads,agent}.py`، `tests/test_dom_xss.py` بملفات JS fixtures معروفة (تدفق مؤكد، sink بلا source = لا شيء، sink مُرمَّز = لا شيء).

**معيار النجاح:** على صفحة fixture مبنية للاختبار (source في `location.hash` → `innerHTML`) يُكتشف التدفق ويُؤكَّد بمتصفح بدون أي إرسال يفوق النطاق.

---

## §3. Source maps وأسرار العميل

**الفجوة:** معظم المواقع تترك `.map` مكشوفة — إعادة بناء الكود الأصلي (TS/JSX) تكشف endpoints وsecrets ومنطقًا كاملًا.

**التصميم:**

- توسيع `js_discovery`: probe على `{js_url}.map` و`//# sourceMappingURL=`، flag `enable_sourcemap_probe` (افتراضي False).
- `sourcemap_reconstruct.py`: قراءة `sourcesContent`، بناء شجرة ملفات في الذاكرة (لا تُكتب للقرص إلا في `proof_bundle`).
- مسح secrets: `secret_scanner.py` بأنماط مرتبة (AWS keys، JWTs، Google keys، private key headers، endpoints داخلية) — كل نمط مرتبط بـ vuln_class موجود في `artifact_graph` كي يغذي الـ chain v3.

**الاختبارات:** fixture sourcemap JSON، reconstruction دقيق، scanner بلا false-positive على كود عادي، فشل مغلق عند 404.

**معيار النجاح:** خريطة مكشوفة في fixture تُنتج findings من فئة `info_disclosure` مرتبطة chain-wise مع `ssrf`/`open_redirect` من نفس الجرد.

---

## §4. مصفوفة الأدوار متعددة الحسابات (role matrix)

**الفجوة:** `access_control` موجود لكن الجلسات تُدخل يدويًا. الحقيقة: ثغرات الـ IDOR/التفويض تُكتشف بمقارنة أدوار حقيقية متعددة.

**التصميم:**

- موديول `src/webpent/agents/role_matrix/`:
  - `sessions.py` — التقاط/تسجيل جلسة لكل دور (تسجيل آلي ببيانات اعتماد من مخزن المشغّل المشفر، أو استيراد cookies) مع تحقق من الهوية لكل جلسة (تحقق من عنصر تحكم الدور قبل أي تمرير).
  - `matrix.py` — البناء الحتمي: كل (دور A → مورد B) زوجًا اختبارًا؛ الطلب بجلسة A على مورد B؛ إثبات الاختراق = 2xx + فرق قابل للملاحظة عن استجابة B نفسها (differential مثل workflow fuzzing).
  - يغذي `bac_identity_tester`/`authorization_matrix` بدلًا من إعادة اختراعها — هذا طبقة تنفيذ فوقهما.

**الـ flag:** `enable_role_matrix` (افتراضي False) + سقف الأزواج `role_matrix_max_pairs` (افتراضي 200).

**الاختبارات:** fixture سيرفر بدورين وثغرة IDOR مقصودة: matrix يلتقطها ويُفشل مغلق عند نقص جلسة أو انتهاء صلاحيتها.

**معيار النجاح:** IDOR بين أدوار في fixture يُؤكَّد، والأدوار السليمة تُرجع `refuted` بلا false positive.

---

## §5. HTTP/2 single-packet race attack

**الفجوة:** الـ race الحالي threads — تحت زمن شبكة حقيقي يفقد التزامن. حالة الفن (Kettle): إرسال N إطارات header+DATA في حزمة TCP واحدة عبر اتصال H2 واحد.

**التصميم:**

- `src/webpent/shared/h2_race.py` فوق مكتبة `h2` (PyPI): فتح اتصال H2، بناء N streams، إرسال الإطارات كلها في `write` واحد، قراءة الاستجابات، تحديد الفائز.
- تكامل `workflow_fuzzing/agent.py`: `_replay` يمرر `transport="h2_single_packet"` عندما يسمى بروتوكول الهدف؛ fallback تلقائي للـ threads عند فشل التفاوض H2 (http/1.1 فقط).
- الـ governor يحسب الـ N طلب دفعة واحدة.

**الـ flag:** `enable_h2_race` (افتراضي False).

**الاختبارات:** سيرفر H2 محلي (ASGI + hypercorn على المنفذ الحر) مع عداد تجاوز (counter بدون قفل): الثنائية single-packet تُفعل الـ counter ليصل 2، والثنائية المُتسلسلة لا. اختبار fallback.

**معيار النجاح:** mutation `race_on_step` في workflow fuzzing يستخدم H2 ضد هدف H2، والـ control twin يظل بلا تأكيد.

---

## §6. توسيع الكاش: اكتشاف مفاتيح التخزين المؤقت (Param Miner style)

**الفجوة:** validator التسميم موجود لكنه يفترض header معروفًا. الأرباح الحقيقية في **اكتشاف** الـ header/param غير المُخزَّن (unkeyed).

**التصميم:**

- `src/webpent/shared/cache_key_discovery.py`: لكل endpoint، أرسل الطلب مرتين بقيم عشوائية في header مرشح (قاموس ~40 header شائع: `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`...) وparam، وراقب انعكاس القيمة في استجابة **مخزنة** (عنوان cache-hit مميز).
- صارم: انعكاس بلا تخزين = refuted؛ تخزين بلا انعكاس = inconclusive؛ الاثنان معًا فقط = candidate يمر لـ validator التسميم الموجود.

**الـ flag:** `enable_cache_key_discovery` (افتراضي False) + سقف 15 endpoint لكل حملة.

**الاختبارات:** fixture سيرفر يخزن ويعكس `X-Forwarded-Host`: يُكتشف؛ سيرفر يخزن ولا يعكس: refuted.

---

## §7. حزمة الدليل الكاملة (evidence bundle)

**الفجوة:** `proof_bundle_store` موجود لكن المخرج النهائي (تقرير bounty) لا يحمل HAR ولا screenshots ولا ربط خطي للتسلسل.

**التصميم:**

- `src/webpent/reporter/evidence_bundle.py`: يبني ZIP لكل finding: `requests.har` (مولَّد من `request_ledger` — مكتمل إحصائيًا، أي إدخال ناقص = تحذير صريح)، screenshots من `browser_proof_runner`، `poc.sh` من الـ chain v3، و`cvss.json` (تحقق من `cvss_engine`: إضافة متجه CVSS v4 إن لم يوجد، وإلا نُبقي v3 ونوثق ذلك بصراحة).
- `dedupe.py`: توحيد الجذور — نفس الـ vuln_class + نفس نقطة الجذر (endpoint الوارد الأول في السلسلة) = finding واحد بكل سلاسله.
- ربط اختياري في `bounty_report.py`: إخراج بصيغة JSON متوافقة مع API للمنصة، **مع بوابة موافقة بشرية إلزامية** (خطوة توافق صريحة في الـ workflow؛ لا إرسال آلي أبدًا).

**الـ flag:** `enable_evidence_bundle` (افتراضي False) + `enable_external_submission` (افتراضي False، ولا يعمل إلا مع تسجيل موافقة صريحة في الـ engagement).

**الاختبارات:** bundle من حملة fixture: HAR صالح برمجيًا، dedupe يدمج سلسلتين بنفس الجذر، الإرسال الخارجي يرفض بدون موافقة مسجلة (فشل مغلق).

---

## §8. اختبارات معايير حية (live benchmarks) بأرض حقيقية

**الفجوة:** `vabhfil_v8/benchmark.py` صراحةً "never contacts a target" — تقييم artifacts فقط. بلا ground truth حقيقي لا يقاس تقدم ولا يدَّعى تنافس.

**التصميم:**

- `src/webpent/benchmarks/`: runners للأهداف **المحلية فقط**: Juice Shop، DVWA، وlabs PortSwigger المحلولة محليًا إن توفرت — عبر `benchmark_target = localhost:<port>` مضبوط صراحة.
- `ground_truth.py`: JSON لكل هدف بالثغرات المعروفة (فئة + endpoint)؛ الـ scoreboard: detection rate لكل فئة، وقت الحل، التكلفة بالتوكن.
- صارم: `enable_live_benchmarks` (افتراضي False) ويرفض أي host ليس `localhost`/`127.0.0.1` (فشل مغلق) — لا يجري الاختبار على هدف منتج أبدًا.
- إخراج: `benchmark_scoreboard.json` يُخزن versioned ويُقارن بين الإصدارات (regression عند أي تغيير في الموديولات).

**الاختبارات:** runner ضد Juice Shop في حاوية محلية (اختبار اختياري بعلامة `@pytest.mark.benchmark_live` لا يدخل الـ CI الافتراضي)، محرك scoreboard ضد ground truth ثابت.

**معيار النجاح:** جدول موثق في `docs/benchmarks.md`: نسبة كشف لكل فئة على Juice Shop، تعيد ترقيمه عند كل تحسين لاحق.

---

## §9. توجيه الـ LLM حسب الكلفة (model tiering)

**الفجوة:** `spend_governor` يحد الإنفاق لكنه لا **يوجّهه**. الاستكشاف لا يحتاج النموذج الأقوى، والـ exploitation يحتاجه.

**التصميم:**

- `src/webpent/llm_researcher/tiering.py`: جدول حتمي task→tier (`crawler_summary/exploration → tier: fast`, `hypothesis/exploit/poc → tier: strong`)، مع fallback تلقائي للمتاح عند غياب tier.
- تكامل: كل استدعاء LLM في الـ providers يمر بالـ router؛ التكلفة تُسجل في `spend_governor` لكل tier (يظهر في التقرير أين ذهب الإنفاق).

**الـ flag:** `enable_model_tiering` (افتراضي False) + `model_tier_fast`/`model_tier_strong` (أسماء نماذج من ضبط المشغّل).

**الاختبارات:** router حتمي، fallback عند tier ناقص، تسجيل إنفاق منفصل لكل tier.

---

## §10. محرك البرامج واختيار الهدف (act like a real hunter)

**الفجوة:** `scope_enforcer` **يجبر** على النطاق لكن **المشغّل** هو من يختار الهدف والترتيب. البشري المحترف يختار بأرباح البرامج وتاريخه.

**التصميم:**

- `src/webpent/targeting/program_brief.py`: استيراد brief برنامج (Markdown/JSON من المشغّل يدويًا — لا زحف لمنصات خارجية): scope (wildcards)، out-of-scope صريح، جدول مكافآت، ملاحظات.
- `selector.py`: UCB1 حتمي (بذرة معلنة) فوق تاريخ `attack_memory`: كل هدف = ذراع بفئة (الثغرات المكتشفة + المكافأة المتوقعة من جدول البرنامج). الاختيار **يُسجل دائمًا مع سببه** في الـ status snapshot (شفافية كاملة للمشغّل).
- تكامل: يوصي فقط؛ القبول النهائي بيد المشغّل (خطوة موافقة) — والـ `scope_enforcer` يظل حكمًا نهائيًا فوق أي اختيار.

**الـ flag:** `enable_target_selector` (افتراضي False).

**الاختبارات:** اختيار حتمي ببذرة ثابتة، عدالة الاستكشاف (كل هدف يُجرَّب مرة قبل التصعيد)، فشل مغلق عند brief بلا scope.

---

## §11. التعلم عبر الحملات (cross-campaign learning)

**الفجوة:** `attack_memory` داخل الحملة، `disclosed_report_intel` للقراءة فقط — لا حلقة بينهما.

**التصميم:**

- `src/webpent/learning/technique_library.py`: مكتبة تقنيات versioned (JSON): (فئة ثغرة + فئة WAF + بنية تقنية) → (قائمة payloads + نسب نجاح تتجمع من الحملات).
- استهلاك: `payload_optimizer` يقرأ المكتبة قبل صياغة payloads؛ إنتاج: كل نهاية حملة تُحدّث النسب (تحديث بيتا إقليدي بسيط ومحتم، مع سقف تذكّر).
- dedupe عبر الحملات: تشابه نصي مرجح (Jaccard على tokens الـ endpoint+فئة — بلا embeddings خارجية حفاظًا على الخصوصية والبساطة) ضد سجل الجرد المشترك: التكرار المحتمل يُعلَّم `possible_duplicate` في التقرير.

**الـ flag:** `enable_cross_campaign_learning` (افتراضي False) — بدونها لا تُكتب المكتبة أصلًا.

**الاختبارات:** تحديث نسب حتمي، تعطيل كامل بالـ flag، dedupe يلتقط تكرارًا مصطنعًا ويتجاهل السليم.

---

## §12. الحكم الحي (live ops stream)

**الفجوة:** `status_snapshot` و`request_ledger` موجودان لكن الشخص يرى التقدم بالسحب فقط. الثقة في أداة مستقلة تُبنى بالشفافية اللحظية.

**التصميم:**

- `src/webpent/api/live_stream.py`: SSE endpoint في `api/app.py` (بلا مكتبات جديدة — `StreamingResponse`) يبث أحداث الحملة: فرضية جديدة، فحص مؤكد/مُهدم/مبهم، الإنفاق اللحظي من `spend_governor`، وحالة الـ kill_switch.
- حدث واحد = سطر واحد JSON من قاموس `status_snapshot` الحالي (لا حالة جديدة تُخزن — العرض فوق الموجود).
- الـ flag: `enable_live_stream` (افتراضي False).

**الاختبارات:** SSE ضد عميل httpx محلي: تسلسل الأحداث يحاكي أحداث حملة fixture بالترتيب، والإغلاق نظيف عند فصل العميل.

---

## §13. ترتيب التنفيذ (لماذا هذا الترتيب)

| # | الاقتراح | الجهد | يعتمد على | لماذا هنا |
|---|----------|-------|-----------|-----------|
| 1 | §1 OAST | L | — | بدون تأكيد blind لا قيمة لنصف الفئات؛ كل ما بعده يبنى فوقه |
| 2 | §2 DOM XSS | L | — | أكبر مساحة اكتشاف مفقودة؛ محرك التأكيد بالمتصفح يخدم §7 أيضًا |
| 3 | §3 Source maps | S | — | مكسب سريع منخفض المخاطر، يغذي الـ chain v3 |
| 4 | §7 Evidence bundle | M | §2 (لقطات) | يحوّل ما سبق إلى مخرج قابل للتقديم |
| 5 | §4 Role matrix | M | — | يرفع دقة التفويض ويقلل false positives |
| 6 | §5 H2 race | M | — | حالة الفن للـ race |
| 7 | §6 Cache keys | S | — | سريع ويستخدم validator موجود |
| 8 | §8 Live benchmarks | M | 1-7 | الآن نقيس الفعالية الحقيقية ونثبت التحسين |
| 9 | §9 Model tiering | S | — | خفض كلفة مباشر قبل توسيع الاستخدام |
| 10 | §10 Target selector | M | §8 (تاريخ موثوق) | الاختيار الذكي يحتاج بيانات أداء حقيقية |
| 11 | §11 Cross-campaign | M | §8 | حلقة التعلم تحتاج حملات حية تقيس |
| 12 | §12 Live stream | S | — | أخيرًا: واجهة فوق كل شيء |

القاعدة: كل اقتراح — flag جديد افتراضي False، فشل مغلق، اختبارات ملحقة، وبعد الاقتراحات التي تمس ملفات مجمّدة: إعادة تجميد Item جديد ببروتوكول PRE/POST_HASHES المعهود. التجميع في commits: اقتراح واحد = commit واحد (أو أكثر)، ولا يُدمج اقتراحان في commit واحد.

---

## §14. ملاحظة ختامية

الجولة الأولى بنت **هيكلًا** (حوكمة، سلاسل، فحص نزاهة). هذه الجولة تضيف **القدرات** التي يدفع عليها السوق فعليًا: التأكيد العمياء، ثغرات العميل، حالة الفن، والاختيار البشري الذكي. بعد §8 سيكون لدينا أول جدول قياس موثق — وحين يظهر تحسن مستمر عبر إصداراته، تتحول الجملة "ينافس الشركات" من ادعاء إلى نتيجة مقاسة.
