# WebPent — الإمكانيات الكاملة والمعمارية (Capabilities & Architecture)

> مرجع شامل لما تفعله الأداة، كيف مبنية، وكيف تُشغَّل وتُقاس. الأرقام من الشجرة
> المدموجة الفعلية (WebPent_UNIFIED، نوفمبر 2026).

---

## 1) واجهة واحدة: ماذا تفعل الأداة

وجّهها إلى هدف **مصرّح لك** باختباره، وهي تدير دورة كاملة: تخطيط ميزانية ديناميكية →
استطلاع وفهم هدف → توليد فرضيات هجومية → تحقق بأدوات وأدلة حقيقية → تقييم
ذاتي واعتراف بالفشل → تقرير bug-bounty جاهز. كل finding يمر بعقد إثبات صارم
(سلوك فعلي + evidence + شروط إعادة تحقق) قبل أن يُعلن.

```bash
./install.sh                    # تثبيت موجه
webpent init                    # إعداد أول حملة (هدف + تفويض + وضع)
webpent hunt --url <target> --mode quick|standard|deep --authorization <ref>
webpent doctor                  # فحص صحة: DB + مفاتيح LLM + الأدوات الخارجية
```

يعمل **بلا أي مفتاح LLM** (`LLM_ENABLED=false`) عبر المسار الحتمي الكامل.

## 2) مصفوفة الإمكانيات (59 حزمة وكلاء + الطبقات المتقدمة)

### استطلاع وفهم الهدف
| القدرة | التفاصيل |
|---|---|
| Crawl واكتشاف | crawler، js_discovery، javascript_intelligence (نقاط نهاية من البَندلات)، sourcemap_analysis (أسرار من .maps)، subdomain_takeover |
| أدوات خارجية مقيدة | nuclei وsqlmap وdalfox وkatana وarjun وffuf وsubfinder وgau وnmap — كلها عبر registry مع preflight وتفويض |
| فهم الهدف | target_understanding، attack_graph، surface sizing لحساب الميزانية، business_impact |
| تقنية وWAF | waf_detector + waf_fingerprints + cache_key_discovery، مؤشرات تطبيقات الجوال |

### توليد وتنفيذ الفرضيات
| القدرة | التفاصيل |
|---|---|
| عائلات ثغرات | access_control/IDOR، auth جلسات، business_logic_fuzzer، race_conditions، multi_step_auth، oauth_hunter، graphql_testing، cache_poisoning، prototype_pollution، request_smuggling، tenant_isolation، dom_xss (محلل AST عبر esprima)، cloud_storage، file uploads |
| سلاسل الاستغلال | chain_planner + exploit_chainer + PreconditionGraphBuilder + chained_exploits/graph_v3 (legacy) |
| الحمولات | payload_generator/optimizer + docs/payload_library.json (≈900KB) |
| التنفيذ الآمن | execution_sandbox، personas، planner/strategist، rabbit_hole (ضبط الانحراف) |
| الاستطلاع خارج النطاق | OOB provider + خادم OAST كامل (طبقة legacy جاهزة للتوصيل — انظر ملف الاقتراحات ق1) |

### التحقق والجودة (قلب الفلسفة)
| القدرة | التفاصيل |
|---|---|
| EGAIE | حلقة تحقيق مغلقة: InformationGainSelector، سجل تكرار، متطلبات مسبقة، planner — تُنفذ عبر نقل HTTP حقيقي بلا مسارات خام |
| cqa_v2 | CausalGuard + ProofBundle + ReplayVerifier: برهان كامل قابل للإعادة بأثر sha256 |
| validators حتمية | GraphQL، OAuth، family_checks (6 عائلات) — fail-closed |
| devil's advocate | challenge إلزامي للنتائج قبل الترقية + self-critique checkpoints |
| occlusion | عند فشل التحقق تبقى النتيجة inconclusive — لا ترقية قسرية أبدًا |

### الطبقات المتقدمة (CLI مباشر)
| الأمر | الطبقة |
|---|---|
| `webpent apex` | Apex Predator: أولوية الأهداف حسب العائد |
| `webpent oracle` | استطلاع سلبي Zero-Touch |
| `webpent jc` | مجتمع النقد: skeptic/judge/advocate على كل قرار |
| `webpent econ` | اقتصاد الحملة: تكلفة/عائد لكل خطوة + portfolio |
| `webpent prism` | الامتثال والتدقيق الأخلاقي للحملة |
| `webpent dojo` | مختبر تدريب: توليد labs، بطولات، تقييم مهارات، sparring هجوم/دفاع |
| `webpent cem` | حلقة الكفاءة المستمرة |
| `webpent vip` | طبقة الحملات المستقلة: orchestrator بأدوار (leader/strategist/economist/tactician) |
| `webpent retest` | إعادة اختبار منضبطة لنتيجة سابقة داخل النطاق |
| `webpent ops` | تشغيل العمال والمزامنة |

### التقارير والتشغيل
تقارير JSON/HTML بملخص تنفيذي وauthorization matrix appendix وredaction كامل،
قوالب HackerOne/Bugcrowd، ترتيب أولويات EPSS، إشعارات لحظية (webhook موقّع/JSONL)،
مراقبة Celery workers حية (`/api/v1/workers/status` + dashboard)، check/resume
للحملات، عزل ذاكرة بـclient_id/engagement_id.

## 3) المعمارية

### 3.1 الطبقات (من الأعلى للأسفل)
```
CLI / API (FastAPI) ── Docker / workers (Celery)
        │
   LangGraph Hunter (80+ عقدة؛ builder.py وحده 59)
   planner→recon→crawler→understanding→hypotheses→probes→validation→reflection→report
        │
┌───────┼─────────────────────────────────────────────┐
│ VIP (orchestration) │ EGAIE (experimentation) │ dojo/econ/jc/prism (طبقات قرار) │
└───────┼─────────────────────────────────────────────┘
        │
   cqa_v2: CausalGuard → ProofBundle → Replay  (عقد الإثبات)
        │
   shared/ (models, oob, safety, LLM helpers, كواشف حتمية) + state (PentestState)
        │
   adapters (juice_shop/crapi/dvwa/webgoat/generic) + tools registry + knowledge_pack (RAG)
```

### 3.2 تدفق الإثبات (لماذا تثق بالنتيجة)
1. كل فرضية تولد مع precondition مسجلة؛ 2. الـprobe يُنفذ عبر ActionExecutor
الإنتاجي (نفس مسار الإنتاج بلا استثناءات)؛ 3. الملاحظة تُغلَّف في
`GuardedCausalResult` مع digest؛ 4. الـvalidator الحتمي يقرر (fail-closed)؛
5. devil's advocate يعترض أو يوافق؛ 6. `ProductionTrace.summary()` يحسب
chain_verified (اكتمال + تحقق digest + تدقيق)؛ 7. التقرير يعرض evidence raw
قابل للإعادة replay.

### 3.3 نموذج الحالة والذاكرة
`PentestState` بقنوات append-only (فرضيات/ملاحظات/أدلة/علاقات) + `UnifiedState`
للحملات عبر الإصدارات؛ ChromaDB للـRAG مع عزل client_id؛ lessons عبر ledger
قابل للتعطيل؛ checkpoints للاستئناف.

### 3.4 الجودة كطبقة معمارية (ما يميز المشروع)
| البوابة | الآلية |
|---|---|
| عدد الاختبارات | `verify_test_count.py` — floor مجمّد = 7,958 (أعيد قياسه بالعد الفعلي للـpytest) |
| التجميد | 659 ملفًا بتجزئة sha256 — أي تحرك يفشل الاختبار (refreeze موثق فقط) |
| Lint | ruff ratchet: يمنع الزيادة، والتخفيضات تُجمَّد |
| CVEs | pip-audit بallowlist موقع + بوابة حاجبة |
| الأسرار | فحص fingerprint-precise بallowlist |
| SAST | bandit عالي الخطورة حاجب |
| SBOM | CycloneDX من البيئة المقفولة في كل CI |
| canary | ليلي مجدول مع evidence |
| CI | خطوتا إضافيتان مدموجتان من v15.2: Playwright Chromium + Build-info honesty |

### 3.5 التشغيل والنشر
- **uv** (248 حزمة مقفولة) / Python 3.12 / `pip install -e ".[dev]"`.
- Docker: `make build/dev-up/prod-up` + وضع **rootless** كامل (0.28.0).
- خادم API: FastAPI (uvicorn) + Celery workers للتوازي + rate governor عابر للحملات.

## 4) أرقام النسخة الحالية (مقاسة، لا مقدرة)

| المقياس | القيمة |
|---|---|
| ملفات المشروع | 4,634 (النسخة الكاملة) / 3,680 (SLIM الإنتاجية) |
| ملفات Python | 2,466 (سليمة نحويًا 2,465 — الاستثناء قالب مقصود) |
| الاختبارات | 7,958 مجمعة (الكاملة) / 7,116 (SLIM) — صفر أخطاء collection |
| حزم وكلاء | 59 حزمة في src/webpent/agents |
| عقد الرسم | 59 في builder.py (+80+ مع المسارات الكاملة) |
| حزم النظام | 60+ حزمة top-level تحت src/webpent |
| تبعيات مقفولة | 248 (uv.lock) |
| بوابات CI حاجبة | 9 (جدول 3.4) |
| docs | 80+ وثيقة هندسية وتشغيلية |

## 5) حالات الاستخدام النموذجية
1. **Bug bounty شخصي:** init → hunt standard → راجع التقرير → أعد إرسال
   retest بعد إصلاح الجهة المستهدفة.
2. **فريق أمن مؤسسي:** Docker rootless + workers متوازية + إشعارات webhook +
   dashboard مراقبة + تقارير بملخص تنفيذي للإدارة.
3. **تدريب وبناء فريق:** dojo (labs + بطولات + تقييم مهارات) على بيئات معزولة.
4. **بحث وتطوير:** EGAIE كمنصة تجارب مقننة + benchmark المحلي + baseline مفروش
   (golden benchmark) لقياس أي تعديل في المحرك.
