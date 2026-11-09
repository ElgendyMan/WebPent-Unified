# تقرير الدمج الشامل — WebPent UNIFIED (كل النسخ في ملف واحد)

> **المهمة:** دمج ملفات المشروع الأربعة (نسخ مختلفة بنفس المشروع) في ملف نهائي واحد
> يحتوي على **كل المميزات والإصلاحات الموجودة في كل النسخ دون فقدان أي محتوى**.
>
> **تاريخ الدمج:** 2026-11-02

---

## 1) النسخ الأربع المدروسة وترتيبها الزمني المؤكد

| # | النسخة (الملف المرفوع) | إصدار `pyproject.toml` | أحدث دليل تاريخي | عدد الاختبارات | الدور في الخط الزمني |
|---|---|---|---|---|---|
| 1 | `webpent_v4_start.zip` | **0.3.0** | تقارير 2026-10-22 | — | نقطة البداية (الأقدم) |
| 2 | `webpent_l10_wip.zip` | **0.12.0** | بوابة L10 (2026-10-30) | — | نسخة عمل وسطى (معالم L7–L10) |
| 3 | `WebPent_v15.2_MERGED_R4_FINAL_20261101.zip` | 0.3.0 (قديم — اسم v15.2 تسمية تسليم فقط) | Phase-2 R4/R6 بتاريخ **2026-11-01** | 3,415 | خط فرعي أقدم معماريًا + دمج R4 |
| 4 | `webpent_ULTIMATE_0.34.0_r2_complete_20261102.zip` | **0.34.0** | نافذة red-team R2 بتاريخ **2026-11-02** | **6,740** | **الأحدث والأكمل — أساس الدمج** |

**الأدلة على الترتيب:** إصدار الحزمة في `pyproject.toml` (0.3.0 → 0.12.0 → 0.34.0)، سجل
`CHANGELOG.md` في نسخة ULTIMATE (145 ألف بايت يوثق نوافذ حتى 0.34.0 بتاريخ 2026-11-02)،
تقارير `reports/canary/CANARY_7X_*_0.34.0` (2026-11-01)، و`BUILD_INFO.json` الذي يقرر صراحة
أن «المرجع SSOT لإصدار الحزمة هو pyproject.toml/CHANGELOG.md» وأن اسم v15.2 مجرد
«تسمية تسليم قديمة» (legacy delivery label) وليس رقم إصدار فعليًا.

**طبيعة العلاقة بين النسخ:** في خطَّي تطور رئيسيان:
- **خط متطور (0.12.0 → 0.34.0):** l10 ← ULTIMATE — أُعيدت فيه هيكلة البروتوتايبات القديمة
  (abhc/abhie/asros/dcvu/goed_v1/…) إلى `archive/pre_v10_prototypes/`، وأضيف الجديد
  (dojo، econ، jc، prism، vip، production، dashboard…).
- **خط فرعي قديم (0.3.0):** v4 ← v15.2 R4 — احتفظ بالبنية القديمة وأضاف عمل R4/R6
  الخاص به (وكيلان جديدان + اختبارات تحصين).

## 2) سياسة الدمج المتبعة

1. **الأساس = ULTIMATE 0.34.0 r2 كاملة بايت-ببايت** (3,781 ملف) — لأنها الأحدث تاريخًا
   والأعلى إصدارًا والأوسع تغطية اختبارًا، واختبارات الـ frozen-manifest (659 ملفًا
   مجمدًا) تعتمد على بقاء هذه الملفات كما هي — وقد حافظ الدمج على تجميدها بالكامل.
2. **اتحاد كامل:** كل ملف لا يوجد في ULTIMATE أُحضر من أحدث نسخة لديه:
   v15.2 R4 ثم l10 ثم v4 — **بنفس مساره الأصلي**.
3. **الملفات المتضاربة** (موجودة في أكثر من نسخة بمحتوى مختلف = 666 ملفًا):
   اعتُمدت نسخة ULTIMATE (الخط الأحدث) — ما لم يكن في نسخة أخرى **إضافة صريحة
   غائبة** عنها، وهذه حُلّت بدمج يدوي على مستوى المحتوى (البند 4).
4. **إلغاء التكرار:** 36 ملفًا من v4 لم تُكرِّر في الجذر لأن محتواها بايت-ببايت
   موجود أصلًا في ULTIMATE ضمن أرشيف `docs/archive/…` (تقارير MERGE_NOTES،
   RED_TEAM_REPORT، ADDITIONS_AND_FIXES…). لا شيء حُذف — المحتوى موجود بالشجرة.
5. **حزم البروتوتايبات القديمة** (17 حزمة: abhc, abhie, asros, dcvu…):
   نسخ ULTIMATE المؤرشفة منها موجودة في `archive/pre_v10_prototypes/`، والنسخ القديمة
   من خط v4/v15.2 أُعيدت إلى مساراتها في `src/webpent/…` (إضافية لا تتعارض مع أي
   استيراد قائم). حزمة `goed_v1` وحدها كانت مطابقة تمامًا للأرشيف فلم تُكرر.

## 3) إحصائيات الدمج

| البند | العدد |
|---|---|
| إجمالي المسارات الفريدة عبر النسخ الأربع | 4,679 |
| ملفات الأساس من ULTIMATE | 3,781 |
| ملفات أُحضرت من **v15.2 R4** | **530** |
| ملفات أُحضرت من **l10 WIP** | **190** |
| ملفات أُحضرت من **v4 start** | **142** |
| ملفات استُبعدت لأنها مكررة حرفيًا (موجودة مؤرشفة) | 36 |
| **إجمالي الملفات في الملف النهائي** | **4,643** |
| تعارضات محسومة لصالح النسخة الأحدث | 666 |
| ملفات Python | 2,466 |
| ملفات بايثون سليمة نحويًا (py_compile) | 2,465 / 2,466 |
| الاستثناء الوحيد | `benchmarks/goed_v1_5/target_template.py` — **قالب بنيوي بمتغيرات `@@…@@` يقصد به عدم صلاحيته نحويًا في النسخ الأربع كلها** (يُولِّد منه ملفات targets)، ليس عيبًا من الدمج |

## 4) الدمج اليدوي على مستوى المحتوى (5 ملفات)

اكتشف الفحص أن نسخة ULTIMATE فيها **مراجع معلّقة** لملفات لا تملكها، وأن v15.2 R4
فيها إضافات غائبة عنها — فعولجت كالتالي:

| الملف | ما أُضيف ومن أي نسخة |
|---|---|
| `Makefile` | هدف `tool-boundary-gate` كامل من **v15.2** + إلحاقه بهدف `ci` — وبذلك تكتمل سلسلة بوابات CI |
| `.github/workflows/ci.yml` | خطوتان من **v15.2**: تثبيت `Playwright Chromium` (اختبارات المتصفح كانت لن تنجح على runner افتراضي) وبوابة `Build-info honesty (P2-205)` — مع الإبقاء الكامل على بوابات ULTIMATE (ruff ratchet، CVE gate، secret scan، bandit SAST، SBOM). لم تُضف خطوات v15.2 لـ `ruff check .` الصارمة صفر-نتائج لأنها ستكسر CI مع آلاف الملفات التاريخية المدموجة — نظام الـ ratchet المتدرج في ULTIMATE هو المعتمد |
| `.gitignore` | أُلحقت قائمة استثناءات `P2-404` من **v15.2** (تنقيط 13 مسار مانيفست/إثبات بـ `!/…`) — تمنع تكرار «فقدان 27 ملفًا أثناء النقل» الموثق في حوادث #2/#3/#4 |
| `.env.example` | 11 مفتاحًا غائبًا من **v15.2** أُضيفت في قسم معلَّم `(legacy)` — منها `ADMIN_PASSWORD`, `BBSCOUT_*`, `JWT_AUDIENCE`, `WEBPENT_GLOBAL_ADMINS` |
| `.env.llm.example` | مفاتيح مزودي LLM من **v4** (OpenRouter/Groq/Cerebras/Gemini/Mistral/Cloudflare/Cohere/ZAI/OLLAMA) — لم تكن كلها في نسخة ULTIMATE |

**إصلاح جانبي مهم حققه الدمج:** Makefile في ULTIMATE كان يشير إلى ملفات غير موجودة
عنده (`src/webpent/labsuite/*`، `src/webpent/egaie/benchmark/*`، `tests/egaie/*`،
`tests/labsuite/*` في هدف lint) — كلها الآن موجودة أُحضرت من l10، فأصبح هدف lint
وكل مراجع CI صالحة.

## 5) أبرز ما أضافته كل نسخة للملف النهائي

**من ULTIMATE 0.34.0 (الأساس — كل المحتوى):**
- حزم `dojo` (تدريب/بطولات)، `econ`، `jc`، `prism`، `vip` (حملات مستقلة)،
  `production` (تحصين 0.27.0–0.33.0: concurrency_governor، cross_process_leases،
  worker_coordination، portfolio_manager…)، `dashboard/workers_page.html`،
  `cli/doctor|ops|retest|unified_hunt`، `state/unified_state.py`،
  `graph/detector_nodes|lesson_nodes|surface_sizing`، `validators/graphql|oauth`،
  `shared/cache_poisoning_detector|prototype_pollution_detector|waf_fingerprints|epss…`
- بوابات الجودة: `check_ruff_ratchet`، `check_deps_gate`، `check_secrets`،
  `install.sh`، `docker-compose.rootless.yml`، `nightly.yml`، تقارير canary حتى 0.34.0
- إصلاحات جولة red-team R2 الموثقة في CHANGELOG (R2-graph-01…04، R2-jc، R2-dojo،
  R2-econ، R2-prism — عشر نتائج حرجة/عالية + 18 متوسطة)

**من v15.2 R4 FINAL (530 ملفًا):**
- وكيلان جديدان كاملان: `agents/cache_poisoning/` و `agents/prototype_pollution/`
  + اختباراتهما
- اختبارات تحصين R4/R6: `test_r4_production_hardening.py`،
  `test_concurrency_governor_isolation.py`، `test_hunter_graph_replan_r6.py`،
  `test_identity_ladder_r6.py`، `test_login_validation_r6.py`
- سكربتات وبوابات: `check_build_info_honesty.py`، `run_pip_audit.sh` +
  `pip_audit_allowlist.txt` + `pip_audit_filter.py`، `production_ready_gate.sh`،
  `check_no_manual_asyncio_run.py`، سكربتات refreeze/regen (R4/R6c/R9a)
- توثيق R4: `PRODUCTION_HARDENING_PLAN_R4.md`، `docs/CLAIMS_VS_REALITY_P2.md`،
  `docs/CLI_DECISION_MATRIX.md`، `docs/VERSIONING.md`
- أرشيف إثباتات التعميم الكامل: `archive/generalization_evidence/` (DVWA،
  WebGoat، Juice Shop، CRAPI) و`archive/deliverables/` (دوسيات M2/M2a/R2/R3)

**من l10 WIP (190 ملفًا):**
- حزم كاملة كانت غائبة عن ULTIMATE (وتُشار إليها في Makefile لديه!):
  `src/webpent/appsuite/` (12 وحدة: berth، consign، docvault، ledgerflow،
  market، permit، requisitions، slots، ticketflow…)، `src/webpent/labsuite/`،
  وملفات `egaie` الأساسية: `assertions.py`، `planner.py`، `prerequisites.py`،
  `workflow_discovery.py` + `egaie/benchmark/` (fixed_prerequisites،
  instrumentation، provenance، strategies)
- اختباراتها: `tests/appsuite/`، `tests/egaie/` (15 ملفًا)،
  `tests/labsuite/`، `tests/test_autonomous_hunt_cli.py`
- سكربتات قياس L7–L10 (`l7_ablation_matrix`، `l8_discovery_matrix`،
  `l9_planner_matrix`، `l10_matrix`، `l10_red_first_probe`، `diag_l10_*`)
- توثيق المعالم: `docs/L7…L10_*`، `AUTONOMOUS_BUG_HUNTER_MASTER_PLAN.md`

**من v4 start (142 ملفًا):**
- وحدات لم يعد لها وجود في الخط المتطور: `oast/` (خادم OAST + correlate)،
  `safety/` (kill_switch، spend_governor، request_ledger، agency…)،
  `scheduler/campaign_scheduler`، `targeting/` (selector + program_brief)،
  `secrets_scanner/`، `waf_evasion/adaptive`، `workflow_fuzzing/` (وكيل + استراتيجيات)،
  `agents/` (dom_xss، graphql_testing، js_discovery، role_matrix،
  sourcemap_analysis، advanced_web_vulns)، `monitor/regression_monitor`،
  `resume/campaign_checkpoints`، `integrations/notifications/` (Slack/Discord/Telegram)،
  `benchmark/` (vulnbox_app، live_runner، scoreboard، metrics_store)
- وحدات مشتركة: `shared/h2_race`، `shared/oob`، `shared/cache_key_discovery`،
  `chained_exploits/graph_v3`، `business_logic/value_fuzzer`،
  `llm_researcher/tiering`، `learning/` (feedback_loop، refutation_ledger،
  technique_library، campaign_dedupe)، `coverage/cell_model+scheduler`،
  `production/` القديمة (validators متقدمة)، `recon/takeover`،
  `reporter/chain_review+evidence_bundle+platform_export`، `tools/js_extractors`،
  `brain/lesson_emission`
- ~45 اختبارًا لتلك الوحدات + تقارير وفهارس الجذر (PROPOSALS_ULTIMATE V1–V4،
  TEAM1/TEAM2 evidence، hashes…)

## 6) ملاحظات تكامل صادقة (مهمة قبل التشغيل)

1. **الشجرة اتحاد كامل ولا تنكسر استيرادات الكود الأساسي:** كل ملفات ULTIMATE
   المجمدة (frozen 659) بايت-ببايت كما هي، وكل الإضافات جديدة المسار لا تلغي شيئًا.
2. **اختبارات v15.2 R4/R6 الـ 5** كُتبت ضد كود خط 0.3.0 وقد لا تنجح كلها ضد كود
   0.34.0 في بعض التفاصيل — هي مضافة كما هي للتوثيق وإعادة الربط لاحقًا.
3. **وحدات v4 القديمة** (oast/safety/scheduler/…) أُعيدت لمساراتها لأنها مميزات طلبها
   الدمج، لكنها لم تعد جزءًا من معمارية 0.34.0 النشطة — بعضها قد يستدعي توقيعات
   وحدات قديمة، فتعامل معها كطبقة legacy متاحة للاستخدام وليست مفعّلة افتراضيًا.
   نسخ ULTIMATE المؤرشفة من البروتوتايبات القديمة موجودة أيضًا في
   `archive/pre_v10_prototypes/`.
4. **قاعدة البيانات** `webpent.db` (72K من v4) أُدرجت كما وردت في المرفوعات.
5. نتيجة `py_compile` للشجرة كلها: **2,465/2,466 سليمة**؛ الاستثناء الوحيد قالب
   `@@ROLES_LIST@@` المقصود (بند 3).
6. لم يُغيَّر إصدار الحزمة (يبقى **0.34.0** في `pyproject.toml/CHANGELOG.md` مرجعًا
   رسميًا لـ SSOT وفق `BUILD_INFO.json`) — هذا الدمج موثق في هذا التقرير بدلًا من
   العبث بسلسلة الإصدارات المجمدة.

## 7) خريطة الحزم الفريدة للتحقق السريع

```
src/webpent/
├── [ULTIMATE 0.34.0]  apex campaign causal_reasoning{,_v2} chained_exploits core
│                        dashboard deep dojo econ egaie evalsuite explorer families
│                        forge graph jc learning multi_step_auth oauth oracle prism
│                        remediation reporting tenant_isolation verification vip …
├── [v15.2 R4]         agents/cache_poisoning  agents/prototype_pollution
├── [v4]               oast  safety  scheduler  targeting  secrets_scanner
│                        waf_evasion  workflow_fuzzing  agents/{dom_xss,graphql_testing,
│                        js_discovery,role_matrix,sourcemap_analysis,advanced_web_vulns}
│                        monitor  resume  benchmark  goed_v1  cqa  asros …
├── [l10]              appsuite  labsuite  egaie/{assertions,planner,prerequisites,
│                        workflow_discovery,benchmark/*}
└── [archive/ULTIMATE]  pre_v10_prototypes/{abhc,abhie,abhip,adi,asros,avde,avrip,
                         avrp,cqa,dcvu,goed_v1,rta,vabh*}
```
