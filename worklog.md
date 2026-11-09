# Worklog — WebPent Roadmap Execution

---

---
Task ID: 12
Agent: main (Z.ai)
Date: 2026-11-05 (جلسة استكمال M1 + M1b)
Task: ولاية التنفيذ الذاتي — استكمال M1-A/M1-C/M1-D (إغلاق M1a) + جوهر M1b (العقود والنماذج) بعد التحقق من حالة UM-DR-10/11 القائمة.

Work Log:
- تأكيد الحالة أولًا (عدم إعادة عمل منجز): M0 منجز (10 مخرجات في download/M0/)؛ M1-B منجز (UM-DR-10، اختباراته خضراء)؛ M1-A منجز لكن **إدخال UM-DR-11 مفقود من السجل** (السكربت يعلنه والدخول غير مكتوب) — كُتب بأثر رجعي بعد إعادة تحقق أولي من الكود والاختبارات.
- بيئة التشغيل: تركيب الاعتماديات المعلنة المفقودة (langchain-core/langgraph+checkpoint-sqlite/bcrypt/esprima/celery/jsbeautifier) → **التجميع صفر أخطاء: 8,223 اختبارًا** (كان 91 خطأ تجميع و7,369).
- M1-C (UM-DR-12): إعلان الأعلام المُشار إليها غير المُعلنة فاشلة مغلقة (enable_oast + عقد OAST الخمسة، enable_causal_chain_candidates، enable_campaign_resume)؛ إصلاح انحدار M-5 الكامن (نقل SSRF الآمن كان يُبطل قاعدة loopback الموثقة — 4 إخفاقات حية) عبر استثناء loopback الموثوق بالنطاق (contextvar، loopback فقط، افتراضي مغلق) في shared/http.py + oob.py + dispatch.py؛ توصيل مرشحات السلاسل السباعية خلف العلم (استشاري حصرًا)؛ سطحا CLI: webpent bounty (معاينة فقط — لا submit بنيويًا) وwebpent portfolio (ترتيب موجات فقط)؛ توصيل E-4؛ ratchet التغطية في Makefile+CI وق5 self-benchmark في nightly. اختبارات جديدة: test_m1c_loopback_trusted_endpoint (7) + test_m1c_cli_surfaces (7) + test_m1c_e4_oauth_wiring (5).
- M1-D (UM-DR-12): حذف 5 ملفات .orig بعد تطابق بايتي مؤرشف؛ أرشفة api/live_stream.py + اختباره إلى archive/superseded_20261105_m1d؛ تشغيل محرك ق9 الموثق — **كشف خلل over-match في المحرك نفسه** (variant الأب كان يدخل مطابقة المساواة: ~190 مستوردًا زائفًا، والمحرك كان يمسح الملف بنفسه)؛ الإصلاح (الاسم الكامل فقط + إكمال الاسم بلا بوابة) مع test_m1d_legacy_disposition_overmatch (7) والطقم المثبت 15/15؛ إعادة التشغيل الأمين: 5 review (فايتة 0.34.2) و4 absorbed بمستوردين حقيقيين؛ **اكتشاف وإصلاح tabs لملف Makefile** (الشجرة العاملة فقدت كل التبويبات — كل أهداف make كانت ميتة) واسترجاعه من git HEAD؛ مزامنة docs/CURRENT_RELEASE.md (0.33.0 العتيق → 0.34.0).
- Refreeze موحد (UM-DR-12): 4 ملفات مجمّدة معلنة (settings.py، shared/http.py، validator/agent.py، cli/commands.py) — scripts/refreeze_manifest_m1c_m1d_wiring_disposition.py، فحص ذاتي ناجح.
- M1b (UM-DR-13): models/contracts.py — كتالوج عقود النطاق (8 كيانات تستورد أصنافها المرجعية، EngagementContract بإلزام client_id+engagement_id — عزل بالبناء)، سجل مصدر الحقيقة لـ9 أنواع بيانات، تصدير متسلسل الإصدار docs/domain_contracts_export.json؛ **إصلاح اتساق الحالة**: 5 قنوات في unified_state.py كانت تُظلّل قنوات PentestState المعلّقة بـmerge reducers (الفقد الصامت لدلالات الدمج في التشغيل الموحد — اكتشفه اختبار التساوي reducer-for-reducer)؛ tests/test_m1b_domain_contracts.py (8: الكتالوج، العزل على المخزن الحقيقي، الاتساق، جسر round-trip). Refreeze: ملف واحد معلن.
- توثيق الإغلاق: docs/engineering/M1_PHASE_REPORT.md (تصرفات 22 نتيجة M0 + 10 اختبارات الانحدار المسماة + البوابات) + docs/engineering/M1b_CONTRACTS_REPORT.md + تحديث CANONICAL_PHASE_REGISTRY (M1a: COMPLETE، M1b: جوهر المعايير محقق والبقايا مسجلة) + إدخال CHANGELOG الموحد.
- بوابات الجلسة: frozen 659/659؛ البوابة المجمّدة + كل أطقم M1: **1,003 نجاح / 2 skip موثق**؛ 8,242 قابلًا للتجميع بلا أخطاء؛ العد 8,242 ≥ 8,115؛ ratchet أخضر 4.27% ≥ 4.07%.

Stage Summary:
- M1a: مكتمل بجميع تصرفاته. M1b: جوهر معايير القبول محقق (عقود موقعة الإصدار + عزل مثبت + اتساق حالة مثبت) والبقايا مسجلة لجلسة قادمة (مصفوفة checkpoint عبر العائلات، توصيل tenant_isolation بالمجرى — عقد M3، ملكية ملفات artifacts).
- الخطوة التالية بالسجل القانوني: إكمال بقايا M1b ثم **M2 — Authorization Manifest + corpora الاختبارات المعادية للنطاق** (كثير من عموده قائم ومتحقق: SSRF pinning في 53 وحدة، ScopeLaw، ToolBoundary، HITL).


---
Task ID: 11
Agent: main (Z.ai)
Date: 2026-10-29 (جلسة سابعة)
Task: "تنفيذ C-9/C-10 (مجدول نافذتي A/B الفعليتين + العتبات الرقمية المعلنة) ثم نفذ ملف docs/PRODUCTION_FIX_PLAN_0270.md" — الجلسة السابقة قُطعت قبل حفظ ملف الخطة؛ أُعيد الـred teaming وتوثيقه ثم نُفذ بنوداه العلويان → 0.27.0.

Work Log:
- استعادة الحقيقة أولًا: ملف الخطة المُشار إليه لم يكن محفوظًا (الجلسة قُطعت) — أعيد الـred teaming المركّز بأدلة file:line وكُتب docs/PRODUCTION_FIX_PLAN_0270.md (C-9/C-10 عاليتي الخطورة مع D-1/D-2/G-1 موثقة خارج النطاق).
- C-9 المجدول (memory/ab_lab.py جديد — memory/ مصدر الحقيقة وفق قرار 6.1/6.2): كل أسبوع ISO لكل (client, target): زوج نافذتين حقيقيتين متتاليتين — control بـENABLE_LESSON_CONSULTATION=false على مستوى العملية ثم treatment بالافتراضي. SQLite إضافي (ab_weeks/ab_runs) بحالة موثقة وفتح idempotent fail-closed. tick ينفذ نافذة مستحقة واحدة كحد أقصى، وبلا runner خطة جافة صادقة. الأسبوع العالق عند حد الأسبوع يكمل (أقدم أسبوع غير منتهٍ).
- صدق المقاييس (العقد المعلن): runner قابل للحقن → metrics_lookup لمعمارية الخدمة (يقرأ ImprovementTracker الذي تكتبه facade.complete) → record_run_metrics صريح → وإلا metrics_missing والحكم inconclusive بسببه. لا أرقام مخترعة. runner الإنتاج: make_hunt_subprocess_runner (webpent hunt حقيقي ببيئة مفرّطة لكل ذراع).
- C-10 العتبات المعلنة (AB_THRESHOLDS مجمّدة): min_tested_per_arm=10، promotion=+0.10، regression=-0.20، require_no_confirmed_loss=True (فقدان أي مؤكد يُسقط الحكم)، max_inconclusive_weeks=4 (paused_advisory توصية). evaluate_ab_pair دالة نقية بمفاضلة كسرية دقيقة (Fraction) فلا تنقلب الحدود المعلنة بخطأ الفواصل العائمة — عللة حقيقية التُقطت بالاختبارات (1-9/10 = 0.0999…).
- CLI: webpent ops learning-ab open|tick|status|record-metrics — الكتابة خلف run_campaign المجمدة، status يعرض العتبات المعلنة نفسها.
- بروتوكول النافذة المجمدة: refreeze 0.27.0 (659 = 658 + ab_lab.py scope completion؛ ops.py يركب عضويته القائمة)؛ AB_LAB_20261029_* في بوابة المجمدة؛ regen متعمد لجرد I/O المباشر (815→817: هويتا subprocess للقاذف — نفس عائلة verdict_bridge المثبتة؛ pin 31→33 سجلًا / 25→27 هوية موثقًا).
- بيئة الجلسة: فقدت langgraph/celery/bcrypt/filetype وتثبيت الحزمة نفسها — أُعيدت وفق uv.lock/المثبتات (langgraph 1.2.10 وlangchain-core 1.6.7 بالتثبيت المقفول بعد أن كسر 1.2.18 اختبار تركيب S2 عبر filetype غير محتسبة).
- علل مُصلحة أثناء البناء: تقييم مبكر لأسبوع قبل اكتمال الذراعين (بوابة terminal الاثنين)، فقدان جدول بذاكرة :memory: عبر اتصالات لكل-عملية (اتصال مشترك دائم)، ومسار فشل الrunner كان يعود قبل التقييم النهائي.
- اختبارات: +38 (test_ab_lab.py). السويت الكامل 6747 أخضر/0 فاشل. canary 7x STABLE (855×8، توقيع الدخان مطابق) — الأدلة reports/canary/CANARY_7X_20261029_0.27.0.*. ruff: الملفات الجديدة نظيفة والratchet مجمّد 6250 بالضبط. pyproject/`__init__`/BUILD_INFO/CURRENT_RELEASE → 0.27.0. DRIFT_REGISTER: DR-016.

Stage Summary:
- 0.27.0: المسار 6.5 صار حلقة تعلم أسبوعية فعلية: نافذتان حقيقيتان (control بلا دروس vs treatment بالدروس) على نفس الهدف، مقاييس صادقة بمصادر معلنة، وحكم رقمي حتمي بعتبات معلنة قابلة للتدقيق — بلا أي تغيير على نتائج الأمان أو مسارات الحملات (كله إضافي/اختياري).
- المتبقي معلنًا في ملف الخطة: D-1 وضع rootless موثق للحاوية + تحقق سقوط الصلاحيات في entrypoint، D-2 تحذير credentials_template.json التوثيقي، G-1 حذف brain/lessons.py المتقاعد بنافذة إعلان خاصة.
---
Task ID: 10
Agent: main (Z.ai)
Date: 2026-10-29 (جلسة سادسة)
Task: "فيه اجزاء من ملف ال md ده ماتنفذتش شوف اية اللي ماتنفذش وفاضل ونفذه" — تدقيق مستقل لكل مسارات الخارطة الموحدة ضد الشجرة 0.25.0، ثم تنفيذ كل الفجوات المتبقية → 0.26.0.

Work Log:
- تدقيق أولًا: 4 وكلاء استكشاف متوازيون راجعوا المسارات 0-12 بندًا بندًا (DONE/PARTIAL/MISSING بأدلة file:line). النتيجة: 11/12 مغطاة تنفيذيًا من 0.14.0→0.25.0، والفجوات الحقيقية في: بوابات CI (report-only/مفقودة)، doctor غير موجود رغم 4 مراجع معلقة، مخرجات بلا وقت/تكلفة/قوالب منصات، معاير بلا كتابة ولا قراءة، EPSS/فرز بصري/جوال غائبة، سجلات تشغيل ميتة، وجذر يحمل ~95 أثرًا تاريخيًا.
- بوابة CI حاجبة: ruff ratchet (baseline 7278→6289 بعد إغلاق الجذر، التحسّن مُجمّد)، CVE allowlist gate (البذرة فارغة — لوك langgraph 1.x نظيف 0 ثغرات)، فحص أسرار حتمي بلا طباعة قيم (allowlist ببصمة القيمة — أي قيمة جديدة تُكتشف)، bandit/SBOM/تغطية (أرضية 72% مقاسة على 6698 اختبار)/canary ليلي مجدول.
- webpent doctor (cli/doctor.py جديد): DB عبر المدير القياسي + LLM عبر _check_llm_providers نفسها + 6 أدوات خارجية + معرفة + playwright؛ exit 0/1/2؛ أصلحت المراجع المعلقة الأربعة. وinstall.sh: توقيع llm-keys add كان مستحيل النجاح — صار يكتب .env (0600) ويسجل مرجع env-var الصحيح.
- هوية الإصدار: __version__ عالق "0.14.0" عبر 11 إصدارًا (اكتشاف أثناء إصلاح بوابة packaging الأحفورية) → 0.26.0؛ BUILD_INFO (v15.2) وCURRENT_RELEASE (0.3.0) مواءمان؛ بوابة packaging صارت عقدًا ديناميكيًا.
- مخرجات: تقدم حي بوقت مقاس وسقوف معلنة وعدادات tokens حقيقية (بلا دولار مخترع — unpriced بحكم التصميم)؛ HTML exec summary ببلوك metadata + human_review_decision؛ H1/Bugcrowd قوالب عبر reports --platform (P1..P5 بتحويل CVSS موثق، الهدف من أول خطوة إعادة مغلقة).
- تعلم: قرار مصدر الحقيقة موثق (memory/ vs brain/ — brain/lessons.py متقاعد، إعفاء hunt-auto موثق) في docs/learning_source_of_truth.md؛ المعاير موصول: ops review decide --calibration-store يكتب (fail-open)، ops calibration --candidates يستهلك calibrated_order.
- تغطية/ميزات: EPSS (كتالوج محقن + إثراء + فرز KEV→EPSS→conf، بلا كتالوج = الترتيب القديم حرفيًا)؛ mobile_app_indicators (ZIP فقط، تصنيف نطاق، أسرار بصِم)؛ asset_triage (بوابة ScopeEnforcer قبل أي بايت، التقاط محقون، احتياز dry-run)؛ CEM→notifications bridge (critical/signal-high فقط، redact، idempotent)؛ JsonLogFormatter (WEBPENT_LOG_FORMAT=json كان ميتًا)؛ حلقة stalled-worker اختيارية في app.py؛ docs/workers_ops_runbook.md.
- إغلاق الجذر: 78 ملفًا → docs/archive/2026-10-28-root-artifacts/ بفهرس + goed_v1_8* (5 مجلدات، 9,515 سطرًا) → docs/archive/2026-10-28-goed-v1.8-root-dirs/؛ كل نقل بعد فحص مراجع آلي (11 ملفًا محجوزًا بمرجع نشط، موثقة في الفهرس)؛ الخارطة الموحدة أُدرجت في docs/ + README.
- بوابة المجمدة: نافذة RESIDUAL CLOSURE 2026-10-29 — refreeze بـ scripts/refreeze_manifest_0260_residual_closure.py (658 = 653 + 5 scope-completion جديدة)؛ مجموعتا النافذة في بوابة الاختبار (7 ملفات thaw + 5 scope completions، كلها موثقة بسببه).
- إصلاح 3 أحافير اختبارات كانت فاشلة سلفًا في 0.25.0 (packaging pins 0.14.0، عدّ العقد 55/57 قبل dedup_gate، وadvisory vocabulary الadapter) — موثقة داخل كل اختبار.
- اختبارات: +63. ruff نظيف على الملفات المنشأة بالكامل (الموروث داخل الملفات المعدلة تحت الratchet بلا زيادة). السوت الكامل بالأدلة: 6708 أخضر/0 فاشل + تغطية 72.72% (الأرضية 72 مفروضة داخل run_tests_with_evidence). canary 7x STABLE 854×8. ruff ratchet مجمّد 6250. pyproject 0.26.0. حزمة: download/webpent_ULTIMATE_0.26.0_residual_closure_20261029.zip.

Stage Summary:
- 0.26.0: خارطة الطريق الموحدة — كل بنودها القابلة للتنفيذ البرمجي المنفيذة، وبوابات الإصدار صارت حاجبة فعلًا (ratchet/CVE/secrets/SAST/SBOM/coverage/canary)، والهوية الإصدارية موحدة، والجذر نظيف.
- المتبقي معلنًا (خارج نطاق الكود أو نافذة لاحقة): A/B ظلّي لأثر الدروس (6.5 — يوجد schema فقط)، تعزيز bandit إلى قوائم ثانوية، ترقية المستودع إلى Git نظيف برُؤوس سجل، وتصعيد التغطية تدريجيًا فوق 72%.

---
---
Task ID: 9
Agent: main (Z.ai)
Date: 2026-10-28 (جلسة خامسة)
Task: "خش ياحبييييييب" — متابعة "خلصهم كلهم": الخطوة التالية الموثقة من 0.24.0 → 0.25.0 (توصيل WorkerCoordinator بـ MultiCampaignService + أوامر كتابة خلف RBAC).

Work Log:
- تحقق صحة أولاً: بيئة الجلسة فقدت langgraph (81 خطأ جمع في الـ suite الكامل) → تثبيت langgraph + langgraph-checkpoint-sqlite؛ وفقدت frozen_modules.sha256 (كانت تعيش في شجرة العمل فقط، غير مرفوعة في أي commit) → استرجاع حرفي من حزمة 0.24.0 في download/ (651 مدخلًا) → البوابة 653 أخضر ومجموعة الانحدار 847 أخضر قبل أي تعديل.
- 12.3 تشغيليًا: campaign_worker_claims.py — CampaignWorkerClaims (ادعاء على مستوى الحملة طوال عمرها RUNNING؛ scope_hash محتكم من (client,target)؛ إسقاط النتائج: BUSY/SCOPE_CONFLICT رفض fail-closed، DENIED_ERROR فشل مفتوح موسوم، الإنجازات محتفظة). ربط facade.py: ادعاء بعد تذكرة governor في start (رفض يحرر التذكرة)، تحرير مضمون في halt/complete/فشل start، الافتراضي المعطل سلوك مطابق حرفيًا (اختبار يؤكد عدم إنشاء مجلد التنسيق). إعدادان: worker_coordination_enabled (false) + worker_coordination_dir — نمط backend الاختياري نفسه؛ فشل البناء → None.
- كتابة خلف RBAC: ops_state.py — حالة JSON دائمة (0600، كتابة ذرية) + تدقيق JSONL إلحاقي؛ إعادة بناء عبر واجهات عامة فقط (المحرك يعيد فرض قواعده أثناء الاسترجاع: صوت/محلل، N موافقات، كابس الصرف)؛ حالة مزورة أو متجاوزة للكابس تُرفض fail-closed. أوامر ops: users bootstrap-admin|grant (admin فقط، تمهيد فقط والسجل فارغ)، review enqueue|claim|decide|pending، portfolio register|admit|spend|status (lead/admin بامتداد موثق PORTFOLIO_WRITE_ROLES — المصفوفة المجمدة لم تُمَس). عللة أصلحت أثناء الاختبار: enqueue بدون --item كان يخزن id فارغًا → توليد rev-<hex> تلقائي.
- عللة كامنة جوهرية أصلحت (من نافذة 0.18.0): محدد التزامن عملية-عالمية كان يتسرب بين الاختبارات — test_multi_campaign_service كان يفشل منفردًا منذ 0.18.0 (حملة RUNNING تلتهم slots اختبار تالٍ) ولم يُلتقط لأن مجموعة الـcanary لا تضمه → autouse fixture بالـ reset_concurrency_governor() الموجود سلفًا.
- بوابة المجمدة: نافذة OPS WRITE + WORKER CLAIMS 2026-10-28 — إعادة تثبيت manifest بـ scripts/refreeze_manifest_0250_ops_write.py (653 مدخلًا، نفس المسارات والترتيب + ملفان جددا scope-completion)؛ توثيق OPS_WRITE_20261028_SCOPE_COMPLETION_PATHS في اختبار البوابة.
- نظافة ruff على نطاق النافذة كاملة: الأربعة والثلاثون الوراثية داخل الملفات المعدلة نفسها أصلحت (E501/B008/I001/UP035/SIM105/C401/SIM300/F401) + استثناء B008 الموثق لـ cli/ops.py في per-file-ignores (نمط Typer التصريحي؛ commands.py يتجنبه بأسلوب Annotated). ruff: All checks passed.
- اختبارات: +53 جديدة. بوابة 655 أخضر، الانحدار مع الجديد 900 أخضر، canary 7x STABLE (849×8، توقيع دخان مطابق). pyproject 0.25.0. Commit: هذا الإصدار. حزمة: download/webpent_ULTIMATE_0.25.0_worker_claims_rbac_writes_20261028.zip.

Stage Summary:
- 0.25.0: البند 12.3 صار تشغيليًا في طبقة الخدمة (لا وحدة معزولة) + سطح كتابة محدود خلف RBAC بحالة دائمة وتدقيق. خارطة الطريق الموحدة: منفذة وموصولة، والإثباتات خضراء (900 + canary STABLE 7/7).
- الخطوات التالية المقترحة: ربط opsb بالحالة الفعلية للحملات (ops portfolio admit يستهلك من manager.plan فعليًا عند طلب المشغل)، أو SSO seam حقيقي عبر مهايئ IdP خارجي، أو تثبيت نشر (Docker غير-root + أسرار خارجية) وفق المسار 3.

---
Task ID: 8
Agent: main (Z.ai)
Date: 2026-10-28 (جلسة رابعة)
Task: "ابدأ التنفيذ" — بندا الخطوة التالية: canary 7x وفق DoD + ربط Track 12 بCLI عبر النافذة المجمدة → 0.24.0.

Work Log:
- Canary: scripts/canary_7x_20261028.py — كل تشغيل = 847 اختبار انحدار + دخان مختبري وظيفي حتمي (محرك→عمال→خطة→محفظة→OOB→معايرة). معيار الاستقرار: أخضر + نفس العدد + توقيع دخان مطابق للbaseline. عللتان أثناء البناء: ترتيب خطوة سقف المحفظة (سقف الحملة يسبق سقف العميل) ومقارنات enum. النتيجة: STABLE 7/7 + ruff نظيف. أدلة: reports/canary/.
- CLI: cli/ops.py جديد (ops governor/workers/graph/calibration/protection — قراءة فقط) + دلتا سطرين في commands.py (نمط نافذة retest). عللة أصلحت: استيراد داخل حلقة → UnboundLocalError عندما تكون قائمة الفئات فارغة. بروتوكول النافذة: إعادة تثبيت manifest (651) + تثبيت ops.py كـCLI_OPS_20261028 scope-completion + دلتا commands.py داخل مجموعة thaw الموثقة.
- اختبارات: +15 CLI. بوابة المجمدة 653 أخضر. canary 847×8 (baseline+7) أخضر.
- Commit c75e90b. حزمة: download/webpent_ULTIMATE_0.24.0_dod_canary_cli_ops_20261028.zip.

Stage Summary:
- 0.24.0: خارطة الطريق الموحدة منفذة + مثبتة canary 7x + مكشوفة تشغيليًا عبر CLI قراءة-فقط.
- الخطوات التالية المقترحة: أوامر كتابة محدودة (portfolio admit / review queue) خلف RBAC عند طلب المشغل، أو توصيل WorkerCoordinator بMultiCampaignService (نفس نمط دمج المحرك 0.18.0).
---
Task ID: 7
Agent: main (Z.ai)
Date: 2026-10-28 (جلسة ثالثة — تكملة)
Task: بند 12.9 التشغيل المؤسسي → 0.23.0 — إغلاق المسار 12 وخارطة الطريق الموحدة كاملة.

Work Log:
- enterprise_operations.py — RBAC مصفوفة مجمّدة fail-closed، SSO seam (لا عميل شبكي، سقوط آمن إلى viewer)، عزل مساحات بالعضوية الصريحة، طابور مراجعة بقاعدة N موافقات مميزة، احتفاظ dry-run افتراضي، تصدير تدقيق لعميل واحد.
- اختبارات: +17. ruff نظيف. Commit f689de3. حزمة 0.23.0.

Stage Summary:
- المسار 12 مكتمل (1-9). المسار 11 مكتمل (1-8). خارطة الطريق الموحدة: كل بنودها القابلة للتنفيذ البرمجي منفذة عبر 0.14.0 → 0.23.0.
- الخطوات التالية المقترحة للمشغل (خارج نطاق الكود): تفعيل تدريجي بالإعدادات، ربط الوحدات الجديدة بواجهات CLI/API القائمة، وتشغيل canary مختبري 7x وفق Definition of Done.
---
Task ID: 6
Agent: main (Z.ai)
Date: 2026-10-28 (جلسة ثالثة — تكملة)
Task: بندا المسار 12 (5) منطق الأعمال و(7) OOB → 0.22.0.

Work Log:
- 12.5: business_logic_workflows.py — نماذج تصريحة، حدود محافظة مفروضة (12 خطوة، أفعال ممنوعة، بيئة+تفويض)، مراجعة بشرية مرتبطة بdigest الخطة.
- 12.7: oob_verification.py — بوابة تفعيل صلبة (سيطرة مستخدم+موافقة+نطاق)، رموز تفاعل حتمية، ائتمان محدود بالنطاق، دفتر JSONL.
- اختبارات: +19. ruff نظيف.

Stage Summary:
- المسار 12: 1✅ 2✅ 3✅ 4✅ 5✅ 6✅ 7✅ 8✅ — بقي 9 المؤسسي فقط → 0.23.0.
---
Task ID: 5
Agent: main (Z.ai)
Date: 2026-10-28 (جلسة ثالثة — تكملة)
Task: بندا المسار 12 (1) إدارة المحفظة و(8) التعلم المعاير → 0.21.0.

Work Log:
- 12.1: portfolio_manager.py — ترتيب EV حتمي + موازنة موحدة (إجمالي/عميل/حملة)، قبول وتسجيل مصاريف fail-closed، سجل تدقيق.
- 12.8: confidence_calibration.py — مضاعفات محدودة [0.5,2.0] من قرارات بشرية، تجميعات فقط (لا حقول بيانات خام في النوع)، عزل عملاء بالبناء، Laplace + مزج محايد، إعادة ترتيب فقط لا تعديل ثقة.
- اختبارات: +24. ruff نظيف. Commit a99dad3. حزمة 0.21.0.

Stage Summary:
- المسار 12: 1✅ 2✅ 3✅ 4✅ 6✅ 8✅ — المتبقي: 5 (منطق الأعمال) + 7 (OOB) → 0.22.0، ثم 9 المؤسسي → 0.23.0.
---
Task ID: 4
Agent: main (Z.ai)
Date: 2026-10-28 (جلسة ثالثة — تكملة)
Task: بندا المسار 12 (4) رسم علاقات النتائج و(6) سياسة ضوابط الحماية → 0.20.0.

Work Log:
- 12.4: finding_relation_graph.py — مُركّب حتمي redaction-first (asset/finding/evidence-hash/impact + علاقات معلنة فقط)، عارض HTML مكتفٍ ذاتيًا بلا شبكة + مُصدّرا JSON/DOT. عللة أمنية حقيقية أصلحت: JSON مضمن في <script> بالنص الخام (كسر </script>) → تأمين \u003c.
- 12.6: protection_controls.py — كشف حتمي (waf_block/rate_limit/challenge/backend_throttle) + سياسة توقف/مراجعة، تراجع مؤدب بحد أقصى، تصعيد عند التكرار، FORBIDDEN_EVASIONS مثبتة، سجل تدقيق JSONL.
- اختبارات: +29. ruff نظيف. Commit 3a6ad0b. حزمة 0.20.0.

Stage Summary:
- المسار 12: 2✅ 3✅ 4✅ 6✅ — المتبقي: 1 (المحفظة) + 8 (التعلم المعاير) → 0.21.0، ثم 5+7 → 0.22.0، ثم 9 المؤسسي → 0.23.0.
# Worklog — WebPent Roadmap Execution

---
Task ID: 3
Agent: main (Z.ai)
Date: 2026-10-28 (جلسة ثالثة)
Task: "خلصهم كلهم بالترتيب المناسب / كمل من version 18" — إكمال بقية المسار 12 من v0.18.0.

Work Log:
- تأكيد الحالة: الورشة عند 0.18.0 (commit 8cb36ca نظيف). المسار 11 مكتمل (1-8)؛ المسار 12 عند بند 2 طور 1. الترتيب المنفذ: (2 ط2 + 3) → 0.19.0، ثم (4 + 6) → 0.20.0، (1 + 8) → 0.21.0، (5 + 7) → 0.22.0، (9) → 0.23.0.
- 12.2 طور 2: cross_process_leases.py — FileLeaseBackend (flock سلوتس مشتركة، أمان انهيار نواة، all-or-nothing بترتيب ثابت، إعادة اقتراع للنادل المحجوب بالعقود فقط مع حفظ رأس FIFO، fail-open). دمج خلف نفس الواجهة (lease_backend seam) في try_acquire/acquire/release/_promote_waiters/snapshot. عللتان أصلحتا أثناء التطوير: (1) الحلقة الأولى كانت تحجز كل ملفات السلوتس بدل واحد لكل بُعد، (2) بلع أخطاء الفحص الداخلي كان يكسر عقد fail-open — أُعيد إتاحتها للانتشار.
- 12.3: worker_coordination.py — WorkerCoordinator: سجل مطالبات flock ذري (ACQUIRED/RENEWED/TAKEOVER بعد TTL/SCOPE_CONFLICT لا يُستولى أبدًا)، بصمات O_EXCL عبر-العمال، سجل تغييرات JSONL، عزل عميل بالبناء، فشل السجل لا يمنع الإبلاغ. عللة: فشل mkdir كان يُRaise خارج حارس fail-safe — لُفّ.
- بوابة المجمد: إعادة تثبيت manifest (650) + مجموعة thaw موثقة لfacade.py (652 اختبار أخضر).
- اختبارات: +48 جديدة (بينها إثبات عبر-عمليات SIGKILL حقيقي). ruff نظيف. الإجمالي مع الجلسات: 153.
- توثيق: CHANGELOG 0.19.0، pyproject 0.19.0. Commit 2d95548. حزمة: download/webpent_ULTIMATE_0.19.0_track12_leases_coordination_20261028.zip.

Stage Summary:
- الإصدار الحالي: 0.19.0 — المسار 12: البندان 2 (كامل) و3 (كامل).
- الخطوة التالية: بند 4 (رسم علاقات النتائج) + بند 6 (سياسة ضوابط الحماية) → 0.20.0.
