# خطة تنفيذ THE ECONOMIST CHARTER (NC-ECON-1) — Economic Brain v1

التاريخ: 2026-10-16. الأساس: v83.1 (0.8.1، 2567 اختبار).
المصدر الملزم: NC-ECON-1 (charter المُسلّم من المشغّل) — يُنفَّذ بحذافيره.
القوانين الحاكمة L-1..L-8 مطبقة حرفيًا (advisory-only، صفر network من الـ core،
deterministic، transparency، preamble+DoD، suite monotic، deferrals مُرقّمة، human-in-the-loop).

## الخريطة

| الموجة | الوحدات | ملفات |
|---|---|---|
| 1 | U-ECON-1..3 | econ/{__init__,market_kb,target_scorer,scope_negotiator}.py + config/econ/{programs,payout_curves}.yaml + tests/econ/{test_market_kb,test_target_scorer,test_scope_negotiator}.py + docs/econ/{README,schema}.md |
| 2 | U-ECON-4..6 | econ/{roi_optimizer,timing_advisor,budget_mapper}.py + config/econ/roi_params.yaml + 3 ملفات اختبار + docs/econ/decision_matrix.md |
| 3 | U-ECON-7..9 | econ/{competitive,saturation,blind_spots}.py + config/econ/competition_params.yaml + 3 ملفات اختبار + download/econ/competitive.db |
| 4 | U-ECON-10..12 | econ/{portfolio,learning_loop,dashboard}.py + cli/econ.py + config/econ/portfolio.yaml + test_{portfolio,learning_loop,dashboard}.py + download/econ/{RUNNING_LOG.md,ingest_log.jsonl,audit.jsonl} |

## المهام (بترتيب التنفيذ)

### Task 1 — U-ECON-1 MarketKB
Files: src/webpent/econ/__init__.py، src/webpent/econ/market_kb.py، config/econ/programs.yaml، config/econ/payout_curves.yaml، tests/econ/test_market_kb.py، docs/econ/schema.md
1. الاختبارات الستة المسمّاة في الcharter (load schema، payout range، unknown program، dry-run، untrusted source، append-only log).
2. التنفيذ: MarketKB + Program/PayoutRange/ResponseStats/IngestReport + Target مشتركة؛
   ingest_snapshot(dry_run=True default) يقرأ snapshots محلية فقط، يرفض مصادر غير موثقة، يسجّل كل fetch في download/econ/ingest_log.jsonl (append-only)، redact() على كل ما يُخزَّن.
3. programs.yaml: ≥10 برامج بيانات عامة موثقة المصدر.

### Task 2 — U-ECON-2 TargetScorer
Files: src/webpent/econ/target_scorer.py، tests/econ/test_target_scorer.py
1. Formula charter §U-ECON-2 موثقة docstring + جدول components؛ score deterministic، clamped 0-100، tiers S/A/B/C/D.
2. الاختبارات الستة المسمّاة.

### Task 3 — U-ECON-3 ScopeNegotiator
Files: src/webpent/econ/scope_negotiator.py، tests/econ/test_scope_negotiator.py
1. Parser YAML/JSON/markdown؛ ambiguity ≥3 أنماط؛ gray zones؛ generate_inquiry template (لا إرسال)؛
   اختبار zero-network بmock socket.
2. الاختبارات الخمسة المسمّاة.

### Task 4 — U-ECON-4 ROIOptimizer
Files: src/webpent/econ/roi_optimizer.py، config/econ/roi_params.yaml، tests/econ/test_roi_optimizer.py
1. EV(f) formula كما في الcharter حرفيًا؛ FindingValuation {ev_usd, ev_range, recommendation, components, confidence, rationale}؛
   batch_value == value لكل عنصر.
2. الاختبارات الستة المسمّاة.

### Task 5 — U-ECON-5 TimingAdvisor ⭐
Files: src/webpent/econ/timing_advisor.py، docs/econ/decision_matrix.md، tests/econ/test_timing_advisor.py
1. matrix السيناريوهات الستة (REPORT_NOW/REPORT_SOON/IMPROVE_FIRST/COLLECT_MORE/HOLD/DEFER) بقواعد موثقة + deadline + prerequisites.
2. الاختبارات الستة المسمّاة.

### Task 6 — U-ECON-6 BudgetMapper
Files: src/webpent/econ/budget_mapper.py، tests/econ/test_budget_mapper.py
1. EV/hour → INTENSIVE 60% / ROUTINE 30% / DORMANT 10%؛ مجموع الساعات = المدخل دائمًا.
2. الاختبارات الخمسة المسمّاة.

### Task 7 — U-ECON-7 CompetitiveRadar
Files: src/webpent/econ/competitive.py، config/econ/competition_params.yaml، download/econ/competitive.db، tests/econ/test_competitive.py
1. SQLite محلي فقط؛ PublicFinding بلا أي PII؛ ingest(source, dry_run=True) يقرأ snapshots محلية من مصادر موثقة فقط؛
   find_opportunities = vuln classes في الscope بلا findings عامة آخر N يوم.
2. الاختبارات الستة المسمّاة (منها no-PII schema audit وdb-local-only).

### Task 8 — U-ECON-8 SaturationEstimator
Files: src/webpent/econ/saturation.py، tests/econ/test_saturation.py
1. Formula 0.5/0.3/0.2 × 100؛ tiers LOW/MEDIUM/HIGH/SATURATED؛ بيانات ناقصة → insufficient_signal.
2. الاختبارات الخمسة المسمّاة.

### Task 9 — U-ECON-9 BlindSpotLocator ⭐⭐
Files: src/webpent/econ/blind_spots.py، tests/econ/test_blind_spots.py
1. Cross-reference (radar findings × scope entries × vuln registry) → path_region/vuln_class/subdomain؛
   rank بـestimated_ev؛ deterministic ordering؛ confidence يعكس حجم البيانات.
2. الاختبارات الستة المسمّاة.

### Task 10 — U-ECON-10 PortfolioManager
Files: src/webpent/econ/portfolio.py، config/econ/portfolio.yaml، tests/econ/test_portfolio.py
1. State machine (ACTIVE/WATCHING/DORMANT/ARCHIVED) بجدول transitions المسموح فيه فقط؛
   load/transition/auto_transition/daily_plan؛ كل transition معاه reason ويُسجَّل.
2. الاختبارات الستة المسمّاة؛ portfolio.yaml فيه ≥20 target (بوابة DoD #7).

### Task 11 — U-ECON-11 LearningLoop ⭐
Files: src/webpent/econ/learning_loop.py، tests/econ/test_learning_loop.py
1. أربعة تحليلات (class_focus/program_focus/timing_adjust/dup_pattern) بعتبة 10 data points؛
   apply_to_scheduler يرجع SchedulerDelta advisory-only (لا تعديل مباشر)؛ insights تُسجَّل.
2. الاختبارات الستة المسمّاة.

### Task 12 — U-ECON-12 Dashboard + CLI
Files: src/webpent/econ/dashboard.py، src/webpent/cli/econ.py، tests/econ/test_dashboard.py، download/econ/{RUNNING_LOG.md,audit.jsonl}
1. digest بصيغتي md/json (محفظة، top/bottom 5، pipeline، earnings projection، alerts)؛
   CLI: econ targets list/score، findings value/timing، portfolio plan/transition، digest، insights، blind-spots، opportunities؛
   كل استدعاء يُدوَّن في download/econ/audit.jsonl؛ تسجيل econ_app في cli/commands.py.
2. الاختبارات الستة المسمّاة.

### Task 13 — البوابة النهائية
1. pytest tests/ -q كاملًا (عدد متصاعد عن 2567).
2. ruff نظيف على كل ملف جديد.
3. جرد direct-IO سليم (إعادة توليد لو المصادر تحركت).
4. بوابات §4 الخمسة عشر يُتحقق منها سطرًا بسطر مع evidence.
5. CHANGELOG + README + traceability + version 0.8.2، إعادة بناء الزيب والتحقق من محتواه، التسليم بـ"تمام خلصت".

## سجل التنفيذ

(يُملأ أثناء التنفيذ مع الدليل لكل وحدة.)
