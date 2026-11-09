# WebPent → Autonomous Bug Hunter — Master Plan

**Date:** 2026-10-12
**Scope:** تحويل WebPent من "مشروع تحت الإنشاء" إلى **Autonomous Bug Hunter** حقيقي، مع الحفاظ على كل الضوابط الأمنية القائمة.
**Constraint:** لا يُخفَّض أي gate أمني (scope / auth / rate-limit / SSRF / evidence) لزيادة recall. كل ترقية إما additive أو fail-closed.

---

## 0. الوضع الحقيقي بعد الفحص (Baseline Truth)

| البند | الحالة الفعلية المقيسة |
|---|---|
| حجم المشروع | 2468 ملف، 1125 ملف Python، 240 ملف اختبار |
| الـtests | **2123 مُجمَّعة، 2114 ناجحة، 9 فاشلة** (فشل ترتيب/بيئة، ليست عيوب منطقية) |
| البيئة | langgraph / langchain / fastapi / pydantic / chromadb / celery / typer — كلها تعمل بعد التثبيت |
| المحرك الأساسي | `goed_v1` + `cqa_v2` + `smart` يعملان بدون langgraph |
| AutonomousController | موجود (`shared/autonomous_controller.py`) — bounded loop، لكن **غير موصول بمسار تنفيذ حقيقي end-to-end** |
| CQA v2 Autonomous Loop | موجود (`cqa_v2/autonomous_loop.py`) — pattern library ثابتة، **offline fixtures فقط** |
| Smart Campaigns | موجود (2165 سطر) — planning + execution، مربوط بالـgraph |
| Hunter Runner | موجود (514 سطر) — live bounded campaign orchestration |
| الفجوة الجوهرية | المكوّنات موجودة **لكنها جزر منفصلة**؛ لا يوجد **حلقة اكتشاف مستقلة واحدة** تبدأ من target وتنتهي بـProofBundle مؤكد بدون تدخل بشري لكل خطوة |

**التصنيف الصادق الحالي:** `Autonomous Candidate / Early Beta` — وليس Autonomous Bug Hunter كامل.

---

## 1. تعريف "Autonomous Bug Hunter" (معيار القبول النهائي)

النظام يصبح Autonomous Bug Hunter عندما يحقق **الستة** معًا:

1. **Self-directed loop** — يبدأ من target واحد، يولّد hypotheses، يختار الأفضل، ينفّذ، يتعلّم، ويكرر — بدون تدخل بشري بين الخطوات.
2. **Real execution path** — الـloop ينفّذ HTTP حقيقي عبر ActionExecutor المُصرَّح، لا fixtures.
3. **Evidence-first promotion** — لا Finding مؤكد بدون ProofBundle مختوم + negative control.
4. **Bounded & fail-closed** — budget، idempotency، stop conditions، وكل فشل capability يصبح typed blocker لا "clean".
5. **Learning that changes behavior** — الذاكرة تغيّر ترتيب الـhypotheses فعليًا (قابل للإثبات offline).
6. **One command** — `python main.py hunt --url ... --mode authorized-active` يشغّل كل ذلك.

---

## 2. المعمارية المستهدفة

```
                    ┌─────────────────────────────────────────┐
                    │        AUTONOMOUS HUNT ORCHESTRATOR      │
                    │  (حلقة واحدة: plan→act→observe→learn)    │
                    └─────────────────────────────────────────┘
                                       │
        ┌──────────────┬───────────────┼───────────────┬──────────────┐
        ▼              ▼               ▼               ▼              ▼
   ┌─────────┐   ┌──────────┐   ┌───────────┐   ┌───────────┐  ┌──────────┐
   │ RECON   │   │ HYPOTHESIS│  │  ACTION   │   │  EVIDENCE │  │ LEARNING │
   │ (surface│   │  ENGINE   │  │ EXECUTOR  │   │  + PROOF  │  │  MEMORY  │
   │  graph) │   │ (ranked)  │  │ (bounded) │   │ (sealed)  │  │(isolated)│
   └─────────┘   └──────────┘   └───────────┘   └───────────┘  └──────────┘
        │              │               │               │              │
        └──────────────┴───────────────┴───────────────┴──────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │   GOVERNANCE SPINE (always on)      │
                    │ scope · authority · budget ·        │
                    │ idempotency · redaction · fail-closed│
                    └─────────────────────────────────────┘
```

**المبدأ:** الـOrchestrator جديد ورفيع؛ يعيد استخدام المكوّنات الموجودة ولا يعيد كتابتها.

---

## 3. خطة التنفيذ — 7 مراحل (Phases)

### PHASE 0 — Stabilize & Baseline (تثبيت الأساس)
**الهدف:** بيئة قابلة للتشغيل + baseline نظيف موثّق.
- **0.1** توثيق dependencies الناقصة وإضافتها لـ`pyproject.toml` (langgraph-checkpoint-sqlite، pydantic-settings، pytest-asyncio، python-multipart، typer، rich، celery، redis، chromadb).
- **0.2** إصلاح الـ9 اختبارات الحساسة للترتيب (isolation fixtures) → baseline نظيف 100%.
- **0.3** إصلاح `webpent.cli` export gap (`app`, `_parse_report_formats`) عند غياب langgraph.
- **0.4** إنشاء `scripts/autonomous_baseline.py` يقيس ويحفظ baseline JSON.
- **القبول:** `pytest -q` = 0 failures، و`main.py --help` يعمل.

### PHASE 1 — Autonomous Hunt Orchestrator (القلب الجديد)
**الهدف:** حلقة مستقلة واحدة تربط المكوّنات الموجودة.
- **1.1** إنشاء `src/webpent/autonomous/hunt_orchestrator.py` — الحلقة الرئيسية.
- **1.2** إنشاء `src/webpent/autonomous/hunt_state.py` — حالة الحملة المستقلة (additive على PentestState).
- **1.3** إنشاء `src/webpent/autonomous/hunt_contracts.py` — عقود typed (HuntPhase, HuntOutcome, StopReason).
- **1.4** ربط الحلقة بـ: Recon → HypothesisGenerator → SmartStrategyEngine → ActionExecutor → Validator/ProofBundle → SmartMemory.
- **1.5** Stop conditions صريحة: budget، no-new-evidence، repeated-action، negative-control-contradiction، capability-blocked.
- **القبول:** حلقة تعمل end-to-end على fixture محلي وتنتج ProofBundle.

### PHASE 2 — Real Execution Wiring (التنفيذ الحقيقي)
**الهدف:** الـloop ينفّذ HTTP حقيقي عبر المسار المُصرَّح.
- **2.1** ربط `ActionExecutor` + `RuntimeContext` بالـOrchestrator (نفس spine الموجود).
- **2.2** تسجيل adapter `hunt_http` مع scope policy + proof contract.
- **2.3** تفعيل method-aware execution (GET/HEAD افتراضيًا، POST في authorized-active فقط).
- **2.4** ضمان أن كل action يمر عبر: scope check → authority check → budget → idempotency → cleanup.
- **القبول:** اختبار يثبت أن action غير مصرّح يُرفض fail-closed، والمصرّح يُنفَّذ ويُسجَّل.

### PHASE 3 — Evidence & Proof Integration (الإثبات)
**الهدف:** كل نتيجة مؤكدة تحمل ProofBundle مختومًا قابلاً للـreplay.
- **3.1** توصيل `build_complete_proof_bundle` + `validate_proof_bundle` + `verify_replay` داخل الـloop.
- **3.2** negative control إلزامي لكل فئة تتطلبه.
- **3.3** منع أي promotion من heuristic/keyword/LLM نص.
- **3.4** ربط الـbundles بالـreporter.
- **القبول:** mutation test — إزالة evidence أو control تُفشل الـseal.

### PHASE 4 — Learning Loop (التعلّم الفعلي)
**الهدف:** الذاكرة تغيّر ترتيب الـhypotheses بشكل قابل للإثبات.
- **4.1** ترقية `SmartMemory` إلى ذاكرة معزولة بـ`engagement_id:target_id`.
- **4.2** offline replay يثبت تحسّن الترتيب بدون زيادة false positives.
- **4.3** cap hint عند 0.75 (حفاظًا على governance).
- **القبول:** test يثبت أن نفس الـhypotheses تُرتَّب مختلفًا بعد outcomes.

### PHASE 5 — CLI & One-Command Hunt (الواجهة)
**الهدف:** أمر واحد يشغّل كل شيء.
- **5.1** إضافة `python main.py hunt --url ... --mode ... --max-iterations ...`.
- **5.2** مخرجات JSON + HTML للـhunt.
- **5.3** `--dry-run` و`--resume`.
- **القبول:** الأمر يعمل على fixture وينتج تقريرًا.

### PHASE 6 — Verification & Release Gates (التحقق)
**الهدف:** إثبات أن النظام autonomous bug hunter فعلاً.
- **6.1** اختبارات end-to-end للـorchestrator.
- **6.2** regression كامل (0 failures).
- **6.3** Ruff نظيف.
- **6.4** تقرير qualification صادق (لا مبالغة).
- **6.5** تحديث التوثيق (README + traceability matrix).
- **القبول:** كل الـgates خضراء + تقرير صادق.

---

## 4. ضوابط الأمان غير القابلة للتفاوض

1. لا تعديل على WAPTLab أو أي target خارجي.
2. لا تخفيف scope/auth/rate-limit/SSRF/evidence gates.
3. الـLLM يقترح ويرتّب فقط — لا يُصرّح ولا يُثبت ولا يوسّع scope.
4. غياب capability = typed blocker، لا "clean".
5. كل action نشط يحتاج: policy + budget + idempotency + cleanup + terminal classification.
6. لا Finding مؤكد بدون ProofBundle قابل للـreplay.
7. لا credentials/cookies/tokens في أي artifact أو ZIP.

---

## 5. المخرجات النهائية

- كود جديد: `src/webpent/autonomous/` (orchestrator + state + contracts).
- CLI جديد: `main.py hunt`.
- اختبارات جديدة: `tests/test_autonomous_hunt_*.py`.
- توثيق محدّث: README + traceability matrix + qualification report.
- **ZIP نهائي** يحتوي كل ذلك.

---

## 6. معيار النجاح النهائي

النظام يُسمّى Autonomous Bug Hunter عندما:
- ✅ حلقة مستقلة تعمل end-to-end بأمر واحد.
- ✅ تنفيذ HTTP حقيقي مُصرَّح ومُقيَّد.
- ✅ ProofBundle مختوم لكل نتيجة مؤكدة.
- ✅ تعلّم يغيّر السلوك (مُثبَت offline).
- ✅ كل gates خضراء (tests + ruff).
- ✅ تقرير صادق بلا مبالغة.

---

## 7. ترتيب التنفيذ

```
PHASE 0 → PHASE 1 → PHASE 2 → PHASE 3 → PHASE 4 → PHASE 5 → PHASE 6
(stabilize) (orchestrator) (execution) (proof) (learning) (CLI) (verify)
```

كل مرحلة: كود + اختبار + تشغيل + rollback point.
