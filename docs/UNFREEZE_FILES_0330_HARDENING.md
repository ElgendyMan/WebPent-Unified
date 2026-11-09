# UNFREEZE_FILES_0330_HARDENING — نافذة إلغاء التجميد المعلنة 0.33.0 (2026-11-01)

> **النافذة:** 0.33.0 — PRODUCTION HARDENING (docs/PRODUCTION_HARDENING_PLAN_0330.md)
> **البروتوكول:** DR-009 — إعلان قبل التعديل، إعادة تجميد بعد التحقق.
> **سكربت إعادة التجميد:** `scripts/refreeze_manifest_0330_hardening.py`
> **سكربت جرد I/O:** `scripts/regen_direct_io_inventory_0330_hardening.py` (815 → 814 سجلًا)

## الملفات المعدلة المثبتة في الmanifest (23)

| الملف | بنود الخطة |
|---|---|
| `src/webpent/__init__.py` | ترقية SSOT 0.32.0 → 0.33.0 |
| `src/webpent/adapters/controlled_target/adapter.py` | P1-14 (قفل الميزانية/start) |
| `src/webpent/agents/validator/agent.py` | P2-11 (B025 ImportError ميتة) |
| `src/webpent/api/auth.py` | P2-04 (dummy-hash ضد تعداد المستخدمين) |
| `src/webpent/api/scan_registry.py` | P2-05 (claim شرطي بـrowcount) |
| `src/webpent/api/workers_status.py` | F-05 (مصادقة require_viewer) |
| `src/webpent/autonomous/hunt_memory.py` | P1-06 (تحقق التوقيع)، P1-07 (سقف الupsert) |
| `src/webpent/autonomous/hunt_orchestrator.py` | P1-01 (تصفير عدّاد الصمت) |
| `src/webpent/brain/ev_scheduler.py` | P1-05 (أرضية داخل السقف) |
| `src/webpent/causal_reasoning_v2/causal_adapter_v2.py` | P2-10 (F402 تظليل) |
| `src/webpent/llm_researcher/interface.py` | P1-15 (ذاكرة محدودة) |
| `src/webpent/llm_researcher/providers/openai_compatible.py` | F-02 (توقيع البناء)، F-03 (close) |
| `src/webpent/llm_researcher/providers/pool.py` | F-02 (بناء صحيح + صدق فشل)، F-03 (إغلاق في finally) |
| `src/webpent/memory/ab_lab.py` | F-01 (run_id بالهدف)، P1-02 (حجز شرطي)، P1-03 (رفض تعارض التفويض)، P1-08 (stale skip) |
| `src/webpent/production/advisory_registration.py` | P2-10 (F402 تظليل) |
| `src/webpent/production/modern_spine.py` | F-04 (إغلاق fallback SSRF)، P1-13 (bounded_stop)، إصلاح انحدار execute_real_request (تسجيل هدف الاشتراك + guard_redirects=False — 15 اختبار team1) |
| `src/webpent/recon/auth_handler.py` | P2-09 (E722) |
| `src/webpent/recon/browser_crawler.py` | P1-16 (إغلاق المتصفح أولًا) |
| `src/webpent/reporter/poc_recorder.py` | P2-18 (encoding) |
| `src/webpent/service/api.py` | P2-02 (is_global_admin) |
| `src/webpent/shared/engagement_scope.py` | F-06 (بوابة أهداف خاصة) |
| `src/webpent/shared/persistent_finding_ledger.py` | P1-17 (WAL + busy_timeout) |
| `src/webpent/workers/pentest_worker.py` | P2-01 (اسم متغير البيئة الصحيح) |

## ملفات معدلة غير مثبتة في الmanifest (5 — أُعلنها للشفافية)

`api/app.py` (F-06)، `autonomous_hunter.py` (P1-10/P1-11)،
`campaign/executor/pivot_engine.py` (P1-09)، `core/infrastructure.py` (P1-12)،
`memory/db.py` (P1-04).

## انحراف الثواب المُعلن

- **frozen gate**: إعادة تثبيت 25 مدخلًا؛ مجموعة `HARDENING_20261101_THAW_PATHS`
  (8 ملفات غير مغطاة بمجموعات سابقة) أُضيفت لـ`test_baseline_disagrees_only_on_documented_unfreeze_paths`.
- **direct-I/O inventory**: deltas معلنة — `service/api.py[dynamic_resolution]`
  4→2 (P2-02)، `pool.py[dynamic_resolution]` 0→1 (F-02)؛ صفر مواقع raw-transport جديدة؛
  pin غير-المعتمد دون تغيير.
- **construction authority**: `tests/test_hardening_0330_b3.py` أُضيف لقائمة
  allowlist المُراجعة (عقد P1-13).
- **الاختبارات**: b1=10/b2=12/b3=21 جديد = 43؛ خط التجميع 6740 → **6783**.
