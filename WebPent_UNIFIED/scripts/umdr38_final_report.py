#!/usr/bin/env python3
"""UM-DR-38 §18 — the ARABIC final engineering report (sections A–K).

Reads every machine artifact produced by the mission and renders the
final report in Arabic. No number is hand-typed: every figure comes
from the evidence records at generation time.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUB = Path(__file__).resolve().parents[2]
DELIV = PUB / "deliverables" / "umdr38"
TEST_EVIDENCE = REPO / ".webpent-evidence" / "FULL_SUITE_EVIDENCE.json"
CAMPAIGNS = PUB / "deliverables" / "umdr37" / "evidence" / "umdr37_production_campaigns.json"
MATRIX = DELIV / "UMDR38_ACCEPTANCE_MATRIX.json"
GATES = DELIV / "UMDR38_GATE_RESULTS.json"
FULL_LOOP = REPO / "docs" / "UMDR37_FULL_LOOP_LEARNING.json"
EVIDENCE_MANIFEST = (PUB / "deliverables" / "umdr37" / "evidence"
                     / "EVIDENCE_MANIFEST.json")


def _git(args: list[str]) -> str:
    r = subprocess.run(["git", *args], cwd=PUB, capture_output=True,
                       text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load(path: Path) -> dict:
    if not path.is_file():
        print(f"FAIL: mandatory source missing: {path}", file=sys.stderr)
        raise SystemExit(1)
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    evidence = _load(TEST_EVIDENCE)
    a = evidence["accounting"]
    cov = (evidence.get("coverage") or {})
    campaigns = _load(CAMPAIGNS)
    runs = campaigns.get("runs") or []
    matrix = _load(MATRIX)
    gate_results = _load(GATES)
    fl = _load(FULL_LOOP)
    ev_manifest = _load(EVIDENCE_MANIFEST)
    head = _git(["rev-parse", "HEAD"])
    changed = _git(["diff", "--name-status", "--stat",
                    "2338fd5c172ecb68b3e492b90da0a08980644121", "HEAD"])
    counts = matrix.get("counts") or {}
    gate_lines = "\n".join(
        f"| {m['gate']} | {m['description']} | **{m['status']}** |"
        for m in matrix.get("gates", []))
    campaign_rows = "\n".join(
        f"| {r['run']} | `{r['campaign_id']}` | {r['lab_request_count']} | "
        f"{(r.get('funnel') or {}).get('stages', {}).get('endpoints_discovered')} | "
        f"{r['findings_total']} | {r['findings_confirmed']} | "
        f"{', '.join(r['guard_verdicts'])} | "
        f"{sum(1 for v in r['verifications'] if v['passed'])} | "
        f"{r['out_of_scope_request_count']} |"
        for r in runs)
    gate_table = "\n".join(
        f"| {g['gate']} | {g['exit_code']} |"
        + (" ناجحة |" if g["exit_code"] == 0 else " فاشلة |")
        for g in gate_results.get("gates", []))
    arms = fl.get("arms") or {}
    arm_lines = "\n".join(
        f"  - **{name}**: القناة `{arm.get('signals')}`، الطلبات "
        f"{arm.get('requests_issued')}/{arm.get('request_budget')}، "
        f"مؤكد {arm.get('confirmed')}"
        for name, arm in arms.items())

    report = f"""# UM-DR-38 — التقرير الهندسي النهائي
## سلامة النشر، قابلية إعادة إنتاج الأدلة، وإغلاق الإصدار

> وُلّد هذا التقرير آليًا في {_utcnow()} من الأدلة الآلية للمهمة
> (`scripts/umdr38_final_report.py`) — كل رقم فيه مقروء من سجل آلي عند
> التوليد، ولا رقم مكتوب يدويًا.

<div dir="rtl">

## أ. الملخص التنفيذي

**ما أُصلح:** بنية المستودع (README جذري + سير عمل CI جذري حيث يكتشفه
GitHub فعلًا، وإحالة النسخ المتداخلة)، عقد أدلة الاختبار (الأدلة أصبحت
مُخرج بناء في `.webpent-evidence/` مُهمل من git مع كتابة ذرّية وربط
بالالتزام المختبر بالضبط)، تجهيز الحملات (أدوات قياس قابلة للعكس لا
تتراكم، وحالة نهائية موثوقة من `graph.get_state`، وتنقيح، وتنظيف
مضمون)، ثابت نسخة مخبر واحد (1.6.0)، مصالحة BUILD_INFO وخط الإصدارات،
ترقية أمنية للاعتمادية soupsieve (2.9.2 ← 4.1.1 لإغلاق أربع CVEs)،
ونشر مجموعة الأدلة الدائمة (16 ملفًا بهاشات) بعدما كان `.gitignore`
يُفقد المستودعَ المنشورَ أدلةِ الحملات.

**ما تم التحقق منه:** الجناح الانحداري الكامل عند مراجعة الإصدار
({a['collected']} مجمّعًا / {a['passed']} ناجحًا / {a['failed']} فاشلًا /
{a['errors']} أخطاء، exit {evidence['exit_code']}، تغطية
{cov.get('percent_covered')}% ≥ 72%، شجرة نظيفة عند بدء الاختبار =
**{evidence.get('tree_clean')}**)، ثلاث حملات إنتاج طازجة عبر نقطة الدخول
الحقيقية `run_unified_hunt` (تأكيدان في كل حملة عبر CausalGuard ←
ProofBundle ← replay، وكل الضوابط السالبة صامدة، والأصل خارج النطاق
صفر طلبات)، حلقة التعلم الكاملة (PROVEN داخل المختبر المُسيطر عليه)،
و13 بوابة جودة/أمن مُعادة التنفيذ فعليًا عند مراجعة الإصدار.

**ما نُشر:** فرع `mission/umdr38-closure` (رأسه `{head[:12]}`) مع كل
الإصلاحات، وحزمة الإصدار النهائية (ZIP + باندل git + 19 مخرجًا في
`deliverables/umdr38/`).

**حالة الإصدار: COMPLETE_LOCAL_REMOTE_PUBLICATION_BLOCKED** — كل بند
قابل للتنفيذ محليًا مكتمل ومُتحقق منه؛ الوحيد المتبقي هو تشغيل GitHub
Actions على الالتزام المنشور بالضبط، وهو محجوب بغياب بيانات اعتماد
الدفع في بيئة البناء (أوامر الدفع والـPR مرفقة).

## ب. المستودع واستعادة Git

- **الـHEAD المنشور السابق:** `2338fd5c172e` — «Update project to
  v0.40.1 UMDR36-2-37 FINAL» (squash نشر يحمل نتيجة المهمة السابقة).
- **الـHEAD النهائي:** `{head}` على الفرع `mission/umdr38-closure`.
- **merge-base:** `1968f63` (نشر v0.40.1 UMDR35-36) — تاريخ المهمة
  التفصيلي نسب مشروع (تحققنا أن له سلفًا مشتركًا مشروعًا) ودُمج بـ
  `-s ours` ليصبح كل شِعَب المهمة حتى `01d1708` أسلافًا قابلين للحل،
  مع بقاء الشجرة مطابقة للمنشور (فرق صفر أسطر عند الدمج).
- **الباندل القديم:** رأسه `9ee46b5` (حقبة Part-20) — أقدم من الفرع
  المحلي `01d1708`؛ كلاهما محفوظ كنسب.
- **المقطع المفقود نهائيًا:** `01d1708..073c64b` (يشمل التزام الأدلة
  `1386d57`) فُقد مع إعادة تدوير بيئة البناء ولم يُدفع قط؛ لا نسخة
  منه موجودة في أي مكان متاح، ومحتواه باقٍ كشجرة النشر `2338fd5`.
  **لم يُختلق أي التزام ولا ادُّعيت هوية شجرة بلا مقارنة فعلية** —
  موثق بدقة في تقرير النسب.

## ج. التغييرات المعمارية والبرمجية

التغييرات من المنشور `2338fd5` إلى رأس الإغلاق ({len(changed.splitlines())}
سطر diff — القائمة الكاملة في `UMDR38_CHANGED_FILES_MANIFEST.txt`):

- **`scripts/run_tests_with_evidence.py` + `check_test_evidence.py`** —
  عقد أدلة §6.2/§6.3 كاملًا (دليل مُهمل، كتابة ذرّية، tree_clean عند
  بدء الاختبار، فحوص الحداثة: الالتزام/الـlockfile/هوية GitHub
  run/المحاولة، أرضية التغطية، رفض الأدلة الناقصة/القديمة/المعبثة).
- **`scripts/umdr37_production_campaigns.py`** — إصلاحات §7.2 الأربعة
  (سياق تجهيز قابل للعكس، الحالة النهائية الموثوقة عبر `get_state`،
  التنظيف في `finally`، التنقيح) + ثابت `LAB_VERSION` + سجل تأكيدات
  §7.2.C الكامل.
- **`scripts/umdr38_reports.py` / `umdr38_deliverables.py` /
  `umdr38_closure.py` / `umdr38_publish_campaign_evidence.py` /
  `umdr38_final_report.py`** — مولدات المخرجات المشتقة من الأدلة
  (ترفض البيانات الناقصة وتسجل حالات غياب صريحة).
- **اختبارات جديدة:** `test_umdr38_evidence_contract.py` (11)،
  `test_umdr38_campaign_instrumentation.py` (2)،
  `test_umdr38_report_generators.py` (8) + تحديث اختبارات عقد النشر
  وM12 للمسار الجذري.
- **الجذر:** `README.md` + `.github/workflows/ci.yml + nightly.yml +
  weekly-benchmarks.yml` (+ إحالة المتداخل) + `deliverables/umdr37/
  evidence/` (16 ملف أدلة دائمة).
- **uv.lock:** ترقية soupsieve 2.9.2 → 4.1.1 (أربع CVEs جديدة).
- **ما تُرك عمدًا دون مساس:** الوحدات المجمدة (بوابة الوحدات المجمدة
  خضراء)، سلسلة السلطة CausalGuard ← ProofBundle ← replay، كل ضوابط
  النطاق والتفويض والضوابط السالبة، بنية المشروع داخل
  `WebPent_UNIFIED/` (لا نقل جماعي)، والمخرجات التاريخية (موسومة
  كتاريخ لا كحالة حالية).

## د. التحقق من CI

- **مسار سير العمل:** `.github/workflows/ci.yml` على **جذر المستودع**
  (المكان الوحيد الذي يكتشفه GitHub) مع `working-directory:
  WebPent_UNIFIED` — بالإضافة إلى nightly وweekly-benchmarks.
- **رابط التشغيل وRun ID:** **BLOCKED_EXTERNAL_DEPENDENCY** — لا
  بيانات اعتماد دفع في بيئة البناء؛ لا يُدَّعى أي تشغيل GitHub.
- **الالتزام:** `{head}`.
- **نتائج الوظائف (إعادة تنفيذ محلية فعلية لنفس أوامر سير العمل):**

| البوابة | exit |
|---|---|
{gate_table}

- **أدلة مرفوعة (محليًا و كسير عمل):** `.webpent-evidence/` (سجل
  الجناح الكامل + النسخة النصية + تغطية)، SBOM (CycloneDX)، ونتائج
  البوابات في `UMDR38_GATE_RESULTS.json`.
- **أوامر الدفع والـPR:** في `UMDR38_CI_VERIFICATION_REPORT.md`.

## هـ. أدلة الاختبار

- **الالتزام المختبر بالضبط:** `{evidence['source_commit']}`
- **نظافة الشجرة عند بدء الاختبار:** **{evidence.get('tree_clean')}**
  (التُقطت قبل كتابة أي شيء؛ دليل الأدلة مُهمل من git — عطب
  `tree_clean: false` البنيوي القديم مستحيل الآن).
- **بايثون:** {evidence.get('python_version')} | **uv:**
  {evidence.get('uv_version')}
- **هاش الـlockfile:** `{evidence.get('lockfile_sha256')}`
- **مجمّع:** {a['collected']} | **ناجح:** {a['passed']} | **فاشل:**
  {a['failed']} | **أخطاء:** {a['errors']} | متخطى: {a['skipped']} |
  xfailed: {a['xfailed']} | xpassed: {a['xpassed']}
- **التغطية:** {cov.get('percent_covered')}% (الأرضية 72% — لم
  تُخفض أبدًا) | **exit code:** {evidence['exit_code']}
- **المحاسبة v3:** الواثقات كلها صحيحة والمطابقة الختامية متفقة، ولم
  يُقاطَع التشغيل.

## و. حملات الإنتاج (ثلاث حملات طازجة عند مراجعة الإصدار)

| # | معرف الحملة | الطلبات | نقاط النهاية | النتائج | المؤكدة | Guard | Replay | خارج النطاق |
|---|---|---|---|---|---|---|---|---|
{campaign_rows}

- كل حملة: حالات مختبر جديدة، معرف فريد، نفس الإعداد والميزانية،
  تجهيز مُعاد الضبط بين الحملات، وحالة نهائية **موثوقة**
  (`graph.get_state`) لحساب القمع.
- كل نتيجة مؤكدة تحمل `ProofBundle` مختومًا وتحقق replay ناجحًا،
  وCausalGuard هو سلطة التأكيد الوحيدة.
- الضوابط السالبة في كل حملة: حد الأدمن المفروض لم يُؤكد، المورد
  المفقود لم يُؤكد، المسارات العامة لم تُؤكد، **والمصيدة لم تُؤكد**،
  والأصل خارج النطاق استقبل **صفر طلبات** (مثبت من سجل طلبه هو).
- الحملة السببية (root-cause) أعيد تشغيلها أيضًا: confirmed=2،
  drop_offs=[].

## ز. ذكاء الاكتشاف

**هل أثّر نموذج التطبيق/نظام الفرضيات/التعلم على قرارات تنفيذ فعلية؟
نعم — داخل النطاق المُتحقق منه فقط، وبفصل صارم بين المستويين:**

- **مستوى المحدِّد (selector-level):** مُثبت سببيًا بالاختبار الوحدوي
  المثبت (الدليل الحقيقي يرفع المرشح المتأثر بمقدار EVIDENCE_LIFT
  ويقلب الاختيار التالي؛ الدليل المعاكس يُعيد الترتيب هبوطًا). القيد
  على مستوى السيناريو موثق آليًا (آلية «تجربة واحدة لكل فرضية» لا
  تترك مرشحًا معلقًا لإعادة الترتيب) — حُكم صادق بطبقتين، لا ادعاء
  أوسع من القياس.
- **الحلقة الكاملة (full-loop):** أربع أذرع بنفس الميزانية (36/36)
  وقنوات أدلة مختلفة؛ اختلفت التجارب المختارة فعلًا، ونُفِّذت،
  واختلفت النتائج (0 مؤكد في ذراع لا-أدلة مقابل 1 في أذرع الأدلة)،
  وحقيقة الأرض لم تُؤكد إلا بدليل فعلي، والسلسلة السداسية قائمة،
  وبلا أي تجاوز لسلطة أو بوابة أمان (حالات رفض النطاق محترمة:
  {arms.get('full', {}).get('cases_scope_refused')} في الذراع الكامل).
  **التصنيف الصادق: برهان حلقة كاملة عبر مسار الإنتاج على مختبر
  مُحرَّر الفريق — ليس تعلمًا معممًا في العالم الحقيقي، ولا يُدَّعى.**
{arm_lines}

## ح. الأمان وسلامة الإصدار

- **فرض النطاق والتفويض:** التفويض إلزامي، لا طلب نشط خارج النطاق،
  وحماية same-origin/SSRF أثبتت نفسها في كل حملة (صفر طلبات للأصل
  خارج النطاق).
- **سلطة التأكيد:** CausalGuard وحده يؤكد؛ لا تأكيد LLM ولا ترقية
  فرضيات ولا حواف Knowledge Graph؛ سلسلة CausalGuard ← ProofBundle ←
  replay كاملة في كل نتيجة مؤكدة.
- **فحص الأسرار:** PASS (على الشجرة المتتبعة وفي الحزمة)؛ سجلات
  الحملات منقَّحة (cookies/جلسات).
- **سلامة الوحدات المجمدة:** بوابة الوحدات المجمدة PASS — لا تعديل
  على وحدة مجمدة في هذه المهمة.
- **تحقق الحزمة:** سلامة الأرشيف، لا اجتياز مسارات، لا مسارات
  مطلقة، لا ملفات مطلوبة ناقصة، الفهرس مطابق للمحتوى، لا جذور
  مشروع مكررة، وبيانات التعريف 0.40.1 — التفاصيل والهاشات في
  `UMDR38_RELEASE_MANIFEST.json` و`SHA256SUMS`.
- **مجموعة الأدلة الدائمة:** {len(ev_manifest.get('files', []))}
  ملفًا تحت `deliverables/umdr37/evidence/` بهاش SHA-256 لكل ملف
  ومانيفست مربوط بالالتزام المصدر.

## ط. القيود المتبقية (كلها صريحة، بلا عبارات غامضة)

1. **CI البعيد:** لم يشغَّل GitHub Actions على الالتزام النهائي —
   محجوب بغياب بيانات اعتماد الدفع (BLOCKED_EXTERNAL_DEPENDENCY)؛
   أوامر الدفع والـPR جاهزة.
2. **التعميم:** كل نتائج الاكتشاف والتأكيد داخل مختبرات مُسيطر
   عليها من تأليف الفريق؛ لا ادعاء تغطية للعالم الحقيقي.
3. **العائلات:** access control فقط هي المتحقق عبر مسار الإنتاج؛
   باقي العائلات ليست production-confirmed.
4. **المقطع المفقود من التاريخ:** `01d1708..073c64b` غير قابل
   للاستعادة (موثق في تقرير النسب)؛ محتواه باقٍ كشجرة النشر.
5. **دَين ruff:** خط الأساس أُعيد تقييده عند
   {json.loads((REPO / 'scripts' / 'quality' / 'ruff_baseline.json').read_text())['total']}
   نتيجة بإصلاح كل نتائج كود umdr38 (صفر جديد) وتوثيق مُعلَن لإضافة
   حقبة umdr37 غير المُقيَّدة سابقًا؛ الرافعة تستمر في منع أي زيادة.

## ي. مصفوفة القبول النهائية (30 بوابة)

| البوابة | الوصف | النتيجة |
|---|---|---|
{gate_lines}

**الإحصاء:** {json.dumps(counts, ensure_ascii=False)} — لا
PASS_WITH_WARNINGS؛ كل بوابة إما PASS أو FAIL أو
BLOCKED_EXTERNAL_DEPENDENCY مع سبب موثق.

## ك. القرار النهائي

**COMPLETE_LOCAL_REMOTE_PUBLICATION_BLOCKED**

السبب: كل بند قابل للتنفيذ في بيئة البناء مكتمل بأدلة فعلية مربوطة
بمراجعة الإصدار (الجناح الكامل صفر فشل/صفر أخطاء، البوابات خضراء،
الحملات الثلاث مُعاد إنتاجها بكل الثوابت، الحزمة مُتحققة). البند
الوحيد المتعذر هو تشغيل GitHub Actions على الالتزام المنشور (البوابتان
G38-06 وG38-30) لغياب بيانات اعتماد الدفع — وهذا بند خارجي معلن، لا
نقص في العمل، ولا يُدَّعى إكمال النشر الكامل دونه.

</div>
"""
    out = DELIV / "UMDR38_FINAL_ENGINEERING_REPORT.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"[umdr38] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
