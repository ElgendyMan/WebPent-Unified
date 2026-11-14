# Economist Schemas (NC-ECON-1)

المصطلحات موحدة حرفيًا مع §1 من الcharter: Program / Target / Finding / EV / ROI /
Saturation / Freshness / P_accept / P_dup / Blind Spot. ممنوع المرادفات.

## `config/econ/programs.yaml` — MarketKB seed

كل برنامج سطر schema كامل:

| الحقل | النوع | المعنى |
|---|---|---|
| `id` | str | معرّف البرنامج (مفتاح كل lookups) |
| `platform` | str | hackerone / bugcrowd / private |
| `scope_url` | str | رابط صفحة الscope العامة |
| `last_updated` | date | تاريخ آخر تحديث؛ >90 يوم = stale (تحذير إلزامي) |
| `payout_curves` | map severity→{min,max,typical} | USD لكل severity (critical/high/medium/low) |
| `stats.dup_rate` | float 0-1 | نسبة الduplicates المتوقعة |
| `stats.bounty_ratio` | float 0-1 | نسبة التقارير المؤهلة لمكافأة |
| `stats.response_time_days` | {typical,p90} | زمن رد البرنامج بالأيام |
| `vuln_weights` | map class→multiplier | مضاعف القيمة لكل عائلة ثغرات |
| `notes` | str | مصدر البيانات وتاريخها (public data only) |

## `config/econ/payout_curves.yaml`

منحنيات عامة احتياطية لكل severity تُستخدم عندما يفتقد برنامج منحنى خاصًا به.
منحنى البرنامج نفسه يتفوق دائمًا على العام.

## كائنات API الرئيسية

- `PayoutRange(severity, minimum, maximum, typical)` — دائمًا min ≤ typical ≤ max.
- `ResponseStats(typical_days, p90_days)`.
- `Program` — كل ما سبق مجمّعًا + `vuln_weights`.
- `Target` — `target_id`, `program_id`, `last_change_ts` (من CEM)،
  `deploy_rhythm_bonus` (1.0-1.5، من CEM rhythm)، `effort_estimate` (0.5-3.0 ساعة)،
  `saturation` (0-100 أو None)، `scope_entries`. كل نسخة تمر على `sanitized()`:
  bounds + redact قبل أي استخدام أو تخزين.
- `IngestReport` — نتيجة أي `ingest_snapshot`: {source, dry_run, status,
  programs_seen, programs_accepted, reason}؛ status ∈
  {ingested, would_ingest, rejected, error}.

## قواعد الIngestion (L-2 / DoD U-ECON-1)

- المصادر الموثوقة فقط: `hackerone`, `hackerone_hacktivity`, `bugcrowd`,
  `cvss_public`, `program_policy_page`. أي شيء آخر → rejected ولا يُدمج.
- الsnapshot ملف JSON محلي `{"source": ..., "programs": [...]}` ينتجه سكربت
  offline يشغّله المشغّل (روبوتات robots.txt وrate-limit مسؤولية السكربت،
  ويُسجّل كل fetch عنده).
- `dry_run=True` افتراضيًا: لا كتابة على أي ملف إطلاقًا.
- الالتقاف المقبول يُلحق سطر JSON واحد redacted في `download/econ/ingest_log.jsonl`
  (append-only).
