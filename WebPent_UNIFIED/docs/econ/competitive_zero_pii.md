# CompetitiveRadar — ضمان الـ Zero-PII (NC-ECON-1, U-ECON-7)

## القاعدة

قاعدة `findings` في `download/econ/competitive.db` تحمل ستة أعمدة بالضبط،
لا أكثر ولا أقل:

| العمود | النوع | المحتوى |
|---|---|---|
| `program_id` | TEXT | معرّف البرنامج (عام أصلًا) |
| `severity` | TEXT | critical/high/medium/low |
| `vuln_class` | TEXT | صنف الثغرة |
| `endpoint_signature` | TEXT | نمط المسار (بلا query strings ولا بيانات مستخدمين)، يُمرر عبر `redact()` |
| `disclosed_at` | TEXT | تاريخ الإفصاح العام ISO-8601 |
| `source` | TEXT | اسم المصدر الموثّق فقط |

## ما لا يمكن أن يدخل القاعدة أصلًا

لا أسماء صيّادين، لا usernames، لا handles، لا صور، لا روابط للملفات
الشخصية، لا نصوص حرة من التقارير، لا هويات الباحثين إطلاقًا: الأمان
مفروض بـ *السكيما نفسها* (test_no_pii_in_db يفحص الأعمدة)، لا بضبط
النفس. الـ ingestion يركّز على الـ findings نفسها.

## المصادر الموثوقة فقط

`TRUSTED_FINDING_SOURCES`: hackerone_hacktivity، bugcrowd_crowdstream،
github_advisories، medium_disclosure، twitter_disclosure. أي اسم مصدر
آخر يُرفض outright، dry-run أو لا.

## قواعد L-2

- النواة لا تلمس الشبكة إطلاقًا: `ingest()` يقرأ ملف snapshot محلي
  ينتجه سكربت يفعّله المشغّل بنفسه (يحترم robots.txt ومعدل الطلبات).
- مسار القاعدة يجب أن يكون مسار ملفات محليًا؛ أي شيء يشبه URL يُرفض.
- `dry_run=True` (الافتراضي) لا يكتب شيئًا.
- كل القراءات/الكتابات تحدث بـ queries مُعامَلة (parameterized)؛ فشل
  SQLite → سجل تحذير وذاكرة داخلية، لا انهيار (fail-soft).
