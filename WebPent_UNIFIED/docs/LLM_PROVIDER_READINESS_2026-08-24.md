# LLM Provider Readiness — 2026-08-24

## النطاق

تم فحص مفاتيح الـLLM التي قدمها المستخدم وربطها محليًا عبر environment مؤقت بصلاحية `600` خارج المستودع. لم يتم إدخال أي secret في source أو Git أو archive، ولم يتم استخدام مفاتيح GitHub/Hugging Face في تشغيل WAPTLab. التشغيل كان على WAPTLab محلي مصرح به فقط، بدون signup أو login أو CAPTCHA bypass أو OAST/provider callback أو target عام.

## إعداد WebPent

التعديل المنشور في commit `8f83c7a` يضيف اختيارًا provider-aware للـmodel IDs عبر environment overrides، مع إبقاء fallback deterministic وقواعد `Scope/Authority/Evidence/Proof` كما هي. أسماء المتغيرات الموثقة في `.env.example` هي:

```dotenv
MISTRAL_API_KEY=<secret>
GEMINI_API_KEY=<secret>
COHERE_API_KEY=<secret>
CLOUDFLARE_API_KEY=<secret>
CLOUDFLARE_ACCOUNT_ID=<account-id>
MISTRAL_MODEL=mistral-small-latest
GEMINI_MODEL=gemini-2.5-flash
COHERE_MODEL=command-a-03-2025
CLOUDFLARE_MODEL=@cf/meta/llama-3.2-3b-instruct
LLM_ENABLED=true
```

يجب تمرير القيم من secret manager أو environment محلي بصلاحية مقيدة. لا يجب نسخ الملف المرفق الذي يحتوي على المفاتيح إلى repository أو ZIP أو logs أو prompts. عند انتهاء quota أو رجوع provider بخطأ، لا تتحول النتيجة إلى `clean`؛ يتم تسجيل provider failure ويُستخدم deterministic fallback أو knowledge gap.

## نتيجة فحص WAPTLab مع LLM

تم تنفيذ scan مستقل جديد بعد نجاح تثبيت Chromium الخاص بـPlaywright، باستخدام `--profile smart-observe` و`--mode safe-smart` وworkspace/ledgers منفصلة. النتيجة قابلة للمراجعة في artifact خارج Git:

| المقياس | النتيجة |
|---|---:|
| Exit code | `0` |
| Candidate findings | `1` |
| Candidate class | SSTI، endpoint محلي في WAPTLab |
| Highest severity | High |
| Strict confirmed | `0` |
| Evidence-confirmed | `0` |
| Promoted ProofBundles | `0` |
| Evidence classification | `unconfirmed` |
| LLM trace records | `12` |
| Successful usage records | `11` من Cohere |
| LLM errors | OpenAI permission/maintenance error؛ fallback استمر |
| Playwright preflight | Available |
| Browser execution adapter | ما زال runtime gap؛ لا يوجد typed handler تنفيذي مربوط بالـActionExecutor |
| External tools | `httpx-pd` و`nuclei` و`katana` غير موجودة في هذه البيئة، مع fallback محدود حيث يسمح policy |
| PDF export | لم يُنشأ في هذه البيئة؛ HTML/JSON/Markdown متاحون |
| Qualification status | `NOT QUALIFIED` |

استخدام LLM حسّن مسار التحليل والتلخيص فقط؛ لم يرفع candidate إلى confirmed ولم ينشئ evidence أو proof. هذا السلوك مقصود ومطلوب. كما أن ظهور finding واحدة لا يعني أن WAPTLab نظيف أو أن التغطية مكتملة، لأن target أعاد قيود وصول ولأن أدوات discovery الخارجية وtyped browser handler غير متاحة في البيئة الحالية.

## القرار

الربط المحلي ناجح من ناحية configuration وfallback، والاختبار انتهى بدون crash أو secret leakage. لكنه ليس qualification لـVIP Smart Autonomous Bug Hunter. للوصول إلى qualification يجب توفير runtime adapters حقيقية محكومة بالـscope والـSSRF وربط Playwright بـ`ActionExecutor`، ثم الحصول على causal signal وindependent negative control وsealed/replayable ProofBundle مع replay ناجح. لا يجوز استبدال هذه الشروط بزيادة عدد candidates أو بادعاء confirmations من مخرجات LLM.

> هذه الصفحة لا تحتوي على مفاتيح أو cookies أو tokens أو payload secrets؛ أي artifact تشغيلي يحتوي على runtime state يظل خارج release archive.

## الملفات ذات الصلة

- [`../README.md`](../README.md)
- [`V75_MATURITY_SCORECARD.md`](V75_MATURITY_SCORECARD.md)
- [`../.env.example`](../.env.example)
- `report.json` و`report.html` و`report.md` من WAPTLab v5 محفوظة خارج Git تحت `/tmp/webpent-waptlab-llm-run-v5/`.
- الملخص المحلي sanitized محفوظ خارج Git تحت `/tmp/waptlab-llm-v4-summary.txt`.
