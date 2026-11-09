#!/usr/bin/env bash
# install.sh — نقطة تثبيت واحدة لـ WebPent (Ultimate plan 2026-10-27, proposal 11).
#
# يكتشف البيئة، يسأل سؤال أو اتنين بس، ويجهز كل حاجة بـ defaults آمنة موثقة.
# ما لا يفعله هذا السكريبت عمدًا: لا يخترع تفاعلًا معقدًا، لا يثبت أدوات
# خارجية اختيارية (nuclei/sqlmap/arjun/gau — فحصها لاحقًا عبر webpent doctor)،
# ولا يشغّل أي حملة فحص.
set -euo pipefail

BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
say()  { printf '%s\n' "${BOLD}$1${RESET}"; }
ok()   { printf '  %s\n' "${GREEN}✓$RESET $1"; }
warn() { printf '  %s\n' "${YELLOW}!$RESET $1"; }
fail() { printf '  %s\n' "${RED}✗$RESET $1"; exit 1; }

cd "$(dirname "$0")"

say "🔍 بفحص المتطلبات..."

# --- Python 3.12+ -------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    fail "Python غير موجود. ثبّت Python 3.12+ الأول: https://www.python.org/downloads/"
fi
PYVER=$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
    || fail "محتاجين Python 3.12+ (الموجود $PYVER)"
ok "Python $PYVER"

# --- Docker (اختياري) ---------------------------------------------------
HAS_DOCKER=no
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    HAS_DOCKER=yes
    ok "Docker Compose موجود (خيار متاح)"
else
    warn "Docker Compose مش موجود — هنبقى على التثبيت المحلي (مفيش مشكلة)"
fi

# --- السؤال الوحيد تقريبًا: Docker أم محلي؟ ------------------------------
MODE=""
if [ "${WEBPENT_INSTALL_MODE:-}" != "" ]; then
    MODE="${WEBPENT_INSTALL_MODE}"
elif [ "$HAS_DOCKER" = "yes" ]; then
    printf '%s' "${BOLD}التثبيت بـ Docker (أسهل وأنظف) ولا محلي (venv مباشر)؟ [docker/local]: ${RESET}"
    read -r REPLY || REPLY="local"
    case "$REPLY" in
        d|D|docker|dockercompose) MODE="docker" ;;
        *) MODE="local" ;;
    esac
else
    MODE="local"
fi

if [ "$MODE" = "docker" ]; then
    say "🐳 التثبيت بـ Docker..."
    [ -f .env ] || cp .env.minimal.example .env
    docker compose --profile quickstart up -d --build
    ok "الحاوية شغالة"
    say ""
    say "✅ جاهز! جرّب أول فحص:"
    printf '   docker compose exec webpent webpent init\n'
    printf '   docker compose exec webpent webpent hunt --url https://your-authorized-target.com --mode quick --authorization "ref"\n'
    exit 0
fi

say "🐍 التثبيت المحلي..."

# --- venv + dependencies --------------------------------------------------
if [ ! -d .venv ]; then
    "$PY" -m venv .venv
    ok "venv اتعمل"
fi
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip --quiet
say "📦 بتثبت الـdependencies (دقيقتين بالكتير)..."
if python -m pip install -e . --quiet; then
    ok "الحزمة الأساسية اتثبتت"
else
    fail "فشل تثبيت الحزمة — شوف الرسالة فوق، وأهم سبق معروف: SQLite build headers (apt install python3.12-dev أو ما يعادلها)"
fi

# --- البيئة ---------------------------------------------------------------
if [ ! -f .env ]; then
    cp .env.minimal.example .env
    ok "اتعمل .env من النسخة المبدئية (10 أسطر)"
else
    warn ".env موجود بالفعل — مش هنلمسه"
fi

# --- مفتاح LLM (اختياري) ---------------------------------------------------
if [ "${WEBPENT_SKIP_LLM_KEY:-}" != "1" ]; then
    say "🔑 عايز تضيف مفتاح LLM دلوقتي؟ (اختياري — المسار الحتمي يشتغل بدونه، وتقدر تضيفه بعدين بـ webpent llm-keys add)"
    printf '%s' "${BOLD}[anthropic/openai/سيب فاضي دلوقتي]: ${RESET}"
    read -r PROVIDER || PROVIDER=""
    case "$PROVIDER" in
        anthropic|openai)
            printf '%s' "الصق المفتاح (يتكتب في .env غير المتتبَّع بس — مش في أي ملف متتبَّع): "
            read -r KEY
            if [ -n "$KEY" ]; then
                if grep -q "^LLM_ENABLED=" .env; then
                    sed -i.bak "s|^LLM_ENABLED=.*|LLM_ENABLED=true|" .env && rm -f .env.bak
                else
                    printf 'LLM_ENABLED=true\n' >> .env
                fi
                # اسم متغير البيئة بالاتفاقية المشروعة في الإعدادات: {provider}_api_key
                ENVVAR="$(printf '%s' "$PROVIDER" | tr '[:lower:]' '[:upper:]')_API_KEY"
                # الموديل الافتراضي = نفس سلسلة FAST في src/webpent/shared/llm.py
                # (لا نخترع slug جديد هنا عمدًا — لو اتغير في llm.py يُحدَّث هنا)
                case "$PROVIDER" in
                    anthropic) MODEL="claude-sonnet-5" ;;
                    openai)    MODEL="gpt-4o" ;;
                esac
                printf '%s=%s\n' "$ENVVAR" "$KEY" >> .env
                chmod 600 .env 2>/dev/null || true
                # تسجيل مرجع متغير البيئة في key store المشروع — قيمة السر
                # نفسها ما بتتقروش ولا تتطبع هنا (عقد webpent llm-keys add)
                if webpent llm-keys add "$PROVIDER" "$MODEL" --env-var "$ENVVAR" 2>/dev/null; then
                    ok "سجلنا $PROVIDER/$MODEL عبر $ENVVAR (القيمة في .env غير المتتبَّع)"
                else
                    warn "اتكتب $ENVVAR في .env — سجّله يدويًا: webpent llm-keys add $PROVIDER $MODEL --env-var $ENVVAR"
                fi
            fi
            ;;
        *)  say "تمام — تقدر تضيفه في أي وقت: webpent llm-keys add anthropic claude-sonnet-5 --env-var ANTHROPIC_API_KEY" ;;
    esac
fi

# --- فحص صحة ما بعد التثبيت -------------------------------------------------
say "🩺 فحص صحة التثبيت (webpent doctor)..."
if webpent doctor 2>/dev/null || python scripts/doctor.py --timeout 10 2>/dev/null; then
    ok "الفحص الصحي عدّى"
else
    warn "doctor لفت النظر لحاجة — راجع السبب (غالبًا أداة خارجية اختيارية مش متثبتة — ده طبيعي)"
fi

say ""
say "✅ جاهز! جرّب أول فحص:"
printf '   webpent init\n'
printf '   webpent hunt --url https://your-authorized-target.com --mode standard --authorization "your written authorization ref"\n'
printf '\nمهم: شغّل الأداة على أهداف مصرَّح لك باختبارها فقط. راجع README قسم "تنبيه قانوني".\n'
