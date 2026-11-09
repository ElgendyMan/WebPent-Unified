"""GOED v1.8.1 — Build Delivery ZIP (Phase 15)
NEVER include API keys or secrets.
"""

import os
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZIP_NAME = os.path.join(ROOT, "WebPent-GOED-v1.8.1-LLM-Full.zip")

INCLUDE = [
    "src/webpent/cqa_v2",
    "src/webpent/models",
    "src/webpent/goed_v1",
    "src/webpent/llm_researcher",
    "src/webpent/smart",
    "src/webpent/agents",
    "src/webpent/__init__.py",
    "release",
    "goed_v1_8",
    "goed_v1_8_1",
    "docs/archive/goed-v1.7",
    "docs/archive/goed-v1.8-rc1",
    "docs/authorization",
    "docs/plans",
    "benchmarks/goed_v1_7_adversarial_v3",
    "benchmarks/goed_v1_7_hidden_v2",
    "reports/goed_v1_8_1",
    "reports/goed_v1_8",
    "reports/goed_v1_7",
]
EXCL_EXT = {".pyc", ".pyo", ".pyd", ".zip", ".gz", ".tar", ".env", ".secret"}
EXCL_DIR = {"__pycache__", ".pytest_cache"}
EXCL_FILE = {".env", "secrets.json", "api_keys.json", ".gitignore"}

if os.path.exists(ZIP_NAME):
    try:
        os.unlink(ZIP_NAME)
    except Exception:
        ZIP_NAME = os.path.join(ROOT, "WebPent-GOED-v1.8.1-LLM-Final.zip")

with zipfile.ZipFile(ZIP_NAME, "w", zipfile.ZIP_DEFLATED) as zf:
    for ip in INCLUDE:
        full = os.path.join(ROOT, ip)
        if not os.path.exists(full):
            continue
        if os.path.isfile(full):
            zf.write(full, ip)
            continue
        for dp, dn, fn in os.walk(full):
            dn[:] = [d for d in dn if d not in EXCL_DIR]
            for f in fn:
                if f in EXCL_FILE:
                    continue
                ext = os.path.splitext(f)[1].lower()
                if ext in EXCL_EXT:
                    continue
                fp = os.path.join(dp, f)
                arc = os.path.relpath(fp, ROOT)
                zf.write(fp, arc)
    zf.writestr(
        "GOVERNANCE.txt",
        "GOVERNANCE NOTICE\n==================\nvip_qualified: false\n"
        "qualification_state: CONDITIONAL\nP10: CLOSED\nP9: CLOSED\n"
        "Scope: local_synthetic_authorized_targets_only\n"
        "This archive contains NO API keys. LLM credentials from env vars only.\n",
    )

zs = os.path.getsize(ZIP_NAME)
with zipfile.ZipFile(ZIP_NAME, "r") as zf:
    names = zf.namelist()
    integ = "OK" if zf.testzip() is None else "ERROR"
sec = any("secret" in n.lower() or "api_key" in n.lower() for n in names)
print(f"📦 {os.path.basename(ZIP_NAME)}")
print(f"   Size: {zs:,} bytes ({zs / 1024:.0f} KB)")
print(f"   Files: {len(names)} | Integrity: {integ}")
print(f"   No secrets: {'✅' if not sec else '⚠️'}")
print("   Governance: vip_qualified=false, P10=CLOSED, CONDITIONAL")
