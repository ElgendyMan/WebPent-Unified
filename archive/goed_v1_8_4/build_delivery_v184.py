"""Create delivery zip with all v1.8.4 artifacts."""

import json
import os
import zipfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
# Determine name
REPORTS = os.path.join(_ROOT, "reports", "goed_v1_8_4")
diff_path = os.path.join(REPORTS, "differential_v184.json")
if os.path.exists(diff_path):
    diff = json.load(open(diff_path))
    cls = diff.get("classification", "UNKNOWN")
    if cls == "MEASURED_GAIN":
        zip_name = "WebPent-GOED-v1.8.4-BlindRealLLM-GAIN.zip"
    elif cls == "NO_MEASURED_GAIN":
        zip_name = "WebPent-GOED-v1.8.4-BlindRealLLM-NOGAIN.zip"
    elif diff.get("status") == "REAL_API_UNAVAILABLE":
        zip_name = "WebPent-GOED-v1.8.4-BlindRealLLM-UNAVAILABLE.zip"
    else:
        zip_name = "WebPent-GOED-v1.8.4-BlindRealLLM.zip"
else:
    zip_name = "WebPent-GOED-v1.8.4-BlindRealLLM.zip"
zip_path = os.path.join(_ROOT, zip_name)
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    # Phase scripts
    for root, dirs, files in os.walk(os.path.join(_ROOT, "goed_v1_8_4")):
        for f in files:
            if f.endswith(".py"):
                full = os.path.join(root, f)
                arc = os.path.relpath(full, _ROOT)
                zf.write(full, arc)

    # Reports
    for root, dirs, files in os.walk(REPORTS):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, _ROOT)
            zf.write(full, arc)

    # Key source files touched by v1.8.4
    v184_src = [
        "src/webpent/cqa_v2/replay_verifier.py",
        "src/webpent/llm_researcher/tool_boundary.py",
        "src/webpent/llm_researcher/providers/__init__.py",
        "src/webpent/llm_researcher/providers/factory.py",
        "src/webpent/llm_researcher/providers/base.py",
        "src/webpent/llm_researcher/providers/pool.py",
        "src/webpent/llm_researcher/interface.py",
    ]
    for p in v184_src:
        full = os.path.join(_ROOT, p)
        if os.path.exists(full):
            zf.write(full, p)

    # Freeze manifests and decisions
    docs_include = [
        "docs/archive/goed-v1.8.3/freeze_manifest.json",
        "docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_MANIFEST.json",
        "docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_DIFF.md",
        "docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_PROVENANCE.json",
        "docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_VERIFICATION.json",
        "docs/decisions/DECISION-2026-09-06-phase18-freeze-contradiction.md",
        "docs/authorization/P10_AUTHORIZATION_REQUEST_v2.md",
        "docs/plans/2026-09-07-webpent-v184-close-vip-path.md",
    ]
    for p in docs_include:
        full = os.path.join(_ROOT, p)
        if os.path.exists(full):
            zf.write(full, p)

    # Benchmark manifest (NOT ground truth — that's for scoring only)
    bm = os.path.join(_ROOT, "benchmarks", "blind_v3", "manifest.json")
    if os.path.exists(bm):
        zf.write(bm, "benchmarks/blind_v3/manifest.json")
print(f"Delivery zip created: {zip_path}")
print(f"Size: {os.path.getsize(zip_path)} bytes")
print(f"Zip name: {zip_name}")
