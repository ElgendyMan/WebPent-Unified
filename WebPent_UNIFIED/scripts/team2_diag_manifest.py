"""Diagnose source-manifest hash methodology variants (TEAM-2 diligence)."""
import hashlib
import os

ROOT = "/home/z/my-project/avi_v12/webpent-goed"
src_dir = os.path.join(ROOT, "src", "webpent")

files = []
for dirpath, _d, filenames in os.walk(src_dir):
    for fn in filenames:
        if fn.endswith(".py"):
            files.append(os.path.relpath(os.path.join(dirpath, fn), ROOT))
files.sort()
print("py files under src/webpent:", len(files))

def manifest_hash(relbase):
    lines = []
    for rel in files:
        arc = os.path.relpath(rel, relbase) if relbase else rel
        h = hashlib.sha256(open(os.path.join(ROOT, rel), "rb").read()).hexdigest()
        lines.append(f"{h}  {arc}\n")
    return hashlib.sha256("".join(lines).encode()).hexdigest()

print("rel from ROOT           :", manifest_hash(None))
print("rel from src/webpent    :", manifest_hash(os.path.join("src", "webpent")))
print("rel from src            :", manifest_hash("src"))

# Maybe they hashed file CONTENT concatenated?
content_concat = hashlib.sha256()
for rel in files:
    content_concat.update(open(os.path.join(ROOT, rel), "rb").read())
print("content concat          :", content_concat.hexdigest())

# Maybe manifest lines sorted differently or 'sha256:' prefix?
lines = []
for rel in files:
    h = hashlib.sha256(open(os.path.join(ROOT, rel), "rb").read()).hexdigest()
    lines.append(f"{h}  {rel}\n")
alt1 = hashlib.sha256("".join(sorted(lines)).encode()).hexdigest()
print("lines sorted            :", alt1)
alt2 = hashlib.sha256(("".join(lines)).encode()).hexdigest()
print("plain join (same as v1) :", alt2)

# include ALL files (not only .py) under src/webpent?
allf = []
for dirpath, _d, filenames in os.walk(src_dir):
    for fn in filenames:
        p = os.path.join(dirpath, fn)
        if os.path.isfile(p) and "__pycache__" not in p:
            allf.append(os.path.relpath(p, ROOT))
allf.sort()
lines2 = []
for rel in allf:
    h = hashlib.sha256(open(os.path.join(ROOT, rel), "rb").read()).hexdigest()
    lines2.append(f"{h}  {rel}\n")
print("all non-pycache files   :", len(allf),
      hashlib.sha256("".join(lines2).encode()).hexdigest()[:16])
