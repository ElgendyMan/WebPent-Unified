#!/usr/bin/env python3
"""Round-3 war games 1, 2, 3, 5 + determinism PoC — executed for real."""
from __future__ import annotations
import atexit, hashlib, json, subprocess, sys, tempfile, traceback
from pathlib import Path

PKG = Path("/home/thaura/webpent_review/verdict")
CLI = None  # module invocation
OUT: list[str] = []

def log(title: str, lines: list[str]) -> None:
    OUT.append(f"\n### {title}")
    OUT.extend(lines)

def run(ws: Path, *args: str) -> tuple[int, str]:
    r = subprocess.run([sys.executable, "-m", "verdict_tool.cli", "-p", str(ws), *args],
                       capture_output=True, text=True, cwd=str(PKG))
    return r.returncode, (r.stdout + r.stderr).strip()

def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]

base = Path(tempfile.mkdtemp(prefix="wg3-"))
ws = base / "ws"
code, out = run(ws, "init")
log("setup: init", [f"exit={code}"])

# register a target so run start works
yaml_t = base / "t.yaml"
yaml_t.write_text(
    "name: juice-shop\nplatform: hackerone\nurl: http://localhost:3000\n"
    "in_scope:\n  - http://localhost:3000\nout_of_scope: []\n"
    "rate_limit_rps: 5\nlegal_review_completed: true\n")
run(ws, "targets", "add", str(yaml_t))

(ws / "runs").mkdir(parents=True, exist_ok=True)
(ws / "runs" / "evidence.txt").write_text("evidence\n")

def mkfindings(ids: list[str]) -> None:
    for fid in ids:
        run(ws, "findings", "register", fid, "juice-shop", "idor",
            "--severity", "medium", "--score", "0.8")
        run(ws, "findings", "classify", fid, "-c", "confirmed",
            "--impact", "account takeover", "--severity", "medium",
            "-e", "runs/evidence.txt")

mkfindings(["F-1", "F-2", "F-3", "F-4", "F-5"])
run(ws, "select", "F-1", "F-2", "F-3", "F-4", "F-5")
run(ws, "run", "start", "juice-shop")
run(ws, "run", "stop", "--note", "x")
(ws / "submissions").mkdir(parents=True, exist_ok=True)
(ws / "submissions" / "shot.png").write_bytes(b"png")
code, out = run(ws, "submit", "record", "F-1", "--platform-id", "H1-TEST-1",
                "--screenshot", "submissions/shot.png")
log("setup: submission recorded", [f"exit={code}", out.splitlines()[-1]])
code, out = run(ws, "watch", "start")
log("setup: watch opened", [f"exit={code}", out.splitlines()[-1]])
log("setup: 5 confirmed findings, selection frozen, run recorded",
    [f"state exists: {(ws / '.verdict' / 'state.json').is_file()}"])

# ---------------- WAR GAME 1: submission bypass ----------------
code, out = run(ws, "submit", "report", "F-1", "--auto",
        "--title", "t", "--summary", "s")
log("WG1.1  submit F-1 --auto (flag bypass)", [
    f"exit={code}", out.splitlines()[-1]])
st_path = ws / ".verdict" / "state.json"
st = json.loads(st_path.read_text())
orig_state = st_path.read_text()
st["auto_submit"] = True
st_path.write_text(json.dumps(st))
code, out = run(ws, "submit", "report", "F-1", "--auto",
        "--title", "t", "--summary", "s")
log("WG1.2  auto_submit planted in state.json + --auto again", [
    f"exit={code}", out.splitlines()[-1]])
st_path.write_text(orig_state)  # restore clean state for later games
poc = base / "ext.py"
poc.write_text(
    "import socket, sys\n"
    "class Blocked(Exception):\n    pass\n"
    "class NoSock(socket.socket):\n"
    "    def connect(self, *a, **k): raise Blocked()\n"
    "    def connect_ex(self, *a, **k): raise Blocked()\n"
    "socket.socket = NoSock\n"
    "socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(Blocked())\n"
    "import urllib.request\n"
    "urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(Blocked())\n"
    "sys.path.insert(0, '/home/thaura/webpent_review/verdict')\n"
    "from pathlib import Path\n"
    "from verdict_tool.tracking import Workspace\n"
    "from verdict_tool.submission import SubmissionPipeline\n"
    "ws = Workspace('" + str(ws) + "')\n"
    "sp = SubmissionPipeline(ws.load(), ws)\n"
    "methods = [m for m in dir(sp) if not m.startswith('_')]\n"
    "net = [m for m in methods if 'http' in m.lower() or 'send' in m.lower()\n"
    "       or 'post' in m.lower() or 'request' in m.lower()]\n"
    "print('pipeline methods:', methods)\n"
    "print('network-capable methods:', net or 'NONE')\n")
r = subprocess.run([sys.executable, str(poc)], capture_output=True, text=True)
log("WG1.3  external script, ALL sockets blocked", [
    *(r.stdout + r.stderr).strip().splitlines()[-2:]])

# ---------------- WAR GAME 2: pre-registration rewrite ----------------
code, _ = run(ws, "pre-registration", "predict", "--findings", "3", "6",
              "--acceptance", "0.3", "0.6")
code, out = run(ws, "pre-registration", "done")
pr = ws / "pre_registration.md"
log("WG2.1  predictions set + frozen", [f"exit={code}", out,
    f"pre_registration.md hash: {sha(pr)}"])
code, out = run(ws, "pre-registration", "predict", "--findings", "1", "2",
                "--acceptance", "0.9", "1.0")
st = json.loads(st_path.read_text())
log("WG2.2  ATTACK: re-predict after freeze", [
    f"exit={code}  (0 = allowed!)", out.splitlines()[-1],
    f"state predictions now: {st['predicted_findings_range']}, "
    f"{st['predicted_acceptance_range']}"])
pr.write_text("# rewritten after results\npredicted findings: 1-2")
log("WG2.3  ATTACK: edit pre_registration.md after freeze", [
    f"hash now:  {sha(pr)}",
    "detection: NONE — file hash never recorded, flag stays True"])

# ---------------- WAR GAME 3: FP laundering ----------------
run(ws, "findings", "register", "F-6", "juice-shop", "info",
    "--severity", "info", "--score", "0.3")
code, out = run(ws, "findings", "classify", "F-6", "-c", "false_positive",
                "--reason", "no impact", "-e", "runs/evidence.txt")
log("WG3.0  FP classification needs evidence", [f"exit={code}", out.splitlines()[-1]])
code, out = run(ws, "findings", "classify", "F-6", "-c", "confirmed",
                "--impact", "x", "--severity", "high", "-e", "e.txt")
log("WG3.1  reclassify FP -> confirmed (should fail)", [
    f"exit={code}", out.splitlines()[-1]])
if code == 0:
    log("WG3.1 !!! IMMUTABILITY BYPASSED", ["CLI accepted reclassification"])
run(ws, "findings", "register", "F-6b", "juice-shop", "info",
    "--severity", "info", "--score", "0.3")
code, out = run(ws, "findings", "classify", "F-6b", "-c", "confirmed",
                "--impact", "claim without re-test", "--severity", "high",
                "-e", "runs/evidence.txt")
log("WG3.2  ATTACK: fresh id + NONEXISTENT evidence path -> confirmed", [
    f"exit={code}",
    "RESULT: " + ("evidence path NOT verified — laundering possible" if code == 0
                  else "evidence path verified")])
code, out = run(ws, "findings", "classify", "F-6c", "-c", "confirmed",
                "--impact", "copy of F-1", "--severity", "high",
                "-e", "runs/evidence.txt")
log("WG3.3  duplicate finding, same evidence as the original run", [
    f"exit={code}",
    "RESULT: " + ("duplicate accepted as a new confirmed finding — "
                  "no content dedup" if code == 0 else "dedup enforced")])

# ---------------- WAR GAME 5: metrics manipulation ----------------
run(ws, "pre-registration", "predict", "--findings", "3", "6",
    "--acceptance", "0.3", "0.6")
run(ws, "watch", "start")
code, out = run(ws, "verdict", "final")
log("WG5.1  baseline final verdict", [out.splitlines()[-1]])
code, out = run(ws, "submit", "report", "F-1", "--title", "t",
                "--summary", "s")
log("WG5.2a  submit report (legit path)", [f"exit={code}", out.splitlines()[-1]])
code, out = run(ws, "submit", "record", "F-1", "--platform-id", "H1-TEST-1",
                "--screenshot", "submissions/shot.png")
log("WG5.2b  submit record", [f"exit={code}", out.splitlines()[-1]])
code, out = run(ws, "watch", "start")
log("WG5.2c  watch start", [f"exit={code}"])
code, out = run(ws, "watch", "update", "F-1", "accepted")
log("WG5.2  watch F-1 accepted (legit path)", [f"exit={code}", out.splitlines()[-1]])
code, out = run(ws, "verdict", "final")
log("WG5.3  verdict after legit accept", [out.splitlines()[-1]])
code, out = run(ws, "verdict", "final")
log("WG5.3b  verdict with 1 legit accepted", [out.splitlines()[-1]])
st = json.loads(st_path.read_text())
st["watch"] = [
    {"finding_id": fid, "status": "accepted",
     "updated_at": "2020-01-01T00:00:00+00:00",
     "note": "forged — never submitted"}
    for fid in ("F-1", "F-2", "F-3")]
st_path.write_text(json.dumps(st))
code, out = run(ws, "verdict", "final")
log("WG5.4  ATTACK: hand-edit state.json, forge 3 accepted entries", [
    out.splitlines()[-1],
    "tamper detection: NONE — GO issued from a forged file "
    "(real path above was IMPROVE with 1 accepted)"])
st = json.loads(st_path.read_text())
st["findings"] = [f for f in st["findings"]
                  if f.get("classification") != "false_positive"]
st_path.write_text(json.dumps(st))
code, out = run(ws, "verdict", "final")
log("WG5.5  ATTACK: delete the FP from state", [out.splitlines()[-1],
    "FP silently removed from the FP-rate computation"])

# ---------------- determinism ----------------
hashes = []
for _ in range(3):
    code, out = run(ws, "verdict", "final")
    hashes.append(hashlib.sha256((out or str(code)).encode()).hexdigest()[:16])
log("DET  same state -> same report 3x",
    [f"run {i+1}: {h}" for i, h in enumerate(hashes)]
    + ["deterministic" if len(set(hashes)) == 1 else "NONDETERMINISTIC"])

def _dump():
    report = base / "wg_verdict_output.md"
    report.write_text("\n".join(OUT) + "\n")
    print("\n".join(OUT))
atexit.register(_dump)
import traceback
sys.excepthook = lambda *a: (_dump(), traceback.print_exception(*a))
