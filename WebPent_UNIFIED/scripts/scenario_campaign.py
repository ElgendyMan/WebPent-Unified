"""SCENARIO CAMPAIGN — live end-to-end proof of the operator workflow
"URL + Credentials (+ Scope أحيانًا)" against the multi-principal scenario lab.

Modes (argv[1]):
  file      — scope file + credentials(user_a) + secondary identity(user_b):
              the FULL scenario. Expects self-login, two-layer recon diff,
              cross-principal BAC probing, scope_source=scope_file, report
              declaration + coverage matrix, checkpoint secret hygiene.
  inferred  — same engagement, NO scope file: scope_source must be
              inferred_from_url and the report must carry the caveat.
  badcreds  — wrong password: authentication_status must be an explicit
              failure (credentials_rejected / unauthenticated), never a
              silent pretend-authenticated run.

Evidence -> /home/z/my-project/verify/results/scenario_<mode>.json
"""
from __future__ import annotations

import glob
import json
import os
import socket
import subprocess
import sys
import time
from collections import Counter

MODE = sys.argv[1] if len(sys.argv) > 1 else "file"
assert MODE in ("file", "inferred", "badcreds"), MODE
LABEL = f"scenario_{MODE}"

TREE = "/home/z/my-project/verify/tree/webpent-goed"
sys.path.insert(0, os.path.join(TREE, "src"))
sys.path.insert(0, os.path.join(TREE, "tests"))
os.chdir(TREE)

TOOLBIN = "/home/z/my-project/tools-bin"
os.environ["WEBPENT_DATABASE_URL"] = f"sqlite:////home/z/my-project/verify/results/{LABEL}.db"
os.environ.pop("DATABASE_URL", None)
os.environ["WEBPENT_LLM_ENABLED"] = "false"   # deterministic scenario proof
os.environ["LLM_ENABLED"] = "false"
os.environ["DALFOX_PATH"] = f"{TOOLBIN}/dalfox"
os.environ["NUCLEI_PATH"] = f"{TOOLBIN}/nuclei"
os.environ["SQLMAP_PATH"] = (
    f"{TOOLBIN}/sqlmap" if os.path.exists(f"{TOOLBIN}/sqlmap") else "/home/z/.venv/bin/sqlmap"
)
os.environ["WEBPENT_CELERY_PAYLOAD_KEY"] = "scenario-campaign-crypto-key-0123456789abcdef"
os.environ["ADMIN_PASSWORD"] = "scenario-operator-password-1"
os.environ["WEBPENT_AUTH_ENABLED"] = "true"
os.environ["JWT_SECRET_KEY"] = "scenario-campaign-jwt-secret-0123456789abcdef0123456789"
os.environ["AUDIT_SECRET_KEY"] = "scenario-campaign-audit-secret-0123456789abcdef01234567"
os.environ["WEBPENT_ALLOW_PLAINTEXT_REDIS"] = "true"
os.environ["MAX_GRAPH_STEPS"] = "60"   # scenario surface + auth + diff needs headroom

import logging  # noqa: E402

logging.basicConfig(level=logging.INFO,
                    filename=f"/home/z/my-project/verify/results/{LABEL}_debug.log",
                    filemode="w")
logging.getLogger("alembic").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.ERROR)

EVIDENCE: dict = {"mode": MODE, "label": LABEL, "probes": {}, "defects_found": []}


def ev(probe: str, **kw):
    EVIDENCE["probes"].setdefault(probe, {}).update(kw)
    print(f"[EVIDENCE] {probe}: {json.dumps(kw, default=str, sort_keys=True)[:700]}")


def defect(msg: str):
    EVIDENCE["defects_found"].append(msg)
    print(f"[DEFECT] {msg}")


# ---------------------------------------------------------------- lab up
PORT_SOCK = socket.socket()
PORT_SOCK.bind(("127.0.0.1", 0))
PORT_N = PORT_SOCK.getsockname()[1]
PORT_SOCK.close()
uv = subprocess.Popen(
    ["/home/z/.venv/bin/python", "-m", "uvicorn", "scenario_lab.app:app",
     "--host", "127.0.0.1", "--port", str(PORT_N)],
    cwd=os.path.join(TREE, "tests"),
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
TARGET = f"http://127.0.0.1:{PORT_N}/"
print(f"[lab] scenario target {TARGET}")
time.sleep(4)

# Smoke the lab first: login works, IDOR is real, safe control is enforced.
import httpx  # noqa: E402

client = httpx.Client(base_url=TARGET, timeout=10)
anon_client = httpx.Client(base_url=TARGET, timeout=10)  # stays cookie-free
r_anon_inv = anon_client.get("/api/invoices/182")
r_login = client.post("/login", data={"username": "user_a", "password": "alpha-pass-1"})
sess_cookie = client.cookies.get("sess") or ""
r_auth_inv_b = client.get("/api/invoices/182")
r_safe = client.get("/api/invoices/mine")
r_anon_dash = anon_client.get("/dashboard")
ev("lab-smoke",
   anon_invoice_status=r_anon_inv.status_code,
   login_ok=r_login.status_code in (302, 303) and bool(sess_cookie),
   auth_cross_principal_status=r_auth_inv_b.status_code,
   auth_cross_principal_leaks=r_auth_inv_b.status_code == 200,
   safe_control_status=r_safe.status_code,
   anon_dashboard_bounces_to_signin="sign in" in r_anon_dash.text.lower())
if not (r_anon_inv.status_code == 401 and r_auth_inv_b.status_code == 200
        and sess_cookie and "sign in" in r_anon_dash.text.lower()):
    defect("lab-smoke mismatch — lab app does not match scenario design")

# ------------------------------------------------------------- engagement
THREAD = f"scenario-{MODE}-001"

SCOPE_FILE_TEXT = (
    "# scenario campaign scope contract\n"
    "127.0.0.1\n"
    "exclude-path: /admin/panel\n"
    "include-path: /\n"
)

CREDS = (
    {"username": "user_a", "password": "WRONG-password"}
    if MODE == "badcreds"
    else {"username": "user_a", "password": "alpha-pass-1"}
)
IDENTITY_PROFILES = {} if MODE == "badcreds" else {
    "user_b": {
        "name": "user_b",
        "role": "secondary",
        "credentials": {"username": "user_b", "password": "beta-pass-2"},
        "owned_object_ids": ["182"],
    },
}

# Clean the report output dir so post-run reads see THIS run's report.
OUTPUT_DIR = os.path.join(TREE, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)
for stale in glob.glob(os.path.join(OUTPUT_DIR, "*")):
    try:
        os.remove(stale)
    except OSError:
        pass

from webpent.workers.pentest_worker import run_pentest_task  # noqa: E402

t_start = time.time()
run_kwargs = dict(
    target_url=TARGET,
    is_portswigger=False,
    thread_id=THREAD,
    auto_approve=True,
    client_id="scenario-client",
    engagement_id=THREAD,
    skip_recon=False,
    credentials=CREDS,
    session_cookies={},
    identity_profiles=IDENTITY_PROFILES,
)
if MODE == "file":
    run_kwargs["scope_file_text"] = SCOPE_FILE_TEXT
try:
    res = run_pentest_task.run(**run_kwargs)
    ev("campaign", status=res.get("status"),
       findings_returned=len(res.get("findings") or []),
       elapsed_s=round(time.time() - t_start, 1))
except Exception as exc:  # noqa: BLE001
    ev("campaign", error=str(exc)[:400], elapsed_s=round(time.time() - t_start, 1))
    defect(f"campaign exception: {str(exc)[:250]}")
    res = {}
finally:
    uv.terminate()
    try:
        uv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        uv.kill()

# ------------------------------------------------- checkpoint read-back
def checkpoint_state(thread_id: str):
    from webpent.graph.checkpoints import get_checkpointer

    ws_dbs = sorted(
        glob.glob(
            f"/home/z/.webpent/workspaces/scenario-client-{thread_id}-*/databases/webpent.sqlite3"
        ),
        key=os.path.getmtime,
    )
    cp_path = None
    if ws_dbs:
        latest_ws = os.path.dirname(os.path.dirname(ws_dbs[-1]))
        cand = os.path.join(latest_ws, "sessions", "checkpoints.sqlite3")
        cp_path = cand if os.path.exists(cand) else None
    if not cp_path:
        return None, ws_dbs
    with get_checkpointer(cp_path) as cp:
        snap = cp.get_tuple({"configurable": {"thread_id": thread_id}})
        if snap is None:
            return None, ws_dbs
        return (snap.checkpoint.get("channel_values", {}) or {}), ws_dbs


vals, ws_dbs = checkpoint_state(THREAD)
if vals is None:
    ev("checkpoint", present=False, workspaces=len(ws_dbs))
    defect("checkpoint missing")
else:
    # ---- scenario phase 1: authentication bootstrap honesty ----
    auth_status = str(vals.get("authentication_status") or "")
    ev("auth-bootstrap", status=auth_status,
       expected=("credentials_rejected_or_unauthenticated" if MODE == "badcreds"
                 else "authenticated"))
    if MODE == "badcreds":
        if auth_status == "authenticated":
            defect("badcreds run claims authenticated — silent fake login!")
        elif auth_status not in ("credentials_rejected", "unauthenticated", ""):
            defect(f"badcreds run has unclear auth status: {auth_status}")
    else:
        if auth_status != "authenticated":
            defect(f"expected self-login to succeed, got auth status={auth_status!r}")

    identity_records = dict(vals.get("identity_records") or {})
    ev("identity-records", count=len(identity_records),
       names=sorted(identity_records.keys())[:6])
    if MODE in ("file", "inferred") and not identity_records:
        defect("no identity records recorded for authenticated run")

    liveness = dict(vals.get("session_liveness") or {})
    ev("session-liveness", recorded=bool(liveness),
       status=str(liveness.get("status") or ""),
       reauth_attempts=liveness.get("reauth_attempts"),
       downgrade=bool(liveness.get("downgrade_requested")))

    pre_snapshot = dict(vals.get("pre_auth_snapshot") or {})
    ev("pre-auth-snapshot", captured=bool(pre_snapshot),
       status=str(pre_snapshot.get("status") or ""),
       links=len(pre_snapshot.get("links") or []),
       forms=len(pre_snapshot.get("forms") or []))

    # ---- scenario phase 2: two-layer recon diff ----
    diff = dict(vals.get("auth_surface_diff") or {})
    counts = dict(diff.get("counts") or {})
    ev("auth-surface-diff", counts=counts,
       endpoints=len(diff.get("endpoints") or diff.get("entries") or []))
    if MODE in ("file", "inferred") and auth_status == "authenticated":
        if int(counts.get("auth_only") or 0) == 0:
            defect("auth_only surface count is 0 — two-layer diff did not fire")

    # ---- scenario phase 0/10: scope source contract ----
    scope_source = str(vals.get("scope_source") or "")
    declaration = dict(vals.get("scope_declaration") or {})
    ev("scope-contract", source=scope_source,
       fingerprint=str(declaration.get("fingerprint") or "")[:20],
       allow_entries=len(declaration.get("allow_entries") or []),
       exclude_paths=len(declaration.get("exclude_paths") or []),
       expected=("scope_file" if MODE == "file" else "inferred_from_url"))
    expected_source = "scope_file" if MODE == "file" else "inferred_from_url"
    if scope_source != expected_source:
        defect(f"scope_source={scope_source!r} expected {expected_source!r}")

    # ---- secret hygiene (phase 0.3/9) ----
    ckpt_creds = vals.get("credentials") or {}
    ckpt_cookies = vals.get("session_cookies") or {}
    blob = json.dumps(
        {k: vals.get(k) for k in ("messages", "decision_log", "engagement_limitations")},
        default=str,
    )
    secrets_leaked = any(
        s in blob for s in ("alpha-pass-1", "beta-pass-2", sess_cookie)
        if sess_cookie
    )
    # Whole-checkpoint scan: the serialized channel_values blob must not
    # contain plaintext passwords (username may be present — it is not a
    # secret; scrubbed_credentials deliberately keeps it).
    import sqlite3 as _sq

    _cp_db = sorted(
        glob.glob(
            f"/home/z/.webpent/workspaces/scenario-client-{THREAD}-*/sessions/checkpoints.sqlite3"
        )
    )[-1]
    _raw = _sq.connect(_cp_db).execute(
        "select checkpoint from checkpoints order by rowid desc limit 1"
    ).fetchone()[0]
    pw_in_checkpoint = (b"alpha-pass-1" in _raw) or (b"beta-pass-2" in _raw)
    cookie_in_checkpoint = bool(sess_cookie) and (sess_cookie.encode() in _raw)
    ev("secret-hygiene", checkpoint_credentials_len=len(ckpt_creds),
       checkpoint_credentials_keys=sorted(str(k) for k in ckpt_creds)[:6],
       checkpoint_cookies_len=len(ckpt_cookies),
       plaintext_password_in_checkpoint=pw_in_checkpoint,
       session_cookie_value_in_checkpoint=cookie_in_checkpoint,
       plaintext_secrets_in_safe_channels=secrets_leaked)
    if pw_in_checkpoint:
        defect("plaintext password present in checkpoint channel_values")
    if cookie_in_checkpoint:
        defect("session cookie value present in checkpoint channel_values")
    if secrets_leaked:
        defect("plaintext credentials/cookies leaked into LLM-visible channels")

    # ---- findings / BAC evidence ----
    findings = vals.get("findings") or []
    f_summary = []
    for f in findings:
        f_summary.append({
            "title": str(getattr(f, "title", ""))[:60],
            "class": str(getattr(f, "vuln_class", "?")),
            "confidence": str(getattr(f, "confidence_level", "?")),
            "url": str(getattr(f, "url", ""))[:70],
        })
    ev("findings-state", count=len(findings), findings=f_summary[:16],
       conf_levels=sorted({str(getattr(f, "confidence_level", "")) for f in findings}))

    bac_findings = [
        f for f in findings
        if str(getattr(f, "vuln_class", "")).lower() in ("idor", "bac", "access_control",
                                                         "broken_access_control")
        or "invoice" in str(getattr(f, "url", "")).lower()
    ]
    ev("bac-evidence", related=len(bac_findings),
       rows=[{"t": str(getattr(f, "title", ""))[:60],
              "c": str(getattr(f, "confidence_level", ""))} for f in bac_findings][:6])
    gaps = vals.get("bac_coverage_gaps") or []
    ev("bac-gaps", count=len(gaps))

    trace = vals.get("node_step_trace") or []
    ev("step-trace", total=len(trace),
       nodes=Counter(e.get("node", "?") for e in trace if isinstance(e, dict)).most_common(10))

# ------------------------------------------------------- report contract
# DEFECT SC-1 evidence path: the reporter writes into the WORKSPACE
# reports/ directory (report.md), not the process CWD output/ dir.
reports = sorted(
    glob.glob(
        f"/home/z/.webpent/workspaces/scenario-client-{THREAD}-*/reports/report.md"
    ),
    key=os.path.getmtime,
)
report_text = ""
if reports:
    with open(reports[-1], encoding="utf-8", errors="replace") as fh:
        report_text = fh.read()
report_has_decl = "## Scope & Session Declaration" in report_text
report_has_matrix = "## Coverage Matrix" in report_text
report_scope_label = (
    "scope_file" if "`scope_file`" in report_text
    else ("inferred_from_url" if "inferred_from_url" in report_text else "missing")
)
report_has_caveat = "Inferred-scope caveat" in report_text
ev("report-contract", report=os.path.basename(reports[-1]) if reports else None,
   has_declaration=report_has_decl, has_coverage_matrix=report_has_matrix,
   scope_label=report_scope_label, has_inferred_caveat=report_has_caveat,
   size_chars=len(report_text))
if not reports:
    defect("no markdown report written")
else:
    if not report_has_decl or not report_has_matrix:
        defect("report missing scenario declaration/coverage matrix sections")
    if MODE == "file" and report_scope_label != "scope_file":
        defect("report does not label scope_file source")
    if MODE in ("inferred", "badcreds") and report_scope_label == "missing":
        defect("report does not surface any scope source label")
    if MODE == "inferred" and not report_has_caveat:
        defect("inferred run report missing the inferred-scope caveat")
    if any(s in report_text for s in ("alpha-pass-1", "beta-pass-2")):
        defect("report contains plaintext credentials!")

# ------------------------------------------------------------------ save
OUT = f"/home/z/my-project/verify/results/{LABEL}.json"
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(EVIDENCE, fh, indent=2, default=str)
print(f"[done] evidence -> {OUT}  defects={len(EVIDENCE['defects_found'])}")
sys.exit(1 if EVIDENCE["defects_found"] else 0)
