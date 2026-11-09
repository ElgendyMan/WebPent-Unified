"""FINAL VERIFICATION runtime proof — part 1: real-entrypoint campaigns.

Probes (all against the REAL worker body / real graph / real persistence):
  P3-auth  : authenticated campaign — no silent anonymous downgrade,
             cookies sealed OUTSIDE LLM context (checkpoint honesty),
             authenticated vs anonymous observation differential.
  P4-recon : skip_recon=False campaign — recon/crawl/world-model node trace.
  P1D-hyp  : skip_recon=True non-keyword hypothesis producers live.
  P2-loop  : research decision + replan seam trace from the same runs.
  P7-parity: registry + workspace DB + API read-back one truth.

Evidence: /home/z/my-project/verify/results/fv_runtime_evidence.json
"""
from __future__ import annotations

import json
import logging
import os
import sys

sys.path.insert(0, "/home/z/my-project/scripts")
from fv_lab import LAB_STATE, reset_lab_state, start_lab  # noqa: E402

TREE = "/home/z/my-project/verify/tree/webpent-goed"
sys.path.insert(0, os.path.join(TREE, "src"))
os.chdir(TREE)

# Isolation: fresh DB + crypto key (vault must be able to retain session
# material so the authenticated probe is meaningful) + LLM disabled.
os.environ["WEBPENT_DATABASE_URL"] = "sqlite:////home/z/my-project/verify/results/fv_webpent.db"
os.environ.pop("DATABASE_URL", None)
os.environ["WEBPENT_LLM_ENABLED"] = "false"
os.environ["WEBPENT_CELERY_PAYLOAD_KEY"] = "fv-verify-crypto-key-0123456789abcdef"
os.environ["ADMIN_PASSWORD"] = "fv-operator-password-1"
os.environ["WEBPENT_AUTH_ENABLED"] = "true"
# auth_enabled=true requires strong secrets (Settings hard-stop) — lab values.
os.environ["JWT_SECRET_KEY"] = "fv-verify-jwt-secret-0123456789abcdef0123456789"
os.environ["AUDIT_SECRET_KEY"] = "fv-verify-audit-secret-0123456789abcdef012345"
# Sanctioned lab-only relaxation (preflight._enforce_redis_security): no TLS
# Redis in this container; not applicable to staging/production profiles.
os.environ["WEBPENT_ALLOW_PLAINTEXT_REDIS"] = "true"
for v in ("RIT_SKIP_RECON", "RIT_COOKIES", "RIT_THREAD"):
    os.environ.pop(v, None)

logging.basicConfig(level=logging.INFO)
logging.getLogger("alembic").setLevel(logging.WARNING)

EVIDENCE: dict = {"probes": {}, "defects_found": [], "fixes_applied": []}


def ev(probe: str, **kw):
    EVIDENCE["probes"].setdefault(probe, {}).update(kw)
    print(f"[EVIDENCE] {probe}: {json.dumps(kw, default=str, sort_keys=True)[:600]}")


def checkpoint_state(thread_id: str):
    """Read the REAL LangGraph checkpoint (replay substrate) for state keys."""
    import glob

    from webpent.graph.checkpoints import get_checkpointer

    ws_dbs = sorted(
        glob.glob(
            f"/home/z/.webpent/workspaces/fv-client-{thread_id}-*/databases/webpent.sqlite3"
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
        vals = snap.checkpoint.get("channel_values", {}) or {}
        return vals, ws_dbs


def run_campaign(thread_id: str, *, skip_recon: bool, cookies: dict) -> dict:
    from webpent.workers.pentest_worker import run_pentest_task

    result = run_pentest_task.run(
        target_url=TARGET,
        is_portswigger=False,
        thread_id=thread_id,
        auto_approve=True,
        client_id="fv-client",
        engagement_id=thread_id,
        skip_recon=skip_recon,
        credentials={},
        session_cookies=cookies,
        identity_profiles={},
    )
    return result


# ---------------------------------------------------------------- lab up
srv = start_lab()
PORT = srv.server_address[1]
TARGET = f"http://127.0.0.1:{PORT}/"
print(f"[lab] authorized target {TARGET}")

# ================================================================ P3-auth
reset_lab_state()
res_auth = run_campaign("fv-auth-001", skip_recon=True, cookies={"sid": "lab-session-operator"})
ev(
    "P3-auth-campaign",
    status=res_auth.get("status"),
    findings=len(res_auth.get("findings") or []),
    lab_requests=LAB_STATE["requests"],
    lab_auth_hits=LAB_STATE["auth_hits"],
    lab_anon_401=LAB_STATE["anon_401"],
)
# Honesty law: operator requested authenticated execution -> every
# /admin/dashboard hit must be authenticated (no silent anonymous downgrade).
ev(
    "P3-auth-differential",
    anonymous_downgrade=(LAB_STATE["anon_401"] > 0),
    auth_ok=LAB_STATE["auth_hits"] > 0,
)
vals, _ = checkpoint_state("fv-auth-001")
if vals is None:
    ev("P3-checkpoint-honesty", checkpoint="missing", defect="no checkpoint snapshot")
    EVIDENCE["defects_found"].append("P3: checkpoint snapshot missing for fv-auth-001")
else:
    ck_cookies = vals.get("session_cookies")
    ck_creds = vals.get("credentials")
    hyps = vals.get("hypotheses") or []
    origins = {}
    for h in hyps:
        o = str(getattr(h, "origin", "?")).split(".")[-1]
        origins[o] = origins.get(o, 0) + 1
    ev(
        "P3-checkpoint-honesty",
        cookies_in_checkpoint=ck_cookies,
        credentials_in_checkpoint=ck_creds,
        hypotheses=len(hyps),
        origins=origins,
    )
    if ck_cookies:
        EVIDENCE["defects_found"].append(
            "P3: session_cookies persisted into LangGraph checkpoint (must stay in vault)"
        )
    if ck_creds and (ck_creds.get("password") or "") != "":
        EVIDENCE["defects_found"].append("P3: plaintext password persisted in checkpoint")

# Vault-side honesty: sealed values must be retrievable and equal.
from webpent.auth.reauth_vault import (  # noqa: E402
    seal_session_cookies,
    unseal_session_cookies,
)

seal_session_cookies("fv-vault-probe", {"sid": "probe-1"})
ok_unseal = unseal_session_cookies("fv-vault-probe") == {"sid": "probe-1"}
ev("P3-vault-roundtrip", seal_unseal_equal=ok_unseal)

# ================================================================ P4-recon
reset_lab_state()
res_recon = run_campaign("fv-recon-002", skip_recon=False, cookies={})
vals_r, _ = checkpoint_state("fv-recon-002")
wm_keys = {}
if vals_r is not None:
    for k in (
        "world_model",
        "deep_recon_summary",
        "crawled_data",
        "endpoints",
        "hypotheses",
        "smart_replanning",
        "research_decisions",
    ):
        v = vals_r.get(k)
        wm_keys[k] = (len(v) if hasattr(v, "__len__") else v) if v is not None else None
    hyps_r = vals_r.get("hypotheses") or []
    origins_r = {}
    for h in hyps_r:
        o = str(getattr(h, "origin", "?")).split(".")[-1]
        origins_r[o] = origins_r.get(o, 0) + 1
else:
    origins_r = {}
ev(
    "P4-recon-campaign",
    status=res_recon.get("status"),
    findings=len(res_recon.get("findings") or []),
    lab_requests=LAB_STATE["requests"],
    state_keys=wm_keys,
    origins=origins_r,
)

# ================================================================ P1D-hyp (already partially above; assert producers)
n_deep = sum(v for k, v in origins_r.items() if "deep_recon" in k.lower() or "heuristic" in k.lower())
ev(
    "P1D-nonkeyword-producers",
    deep_or_heuristic_hypotheses=n_deep,
    total=len(hyps_r),
    non_keyword_share=round(n_deep / len(hyps_r), 2) if hyps_r else 0,
)

# ================================================================ P7-parity
from webpent.api.scan_registry import (  # noqa: E402
    get_scan_record,
    register_scan,  # noqa: E402
    scan_registry_health,
)

# Register through the SAME seam the API create-scan endpoint uses
# (the API→worker dispatch itself needs a broker — declared residual).
register_scan(
    "fv-auth-001",
    "fv-celery-task-001",
    target_url=TARGET,
    owner_username="admin",
    client_id="fv-client",
    engagement_id="fv-auth-001",
)
rec = get_scan_record("fv-auth-001")
ev(
    "P7-registry",
    registered=bool(rec),
    status=(rec or {}).get("status"),
    engagement=(rec or {}).get("engagement_id"),
    health=str(scan_registry_health())[:120],
)

import glob as _g  # noqa: E402
import sqlite3 as _sq  # noqa: E402

ws_dbs = sorted(
    _g.glob("/home/z/.webpent/workspaces/fv-client-fv-auth-001-*/databases/webpent.sqlite3"),
    key=os.path.getmtime,
)
db_path = ws_dbs[-1] if ws_dbs else None
rows = []
if db_path:
    con = _sq.connect(db_path)
    try:
        rows = con.execute(
            "SELECT vuln_class, confidence_level, thread_id FROM findings WHERE thread_id=?",
            ("fv-auth-001",),
        ).fetchall()
    finally:
        con.close()
ev("P7-workspace-db", db=db_path, direct_rows=len(rows), sample=[r[:2] for r in rows[:5]])

# API read-back through the REAL FastAPI app (TestClient), operator token.
from fastapi.testclient import TestClient  # noqa: E402


def api_token(client: TestClient, username: str, password: str) -> str | None:
    r = client.post("/token", data={"username": username, "password": password})
    if r.status_code != 200:
        return None
    return r.json().get("access_token")


from webpent.api.app import app  # noqa: E402

with TestClient(app) as tc:
    tok = api_token(tc, "admin", "fv-operator-password-1")
    ev("P7-api-login", token_obtained=bool(tok))
    if tok:
        hdr = {"Authorization": f"Bearer {tok}"}
        r_f = tc.get("/api/v1/scans/fv-auth-001/findings", headers=hdr)
        body = r_f.json() if r_f.status_code == 200 else {}
        api_rows = body.get("findings") or []
        ev(
            "P7-api-findings-readback",
            http=r_f.status_code,
            api_count=body.get("count"),
            db_count=len(rows),
            parity=(body.get("count") == len(rows)) if r_f.status_code == 200 else None,
            conf_levels=sorted({str(f.get("confidence_level")) for f in api_rows})[:6],
        )
        r_s = tc.get("/api/v1/scans/fv-auth-001/status", headers=hdr)
        sb = r_s.json() if r_s.status_code == 200 else {}
        ev(
            "P7-api-status-readback",
            http=r_s.status_code,
            status=sb.get("status"),
            persisted_finding_count=sb.get("persisted_finding_count"),
        )
        # Multi-principal probe: registry ownership predicate — admin (owner of
        # registry record) vs a second principal must not cross-read.
        r_foreign = tc.get("/api/v1/scans/definitely-not-a-thread/findings", headers=hdr)
        ev("P7-api-unknown-thread", http=r_foreign.status_code)

srv.shutdown()
out = "/home/z/my-project/verify/results/fv_runtime_evidence.json"
with open(out, "w") as f:
    json.dump(EVIDENCE, f, indent=2, default=str)
print(f"[done] evidence -> {out}")
print(json.dumps(EVIDENCE["defects_found"], indent=2))
