"""
WebPent — Approved Synthetic Target v11
Qualification-grade synthetic target.
15 cases × 10 classes.
Local-only, synthetic, no external access, no real credentials.
Port: 9200
"""

from fastapi import FastAPI, Header, Query
from fastapi.responses import JSONResponse

app = FastAPI()

# === Identities ===
USERS = {
    "alice":   {"id": "u001", "role": "admin",    "tenant": "tenant_a"},
    "bob":     {"id": "u002", "role": "user",     "tenant": "tenant_a"},
    "carol":   {"id": "u003", "role": "viewer",   "tenant": "tenant_a"},
    "dave":    {"id": "u004", "role": "admin",    "tenant": "tenant_b"},
    "eve":     {"id": "u005", "role": "user",     "tenant": "tenant_b"},
    "frank":   {"id": "u006", "role": "requester","tenant": "tenant_a"},
    "grace":   {"id": "u007", "role": "approver", "tenant": "tenant_a"},
}

ROLE_LEVEL = {"anonymous": 0, "viewer": 1, "user": 1, "requester": 1,
              "approver": 2, "editor": 2, "owner": 2,
              "manager": 3, "admin": 4}

# === State ===
PROFILES = {
    "u001": {"name": "Alice", "ssn": "XXX-XX-1001", "email": "alice@internal", "tenant": "tenant_a"},
    "u002": {"name": "Bob",   "ssn": "XXX-XX-1002", "email": "bob@internal",   "tenant": "tenant_a"},
    "u003": {"name": "Carol", "ssn": "XXX-XX-1003", "email": "carol@internal", "tenant": "tenant_a"},
    "u004": {"name": "Dave",  "ssn": "XXX-XX-1004", "email": "dave@internal",  "tenant": "tenant_b"},
    "u005": {"name": "Eve",   "ssn": "XXX-XX-1005", "email": "eve@internal",   "tenant": "tenant_b"},
}

ADMIN_DATA = {"users": 150, "active": 142, "audit_events": 847}
AUDIT_LOG = ["login:alice", "update:bob_profile", "transfer:u002→u001:100"]
BILLING = {"tenant_a": {"total": 52400, "records": ["INV-001", "INV-002"]},
           "tenant_b": {"total": 18700, "records": ["INV-010"]}}
TENANT_INTERNAL = {"tenant_a": {"config": "secret_a", "keys": 3},
                   "tenant_b": {"config": "secret_b", "keys": 1}}
MESSAGES = {"u001": ["Re: Q1 planning", "Confidential: budget"],
            "u002": ["Lunch tomorrow?", "Project update"]}
WORKFLOWS = {"wf-001": {"status": "pending", "requester": "u006", "approver": None, "amount": 10000}}
ACCOUNTS = {"u001": {"balance": 5000.0}, "u002": {"balance": 1000.0}}
RESET_TOKENS = {}
MASS_STORE = {}  # For mass assignment testing
RACE_COUNTER = {"value": 100}

def get_user(x):
    return USERS.get(x)

def h(x, extra=None):
    u = get_user(x)
    hdr = {
        "X-Actor-Echo": x or "anon",
        "X-Actor-Role": u["role"] if u else "none",
        "X-Actor-Tenant": u["tenant"] if u else "none",
        "X-Auth-State": "authenticated" if u else "unauth",
    }
    if extra: hdr.update(extra)
    return hdr

# === Entry points ===
@app.get("/")
async def root():
    return JSONResponse(content={"svc": "synth-v11", "v": "1.0"})

@app.get("/health")
async def health(x_actor: str | None = Header(None)):
    return JSONResponse(content={"ok": True}, headers=h(x_actor, {"X-Resource-Type": "health"}))

# === Case 01: IDOR profile ===
@app.get("/api/v11/users/{uid}/profile")
async def case01_idor_profile(uid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    profile = PROFILES.get(uid, {})
    hdrs = h(x_actor, {"X-Resource-Type": "profile_detail", "X-Resource-Owner": uid,
                        "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content=profile, headers=hdrs)

@app.get("/ctrl/api/v11/users/{uid}/profile")
async def case01_idor_profile_ctrl(uid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "profile_detail", "X-Resource-Owner": uid})
    if u["id"] != uid and ROLE_LEVEL.get(u["role"], 0) < 4:
        hdrs["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=hdrs)
    hdrs["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=PROFILES.get(uid, {}), headers=hdrs)

# === Case 02: IDOR other tenant ===
@app.get("/api/v11/tenant/{tid}/users/{uid}")
async def case02_idor_tenant(tid: str, uid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "tenant_user", "X-Resource-Owner": uid,
                        "X-Resource-Tenant": tid, "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content=PROFILES.get(uid, {}), headers=hdrs)

@app.get("/ctrl/api/v11/tenant/{tid}/users/{uid}")
async def case02_idor_tenant_ctrl(tid: str, uid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "tenant_user", "X-Resource-Owner": uid, "X-Resource-Tenant": tid})
    if u["tenant"] != tid and ROLE_LEVEL.get(u["role"], 0) < 4:
        hdrs["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=hdrs)
    hdrs["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=PROFILES.get(uid, {}), headers=hdrs)

# === Case 03: BAC dashboard ===
@app.get("/api/v11/admin/dashboard")
async def case03_bac_dashboard(x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "admin_dashboard", "X-Privilege-Required": "admin",
                        "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content=ADMIN_DATA, headers=hdrs)

@app.get("/ctrl/api/v11/admin/dashboard")
async def case03_bac_dashboard_ctrl(x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "admin_dashboard", "X-Privilege-Required": "admin"})
    if u["role"] != "admin":
        hdrs["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=hdrs)
    hdrs["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=ADMIN_DATA, headers=hdrs)

# === Case 04: BAC audit log ===
@app.get("/api/v11/admin/audit-log")
async def case04_bac_audit(x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "audit_log", "X-Privilege-Required": "admin",
                        "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"entries": AUDIT_LOG}, headers=hdrs)

@app.get("/ctrl/api/v11/admin/audit-log")
async def case04_bac_audit_ctrl(x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "audit_log", "X-Privilege-Required": "admin"})
    if u["role"] != "admin":
        hdrs["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=hdrs)
    hdrs["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content={"entries": AUDIT_LOG}, headers=hdrs)

# === Case 05: Privilege escalation billing ===
@app.get("/api/v11/billing/{tid}/records")
async def case05_privesc_billing(tid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "billing_records", "X-Resource-Tenant": tid,
                        "X-Privilege-Required": "admin", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content=BILLING.get(tid, {}), headers=hdrs)

@app.get("/ctrl/api/v11/billing/{tid}/records")
async def case05_privesc_billing_ctrl(tid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "billing_records", "X-Resource-Tenant": tid, "X-Privilege-Required": "admin"})
    if u["role"] != "admin" and u["tenant"] != tid:
        hdrs["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=hdrs)
    hdrs["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=BILLING.get(tid, {}), headers=hdrs)

# === Case 06: Business logic — negative amount transfer ===
@app.get("/api/v11/accounts/{from_user}/transfer")
async def case06_bizlogic_transfer(from_user: str, to_user: str = Query(...),
                                    amount: float = Query(...), x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    # VULNERABLE: negative amounts not validated — bob can "send" -100 to alice, stealing from her
    hdrs = h(x_actor, {"X-Resource-Type": "transfer", "X-Authorization-Outcome": "granted_full",
                        "X-Effective-Privilege-Granted": u["role"]})
    if from_user in ACCOUNTS and to_user in ACCOUNTS:
        ACCOUNTS[from_user]["balance"] -= amount  # Negative amount = INCREASE for from_user
        ACCOUNTS[to_user]["balance"] += abs(amount)   # Receiver always gets positive
    return JSONResponse(content={
        "from": from_user, "to": to_user, "amount": amount,
        "from_balance": ACCOUNTS.get(from_user, {}).get("balance", 0),
        "to_balance": ACCOUNTS.get(to_user, {}).get("balance", 0),
    }, headers=hdrs)

# === Case 07: Tenant isolation failure ===
@app.get("/api/v11/tenant/{tid}/internal-data")
async def case07_tenant_isolation(tid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "tenant_internal", "X-Resource-Tenant": tid,
                        "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content=TENANT_INTERNAL.get(tid, {}), headers=hdrs)

@app.get("/ctrl/api/v11/tenant/{tid}/internal-data")
async def case07_tenant_isolation_ctrl(tid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "tenant_internal", "X-Resource-Tenant": tid})
    if u["tenant"] != tid:
        hdrs["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=hdrs)
    hdrs["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=TENANT_INTERNAL.get(tid, {}), headers=hdrs)

# === Case 08: Workflow authorization — self-approval ===
@app.get("/api/v11/workflows/{wfid}/approve")
async def case08_workflow_auth(wfid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    wf = WORKFLOWS.get(wfid, {})
    # VULNERABLE: requester can approve their own workflow
    hdrs = h(x_actor, {"X-Resource-Type": "workflow_approval",
                        "X-Workflow-Requester": wf.get("requester", ""),
                        "X-Authorization-Outcome": "granted_full"})
    wf["status"] = "approved"
    wf["approver"] = u["id"]
    return JSONResponse(content={"wfid": wfid, "status": "approved", "approver": u["id"]}, headers=hdrs)

# === Case 09: Sensitive data exposure — messages ===
@app.get("/api/v11/messages/{uid}/inbox")
async def case09_sdata_messages(uid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "private_messages", "X-Resource-Owner": uid,
                        "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"messages": MESSAGES.get(uid, [])}, headers=hdrs)

@app.get("/ctrl/api/v11/messages/{uid}/inbox")
async def case09_sdata_messages_ctrl(uid: str, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "private_messages", "X-Resource-Owner": uid})
    if u["id"] != uid and ROLE_LEVEL.get(u["role"], 0) < 4:
        hdrs["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=hdrs)
    hdrs["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content={"messages": MESSAGES.get(uid, [])}, headers=hdrs)

# === Case 10: Multi-step chain — password reset ===
@app.get("/api/v11/auth/reset/request")
async def case10_multistep_request(for_user: str = Query(...), x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    # VULNERABLE: anyone can request a reset token for any user
    import uuid as _uuid
    token = str(_uuid.uuid4())
    RESET_TOKENS[token] = for_user
    hdrs = h(x_actor, {"X-Resource-Type": "password_reset_request",
                        "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"status": "token_generated", "token": token}, headers=hdrs)

# === Case 11: Mass assignment ===
@app.post("/api/v11/users/{uid}/update")
async def case11_mass_assign(uid: str, data: dict = None, x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    # VULNERABLE: any field can be updated including role
    if uid in PROFILES and data:
        PROFILES[uid].update(data)
        MASS_STORE[uid] = dict(PROFILES[uid])
    hdrs = h(x_actor, {"X-Resource-Type": "user_update", "X-Resource-Owner": uid,
                        "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"updated": uid, "fields": list(data.keys()) if data else []}, headers=hdrs)

# === Case 12: Race condition window ===
@app.get("/api/v11/counter/claim")
async def case12_race_condition(x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    # VULNERABLE: check-then-act race window
    current = RACE_COUNTER["value"]
    if current > 0:
        RACE_COUNTER["value"] = current - 1
        claimed = True
    else:
        claimed = False
    hdrs = h(x_actor, {"X-Resource-Type": "limited_claim",
                        "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"claimed": claimed, "remaining": RACE_COUNTER["value"]}, headers=hdrs)

# === Case 13: Clean — legitimate self access ===
@app.get("/api/v11/me")
async def case13_clean_self(x_actor: str | None = Header(None)):
    u = get_user(x_actor)
    if not u:
        return JSONResponse(status_code=401, content={"error": "unauth"}, headers=h(x_actor))
    hdrs = h(x_actor, {"X-Resource-Type": "self_profile", "X-Resource-Owner": u["id"],
                        "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"id": u["id"], "name": PROFILES.get(u["id"], {}).get("name")}, headers=hdrs)

# === Case 14: Clean — public info ===
@app.get("/api/v11/public/about")
async def case14_clean_public(x_actor: str | None = Header(None)):
    hdrs = h(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"version": "1.0", "company": "SynthCorp"}, headers=hdrs)

# === Case 15: Clean — health/status ===
@app.get("/api/v11/status")
async def case15_clean_status(x_actor: str | None = Header(None)):
    hdrs = h(x_actor, {"X-Resource-Type": "system_status", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"status": "operational", "uptime": 99.9}, headers=hdrs)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9200, log_level="error")
