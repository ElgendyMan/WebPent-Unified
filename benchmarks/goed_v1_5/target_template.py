"""
GOED v1.5 Generative Target: @@TARGET_ID@@
Seed: @@SEED@@ | Port: @@PORT@@
Naming convention: @@ROUTE_PREFIX@@ENTITY@@ROUTE_SUFFIX@@
Roles: @@ROLES_STR@@
Tenants: @@TENANTS_STR@@

GENERATED FILE — DO NOT EDIT MANUALLY
Local-only, synthetic, no external access, no real credentials.
"""
from fastapi import FastAPI, Header, Query
from fastapi.responses import JSONResponse
from typing import Optional

app = FastAPI()

ROLES = @@ROLES_LIST@@
ROLE_LEVEL = @@ROLE_LEVEL@@
TENANTS = @@TENANTS_LIST@@
OBJECTS = @@OBJECTS_LIST@@
FIELDS = @@FIELDS_DICT@@
ACTORS = @@ACTORS_DICT@@

SENSITIVE_DATA = @@SENSITIVE_DATA@@
ADMIN_DATA = {"system_status": "operational", "record_count": 150, "events": ["login", "logout", "access"]}
BILLING_DATA = {t: {"invoices": [f"INV-{i}" for i in range(1, 4)], "total": 50000 + s * 1000} for s, t in enumerate(TENANTS)}
TENANT_INTERNAL = {t: {"internal_metrics": f"sensitive_{t}_data"} for t in TENANTS}
MESSAGES = {OBJECTS[0]: ["private_msg_1", "private_msg_2"], OBJECTS[1]: ["personal_notification"]}
WORKFLOWS = {"@@WF_ID@@": {"status": "pending_approval", "requester": OBJECTS[0]}}
ACCOUNTS = {OBJECTS[0]: {"balance": 5000}, OBJECTS[1]: {"balance": 1000}}
AUDIT_LOG = ["event_1", "event_2", "event_3"]
AUTH_TOKENS = {}

def get_actor(x_actor):
    return ACTORS.get(x_actor)

def ctx_headers(x_actor, extra=None):
    actor = get_actor(x_actor)
    h = {
        "X-Actor-Echo": x_actor or "anonymous",
        "X-Actor-Role": actor["role"] if actor else "none",
        "X-Actor-Tenant": actor["tenant"] if actor else "none",
        "X-Auth-State": "authenticated" if actor else "unauthenticated",
    }
    if extra:
        h.update(extra)
    return h

# === Standard entry points ===
@app.get("/")
async def root():
    return JSONResponse(content={
        "service": "@@TARGET_ID@@",
        "version": "v1.5",
        "links": ["@@ROUTE_PREFIX@@health@@ROUTE_SUFFIX@@", "@@ROUTE_PREFIX@@openapi@@ROUTE_SUFFIX@@"]
    })

@app.get("/openapi.json")
async def openapi_standard(x_actor: Optional[str] = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "openapi_spec", "X-Authorization-Outcome": "granted_full"})
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "@@TARGET_ID@@", "version": "1.0"},
        "paths": {
            "@@ROUTE_PREFIX@@objects/{id}@@ROUTE_SUFFIX@@": {"get": {"summary": "Retrieve object"}},
            "@@ROUTE_PREFIX@@@@ADMIN_ENTITY@@@@ROUTE_SUFFIX@@": {"get": {"summary": "Admin dashboard"}},
            "@@ROUTE_PREFIX@@@@BILLING_ENTITY@@/{tenant}@@ROUTE_SUFFIX@@": {"get": {"summary": "Billing records"}},
            "@@ROUTE_PREFIX@@tenant/{tenant}/@@INTERNAL_ENTITY@@@@ROUTE_SUFFIX@@": {"get": {"summary": "Tenant internal"}},
            "@@ROUTE_PREFIX@@@@MSG_ENTITY@@/{user}/inbox@@ROUTE_SUFFIX@@": {"get": {"summary": "Messages"}},
            "@@ROUTE_PREFIX@@@@WF_ENTITY@@/{wf}/approve@@ROUTE_SUFFIX@@": {"get": {"summary": "Approve"}},
            "@@ROUTE_PREFIX@@@@TRANSFER_ENTITY@@/{from}@@ROUTE_SUFFIX@@": {"get": {"summary": "Transfer"}},
            "@@ROUTE_PREFIX@@@@AUTH_ENTITY@@/request@@ROUTE_SUFFIX@@": {"get": {"summary": "Auth reset"}},
            "@@ROUTE_PREFIX@@@@AUDIT_ENTITY@@@@ROUTE_SUFFIX@@": {"get": {"summary": "Audit log"}},
            "@@ROUTE_PREFIX@@health@@ROUTE_SUFFIX@@": {"get": {"summary": "Health"}},
        }
    }
    return JSONResponse(content=spec, headers=headers)

@app.get("@@ROUTE_PREFIX@@health@@ROUTE_SUFFIX@@")
async def health(x_actor: Optional[str] = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "health_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"status": "ok"}, headers=headers)

@app.get("@@ROUTE_PREFIX@@openapi@@ROUTE_SUFFIX@@")
async def openapi(x_actor: Optional[str] = Header(None)):
    return await openapi_standard(x_actor)

# === VULN 1: IDOR ===
@app.get("@@ROUTE_PREFIX@@objects/{obj_id}@@ROUTE_SUFFIX@@")
async def get_object(obj_id: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    if obj_id in SENSITIVE_DATA:
        headers = ctx_headers(x_actor, {
            "X-Resource-Type": "user_profile", "X-Resource-Owner": obj_id,
            "X-Authorization-Outcome": "granted_full",
        })
        return JSONResponse(content=SENSITIVE_DATA[obj_id], headers=headers)
    return JSONResponse(status_code=404, content={"error": "not_found"})

@app.get("/patched@@ROUTE_PREFIX@@objects/{obj_id}@@ROUTE_SUFFIX@@")
async def get_object_patched(obj_id: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "user_profile", "X-Resource-Owner": obj_id})
    if obj_id not in SENSITIVE_DATA:
        return JSONResponse(status_code=404, content={"error": "not_found"}, headers=headers)
    if actor[FIELDS["id_field"]] != obj_id and ROLE_LEVEL[actor["role"]] < 3:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=SENSITIVE_DATA[obj_id], headers=headers)

# === VULN 2: Broken Access Control ===
@app.get("@@ROUTE_PREFIX@@@@ADMIN_ENTITY@@@@ROUTE_SUFFIX@@")
async def admin_dashboard(x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "admin_dashboard", "X-Privilege-Required": ROLES[-1],
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=ADMIN_DATA, headers=headers)

@app.get("/patched@@ROUTE_PREFIX@@@@ADMIN_ENTITY@@@@ROUTE_SUFFIX@@")
async def admin_dashboard_patched(x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "admin_dashboard", "X-Privilege-Required": ROLES[-1]})
    if ROLE_LEVEL[actor["role"]] < 3:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=ADMIN_DATA, headers=headers)

# === VULN 3: Privilege Escalation ===
@app.get("@@ROUTE_PREFIX@@@@BILLING_ENTITY@@/{tenant}@@ROUTE_SUFFIX@@")
async def billing_records(tenant: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "billing_records", "X-Resource-Tenant": tenant,
        "X-Privilege-Required": ROLES[-1], "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=BILLING_DATA.get(tenant, {}), headers=headers)

@app.get("/patched@@ROUTE_PREFIX@@@@BILLING_ENTITY@@/{tenant}@@ROUTE_SUFFIX@@")
async def billing_records_patched(tenant: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "billing_records", "X-Resource-Tenant": tenant})
    if ROLE_LEVEL[actor["role"]] < 3 or actor["tenant"] != tenant:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=BILLING_DATA.get(tenant, {}), headers=headers)

# === VULN 4: Business Logic Abuse ===
@app.get("@@ROUTE_PREFIX@@@@TRANSFER_ENTITY@@/{from_user}@@ROUTE_SUFFIX@@")
async def transfer_funds(from_user: str, to: str = "@@OBJ_1@@", amount: int = 10,
                         x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor or actor[FIELDS["id_field"]] != from_user:
        return JSONResponse(status_code=403, content={"error": "forbidden"})
    if from_user not in ACCOUNTS or to not in ACCOUNTS:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    ACCOUNTS[from_user]["balance"] -= amount
    ACCOUNTS[to]["balance"] += amount
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "funds_transfer", "X-Privilege-Required": "account_owner",
        "X-Authorization-Outcome": "granted_full",
        "X-Business-Logic-State": "invalid_negative_amount_accepted",
    })
    return JSONResponse(content={
        "from": from_user, "to": to, "amount": amount,
        "balance_from": ACCOUNTS[from_user]["balance"],
        "balance_to": ACCOUNTS[to]["balance"],
    }, headers=headers)

@app.get("/patched@@ROUTE_PREFIX@@@@TRANSFER_ENTITY@@/{from_user}@@ROUTE_SUFFIX@@")
async def transfer_funds_patched(from_user: str, to: str = "@@OBJ_1@@", amount: int = 10,
                                 x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor or actor[FIELDS["id_field"]] != from_user:
        return JSONResponse(status_code=403, content={"error": "forbidden"})
    if amount <= 0:
        headers = ctx_headers(x_actor, {
            "X-Resource-Type": "funds_transfer", "X-Authorization-Outcome": "denied",
            "X-Business-Logic-State": "invalid_amount_rejected",
        })
        return JSONResponse(status_code=400, content={"error": "amount_must_be_positive"}, headers=headers)
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "funds_transfer", "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content={"status": "processed"}, headers=headers)

# === VULN 5: Tenant Isolation Failure ===
@app.get("@@ROUTE_PREFIX@@tenant/{tenant}/@@INTERNAL_ENTITY@@@@ROUTE_SUFFIX@@")
async def tenant_internal(tenant: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "tenant_internal", "X-Resource-Tenant": tenant,
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=TENANT_INTERNAL.get(tenant, {}), headers=headers)

@app.get("/patched@@ROUTE_PREFIX@@tenant/{tenant}/@@INTERNAL_ENTITY@@@@ROUTE_SUFFIX@@")
async def tenant_internal_patched(tenant: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "tenant_internal", "X-Resource-Tenant": tenant})
    if actor["tenant"] != tenant:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=TENANT_INTERNAL.get(tenant, {}), headers=headers)

# === VULN 6: Workflow Authorization Failure ===
@app.get("@@ROUTE_PREFIX@@@@WF_ENTITY@@/{wf_id}/view@@ROUTE_SUFFIX@@")
async def view_workflow(wf_id: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "workflow", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content=WORKFLOWS.get(wf_id, {}), headers=headers)

@app.get("@@ROUTE_PREFIX@@@@WF_ENTITY@@/{wf_id}/approve@@ROUTE_SUFFIX@@")
async def approve_workflow(wf_id: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "workflow_approval", "X-Workflow-State": "approved",
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content={
        "workflow": wf_id, "status": "approved", "approver": actor[FIELDS["id_field"]]
    }, headers=headers)

@app.get("/patched@@ROUTE_PREFIX@@@@WF_ENTITY@@/{wf_id}/approve@@ROUTE_SUFFIX@@")
async def approve_workflow_patched(wf_id: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "workflow_approval"})
    wf = WORKFLOWS.get(wf_id, {})
    if wf.get("requester") == actor[FIELDS["id_field"]] or ROLE_LEVEL[actor["role"]] < 2:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content={"workflow": wf_id, "status": "approved"}, headers=headers)

# === VULN 7: Sensitive Data Exposure ===
@app.get("@@ROUTE_PREFIX@@@@MSG_ENTITY@@/{user}/inbox@@ROUTE_SUFFIX@@")
async def get_messages(user: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "private_messages", "X-Resource-Owner": user,
        "X-Authorization-Outcome": "granted_full", "X-Data-Redacted": "false",
    })
    msgs = MESSAGES.get(user, [])
    return JSONResponse(content={"messages": msgs, "count": len(msgs)}, headers=headers)

@app.get("/patched@@ROUTE_PREFIX@@@@MSG_ENTITY@@/{user}/inbox@@ROUTE_SUFFIX@@")
async def get_messages_patched(user: str, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "private_messages", "X-Resource-Owner": user})
    if actor[FIELDS["id_field"]] != user:
        headers["X-Authorization-Outcome"] = "denied"
        headers["X-Data-Redacted"] = "true"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    msgs = MESSAGES.get(user, [])
    return JSONResponse(content={"messages": msgs, "count": len(msgs)}, headers=headers)

# === VULN 8: Multi-Step Chain ===
@app.get("@@ROUTE_PREFIX@@@@AUTH_ENTITY@@/request@@ROUTE_SUFFIX@@")
async def auth_reset_request(for_user: str = "@@OBJ_0@@", x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "auth_reset", "X-Target-User": for_user,
        "X-Authorization-Outcome": "granted_full",
    })
    token = "reset-" + for_user + "-token"
    AUTH_TOKENS[for_user] = token
    return JSONResponse(content={"token_issued": True, "token": token, "for_user": for_user}, headers=headers)

@app.get("/patched@@ROUTE_PREFIX@@@@AUTH_ENTITY@@/request@@ROUTE_SUFFIX@@")
async def auth_reset_request_patched(for_user: Optional[str] = None, x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "auth_reset"})
    target = for_user or actor[FIELDS["id_field"]]
    if target != actor[FIELDS["id_field"]]:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content={"token_issued": True, "for_user": target}, headers=headers)

# === VULN 9: Audit Log (additional BAC) ===
@app.get("@@ROUTE_PREFIX@@@@AUDIT_ENTITY@@@@ROUTE_SUFFIX@@")
async def get_audit_log(x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "audit_log", "X-Privilege-Required": ROLES[-1],
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content={"entries": AUDIT_LOG, "count": len(AUDIT_LOG)}, headers=headers)

@app.get("/patched@@ROUTE_PREFIX@@@@AUDIT_ENTITY@@@@ROUTE_SUFFIX@@")
async def get_audit_log_patched(x_actor: Optional[str] = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "audit_log", "X-Privilege-Required": ROLES[-1]})
    if ROLE_LEVEL[actor["role"]] < 3:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content={"entries": AUDIT_LOG, "count": len(AUDIT_LOG)}, headers=headers)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=@@PORT@@, log_level="error")
