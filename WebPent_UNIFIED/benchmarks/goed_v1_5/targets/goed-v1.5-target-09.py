"""
GOED v1.5 Generative Target: goed-v1.5-target-09
Seed: 9 | Port: 8909
Naming convention: /app/ENTITY/endpoint
Roles: ['observer', 'operator', 'administrator', 'global_admin']
Tenants: ['partition-172', 'partition-419']

GENERATED FILE — DO NOT EDIT MANUALLY
Local-only, synthetic, no external access, no real credentials.
"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

ROLES = ["observer", "operator", "administrator", "global_admin"]
ROLE_LEVEL = {"observer": 0, "operator": 1, "administrator": 2, "global_admin": 3}
TENANTS = ["partition-172", "partition-419"]
OBJECTS = ["res_a0", "res_d1", "res_d2", "res_g3", "res_f4", "res_a5", "res_c6", "res_a7"]
FIELDS = {"id_field": "subject", "name_field": "full_name", "secret_field": "confidential_ref", "email_field": "email", "balance_field": "account_value"}
ACTORS = {"bob": {"subject": "res_a0", "role": "observer", "tenant": "partition-172"}, "carol": {"subject": "res_d1", "role": "operator", "tenant": "partition-172"}, "dave": {"subject": "res_d2", "role": "observer", "tenant": "partition-419"}, "eve": {"subject": "res_g3", "role": "operator", "tenant": "partition-419"}}

SENSITIVE_DATA = {"res_a0": {"full_name": "Alice", "confidential_ref": "XXX-XX-1000", "email": "alice@partition-172.example", "account_value": 7685}, "res_d1": {"full_name": "Bob", "confidential_ref": "XXX-XX-1001", "email": "bob@partition-172.example", "account_value": 6216}, "res_d2": {"full_name": "Carol", "confidential_ref": "XXX-XX-1002", "email": "carol@partition-172.example", "account_value": 4476}, "res_g3": {"full_name": "Dave", "confidential_ref": "XXX-XX-1003", "email": "dave@partition-419.example", "account_value": 2369}, "res_f4": {"full_name": "Eve", "confidential_ref": "XXX-XX-1004", "email": "eve@partition-419.example", "account_value": 3149}, "res_a5": {"full_name": "Frank", "confidential_ref": "XXX-XX-1005", "email": "frank@partition-419.example", "account_value": 205}}
ADMIN_DATA = {"system_status": "operational", "record_count": 150, "events": ["login", "logout", "access"]}
BILLING_DATA = {t: {"invoices": [f"INV-{i}" for i in range(1, 4)], "total": 50000 + s * 1000} for s, t in enumerate(TENANTS)}
TENANT_INTERNAL = {t: {"internal_metrics": f"sensitive_{t}_data"} for t in TENANTS}
MESSAGES = {OBJECTS[0]: ["private_msg_1", "private_msg_2"], OBJECTS[1]: ["personal_notification"]}
WORKFLOWS = {"wf-res_d2": {"status": "pending_approval", "requester": OBJECTS[0]}}
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
        "service": "goed-v1.5-target-09",
        "version": "v1.5",
        "links": ["/app/health/endpoint", "/app/openapi/endpoint"]
    })

@app.get("/openapi.json")
async def openapi_standard(x_actor: str | None = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "openapi_spec", "X-Authorization-Outcome": "granted_full"})
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "goed-v1.5-target-09", "version": "1.0"},
        "paths": {
            "/app/objects/{id}/endpoint": {"get": {"summary": "Retrieve object"}},
            "/app/management_console/endpoint": {"get": {"summary": "Admin dashboard"}},
            "/app/revenue_reports/{tenant}/endpoint": {"get": {"summary": "Billing records"}},
            "/app/tenant/{tenant}/confidential_records/endpoint": {"get": {"summary": "Tenant internal"}},
            "/app/personal_notifications/{user}/inbox/endpoint": {"get": {"summary": "Messages"}},
            "/app/workflows/{wf}/approve/endpoint": {"get": {"summary": "Approve"}},
            "/app/funds_transfer/{from}/endpoint": {"get": {"summary": "Transfer"}},
            "/app/password_recovery/request/endpoint": {"get": {"summary": "Auth reset"}},
            "/app/access_trail/endpoint": {"get": {"summary": "Audit log"}},
            "/app/health/endpoint": {"get": {"summary": "Health"}},
        }
    }
    return JSONResponse(content=spec, headers=headers)

@app.get("/app/health/endpoint")
async def health(x_actor: str | None = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "health_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"status": "ok"}, headers=headers)

@app.get("/app/openapi/endpoint")
async def openapi(x_actor: str | None = Header(None)):
    return await openapi_standard(x_actor)

# === VULN 1: IDOR ===
@app.get("/app/objects/{obj_id}/endpoint")
async def get_object(obj_id: str, x_actor: str | None = Header(None)):
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

@app.get("/patched/app/objects/{obj_id}/endpoint")
async def get_object_patched(obj_id: str, x_actor: str | None = Header(None)):
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
@app.get("/app/management_console/endpoint")
async def admin_dashboard(x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "admin_dashboard", "X-Privilege-Required": ROLES[-1],
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=ADMIN_DATA, headers=headers)

@app.get("/patched/app/management_console/endpoint")
async def admin_dashboard_patched(x_actor: str | None = Header(None)):
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
@app.get("/app/revenue_reports/{tenant}/endpoint")
async def billing_records(tenant: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "billing_records", "X-Resource-Tenant": tenant,
        "X-Privilege-Required": ROLES[-1], "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=BILLING_DATA.get(tenant, {}), headers=headers)

@app.get("/patched/app/revenue_reports/{tenant}/endpoint")
async def billing_records_patched(tenant: str, x_actor: str | None = Header(None)):
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
@app.get("/app/funds_transfer/{from_user}/endpoint")
async def transfer_funds(from_user: str, to: str = "res_d1", amount: int = 10,
                         x_actor: str | None = Header(None)):
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

@app.get("/patched/app/funds_transfer/{from_user}/endpoint")
async def transfer_funds_patched(from_user: str, to: str = "res_d1", amount: int = 10,
                                 x_actor: str | None = Header(None)):
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
@app.get("/app/tenant/{tenant}/confidential_records/endpoint")
async def tenant_internal(tenant: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "tenant_internal", "X-Resource-Tenant": tenant,
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=TENANT_INTERNAL.get(tenant, {}), headers=headers)

@app.get("/patched/app/tenant/{tenant}/confidential_records/endpoint")
async def tenant_internal_patched(tenant: str, x_actor: str | None = Header(None)):
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
@app.get("/app/workflows/{wf_id}/view/endpoint")
async def view_workflow(wf_id: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "workflow", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content=WORKFLOWS.get(wf_id, {}), headers=headers)

@app.get("/app/workflows/{wf_id}/approve/endpoint")
async def approve_workflow(wf_id: str, x_actor: str | None = Header(None)):
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

@app.get("/patched/app/workflows/{wf_id}/approve/endpoint")
async def approve_workflow_patched(wf_id: str, x_actor: str | None = Header(None)):
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
@app.get("/app/personal_notifications/{user}/inbox/endpoint")
async def get_messages(user: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "private_messages", "X-Resource-Owner": user,
        "X-Authorization-Outcome": "granted_full", "X-Data-Redacted": "false",
    })
    msgs = MESSAGES.get(user, [])
    return JSONResponse(content={"messages": msgs, "count": len(msgs)}, headers=headers)

@app.get("/patched/app/personal_notifications/{user}/inbox/endpoint")
async def get_messages_patched(user: str, x_actor: str | None = Header(None)):
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
@app.get("/app/password_recovery/request/endpoint")
async def auth_reset_request(for_user: str = "res_a0", x_actor: str | None = Header(None)):
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

@app.get("/patched/app/password_recovery/request/endpoint")
async def auth_reset_request_patched(for_user: str | None = None, x_actor: str | None = Header(None)):
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
@app.get("/app/access_trail/endpoint")
async def get_audit_log(x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "audit_log", "X-Privilege-Required": ROLES[-1],
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content={"entries": AUDIT_LOG, "count": len(AUDIT_LOG)}, headers=headers)

@app.get("/patched/app/access_trail/endpoint")
async def get_audit_log_patched(x_actor: str | None = Header(None)):
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
    uvicorn.run(app, host="127.0.0.1", port=8909, log_level="error")
