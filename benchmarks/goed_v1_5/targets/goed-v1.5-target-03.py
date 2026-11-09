"""
GOED v1.5 Generative Target: goed-v1.5-target-03
Seed: 3 | Port: 8903
Naming convention: /services/ENTITY/rest
Roles: ['read_only', 'read_write', 'admin', 'super_admin']
Tenants: ['domain-efbfbe', 'domain-aeaeee']

GENERATED FILE — DO NOT EDIT MANUALLY
Local-only, synthetic, no external access, no real credentials.
"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

ROLES = ["read_only", "read_write", "admin", "super_admin"]
ROLE_LEVEL = {"read_only": 0, "read_write": 1, "admin": 2, "super_admin": 3}
TENANTS = ["domain-efbfbe", "domain-aeaeee"]
OBJECTS = ["asset_0000", "asset_0001", "asset_0002", "asset_0003", "asset_0004", "asset_0005", "asset_0006", "asset_0007"]
FIELDS = {"id_field": "user_id", "name_field": "title", "secret_field": "private_id", "email_field": "mail_address", "balance_field": "funds"}
ACTORS = {"dave": {"user_id": "asset_0000", "role": "read_only", "tenant": "domain-efbfbe"}, "eve": {"user_id": "asset_0001", "role": "read_write", "tenant": "domain-efbfbe"}, "frank": {"user_id": "asset_0002", "role": "read_only", "tenant": "domain-aeaeee"}, "grace": {"user_id": "asset_0003", "role": "read_write", "tenant": "domain-aeaeee"}}

SENSITIVE_DATA = {"asset_0000": {"title": "Alice", "private_id": "XXX-XX-1000", "mail_address": "alice@domain-efbfbe.example", "funds": 3998}, "asset_0001": {"title": "Bob", "private_id": "XXX-XX-1001", "mail_address": "bob@domain-efbfbe.example", "funds": 9809}, "asset_0002": {"title": "Carol", "private_id": "XXX-XX-1002", "mail_address": "carol@domain-efbfbe.example", "funds": 9016}, "asset_0003": {"title": "Dave", "private_id": "XXX-XX-1003", "mail_address": "dave@domain-aeaeee.example", "funds": 2236}, "asset_0004": {"title": "Eve", "private_id": "XXX-XX-1004", "mail_address": "eve@domain-aeaeee.example", "funds": 6161}, "asset_0005": {"title": "Frank", "private_id": "XXX-XX-1005", "mail_address": "frank@domain-aeaeee.example", "funds": 9994}}
ADMIN_DATA = {"system_status": "operational", "record_count": 150, "events": ["login", "logout", "access"]}
BILLING_DATA = {t: {"invoices": [f"INV-{i}" for i in range(1, 4)], "total": 50000 + s * 1000} for s, t in enumerate(TENANTS)}
TENANT_INTERNAL = {t: {"internal_metrics": f"sensitive_{t}_data"} for t in TENANTS}
MESSAGES = {OBJECTS[0]: ["private_msg_1", "private_msg_2"], OBJECTS[1]: ["personal_notification"]}
WORKFLOWS = {"wf-asset_0002": {"status": "pending_approval", "requester": OBJECTS[0]}}
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
        "service": "goed-v1.5-target-03",
        "version": "v1.5",
        "links": ["/services/health/rest", "/services/openapi/rest"]
    })

@app.get("/openapi.json")
async def openapi_standard(x_actor: str | None = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "openapi_spec", "X-Authorization-Outcome": "granted_full"})
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "goed-v1.5-target-03", "version": "1.0"},
        "paths": {
            "/services/objects/{id}/rest": {"get": {"summary": "Retrieve object"}},
            "/services/system_config/rest": {"get": {"summary": "Admin dashboard"}},
            "/services/billing_records/{tenant}/rest": {"get": {"summary": "Billing records"}},
            "/services/tenant/{tenant}/internal_resources/rest": {"get": {"summary": "Tenant internal"}},
            "/services/private_inbox/{user}/inbox/rest": {"get": {"summary": "Messages"}},
            "/services/review_items/{wf}/approve/rest": {"get": {"summary": "Approve"}},
            "/services/funds_transfer/{from}/rest": {"get": {"summary": "Transfer"}},
            "/services/password_recovery/request/rest": {"get": {"summary": "Auth reset"}},
            "/services/access_trail/rest": {"get": {"summary": "Audit log"}},
            "/services/health/rest": {"get": {"summary": "Health"}},
        }
    }
    return JSONResponse(content=spec, headers=headers)

@app.get("/services/health/rest")
async def health(x_actor: str | None = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "health_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"status": "ok"}, headers=headers)

@app.get("/services/openapi/rest")
async def openapi(x_actor: str | None = Header(None)):
    return await openapi_standard(x_actor)

# === VULN 1: IDOR ===
@app.get("/services/objects/{obj_id}/rest")
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

@app.get("/patched/services/objects/{obj_id}/rest")
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
@app.get("/services/system_config/rest")
async def admin_dashboard(x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "admin_dashboard", "X-Privilege-Required": ROLES[-1],
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=ADMIN_DATA, headers=headers)

@app.get("/patched/services/system_config/rest")
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
@app.get("/services/billing_records/{tenant}/rest")
async def billing_records(tenant: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "billing_records", "X-Resource-Tenant": tenant,
        "X-Privilege-Required": ROLES[-1], "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=BILLING_DATA.get(tenant, {}), headers=headers)

@app.get("/patched/services/billing_records/{tenant}/rest")
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
@app.get("/services/funds_transfer/{from_user}/rest")
async def transfer_funds(from_user: str, to: str = "asset_0001", amount: int = 10,
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

@app.get("/patched/services/funds_transfer/{from_user}/rest")
async def transfer_funds_patched(from_user: str, to: str = "asset_0001", amount: int = 10,
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
@app.get("/services/tenant/{tenant}/internal_resources/rest")
async def tenant_internal(tenant: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "tenant_internal", "X-Resource-Tenant": tenant,
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=TENANT_INTERNAL.get(tenant, {}), headers=headers)

@app.get("/patched/services/tenant/{tenant}/internal_resources/rest")
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
@app.get("/services/review_items/{wf_id}/view/rest")
async def view_workflow(wf_id: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "workflow", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content=WORKFLOWS.get(wf_id, {}), headers=headers)

@app.get("/services/review_items/{wf_id}/approve/rest")
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

@app.get("/patched/services/review_items/{wf_id}/approve/rest")
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
@app.get("/services/private_inbox/{user}/inbox/rest")
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

@app.get("/patched/services/private_inbox/{user}/inbox/rest")
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
@app.get("/services/password_recovery/request/rest")
async def auth_reset_request(for_user: str = "asset_0000", x_actor: str | None = Header(None)):
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

@app.get("/patched/services/password_recovery/request/rest")
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
@app.get("/services/access_trail/rest")
async def get_audit_log(x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "audit_log", "X-Privilege-Required": ROLES[-1],
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content={"entries": AUDIT_LOG, "count": len(AUDIT_LOG)}, headers=headers)

@app.get("/patched/services/access_trail/rest")
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
    uvicorn.run(app, host="127.0.0.1", port=8903, log_level="error")
