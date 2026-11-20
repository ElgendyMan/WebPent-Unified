"""
GOED v1.5 Generative Target: goed-v1.5-target-04
Seed: 4 | Port: 8904
Naming convention: /internal/ENTITY
Roles: ['external', 'internal', 'team_lead', 'director']
Tenants: ['team-ACK', 'team-RDC']

GENERATED FILE — DO NOT EDIT MANUALLY
Local-only, synthetic, no external access, no real credentials.
"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

ROLES = ["external", "internal", "team_lead", "director"]
ROLE_LEVEL = {"external": 0, "internal": 1, "team_lead": 2, "director": 3}
TENANTS = ["team-ACK", "team-RDC"]
OBJECTS = ["tok-b0b62aa5", "tok-c5427330", "tok-dc006e09", "tok-3458d6be", "tok-3f1de035", "tok-109622cd", "tok-b97b5f40", "tok-fbd05c19"]
FIELDS = {"id_field": "identity", "name_field": "full_name", "secret_field": "internal_tag", "email_field": "email", "balance_field": "funds"}
ACTORS = {"alice": {"identity": "tok-b0b62aa5", "role": "external", "tenant": "team-ACK"}, "bob": {"identity": "tok-c5427330", "role": "internal", "tenant": "team-ACK"}, "carol": {"identity": "tok-dc006e09", "role": "external", "tenant": "team-RDC"}, "dave": {"identity": "tok-3458d6be", "role": "internal", "tenant": "team-RDC"}}

SENSITIVE_DATA = {"tok-b0b62aa5": {"full_name": "Alice", "internal_tag": "XXX-XX-1000", "email": "alice@team-ACK.example", "funds": 3967}, "tok-c5427330": {"full_name": "Bob", "internal_tag": "XXX-XX-1001", "email": "bob@team-ACK.example", "funds": 5069}, "tok-dc006e09": {"full_name": "Carol", "internal_tag": "XXX-XX-1002", "email": "carol@team-ACK.example", "funds": 1790}, "tok-3458d6be": {"full_name": "Dave", "internal_tag": "XXX-XX-1003", "email": "dave@team-RDC.example", "funds": 6589}, "tok-3f1de035": {"full_name": "Eve", "internal_tag": "XXX-XX-1004", "email": "eve@team-RDC.example", "funds": 7945}, "tok-109622cd": {"full_name": "Frank", "internal_tag": "XXX-XX-1005", "email": "frank@team-RDC.example", "funds": 2639}}
ADMIN_DATA = {"system_status": "operational", "record_count": 150, "events": ["login", "logout", "access"]}
BILLING_DATA = {t: {"invoices": [f"INV-{i}" for i in range(1, 4)], "total": 50000 + s * 1000} for s, t in enumerate(TENANTS)}
TENANT_INTERNAL = {t: {"internal_metrics": f"sensitive_{t}_data"} for t in TENANTS}
MESSAGES = {OBJECTS[0]: ["private_msg_1", "private_msg_2"], OBJECTS[1]: ["personal_notification"]}
WORKFLOWS = {"wf-tok-dc006e09": {"status": "pending_approval", "requester": OBJECTS[0]}}
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
        "service": "goed-v1.5-target-04",
        "version": "v1.5",
        "links": ["/internal/health", "/internal/openapi"]
    })

@app.get("/openapi.json")
async def openapi_standard(x_actor: str | None = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "openapi_spec", "X-Authorization-Outcome": "granted_full"})
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "goed-v1.5-target-04", "version": "1.0"},
        "paths": {
            "/internal/objects/{id}": {"get": {"summary": "Retrieve object"}},
            "/internal/admin_dashboard": {"get": {"summary": "Admin dashboard"}},
            "/internal/billing_records/{tenant}": {"get": {"summary": "Billing records"}},
            "/internal/tenant/{tenant}/internal_resources": {"get": {"summary": "Tenant internal"}},
            "/internal/messages/{user}/inbox": {"get": {"summary": "Messages"}},
            "/internal/review_items/{wf}/approve": {"get": {"summary": "Approve"}},
            "/internal/funds_transfer/{from}": {"get": {"summary": "Transfer"}},
            "/internal/password_recovery/request": {"get": {"summary": "Auth reset"}},
            "/internal/security_records": {"get": {"summary": "Audit log"}},
            "/internal/health": {"get": {"summary": "Health"}},
        }
    }
    return JSONResponse(content=spec, headers=headers)

@app.get("/internal/health")
async def health(x_actor: str | None = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "health_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"status": "ok"}, headers=headers)

@app.get("/internal/openapi")
async def openapi(x_actor: str | None = Header(None)):
    return await openapi_standard(x_actor)

# === VULN 1: IDOR ===
@app.get("/internal/objects/{obj_id}")
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

@app.get("/patched/internal/objects/{obj_id}")
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
@app.get("/internal/admin_dashboard")
async def admin_dashboard(x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "admin_dashboard", "X-Privilege-Required": ROLES[-1],
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=ADMIN_DATA, headers=headers)

@app.get("/patched/internal/admin_dashboard")
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
@app.get("/internal/billing_records/{tenant}")
async def billing_records(tenant: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "billing_records", "X-Resource-Tenant": tenant,
        "X-Privilege-Required": ROLES[-1], "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=BILLING_DATA.get(tenant, {}), headers=headers)

@app.get("/patched/internal/billing_records/{tenant}")
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
@app.get("/internal/funds_transfer/{from_user}")
async def transfer_funds(from_user: str, to: str = "tok-c5427330", amount: int = 10,
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

@app.get("/patched/internal/funds_transfer/{from_user}")
async def transfer_funds_patched(from_user: str, to: str = "tok-c5427330", amount: int = 10,
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
@app.get("/internal/tenant/{tenant}/internal_resources")
async def tenant_internal(tenant: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "tenant_internal", "X-Resource-Tenant": tenant,
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content=TENANT_INTERNAL.get(tenant, {}), headers=headers)

@app.get("/patched/internal/tenant/{tenant}/internal_resources")
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
@app.get("/internal/review_items/{wf_id}/view")
async def view_workflow(wf_id: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "workflow", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content=WORKFLOWS.get(wf_id, {}), headers=headers)

@app.get("/internal/review_items/{wf_id}/approve")
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

@app.get("/patched/internal/review_items/{wf_id}/approve")
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
@app.get("/internal/messages/{user}/inbox")
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

@app.get("/patched/internal/messages/{user}/inbox")
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
@app.get("/internal/password_recovery/request")
async def auth_reset_request(for_user: str = "tok-b0b62aa5", x_actor: str | None = Header(None)):
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

@app.get("/patched/internal/password_recovery/request")
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
@app.get("/internal/security_records")
async def get_audit_log(x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "audit_log", "X-Privilege-Required": ROLES[-1],
        "X-Authorization-Outcome": "granted_full",
    })
    return JSONResponse(content={"entries": AUDIT_LOG, "count": len(AUDIT_LOG)}, headers=headers)

@app.get("/patched/internal/security_records")
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
    uvicorn.run(app, host="127.0.0.1", port=8904, log_level="error")
