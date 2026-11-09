"""
GOED v1 Generative Target — Live validation target
Naming convention: /services/ENTITY/rest
Roles: viewer, editor, manager, supervisor
Tenants: org-00, org-01
"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

ROLES = ["viewer", "editor", "manager", "supervisor"]
ROLE_LEVEL = {r: i for i, r in enumerate(ROLES)}
TENANTS = ["org-00", "org-01"]

ACTORS = {"alice": {"user_id": "res_b0", "role": "supervisor", "tenant": "org-00"}, "bob": {"user_id": "res_a1", "role": "editor", "tenant": "org-00"}, "carol": {"user_id": "res_e2", "role": "viewer", "tenant": "org-00"}, "dave": {"user_id": "res_d3", "role": "supervisor", "tenant": "org-01"}, "eve": {"user_id": "res_d4", "role": "editor", "tenant": "org-01"}}
SENSITIVE_DATA = {"res_b0": {"name": "Alice", "ssn_like": "XXX-XX-0001", "email": "alice@org-00.com", "balance": 5000}, "res_a1": {"name": "Bob", "ssn_like": "XXX-XX-0002", "email": "bob@org-00.com", "balance": 1000}, "res_e2": {"name": "Carol", "ssn_like": "XXX-XX-0003", "email": "carol@org-00.com", "balance": 500}, "res_d3": {"name": "Dave", "ssn_like": "XXX-XX-0004", "email": "dave@org-01.com", "balance": 3000}, "res_d4": {"name": "Eve", "ssn_like": "XXX-XX-0005", "email": "eve@org-01.com", "balance": 800}}
ADMIN_DATA = {"system_status": "operational", "user_count": 150, "audit_logs": ["login", "logout", "access"]}
BILLING_DATA = {"invoices": ["INV-001", "INV-002"], "total_revenue": 50000}
TENANT_INTERNAL = {"org-00": {"internal_metrics": "sensitive_org00_data"}, "org-01": {"internal_metrics": "sensitive_org01_data"}}
MESSAGES = {"res_b0": ["private_msg_1", "private_msg_2"], "res_a1": ["bob_private_1"]}
WORKFLOWS = {"wf-res_02": {"status": "pending_approval", "requester": "res_e2"}}
ACCOUNTS = {"res_a1": {"balance": 1000}, "res_b0": {"balance": 5000}}

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

# === VULN 1: IDOR — /services/objects/{id}/rest ===
@app.get("/services/objects/{obj_id}/rest")
async def get_object(obj_id: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    if obj_id in SENSITIVE_DATA:
        headers = ctx_headers(x_actor, {
            "X-Resource-Type": "user_profile",
            "X-Resource-Owner": obj_id,
            "X-Authorization-Outcome": "granted_full",  # VULN: no ownership check
        })
        return JSONResponse(content=SENSITIVE_DATA[obj_id], headers=headers)
    return JSONResponse(status_code=404, content={"error": "not_found"})

# === PATCHED control for IDOR ===
@app.get("/patched/services/objects/{obj_id}/rest")
async def get_object_patched(obj_id: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "user_profile"})
    if actor["user_id"] != obj_id and ROLE_LEVEL[actor["role"]] < 3:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=SENSITIVE_DATA.get(obj_id, {}), headers=headers)

# === VULN 2: Broken Access Control — /services/admin/dashboard/rest ===
@app.get("/services/admin/dashboard/rest")
async def admin_dashboard(x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "admin_dashboard",
        "X-Privilege-Required": "supervisor",
        "X-Authorization-Outcome": "granted_full",  # VULN: no role check
    })
    return JSONResponse(content=ADMIN_DATA, headers=headers)

@app.get("/patched/services/admin/dashboard/rest")
async def admin_dashboard_patched(x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "admin_dashboard", "X-Privilege-Required": "supervisor"})
    if ROLE_LEVEL[actor["role"]] < 3:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=ADMIN_DATA, headers=headers)

# === VULN 3: Privilege Escalation — /services/billing/{tenant}/records/rest ===
@app.get("/services/billing/{tenant}/records/rest")
async def billing_records(tenant: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "billing_records",
        "X-Resource-Tenant": tenant,
        "X-Privilege-Required": "supervisor",
        "X-Authorization-Outcome": "granted_full",  # VULN
    })
    return JSONResponse(content=BILLING_DATA, headers=headers)

@app.get("/patched/services/billing/{tenant}/records/rest")
async def billing_records_patched(tenant: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "billing_records", "X-Resource-Tenant": tenant})
    if ROLE_LEVEL[actor["role"]] < 3 or actor["tenant"] != tenant:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(content=BILLING_DATA, headers=headers)

# === VULN 4: Tenant Isolation — /services/tenant/{tenant}/internal/rest ===
@app.get("/services/tenant/{tenant}/internal/rest")
async def tenant_internal(tenant: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "tenant_internal",
        "X-Resource-Tenant": tenant,
        "X-Authorization-Outcome": "granted_full",  # VULN: no tenant check
    })
    return JSONResponse(content=TENANT_INTERNAL.get(tenant, {}), headers=headers)

@app.get("/patched/services/tenant/{tenant}/internal/rest")
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

# === VULN 5: Sensitive Data Exposure — /services/messages/{user}/inbox/rest ===
@app.get("/services/messages/{user}/inbox/rest")
async def get_messages(user: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {
        "X-Resource-Type": "private_messages",
        "X-Resource-Owner": user,
        "X-Authorization-Outcome": "granted_full",  # VULN
        "X-Data-Redacted": "false",
    })
    return JSONResponse(content={"messages": MESSAGES.get(user, []), "count": len(MESSAGES.get(user, []))}, headers=headers)

@app.get("/patched/services/messages/{user}/inbox/rest")
async def get_messages_patched(user: str, x_actor: str | None = Header(None)):
    actor = get_actor(x_actor)
    if not actor:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    headers = ctx_headers(x_actor, {"X-Resource-Type": "private_messages", "X-Resource-Owner": user})
    if actor["user_id"] != user:
        headers["X-Authorization-Outcome"] = "denied"
        headers["X-Data-Redacted"] = "true"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    headers["X-Data-Redacted"] = "false"
    return JSONResponse(content={"messages": MESSAGES.get(user, []), "count": len(MESSAGES.get(user, []))}, headers=headers)

# === Public entry points for discovery ===
@app.get("/")
async def root():
    return JSONResponse(content={"service": "GOED Generative Target", "version": "v1",
                                  "links": ["/services/health/rest", "/services/openapi/rest"]})

@app.get("/services/health/rest")
async def health(x_actor: str | None = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "health_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"status": "ok"}, headers=headers)

@app.get("/services/openapi/rest")
async def openapi_spec(x_actor: str | None = Header(None)):
    headers = ctx_headers(x_actor, {"X-Resource-Type": "openapi_spec", "X-Authorization-Outcome": "granted_full"})
    # Hint at some paths via OpenAPI-like structure
    spec = {
        "paths": {
            "/services/objects/{id}/rest": {"get": {"summary": "Get object by ID"}},
            "/services/admin/dashboard/rest": {"get": {"summary": "Admin dashboard"}},
            "/services/billing/{tenant}/records/rest": {"get": {"summary": "Billing records"}},
        }
    }
    return JSONResponse(content=spec, headers=headers)


@app.get("/openapi.json")
async def openapi_standard(x_actor: str | None = Header(None)):
    """Standard OpenAPI discovery endpoint — web convention."""
    headers = ctx_headers(x_actor, {"X-Resource-Type": "openapi_spec", "X-Authorization-Outcome": "granted_full"})
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "GOED Generative Target API", "version": "1.0"},
        "paths": {
            "/services/objects/{id}/rest": {"get": {"summary": "Retrieve object by identifier", "parameters": [{"name": "id", "in": "path"}]}},
            "/services/admin/dashboard/rest": {"get": {"summary": "Administrative dashboard"}},
            "/services/billing/{tenant}/records/rest": {"get": {"summary": "Billing records per tenant", "parameters": [{"name": "tenant", "in": "path"}]}},
            "/services/tenant/{tenant}/internal/rest": {"get": {"summary": "Tenant-internal data", "parameters": [{"name": "tenant", "in": "path"}]}},
            "/services/messages/{user}/inbox/rest": {"get": {"summary": "Private message inbox", "parameters": [{"name": "user", "in": "path"}]}},
            "/services/health/rest": {"get": {"summary": "Health check"}},
        }
    }
    return JSONResponse(content=spec, headers=headers)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8899, log_level="error")
