"""
GOED v1.6 — Adversarial v2 Target
24 cases across 12 adversarial patterns
Local-only, synthetic, no external access.
"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

UID1 = "bdd640fb-0667-1ad1-1c80-317fa3b1799d"
UID2 = "23b8c1e9-3924-56de-3eb1-3b9046685257"
DYN = "a23eb44c"

def hdr(x_actor, extra=None):
    h = {"X-Actor-Echo": x_actor or "anon", "X-Auth-State": "authenticated" if x_actor else "unauth"}
    if extra: h.update(extra)
    return h

# === Pattern 1: same_status_different_semantics ===
@app.get("/adv/p1/data")
async def p1_data(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "public_data", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"public": "info", "value": 123}, headers=h)

@app.get("/adv/p1/secrets")
async def p1_secrets(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "sensitive", "X-Resource-Owner": "target_user",
                       "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"secret": "ADV_SECRET_001", "ssn": "XXX-XX-1234"}, headers=h)

@app.get("/ctrl/adv/p1/secrets")
async def p1_secrets_ctrl(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "sensitive", "X-Authorization-Outcome": "denied"})
    return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)

# === Pattern 2: different_status_same_meaning ===
@app.get("/adv/p2/item")
async def p2_item(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "item", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"id": "item_001", "name": "Widget"}, headers=h)

@app.post("/adv/p2/item")
async def p2_item_create(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "item", "X-Resource-Owner": "other_user",
                       "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=201, content={"id": "new_item", "owner": "other_user"}, headers=h)

@app.post("/ctrl/adv/p2/item")
async def p2_item_create_ctrl(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Authorization-Outcome": "denied"})
    return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)

# === Pattern 3: misleading_endpoint_names (CLEAN) ===
@app.get("/admin/public_info")
async def p3_admin_public(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"info": "this is truly public despite the name"}, headers=h)

# === Pattern 4: misleading_json_fields (CLEAN) ===
@app.get("/adv/p4/profile")
async def p4_profile(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "profile", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"name": "user", "is_admin": True, "actual_role": "viewer"}, headers=h)

# === Pattern 5: decoy_admin_endpoints (CLEAN) ===
@app.get("/adv/p5/admin-panel")
async def p5_decoy_admin(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "marketing_page", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"title": "Welcome", "theme": "default"}, headers=h)

# === Pattern 6: equivalent_public_private_names (CLEAN) ===
@app.get("/public/v6/stats")
async def p6_public(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "public_stats", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"visitors": 1000, "pageviews": 5000}, headers=h)

@app.get("/private/v6/stats")
async def p6_private(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "public_stats", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"visitors": 1000, "pageviews": 5000}, headers=h)

# === Pattern 7: noisy_headers (CLEAN) ===
@app.get("/adv/p7/data")
async def p7_noisy(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {
        "X-Resource-Type": "public_data", "X-Authorization-Outcome": "granted_full",
        "X-Security-Policy": "strict", "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff", "X-HSTS": "max-age=31536000",
    })
    return JSONResponse(content={"data": "public"}, headers=h)

# === Pattern 8: reordered_fields (CLEAN) ===
@app.get("/adv/p8/a")
async def p8_order_a(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "item", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"id": "x", "name": "y", "value": 42}, headers=h)

@app.get("/adv/p8/b")
async def p8_order_b(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "item", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"value": 42, "id": "x", "name": "y"}, headers=h)

# === Pattern 9: randomized_identifiers (VULNERABLE) ===
@app.get(f"/adv/p9/resources/{UID1}")
async def p9_resource(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "resource", "X-Resource-Owner": UID2,
                       "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"id": UID1, "owner": UID2, "data": "sensitive"}, headers=h)

@app.get(f"/ctrl/adv/p9/resources/{UID1}")
async def p9_resource_ctrl(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Authorization-Outcome": "denied"})
    return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)

# === Pattern 10: route_aliases (VULNERABLE) ===
@app.get("/adv/p10/primary")
@app.get("/adv/p10/alias1")
@app.get("/adv/p10/alias2")
async def p10_alias(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "sensitive", "X-Resource-Owner": "target_user",
                       "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"secret": "alias_secret"}, headers=h)

@app.get("/ctrl/adv/p10/primary")
async def p10_alias_ctrl(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Authorization-Outcome": "denied"})
    return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)

# === Pattern 11: nested_apis (VULNERABLE) ===
@app.get("/api/v2/platform/integrations/services/connector/p11/data")
async def p11_nested(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "connector_data", "X-Resource-Owner": "svc_account",
                       "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"api_key": "sk-nested-12345", "config": "sensitive"}, headers=h)

@app.get("/ctrl/api/v2/platform/integrations/services/connector/p11/data")
async def p11_nested_ctrl(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Authorization-Outcome": "denied"})
    return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)

# === Pattern 12: dynamic_links ===
@app.get("/adv/p12/entry")
async def p12_entry(x_actor: str | None = Header(None)):
    h = hdr(x_actor, {"X-Resource-Type": "entry", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"links": [f"/adv/p12/resource/{DYN}", "/adv/p12/info"]}, headers=h)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9100, log_level="error")
