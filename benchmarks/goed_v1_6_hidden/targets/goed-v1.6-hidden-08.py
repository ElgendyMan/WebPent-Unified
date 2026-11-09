"""GOED v1.6 Hidden: goed-v1.6-hidden-08 Port:9008 Route:/sys/ENTITY/do"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()
ROLES = ["circle_bronze", "circle_silver", "circle_gold", "circle_platinum"]
ROLE_LEVEL = {"circle_bronze": 0, "circle_silver": 1, "circle_gold": 2, "circle_platinum": 3}
TENANTS = ["sector_pdyl", "sector_lqtu"]
OBJECTS = ["ref_a98bdc84", "ref_f16d46c7", "ref_9a024b48", "ref_3ece78c8", "ref_3d0c0b28", "ref_acdde123", "ref_4b3e79c7", "ref_85c607a6"]
FIELDS = {"id_field": "ref_id", "name_field": "designation", "secret_field": "restricted_id", "contact_field": "addr", "value_field": "quantum"}
ACTORS = {"x001": {"ref_id": "ref_a98bdc84", "role": "circle_bronze", "tenant": "sector_pdyl"}, "x002": {"ref_id": "ref_f16d46c7", "role": "circle_silver", "tenant": "sector_pdyl"}, "x003": {"ref_id": "ref_9a024b48", "role": "circle_bronze", "tenant": "sector_lqtu"}, "x004": {"ref_id": "ref_3ece78c8", "role": "circle_silver", "tenant": "sector_lqtu"}}
SENSITIVE = {"ref_a98bdc84": {"designation": "Entity-0", "restricted_id": "INT-10000", "addr": "ch000@internal", "quantum": 1006}, "ref_f16d46c7": {"designation": "Entity-1", "restricted_id": "INT-10001", "addr": "ch001@internal", "quantum": 5415}, "ref_9a024b48": {"designation": "Entity-2", "restricted_id": "INT-10002", "addr": "ch002@internal", "quantum": 9682}, "ref_3ece78c8": {"designation": "Entity-3", "restricted_id": "INT-10003", "addr": "ch003@internal", "quantum": 856}, "ref_3d0c0b28": {"designation": "Entity-4", "restricted_id": "INT-10004", "addr": "ch004@internal", "quantum": 6199}, "ref_acdde123": {"designation": "Entity-5", "restricted_id": "INT-10005", "addr": "ch005@internal", "quantum": 2174}}

def get_actor(x): return ACTORS.get(x)
def ctx_h(x, extra=None):
    a = get_actor(x); h = {"X-Actor-Echo": x or "anon", "X-Actor-Role": a["role"] if a else "none",
        "X-Actor-Tenant": a["tenant"] if a else "none", "X-Auth-State": "authenticated" if a else "unauth"}
    if extra: h.update(extra)
    return h

@app.get("/")
async def root(): return JSONResponse(content={"svc": "goed-v1.6-hidden-08", "v": "1.6"})

@app.get("/openapi.json")
async def openapi_spec(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "openapi", "X-Authorization-Outcome": "granted_full"})
    paths = {}
    paths["/sys/vertex/do"] = {"get": {"summary": "op"}}
    paths["/sys/lambda/do"] = {"post": {"summary": "op"}}
    paths["/sys/echo/do"] = {"put": {"summary": "op"}}
    paths["/sys/prism/do"] = {"post": {"summary": "op"}}
    paths["/sys/matrix/do"] = {"put": {"summary": "op"}}
    paths["/sys/vector/do"] = {"patch": {"summary": "op"}}
    paths["/sys/pulse/do"] = {"patch": {"summary": "op"}}
    paths["/sys/sigma/do"] = {"post": {"summary": "op"}}
    paths["/sys/theta/do"] = {"get": {"summary": "op"}}
    paths["/sys/horizon/do"] = {"get": {"summary": "op"}}
    return JSONResponse(content={"openapi": "3.0.0", "paths": paths}, headers=h)

@app.get("/sys/health/do")
async def health(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "health", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"ok": True}, headers=h)


@app.put("/sys/cipher/do")
async def ep_cipher(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "cipher", "X-Resource-Owner": "ref_f16d46c7",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_f16d46c7", {}), headers=h)

@app.put("/ctrl/sys/cipher/do")
async def ctrl_cipher(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "cipher", "X-Resource-Owner": "ref_f16d46c7"})
    is_owner = a[FIELDS["id_field"]] == "ref_f16d46c7"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=404, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_f16d46c7", {}), headers=h)

@app.get("/sys/vertex/do")
async def ep_vertex(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "vertex", "X-Resource-Owner": "ref_9a024b48",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_9a024b48", {}), headers=h)

@app.get("/ctrl/sys/vertex/do")
async def ctrl_vertex(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "vertex", "X-Resource-Owner": "ref_9a024b48"})
    is_owner = a[FIELDS["id_field"]] == "ref_9a024b48"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=200, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_9a024b48", {}), headers=h)

@app.post("/sys/lambda/do")
async def ep_lambda(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "lambda", "X-Resource-Owner": "ref_3ece78c8",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_3ece78c8", {}), headers=h)

@app.post("/ctrl/sys/lambda/do")
async def ctrl_lambda(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "lambda", "X-Resource-Owner": "ref_3ece78c8"})
    is_owner = a[FIELDS["id_field"]] == "ref_3ece78c8"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=401, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_3ece78c8", {}), headers=h)

@app.put("/sys/echo/do")
async def ep_echo(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "echo", "X-Resource-Owner": "ref_3d0c0b28",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_3d0c0b28", {}), headers=h)

@app.put("/ctrl/sys/echo/do")
async def ctrl_echo(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "echo", "X-Resource-Owner": "ref_3d0c0b28"})
    is_owner = a[FIELDS["id_field"]] == "ref_3d0c0b28"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=200, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_3d0c0b28", {}), headers=h)

@app.post("/sys/prism/do")
async def ep_prism(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "prism", "X-Resource-Owner": "ref_acdde123",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_acdde123", {}), headers=h)

@app.post("/ctrl/sys/prism/do")
async def ctrl_prism(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "prism", "X-Resource-Owner": "ref_acdde123"})
    is_owner = a[FIELDS["id_field"]] == "ref_acdde123"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_acdde123", {}), headers=h)

@app.put("/sys/matrix/do")
async def ep_matrix(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "matrix", "X-Resource-Owner": "ref_a98bdc84",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_a98bdc84", {}), headers=h)

@app.put("/ctrl/sys/matrix/do")
async def ctrl_matrix(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "matrix", "X-Resource-Owner": "ref_a98bdc84"})
    is_owner = a[FIELDS["id_field"]] == "ref_a98bdc84"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_a98bdc84", {}), headers=h)

@app.patch("/sys/vector/do")
async def ep_vector(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "vector", "X-Resource-Owner": "ref_f16d46c7",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_f16d46c7", {}), headers=h)

@app.patch("/ctrl/sys/vector/do")
async def ctrl_vector(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "vector", "X-Resource-Owner": "ref_f16d46c7"})
    is_owner = a[FIELDS["id_field"]] == "ref_f16d46c7"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=401, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_f16d46c7", {}), headers=h)

@app.patch("/sys/pulse/do")
async def ep_pulse(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "pulse", "X-Resource-Owner": "ref_9a024b48",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_9a024b48", {}), headers=h)

@app.patch("/ctrl/sys/pulse/do")
async def ctrl_pulse(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "pulse", "X-Resource-Owner": "ref_9a024b48"})
    is_owner = a[FIELDS["id_field"]] == "ref_9a024b48"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_9a024b48", {}), headers=h)

@app.put("/sys/omega/do")
async def ep_omega(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "omega", "X-Resource-Owner": "ref_3ece78c8",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_3ece78c8", {}), headers=h)

@app.put("/ctrl/sys/omega/do")
async def ctrl_omega(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "omega", "X-Resource-Owner": "ref_3ece78c8"})
    is_owner = a[FIELDS["id_field"]] == "ref_3ece78c8"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=200, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_3ece78c8", {}), headers=h)

@app.post("/sys/sigma/do")
async def ep_sigma(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "sigma", "X-Resource-Owner": "ref_3d0c0b28",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_3d0c0b28", {}), headers=h)

@app.post("/ctrl/sys/sigma/do")
async def ctrl_sigma(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "sigma", "X-Resource-Owner": "ref_3d0c0b28"})
    is_owner = a[FIELDS["id_field"]] == "ref_3d0c0b28"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_3d0c0b28", {}), headers=h)

@app.get("/sys/lattice/do")
async def decoy_lattice(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"info": "public", "decoy": True}, headers=h)

@app.get("/sys/flux/do")
async def decoy_flux(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"info": "public", "decoy": True}, headers=h)

@app.get("/sys/nexus/do")
async def decoy_nexus(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"info": "public", "decoy": True}, headers=h)

@app.get("/sys/admin/do")
async def normal_admin(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "standard_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"data": "ok"}, headers=h)

@app.get("/sys/root/do")
async def normal_root(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "standard_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"data": "ok"}, headers=h)

@app.get("/sys/super/do")
async def normal_super(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "standard_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"data": "ok"}, headers=h)

@app.get("/sys/secret/do")
async def normal_secret(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "standard_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"data": "ok"}, headers=h)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9008, log_level="error")
