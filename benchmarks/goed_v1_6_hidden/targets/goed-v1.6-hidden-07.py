"""GOED v1.6 Hidden: goed-v1.6-hidden-07 Port:9007 Route:/nodes/ENTITY/call"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()
ROLES = ["unit_r1", "unit_r2", "unit_r3", "unit_r4"]
ROLE_LEVEL = {"unit_r1": 0, "unit_r2": 1, "unit_r3": 2, "unit_r4": 3}
TENANTS = ["sector_nhtu", "sector_qagi"]
OBJECTS = ["ref_c36b38fa", "ref_9065099b", "ref_a81a956d", "ref_3d804198", "ref_18f4bcc1", "ref_fc70a60b", "ref_c141936f", "ref_2beb6601"]
FIELDS = {"id_field": "ref_id", "name_field": "marker", "secret_field": "conf_idx", "contact_field": "channel", "value_field": "weight"}
ACTORS = {"x001": {"ref_id": "ref_c36b38fa", "role": "unit_r1", "tenant": "sector_nhtu"}, "x002": {"ref_id": "ref_9065099b", "role": "unit_r2", "tenant": "sector_nhtu"}, "x003": {"ref_id": "ref_a81a956d", "role": "unit_r1", "tenant": "sector_qagi"}, "x004": {"ref_id": "ref_3d804198", "role": "unit_r2", "tenant": "sector_qagi"}}
SENSITIVE = {"ref_c36b38fa": {"marker": "Entity-0", "conf_idx": "INT-10000", "channel": "ch000@internal", "weight": 1145}, "ref_9065099b": {"marker": "Entity-1", "conf_idx": "INT-10001", "channel": "ch001@internal", "weight": 3213}, "ref_a81a956d": {"marker": "Entity-2", "conf_idx": "INT-10002", "channel": "ch002@internal", "weight": 7714}, "ref_3d804198": {"marker": "Entity-3", "conf_idx": "INT-10003", "channel": "ch003@internal", "weight": 1358}, "ref_18f4bcc1": {"marker": "Entity-4", "conf_idx": "INT-10004", "channel": "ch004@internal", "weight": 8868}, "ref_fc70a60b": {"marker": "Entity-5", "conf_idx": "INT-10005", "channel": "ch005@internal", "weight": 3825}}

def get_actor(x): return ACTORS.get(x)
def ctx_h(x, extra=None):
    a = get_actor(x); h = {"X-Actor-Echo": x or "anon", "X-Actor-Role": a["role"] if a else "none",
        "X-Actor-Tenant": a["tenant"] if a else "none", "X-Auth-State": "authenticated" if a else "unauth"}
    if extra: h.update(extra)
    return h

@app.get("/")
async def root(): return JSONResponse(content={"svc": "goed-v1.6-hidden-07", "v": "1.6"})

@app.get("/openapi.json")
async def openapi_spec(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "openapi", "X-Authorization-Outcome": "granted_full"})
    paths = {}
    paths["/nodes/flux/call"] = {"patch": {"summary": "op"}}
    paths["/nodes/cipher/call"] = {"put": {"summary": "op"}}
    paths["/nodes/lambda/call"] = {"get": {"summary": "op"}}
    paths["/nodes/lattice/call"] = {"patch": {"summary": "op"}}
    paths["/nodes/pulse/call"] = {"patch": {"summary": "op"}}
    paths["/nodes/quanta/call"] = {"get": {"summary": "op"}}
    paths["/nodes/vertex/call"] = {"patch": {"summary": "op"}}
    paths["/nodes/horizon/call"] = {"put": {"summary": "op"}}
    paths["/nodes/echo/call"] = {"get": {"summary": "op"}}
    paths["/nodes/omega/call"] = {"get": {"summary": "op"}}
    return JSONResponse(content={"openapi": "3.0.0", "paths": paths}, headers=h)

@app.get("/nodes/health/call")
async def health(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "health", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"ok": True}, headers=h)


@app.patch("/nodes/flux/call")
async def ep_flux(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "flux", "X-Resource-Owner": "ref_9065099b",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_9065099b", {}), headers=h)

@app.patch("/ctrl/nodes/flux/call")
async def ctrl_flux(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "flux", "X-Resource-Owner": "ref_9065099b"})
    is_owner = a[FIELDS["id_field"]] == "ref_9065099b"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_9065099b", {}), headers=h)

@app.put("/nodes/cipher/call")
async def ep_cipher(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "cipher", "X-Resource-Owner": "ref_a81a956d",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_a81a956d", {}), headers=h)

@app.put("/ctrl/nodes/cipher/call")
async def ctrl_cipher(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "cipher", "X-Resource-Owner": "ref_a81a956d"})
    is_owner = a[FIELDS["id_field"]] == "ref_a81a956d"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=200, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_a81a956d", {}), headers=h)

@app.get("/nodes/lambda/call")
async def ep_lambda(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "lambda", "X-Resource-Owner": "ref_3d804198",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_3d804198", {}), headers=h)

@app.get("/ctrl/nodes/lambda/call")
async def ctrl_lambda(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "lambda", "X-Resource-Owner": "ref_3d804198"})
    is_owner = a[FIELDS["id_field"]] == "ref_3d804198"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=201, content=SENSITIVE.get("ref_3d804198", {}), headers=h)

@app.patch("/nodes/lattice/call")
async def ep_lattice(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "lattice", "X-Resource-Owner": "ref_18f4bcc1",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_18f4bcc1", {}), headers=h)

@app.patch("/ctrl/nodes/lattice/call")
async def ctrl_lattice(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "lattice", "X-Resource-Owner": "ref_18f4bcc1"})
    is_owner = a[FIELDS["id_field"]] == "ref_18f4bcc1"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=200, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_18f4bcc1", {}), headers=h)

@app.post("/nodes/nexus/call")
async def ep_nexus(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "nexus", "X-Resource-Owner": "ref_fc70a60b",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_fc70a60b", {}), headers=h)

@app.post("/ctrl/nodes/nexus/call")
async def ctrl_nexus(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "nexus", "X-Resource-Owner": "ref_fc70a60b"})
    is_owner = a[FIELDS["id_field"]] == "ref_fc70a60b"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=200, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_fc70a60b", {}), headers=h)

@app.patch("/nodes/pulse/call")
async def ep_pulse(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "pulse", "X-Resource-Owner": "ref_c36b38fa",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_c36b38fa", {}), headers=h)

@app.patch("/ctrl/nodes/pulse/call")
async def ctrl_pulse(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "pulse", "X-Resource-Owner": "ref_c36b38fa"})
    is_owner = a[FIELDS["id_field"]] == "ref_c36b38fa"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=404, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_c36b38fa", {}), headers=h)

@app.get("/nodes/quanta/call")
async def ep_quanta(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "quanta", "X-Resource-Owner": "ref_9065099b",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_9065099b", {}), headers=h)

@app.get("/ctrl/nodes/quanta/call")
async def ctrl_quanta(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "quanta", "X-Resource-Owner": "ref_9065099b"})
    is_owner = a[FIELDS["id_field"]] == "ref_9065099b"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_9065099b", {}), headers=h)

@app.patch("/nodes/vertex/call")
async def ep_vertex(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "vertex", "X-Resource-Owner": "ref_a81a956d",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_a81a956d", {}), headers=h)

@app.patch("/ctrl/nodes/vertex/call")
async def ctrl_vertex(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "vertex", "X-Resource-Owner": "ref_a81a956d"})
    is_owner = a[FIELDS["id_field"]] == "ref_a81a956d"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_a81a956d", {}), headers=h)

@app.put("/nodes/horizon/call")
async def ep_horizon(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "horizon", "X-Resource-Owner": "ref_3d804198",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_3d804198", {}), headers=h)

@app.put("/ctrl/nodes/horizon/call")
async def ctrl_horizon(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "horizon", "X-Resource-Owner": "ref_3d804198"})
    is_owner = a[FIELDS["id_field"]] == "ref_3d804198"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_3d804198", {}), headers=h)

@app.post("/nodes/gamma/call")
async def ep_gamma(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "gamma", "X-Resource-Owner": "ref_18f4bcc1",
        "X-Resource-Tenant": a["tenant"], "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_18f4bcc1", {}), headers=h)

@app.post("/ctrl/nodes/gamma/call")
async def ctrl_gamma(x_actor: str | None = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={"error": "unauth"})
    h = ctx_h(x_actor, {"X-Resource-Type": "gamma", "X-Resource-Owner": "ref_18f4bcc1"})
    is_owner = a[FIELDS["id_field"]] == "ref_18f4bcc1"
    is_high = ROLE_LEVEL.get(a["role"], 0) >= 3
    if not is_owner and not is_high:
        h["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code=403, content={"error": "forbidden"}, headers=h)
    h["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code=200, content=SENSITIVE.get("ref_18f4bcc1", {}), headers=h)

@app.get("/nodes/prism/call")
async def decoy_prism(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"info": "public", "decoy": True}, headers=h)

@app.get("/nodes/delta/call")
async def decoy_delta(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"info": "public", "decoy": True}, headers=h)

@app.get("/nodes/zenith/call")
async def decoy_zenith(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"info": "public", "decoy": True}, headers=h)

@app.get("/nodes/admin/call")
async def normal_admin(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "standard_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"data": "ok"}, headers=h)

@app.get("/nodes/root/call")
async def normal_root(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "standard_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"data": "ok"}, headers=h)

@app.get("/nodes/super/call")
async def normal_super(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "standard_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"data": "ok"}, headers=h)

@app.get("/nodes/secret/call")
async def normal_secret(x_actor: str | None = Header(None)):
    h = ctx_h(x_actor, {"X-Resource-Type": "standard_endpoint", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"data": "ok"}, headers=h)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9007, log_level="error")
