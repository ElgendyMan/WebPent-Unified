"""
GOED v1.6 Hidden Target Generator
Produces executable FastAPI targets from specs.
Structurally independent from v1.5 templates.
"""
import json
import os
import sys

SPEC_DIR = sys.argv[1] if len(sys.argv) > 1 else "benchmarks/goed_v1_6_hidden/targets"
OUT_DIR = sys.argv[2] if len(sys.argv) > 2 else SPEC_DIR

HIDDEN_ROUTE_PREFIXES = [
    lambda ent: f"/{ent}/_",
    lambda ent: f"/x/{ent}",
    lambda ent: f"/zones/{ent}/ops",
    lambda ent: f"/modules/{ent}/exec",
    lambda ent: f"/_/{ent}",
    lambda ent: f"/ctx/{ent}/run",
    lambda ent: f"/e/{ent}/action",
    lambda ent: f"/nodes/{ent}/call",
    lambda ent: f"/sys/{ent}/do",
    lambda ent: f"/io/{ent}/process",
]

ROUTE_PREFIX_MAP = [
    ("/", "/_"),
    ("/x/", ""),
    ("/zones/", "/ops"),
    ("/modules/", "/exec"),
    ("/_/", ""),
    ("/ctx/", "/run"),
    ("/e/", "/action"),
    ("/nodes/", "/call"),
    ("/sys/", "/do"),
    ("/io/", "/process"),
]

TEMPLATE = r'''"""
GOED v1.6 Hidden Target: @@TARGET_ID@@
Seed: @@SEED@@ | Port: @@PORT@@
Route convention: @@ROUTE_PREFIX@@ENTITY@@ROUTE_SUFFIX@@
Roles: @@ROLES_STR@@

GENERATED HIDDEN TARGET — structurally independent from v1.5.
Local-only, synthetic, no external access, no real credentials.
"""
from fastapi import FastAPI, Header, Query, Form
from fastapi.responses import JSONResponse
from typing import Optional

app = FastAPI()

ROLES = @@ROLES_LIST@@
ROLE_LEVEL = @@ROLE_LEVEL@@
TENANTS = @@TENANTS_LIST@@
OBJECTS = @@OBJECTS_LIST@@
FIELDS = @@FIELDS_DICT@@
ACTORS = @@ACTORS_DICT@@
SENSITIVE = @@SENSITIVE_DATA@@

ADMIN_DATA = {"status": "operational", "count": 150, "events": ["ev1", "ev2", "ev3"]}
BILLING_DATA = {t: {"records": [f"R-{i}" for i in range(3)], "total": 50000 + s*1000} for s, t in enumerate(TENANTS)}
TENANT_DATA = {t: {"internal": f"hidden_{t}_data"} for t in TENANTS}
MESSAGES = {OBJECTS[0]: ["msg1", "msg2"], OBJECTS[1]: ["msgA"]}
WORKFLOWS = {"wf_@@WF_OBJ@@": {"status": "pending", "requester": OBJECTS[0]}}
ACCOUNTS = {OBJECTS[0]: {"value": 5000}, OBJECTS[1]: {"value": 1000}}
AUDIT_LOG = ["e1", "e2", "e3"]
TOKENS = {}

def get_actor(x):
    return ACTORS.get(x)

def ctx_h(x_actor, extra=None):
    a = get_actor(x_actor)
    h = {
        "X-Actor-Echo": x_actor or "anon",
        "X-Actor-Role": a["role"] if a else "none",
        "X-Actor-Tenant": a["tenant"] if a else "none",
        "X-Auth-State": "authenticated" if a else "unauth",
    }
    if extra: h.update(extra)
    return h

# === Entry points ===
@app.get("/")
async def root():
    return JSONResponse(content={"svc": "@@TARGET_ID@@", "v": "1.6", "links": ["@@ROUTE_PREFIX@@health@@ROUTE_SUFFIX@@"]})

@app.get("/openapi.json")
async def openapi_spec(x_actor: Optional[str] = Header(None)):
    headers = ctx_h(x_actor, {"X-Resource-Type": "openapi", "X-Authorization-Outcome": "granted_full"})
    paths = {}
    @@OPENAPI_PATHS@@
    return JSONResponse(content={"openapi": "3.0.0", "paths": paths}, headers=headers)

@app.get("@@ROUTE_PREFIX@@health@@ROUTE_SUFFIX@@")
async def health(x_actor: Optional[str] = Header(None)):
    headers = ctx_h(x_actor, {"X-Resource-Type": "health", "X-Authorization-Outcome": "granted_full"})
    return JSONResponse(content={"ok": True}, headers=headers)

# === Vulnerability endpoints ===
@@ENDPOINTS_CODE@@

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=@@PORT@@, log_level="error")
'''

def generate_target(spec):
    route_prefix, route_suffix = ROUTE_PREFIX_MAP[spec["route_style_index"]]

    # Build OpenAPI paths
    openapi_paths = []
    for case_id, case in spec["cases"].items():
        if not case.get("in_openapi", True):
            continue
        route = case["vulnerable_route"]
        method = case["http_method"].lower()
        openapi_paths.append(f'paths["{route}"] = {{"{method}": {{"summary": "operation"}}}}')

    # Build endpoint code for each vulnerable case
    endpoints_code = []
    for case_id, case in spec["cases"].items():
        if not case["is_vulnerable"]:
            continue

        ep = case["endpoint_name"]
        route = case["vulnerable_route"]
        ctrl_route = case["control_route"]
        method = case["http_method"]
        cls = case["class"]
        status_v = case["status_vuln"]
        status_p = case["status_patched"]
        obj = case["target_object"]
        actor = case["actor"]

        # Generate vulnerable endpoint
        vuln_code = f"""
@app.{method.lower()}("{route}")
async def ep_{ep}(x_actor: Optional[str] = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={{"error": "unauth"}})
    headers = ctx_h(x_actor, {{
        "X-Resource-Type": "{ep}",
        "X-Resource-Owner": "{obj}",
        "X-Resource-Tenant": a["tenant"],
        "X-Authorization-Outcome": "granted_full",
    }})
    return JSONResponse(status_code={status_v}, content=SENSITIVE.get("{obj}", {{}}), headers=headers)

@app.{method.lower()}("{ctrl_route}")
async def ctrl_{ep}(x_actor: Optional[str] = Header(None)):
    a = get_actor(x_actor)
    if not a:
        return JSONResponse(status_code=401, content={{"error": "unauth"}})
    headers = ctx_h(x_actor, {{"X-Resource-Type": "{ep}", "X-Resource-Owner": "{obj}"}})
    # FIXED: proper authorization check
    if a[FIELDS["id_field"]] != "{obj}" and ROLE_LEVEL[a["role"]] < 3 and a["tenant"] == TENANTS[0]:
        headers["X-Authorization-Outcome"] = "denied"
        return JSONResponse(status_code={status_p}, content={{"error": "forbidden"}}, headers=headers)
    headers["X-Authorization-Outcome"] = "granted_full"
    return JSONResponse(status_code={status_v}, content=SENSITIVE.get("{obj}", {{}}), headers=headers)
"""
        endpoints_code.append(vuln_code)

    # Add decoy endpoints
    for decoy in spec["decoy_endpoints"]:
        d_route = route_prefix + decoy + route_suffix
        endpoints_code.append(f"""
@app.get("{d_route}")
async def decoy_{decoy}(x_actor: Optional[str] = Header(None)):
    headers = ctx_h(x_actor, {{"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}})
    return JSONResponse(content={{"info": "public", "decoy": True}}, headers=headers)
""")

    # Add normal endpoints with privileged-looking names
    for pname in spec["normal_privileged_looking"]:
        p_route = route_prefix + pname + route_suffix
        endpoints_code.append(f"""
@app.get("{p_route}")
async def normal_{pname}(x_actor: Optional[str] = Header(None)):
    headers = ctx_h(x_actor, {{"X-Resource-Type": "standard_endpoint", "X-Authorization-Outcome": "granted_full"}})
    return JSONResponse(content={{"data": "standard_content", "name": "{pname}"}}, headers=headers)
""")

    replacements = {
        "@@TARGET_ID@@": spec["target_id"],
        "@@SEED@@": spec["seed"],
        "@@PORT@@": spec["port"],
        "@@ROUTE_PREFIX@@": route_prefix,
        "@@ROUTE_SUFFIX@@": route_suffix,
        "@@ROLES_STR@@": ", ".join(spec["roles"]),
        "@@ROLES_LIST@@": json.dumps(spec["roles"]),
        "@@ROLE_LEVEL@@": json.dumps(spec["role_level"]),
        "@@TENANTS_LIST@@": json.dumps(spec["tenants"]),
        "@@OBJECTS_LIST@@": json.dumps(spec["objects"]),
        "@@FIELDS_DICT@@": json.dumps(spec["fields"]),
        "@@ACTORS_DICT@@": json.dumps(spec["actors"]),
        "@@SENSITIVE_DATA@@": json.dumps(spec["sensitive_data"]),
        "@@WF_OBJ@@": spec["objects"][0],
        "@@OPENAPI_PATHS@@": "\n    ".join(openapi_paths),
        "@@ENDPOINTS_CODE@@": "\n".join(endpoints_code),
    }

    code = TEMPLATE
    for k, v in replacements.items():
        code = code.replace(k, str(v))

    return code

if __name__ == "__main__":
    for fname in os.listdir(SPEC_DIR):
        if fname.endswith("_spec.json"):
            with open(os.path.join(SPEC_DIR, fname)) as f:
                spec = json.load(f)
            code = generate_target(spec)
            out_path = os.path.join(OUT_DIR, spec["target_id"] + ".py")
            with open(out_path, "w") as f:
                f.write(code)
            print(f"Generated: {out_path}")
