"""Hidden v2 Target hidden2-04 Port 9304"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

ENTITIES = ['node_a', 'node_b', 'node_c', 'node_d', 'node_e', 'node_f', 'node_g', 'node_h', 'node_i', 'node_j']
SENSITIVE = {'node_a': {'id': 'node_a', 'owner': 'owner_060', 'data': 'secret_node_a_4'}, 'node_b': {'id': 'node_b', 'owner': 'owner_077', 'data': 'secret_node_b_4'}, 'node_c': {'id': 'node_c', 'owner': 'owner_051', 'data': 'secret_node_c_4'}, 'node_d': {'id': 'node_d', 'owner': 'owner_081', 'data': 'secret_node_d_4'}, 'node_e': {'id': 'node_e', 'owner': 'owner_033', 'data': 'secret_node_e_4'}, 'node_f': {'id': 'node_f', 'owner': 'owner_026', 'data': 'secret_node_f_4'}, 'node_g': {'id': 'node_g', 'owner': 'owner_060', 'data': 'secret_node_g_4'}, 'node_h': {'id': 'node_h', 'owner': 'owner_045', 'data': 'secret_node_h_4'}, 'node_i': {'id': 'node_i', 'owner': 'owner_070', 'data': 'secret_node_i_4'}, 'node_j': {'id': 'node_j', 'owner': 'owner_050', 'data': 'secret_node_j_4'}}
ROLES = {'viewer': 1, 'user': 1, 'editor': 2, 'manager': 3, 'admin': 4}
USERS = {'actor_a': {'id': 'u_a', 'role': 'viewer', 'tenant': 't1'}, 'actor_b': {'id': 'u_b', 'role': 'user', 'tenant': 't1'}, 'actor_c': {'id': 'u_c', 'role': 'admin', 'tenant': 't1'}, 'actor_d': {'id': 'u_d', 'role': 'user', 'tenant': 't2'}}

def hdr(x_actor, extra=None):
    u = USERS.get(x_actor, {})
    h = {'X-Actor-Echo': x_actor or 'anon', 'X-Actor-Role': u.get('role', 'none'), 'X-Actor-Tenant': u.get('tenant', 'none'), 'X-Auth-State': 'authenticated' if u else 'unauth'}
    if extra: h.update(extra)
    return h

# BASELINE: actor IS authorized (owner == actor), shares prefix with candidates
@app.get('/net/node_a/mesh/authorized')
async def baseline_authorized(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor, {})
    aid = u.get('id', x_actor or 'anon')
    return JSONResponse(content={"id": aid, "owner": aid}, headers=hdr(x_actor, {"X-Resource-Type": "actor_own", "X-Resource-Owner": aid, "X-Authorization-Outcome": "granted_full"}))

# Vuln 0: idor via path_param
@app.get('/net/node_a/mesh')
async def vuln_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_a', {}), headers=hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['node_a']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'path_param'}))

# Control for vuln 0: same resource_type, but DENIED
@app.get('/net/patched/node_a/mesh')
async def ctrl_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['node_a']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 1: broken_access_control via missing_role_check
@app.get('/net/node_b/mesh')
async def vuln_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_b', {}), headers=hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['node_b']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'missing_role_check'}))

# Control for vuln 1: same resource_type, but DENIED
@app.get('/net/patched/node_b/mesh')
async def ctrl_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['node_b']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 2: privilege_escalation via role_inference
@app.get('/net/node_c/mesh')
async def vuln_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_c', {}), headers=hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['node_c']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'role_inference'}))

# Control for vuln 2: same resource_type, but DENIED
@app.get('/net/patched/node_c/mesh')
async def ctrl_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['node_c']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 3: tenant_isolation_failure via tenant_header_ignored
@app.get('/net/node_d/mesh')
async def vuln_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_d', {}), headers=hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['node_d']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'tenant_header_ignored'}))

# Control for vuln 3: same resource_type, but DENIED
@app.get('/net/patched/node_d/mesh')
async def ctrl_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['node_d']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 4: business_logic_abuse via negative_amount
@app.get('/net/node_e/mesh')
async def vuln_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_e', {}), headers=hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['node_e']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'negative_amount'}))

# Control for vuln 4: same resource_type, but DENIED
@app.get('/net/patched/node_e/mesh')
async def ctrl_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['node_e']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 5: workflow_authorization_failure via self_approval
@app.get('/net/node_f/mesh')
async def vuln_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_f', {}), headers=hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['node_f']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'self_approval'}))

# Control for vuln 5: same resource_type, but DENIED
@app.get('/net/patched/node_f/mesh')
async def ctrl_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['node_f']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 6: sensitive_data_exposure via body_leak
@app.get('/net/node_g/mesh')
async def vuln_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_g', {}), headers=hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['node_g']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'body_leak'}))

# Control for vuln 6: same resource_type, but DENIED
@app.get('/net/patched/node_g/mesh')
async def ctrl_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['node_g']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 7: multi_step_chain via skipped_verification
@app.get('/net/node_h/mesh')
async def vuln_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_h', {}), headers=hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['node_h']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'skipped_verification'}))

# Control for vuln 7: same resource_type, but DENIED
@app.get('/net/patched/node_h/mesh')
async def ctrl_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['node_h']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 8: mass_assignment via protected_field_update
@app.get('/net/node_i/mesh')
async def vuln_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_i', {}), headers=hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['node_i']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'protected_field_update'}))

# Control for vuln 8: same resource_type, but DENIED
@app.get('/net/patched/node_i/mesh')
async def ctrl_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['node_i']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 9: race_condition via limited_claim
@app.get('/net/node_j/mesh')
async def vuln_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('node_j', {}), headers=hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['node_j']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'limited_claim'}))

# Control for vuln 9: same resource_type, but DENIED
@app.get('/net/patched/node_j/mesh')
async def ctrl_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['node_j']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Clean 0
@app.get('/net/public0/mesh')
async def clean_0(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_0"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 1
@app.get('/net/public1/mesh')
async def clean_1(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_1"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 2
@app.get('/net/public2/mesh')
async def clean_2(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_2"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 3
@app.get('/net/public3/mesh')
async def clean_3(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_3"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

@app.get('/')
async def root(): return JSONResponse(content={'svc': 'hidden2-04', 'port': 9304})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=9304, log_level='error')
