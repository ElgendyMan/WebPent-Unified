"""Hidden v2 Target hidden2-07 Port 9307"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

ENTITIES = ['arch', 'beam', 'col', 'dome', 'span', 'truss', 'vault', 'pillar', 'frame', 'pier']
SENSITIVE = {'arch': {'id': 'arch', 'owner': 'owner_088', 'data': 'secret_arch_7'}, 'beam': {'id': 'beam', 'owner': 'owner_086', 'data': 'secret_beam_7'}, 'col': {'id': 'col', 'owner': 'owner_075', 'data': 'secret_col_7'}, 'dome': {'id': 'dome', 'owner': 'owner_058', 'data': 'secret_dome_7'}, 'span': {'id': 'span', 'owner': 'owner_008', 'data': 'secret_span_7'}, 'truss': {'id': 'truss', 'owner': 'owner_031', 'data': 'secret_truss_7'}, 'vault': {'id': 'vault', 'owner': 'owner_062', 'data': 'secret_vault_7'}, 'pillar': {'id': 'pillar', 'owner': 'owner_043', 'data': 'secret_pillar_7'}, 'frame': {'id': 'frame', 'owner': 'owner_071', 'data': 'secret_frame_7'}, 'pier': {'id': 'pier', 'owner': 'owner_034', 'data': 'secret_pier_7'}}
ROLES = {'viewer': 1, 'user': 1, 'editor': 2, 'manager': 3, 'admin': 4}
USERS = {'actor_a': {'id': 'u_a', 'role': 'viewer', 'tenant': 't1'}, 'actor_b': {'id': 'u_b', 'role': 'user', 'tenant': 't1'}, 'actor_c': {'id': 'u_c', 'role': 'admin', 'tenant': 't1'}, 'actor_d': {'id': 'u_d', 'role': 'user', 'tenant': 't2'}}

def hdr(x_actor, extra=None):
    u = USERS.get(x_actor, {})
    h = {'X-Actor-Echo': x_actor or 'anon', 'X-Actor-Role': u.get('role', 'none'), 'X-Actor-Tenant': u.get('tenant', 'none'), 'X-Auth-State': 'authenticated' if u else 'unauth'}
    if extra: h.update(extra)
    return h

# BASELINE: actor IS authorized (owner == actor), shares prefix with candidates
@app.get('/arc/arch/sys/authorized')
async def baseline_authorized(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor, {})
    aid = u.get('id', x_actor or 'anon')
    return JSONResponse(content={"id": aid, "owner": aid}, headers=hdr(x_actor, {"X-Resource-Type": "actor_own", "X-Resource-Owner": aid, "X-Authorization-Outcome": "granted_full"}))

# Vuln 0: idor via json_body_field
@app.get('/arc/arch/sys')
async def vuln_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('arch', {}), headers=hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['arch']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'json_body_field'}))

# Control for vuln 0: same resource_type, but DENIED
@app.get('/arc/patched/arch/sys')
async def ctrl_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['arch']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 1: broken_access_control via missing_role_check
@app.get('/arc/beam/sys')
async def vuln_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('beam', {}), headers=hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['beam']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'missing_role_check'}))

# Control for vuln 1: same resource_type, but DENIED
@app.get('/arc/patched/beam/sys')
async def ctrl_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['beam']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 2: privilege_escalation via role_inference
@app.get('/arc/col/sys')
async def vuln_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('col', {}), headers=hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['col']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'role_inference'}))

# Control for vuln 2: same resource_type, but DENIED
@app.get('/arc/patched/col/sys')
async def ctrl_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['col']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 3: tenant_isolation_failure via cross_tenant_idor
@app.get('/arc/dome/sys')
async def vuln_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('dome', {}), headers=hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['dome']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'cross_tenant_idor'}))

# Control for vuln 3: same resource_type, but DENIED
@app.get('/arc/patched/dome/sys')
async def ctrl_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['dome']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 4: business_logic_abuse via negative_amount
@app.get('/arc/span/sys')
async def vuln_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('span', {}), headers=hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['span']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'negative_amount'}))

# Control for vuln 4: same resource_type, but DENIED
@app.get('/arc/patched/span/sys')
async def ctrl_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['span']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 5: workflow_authorization_failure via self_approval
@app.get('/arc/truss/sys')
async def vuln_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('truss', {}), headers=hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['truss']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'self_approval'}))

# Control for vuln 5: same resource_type, but DENIED
@app.get('/arc/patched/truss/sys')
async def ctrl_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['truss']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 6: sensitive_data_exposure via header_leak
@app.get('/arc/vault/sys')
async def vuln_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('vault', {}), headers=hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['vault']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'header_leak'}))

# Control for vuln 6: same resource_type, but DENIED
@app.get('/arc/patched/vault/sys')
async def ctrl_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['vault']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 7: multi_step_chain via token_for_other_user
@app.get('/arc/pillar/sys')
async def vuln_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('pillar', {}), headers=hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['pillar']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'token_for_other_user'}))

# Control for vuln 7: same resource_type, but DENIED
@app.get('/arc/patched/pillar/sys')
async def ctrl_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['pillar']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 8: mass_assignment via protected_field_update
@app.get('/arc/frame/sys')
async def vuln_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('frame', {}), headers=hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['frame']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'protected_field_update'}))

# Control for vuln 8: same resource_type, but DENIED
@app.get('/arc/patched/frame/sys')
async def ctrl_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['frame']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 9: race_condition via limited_claim
@app.get('/arc/pier/sys')
async def vuln_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('pier', {}), headers=hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['pier']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'limited_claim'}))

# Control for vuln 9: same resource_type, but DENIED
@app.get('/arc/patched/pier/sys')
async def ctrl_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['pier']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Clean 0
@app.get('/arc/public0/sys')
async def clean_0(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_0"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 1
@app.get('/arc/public1/sys')
async def clean_1(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_1"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 2
@app.get('/arc/public2/sys')
async def clean_2(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_2"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 3
@app.get('/arc/public3/sys')
async def clean_3(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_3"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

@app.get('/')
async def root(): return JSONResponse(content={'svc': 'hidden2-07', 'port': 9307})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=9307, log_level='error')
