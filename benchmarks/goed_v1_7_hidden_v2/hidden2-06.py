"""Hidden v2 Target hidden2-06 Port 9306"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

ENTITIES = ['stream', 'river', 'creek', 'brook', 'tide', 'wave', 'surge', 'drift', 'eddy', 'rip']
SENSITIVE = {'stream': {'id': 'stream', 'owner': 'owner_032', 'data': 'secret_stream_6'}, 'river': {'id': 'river', 'owner': 'owner_019', 'data': 'secret_river_6'}, 'creek': {'id': 'creek', 'owner': 'owner_046', 'data': 'secret_creek_6'}, 'brook': {'id': 'brook', 'owner': 'owner_008', 'data': 'secret_brook_6'}, 'tide': {'id': 'tide', 'owner': 'owner_043', 'data': 'secret_tide_6'}, 'wave': {'id': 'wave', 'owner': 'owner_039', 'data': 'secret_wave_6'}, 'surge': {'id': 'surge', 'owner': 'owner_063', 'data': 'secret_surge_6'}, 'drift': {'id': 'drift', 'owner': 'owner_051', 'data': 'secret_drift_6'}, 'eddy': {'id': 'eddy', 'owner': 'owner_038', 'data': 'secret_eddy_6'}, 'rip': {'id': 'rip', 'owner': 'owner_098', 'data': 'secret_rip_6'}}
ROLES = {'viewer': 1, 'user': 1, 'editor': 2, 'manager': 3, 'admin': 4}
USERS = {'actor_a': {'id': 'u_a', 'role': 'viewer', 'tenant': 't1'}, 'actor_b': {'id': 'u_b', 'role': 'user', 'tenant': 't1'}, 'actor_c': {'id': 'u_c', 'role': 'admin', 'tenant': 't1'}, 'actor_d': {'id': 'u_d', 'role': 'user', 'tenant': 't2'}}

def hdr(x_actor, extra=None):
    u = USERS.get(x_actor, {})
    h = {'X-Actor-Echo': x_actor or 'anon', 'X-Actor-Role': u.get('role', 'none'), 'X-Actor-Tenant': u.get('tenant', 'none'), 'X-Auth-State': 'authenticated' if u else 'unauth'}
    if extra: h.update(extra)
    return h

# BASELINE: actor IS authorized (owner == actor), shares prefix with candidates
@app.get('/flow/stream/pipe/authorized')
async def baseline_authorized(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor, {})
    aid = u.get('id', x_actor or 'anon')
    return JSONResponse(content={"id": aid, "owner": aid}, headers=hdr(x_actor, {"X-Resource-Type": "actor_own", "X-Resource-Owner": aid, "X-Authorization-Outcome": "granted_full"}))

# Vuln 0: idor via path_param
@app.get('/flow/stream/pipe')
async def vuln_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('stream', {}), headers=hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['stream']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'path_param'}))

# Control for vuln 0: same resource_type, but DENIED
@app.get('/flow/patched/stream/pipe')
async def ctrl_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['stream']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 1: broken_access_control via bypass_via_get
@app.get('/flow/river/pipe')
async def vuln_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('river', {}), headers=hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['river']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'bypass_via_get'}))

# Control for vuln 1: same resource_type, but DENIED
@app.get('/flow/patched/river/pipe')
async def ctrl_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['river']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 2: privilege_escalation via tenant_bypass
@app.get('/flow/creek/pipe')
async def vuln_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('creek', {}), headers=hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['creek']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'tenant_bypass'}))

# Control for vuln 2: same resource_type, but DENIED
@app.get('/flow/patched/creek/pipe')
async def ctrl_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['creek']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 3: tenant_isolation_failure via tenant_header_ignored
@app.get('/flow/brook/pipe')
async def vuln_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('brook', {}), headers=hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['brook']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'tenant_header_ignored'}))

# Control for vuln 3: same resource_type, but DENIED
@app.get('/flow/patched/brook/pipe')
async def ctrl_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['brook']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 4: business_logic_abuse via ordering_violation
@app.get('/flow/tide/pipe')
async def vuln_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('tide', {}), headers=hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['tide']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'ordering_violation'}))

# Control for vuln 4: same resource_type, but DENIED
@app.get('/flow/patched/tide/pipe')
async def ctrl_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['tide']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 5: workflow_authorization_failure via self_approval
@app.get('/flow/wave/pipe')
async def vuln_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('wave', {}), headers=hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['wave']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'self_approval'}))

# Control for vuln 5: same resource_type, but DENIED
@app.get('/flow/patched/wave/pipe')
async def ctrl_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['wave']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 6: sensitive_data_exposure via header_leak
@app.get('/flow/surge/pipe')
async def vuln_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('surge', {}), headers=hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['surge']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'header_leak'}))

# Control for vuln 6: same resource_type, but DENIED
@app.get('/flow/patched/surge/pipe')
async def ctrl_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['surge']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 7: multi_step_chain via skipped_verification
@app.get('/flow/drift/pipe')
async def vuln_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('drift', {}), headers=hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['drift']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'skipped_verification'}))

# Control for vuln 7: same resource_type, but DENIED
@app.get('/flow/patched/drift/pipe')
async def ctrl_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['drift']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 8: mass_assignment via role_escalation
@app.get('/flow/eddy/pipe')
async def vuln_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('eddy', {}), headers=hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['eddy']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'role_escalation'}))

# Control for vuln 8: same resource_type, but DENIED
@app.get('/flow/patched/eddy/pipe')
async def ctrl_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['eddy']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 9: race_condition via check_then_act_counter
@app.get('/flow/rip/pipe')
async def vuln_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('rip', {}), headers=hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['rip']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'check_then_act_counter'}))

# Control for vuln 9: same resource_type, but DENIED
@app.get('/flow/patched/rip/pipe')
async def ctrl_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['rip']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Clean 0
@app.get('/flow/public0/pipe')
async def clean_0(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_0"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 1
@app.get('/flow/public1/pipe')
async def clean_1(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_1"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 2
@app.get('/flow/public2/pipe')
async def clean_2(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_2"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 3
@app.get('/flow/public3/pipe')
async def clean_3(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_3"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

@app.get('/')
async def root(): return JSONResponse(content={'svc': 'hidden2-06', 'port': 9306})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=9306, log_level='error')
