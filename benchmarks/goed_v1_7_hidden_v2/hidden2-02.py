"""Hidden v2 Target hidden2-02 Port 9302"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

ENTITIES = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta', 'iota', 'kappa']
SENSITIVE = {'alpha': {'id': 'alpha', 'owner': 'owner_066', 'data': 'secret_alpha_2'}, 'beta': {'id': 'beta', 'owner': 'owner_001', 'data': 'secret_beta_2'}, 'gamma': {'id': 'gamma', 'owner': 'owner_031', 'data': 'secret_gamma_2'}, 'delta': {'id': 'delta', 'owner': 'owner_033', 'data': 'secret_delta_2'}, 'epsilon': {'id': 'epsilon', 'owner': 'owner_005', 'data': 'secret_epsilon_2'}, 'zeta': {'id': 'zeta', 'owner': 'owner_055', 'data': 'secret_zeta_2'}, 'eta': {'id': 'eta', 'owner': 'owner_055', 'data': 'secret_eta_2'}, 'theta': {'id': 'theta', 'owner': 'owner_087', 'data': 'secret_theta_2'}, 'iota': {'id': 'iota', 'owner': 'owner_080', 'data': 'secret_iota_2'}, 'kappa': {'id': 'kappa', 'owner': 'owner_080', 'data': 'secret_kappa_2'}}
ROLES = {'viewer': 1, 'user': 1, 'editor': 2, 'manager': 3, 'admin': 4}
USERS = {'actor_a': {'id': 'u_a', 'role': 'viewer', 'tenant': 't1'}, 'actor_b': {'id': 'u_b', 'role': 'user', 'tenant': 't1'}, 'actor_c': {'id': 'u_c', 'role': 'admin', 'tenant': 't1'}, 'actor_d': {'id': 'u_d', 'role': 'user', 'tenant': 't2'}}

def hdr(x_actor, extra=None):
    u = USERS.get(x_actor, {})
    h = {'X-Actor-Echo': x_actor or 'anon', 'X-Actor-Role': u.get('role', 'none'), 'X-Actor-Tenant': u.get('tenant', 'none'), 'X-Auth-State': 'authenticated' if u else 'unauth'}
    if extra: h.update(extra)
    return h

# BASELINE: actor IS authorized (owner == actor), shares prefix with candidates
@app.get('/srv/alpha/io/authorized')
async def baseline_authorized(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor, {})
    aid = u.get('id', x_actor or 'anon')
    return JSONResponse(content={"id": aid, "owner": aid}, headers=hdr(x_actor, {"X-Resource-Type": "actor_own", "X-Resource-Owner": aid, "X-Authorization-Outcome": "granted_full"}))

# Vuln 0: idor via path_param
@app.get('/srv/alpha/io')
async def vuln_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('alpha', {}), headers=hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['alpha']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'path_param'}))

# Control for vuln 0: same resource_type, but DENIED
@app.get('/srv/patched/alpha/io')
async def ctrl_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['alpha']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 1: broken_access_control via bypass_via_get
@app.get('/srv/beta/io')
async def vuln_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('beta', {}), headers=hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['beta']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'bypass_via_get'}))

# Control for vuln 1: same resource_type, but DENIED
@app.get('/srv/patched/beta/io')
async def ctrl_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['beta']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 2: privilege_escalation via tenant_bypass
@app.get('/srv/gamma/io')
async def vuln_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('gamma', {}), headers=hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['gamma']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'tenant_bypass'}))

# Control for vuln 2: same resource_type, but DENIED
@app.get('/srv/patched/gamma/io')
async def ctrl_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['gamma']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 3: tenant_isolation_failure via cross_tenant_idor
@app.get('/srv/delta/io')
async def vuln_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('delta', {}), headers=hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['delta']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'cross_tenant_idor'}))

# Control for vuln 3: same resource_type, but DENIED
@app.get('/srv/patched/delta/io')
async def ctrl_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['delta']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 4: business_logic_abuse via negative_amount
@app.get('/srv/epsilon/io')
async def vuln_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('epsilon', {}), headers=hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['epsilon']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'negative_amount'}))

# Control for vuln 4: same resource_type, but DENIED
@app.get('/srv/patched/epsilon/io')
async def ctrl_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['epsilon']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 5: workflow_authorization_failure via self_approval
@app.get('/srv/zeta/io')
async def vuln_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('zeta', {}), headers=hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['zeta']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'self_approval'}))

# Control for vuln 5: same resource_type, but DENIED
@app.get('/srv/patched/zeta/io')
async def ctrl_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['zeta']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 6: sensitive_data_exposure via body_leak
@app.get('/srv/eta/io')
async def vuln_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('eta', {}), headers=hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['eta']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'body_leak'}))

# Control for vuln 6: same resource_type, but DENIED
@app.get('/srv/patched/eta/io')
async def ctrl_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['eta']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 7: multi_step_chain via skipped_verification
@app.get('/srv/theta/io')
async def vuln_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('theta', {}), headers=hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['theta']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'skipped_verification'}))

# Control for vuln 7: same resource_type, but DENIED
@app.get('/srv/patched/theta/io')
async def ctrl_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['theta']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 8: mass_assignment via protected_field_update
@app.get('/srv/iota/io')
async def vuln_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('iota', {}), headers=hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['iota']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'protected_field_update'}))

# Control for vuln 8: same resource_type, but DENIED
@app.get('/srv/patched/iota/io')
async def ctrl_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['iota']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 9: race_condition via check_then_act_counter
@app.get('/srv/kappa/io')
async def vuln_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('kappa', {}), headers=hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['kappa']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'check_then_act_counter'}))

# Control for vuln 9: same resource_type, but DENIED
@app.get('/srv/patched/kappa/io')
async def ctrl_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['kappa']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Clean 0
@app.get('/srv/public0/io')
async def clean_0(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_0"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 1
@app.get('/srv/public1/io')
async def clean_1(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_1"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 2
@app.get('/srv/public2/io')
async def clean_2(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_2"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 3
@app.get('/srv/public3/io')
async def clean_3(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_3"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

@app.get('/')
async def root(): return JSONResponse(content={'svc': 'hidden2-02', 'port': 9302})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=9302, log_level='error')
