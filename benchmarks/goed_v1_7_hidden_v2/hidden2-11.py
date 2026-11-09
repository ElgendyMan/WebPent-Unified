"""Hidden v2 Target hidden2-11 Port 9311"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()

ENTITIES = ['za', 'zb', 'zc', 'zd', 'ze', 'zf', 'zg', 'zh', 'zi', 'zj']
SENSITIVE = {'za': {'id': 'za', 'owner': 'owner_087', 'data': 'secret_za_11'}, 'zb': {'id': 'zb', 'owner': 'owner_007', 'data': 'secret_zb_11'}, 'zc': {'id': 'zc', 'owner': 'owner_029', 'data': 'secret_zc_11'}, 'zd': {'id': 'zd', 'owner': 'owner_044', 'data': 'secret_zd_11'}, 'ze': {'id': 'ze', 'owner': 'owner_045', 'data': 'secret_ze_11'}, 'zf': {'id': 'zf', 'owner': 'owner_058', 'data': 'secret_zf_11'}, 'zg': {'id': 'zg', 'owner': 'owner_029', 'data': 'secret_zg_11'}, 'zh': {'id': 'zh', 'owner': 'owner_047', 'data': 'secret_zh_11'}, 'zi': {'id': 'zi', 'owner': 'owner_053', 'data': 'secret_zi_11'}, 'zj': {'id': 'zj', 'owner': 'owner_076', 'data': 'secret_zj_11'}}
ROLES = {'viewer': 1, 'user': 1, 'editor': 2, 'manager': 3, 'admin': 4}
USERS = {'actor_a': {'id': 'u_a', 'role': 'viewer', 'tenant': 't1'}, 'actor_b': {'id': 'u_b', 'role': 'user', 'tenant': 't1'}, 'actor_c': {'id': 'u_c', 'role': 'admin', 'tenant': 't1'}, 'actor_d': {'id': 'u_d', 'role': 'user', 'tenant': 't2'}}

def hdr(x_actor, extra=None):
    u = USERS.get(x_actor, {})
    h = {'X-Actor-Echo': x_actor or 'anon', 'X-Actor-Role': u.get('role', 'none'), 'X-Actor-Tenant': u.get('tenant', 'none'), 'X-Auth-State': 'authenticated' if u else 'unauth'}
    if extra: h.update(extra)
    return h

# BASELINE: actor IS authorized (owner == actor), shares prefix with candidates
@app.get('/z/za/fn/authorized')
async def baseline_authorized(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor, {})
    aid = u.get('id', x_actor or 'anon')
    return JSONResponse(content={"id": aid, "owner": aid}, headers=hdr(x_actor, {"X-Resource-Type": "actor_own", "X-Resource-Owner": aid, "X-Authorization-Outcome": "granted_full"}))

# Vuln 0: idor via query_param
@app.get('/z/za/fn')
async def vuln_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('za', {}), headers=hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['za']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'query_param'}))

# Control for vuln 0: same resource_type, but DENIED
@app.get('/z/patched/za/fn')
async def ctrl_0(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'idor', 'X-Resource-Owner': SENSITIVE['za']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 1: broken_access_control via bypass_via_get
@app.get('/z/zb/fn')
async def vuln_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('zb', {}), headers=hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['zb']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'bypass_via_get'}))

# Control for vuln 1: same resource_type, but DENIED
@app.get('/z/patched/zb/fn')
async def ctrl_1(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'broken_access_control', 'X-Resource-Owner': SENSITIVE['zb']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 2: privilege_escalation via tenant_bypass
@app.get('/z/zc/fn')
async def vuln_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('zc', {}), headers=hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['zc']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'tenant_bypass'}))

# Control for vuln 2: same resource_type, but DENIED
@app.get('/z/patched/zc/fn')
async def ctrl_2(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'privilege_escalation', 'X-Resource-Owner': SENSITIVE['zc']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 3: tenant_isolation_failure via cross_tenant_idor
@app.get('/z/zd/fn')
async def vuln_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('zd', {}), headers=hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['zd']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'cross_tenant_idor'}))

# Control for vuln 3: same resource_type, but DENIED
@app.get('/z/patched/zd/fn')
async def ctrl_3(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'tenant_isolation_failure', 'X-Resource-Owner': SENSITIVE['zd']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 4: business_logic_abuse via ordering_violation
@app.get('/z/ze/fn')
async def vuln_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('ze', {}), headers=hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['ze']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'ordering_violation'}))

# Control for vuln 4: same resource_type, but DENIED
@app.get('/z/patched/ze/fn')
async def ctrl_4(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'business_logic_abuse', 'X-Resource-Owner': SENSITIVE['ze']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 5: workflow_authorization_failure via skipped_state
@app.get('/z/zf/fn')
async def vuln_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('zf', {}), headers=hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['zf']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'skipped_state'}))

# Control for vuln 5: same resource_type, but DENIED
@app.get('/z/patched/zf/fn')
async def ctrl_5(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'workflow_authorization_failure', 'X-Resource-Owner': SENSITIVE['zf']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 6: sensitive_data_exposure via header_leak
@app.get('/z/zg/fn')
async def vuln_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('zg', {}), headers=hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['zg']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'header_leak'}))

# Control for vuln 6: same resource_type, but DENIED
@app.get('/z/patched/zg/fn')
async def ctrl_6(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'sensitive_data_exposure', 'X-Resource-Owner': SENSITIVE['zg']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 7: multi_step_chain via token_for_other_user
@app.get('/z/zh/fn')
async def vuln_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('zh', {}), headers=hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['zh']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'token_for_other_user'}))

# Control for vuln 7: same resource_type, but DENIED
@app.get('/z/patched/zh/fn')
async def ctrl_7(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'multi_step_chain', 'X-Resource-Owner': SENSITIVE['zh']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 8: mass_assignment via role_escalation
@app.get('/z/zi/fn')
async def vuln_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('zi', {}), headers=hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['zi']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'role_escalation'}))

# Control for vuln 8: same resource_type, but DENIED
@app.get('/z/patched/zi/fn')
async def ctrl_8(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'mass_assignment', 'X-Resource-Owner': SENSITIVE['zi']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Vuln 9: race_condition via check_then_act_counter
@app.get('/z/zj/fn')
async def vuln_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    return JSONResponse(content=SENSITIVE.get('zj', {}), headers=hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['zj']['owner'], 'X-Resource-Tenant': 't1', 'X-Authorization-Outcome': 'granted_full', 'X-Mechanism': 'check_then_act_counter'}))

# Control for vuln 9: same resource_type, but DENIED
@app.get('/z/patched/zj/fn')
async def ctrl_9(x_actor: str | None = Header(None)):
    u = USERS.get(x_actor)
    if not u: return JSONResponse(status_code=401, content={'error': 'unauth'}, headers=hdr(x_actor))
    hdrs = hdr(x_actor, {'X-Resource-Type': 'race_condition', 'X-Resource-Owner': SENSITIVE['zj']['owner'], 'X-Resource-Tenant': 't1'})
    hdrs["X-Authorization-Outcome"] = "denied"
    return JSONResponse(status_code=403, content={'error': 'forbidden'}, headers=hdrs)

# Clean 0
@app.get('/z/public0/fn')
async def clean_0(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_0"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 1
@app.get('/z/public1/fn')
async def clean_1(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_1"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 2
@app.get('/z/public2/fn')
async def clean_2(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_2"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

# Clean 3
@app.get('/z/public3/fn')
async def clean_3(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "info_3"}, headers=hdr(x_actor, {"X-Resource-Type": "public", "X-Authorization-Outcome": "granted_full"}))

@app.get('/')
async def root(): return JSONResponse(content={'svc': 'hidden2-11', 'port': 9311})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=9311, log_level='error')
