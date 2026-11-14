"""GOED v1.7 - Adversarial v3 Target (CORRECT: control echoes resource_type)"""

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

app = FastAPI()
UID = '47ef8735-65b9-646b-32f7-4aaa1e82cdd1'
UID2 = 'd9bfb6a3-3f86-e369-80c6-bb0fdd4855a4'
ENC = 'dGFyZ2V0X3Jlc291cmNlXzAwMQ=='
NESTED = {'level1': {'level2': {'level3': {'data': 'sensitive_nested', 'owner': 'target_user'}}}}

def hdr(x_actor, extra=None):
    h = {"X-Actor-Echo": x_actor or "anon", "X-Auth-State": "authenticated" if x_actor else "unauth"}
    if extra: h.update(extra)
    return h

# BASELINE: actor IS owner, same prefix /adv3/v1
@app.get('/adv3/v1/own')
async def baseline_own(x_actor: str | None = Header(None)):
    aid = x_actor or "anon"
    return JSONResponse(content={"id": aid, "owner": aid, "data": "actor_own_resource"},
        headers=hdr(x_actor, {"X-Resource-Type": "actor_own", "X-Resource-Owner": aid, "X-Authorization-Outcome": "granted_full"}))

# Vuln 0: same_status_diff_semantics
@app.get('/adv3/v1/secrets')
async def vuln_0(x_actor: str | None = Header(None)):
    return JSONResponse(content={"secret": "SENSITIVE_v1", "ssn": "XXX-XX-9999"}, headers=hdr(x_actor, {"X-Resource-Type": "sensitive_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 0: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/secrets')
async def ctrl_0(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "sensitive_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 1: diff_status_same_meaning
@app.get('/adv3/v1/item-create')
async def vuln_1(x_actor: str | None = Header(None)):
    return JSONResponse(content={"id": "new", "owner": "other_user", "data": "sensitive"}, headers=hdr(x_actor, {"X-Resource-Type": "item_record", "X-Resource-Owner": "other_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 1: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/item-create')
async def ctrl_1(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "item_record", "X-Resource-Owner": "other_user", "X-Authorization-Outcome": "denied"}))

# Vuln 2: identical_body_diff_ownership
@app.get('/adv3/v1/other-profile')
async def vuln_2(x_actor: str | None = Header(None)):
    return JSONResponse(content={"data": "value", "status": "ok"}, headers=hdr(x_actor, {"X-Resource-Type": "profile_record", "X-Resource-Owner": "other_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 2: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/other-profile')
async def ctrl_2(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "profile_record", "X-Resource-Owner": "other_user", "X-Authorization-Outcome": "denied"}))

# Vuln 3: opaque_identifiers
@app.get('/adv3/v1/opaque/47ef8735-65b9-646b-32f7-4aaa1e82cdd1')
async def vuln_3(x_actor: str | None = Header(None)):
    return JSONResponse(content={"id": "47ef8735-65b9-646b-32f7-4aaa1e82cdd1", "owner": "d9bfb6a3-3f86-e369-80c6-bb0fdd4855a4", "data": "sensitive_data"}, headers=hdr(x_actor, {"X-Resource-Type": "opaque_record", "X-Resource-Owner": "d9bfb6a3-3f86-e369-80c6-bb0fdd4855a4", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 3: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/opaque/47ef8735-65b9-646b-32f7-4aaa1e82cdd1')
async def ctrl_3(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "opaque_record", "X-Resource-Owner": "d9bfb6a3-3f86-e369-80c6-bb0fdd4855a4", "X-Authorization-Outcome": "denied"}))

# Vuln 4: nested_json_payloads
@app.get('/adv3/v1/nested-deep')
async def vuln_4(x_actor: str | None = Header(None)):
    return JSONResponse(content=NESTED, headers=hdr(x_actor, {"X-Resource-Type": "nested_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 4: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/nested-deep')
async def ctrl_4(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "nested_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 5: encoded_identifiers
@app.get('/adv3/v1/encoded/dGFyZ2V0X3Jlc291cmNlXzAwMQ==')
async def vuln_5(x_actor: str | None = Header(None)):
    return JSONResponse(content={"encoded_id": "dGFyZ2V0X3Jlc291cmNlXzAwMQ==", "data": "sensitive_encoded", "owner": "target_user"}, headers=hdr(x_actor, {"X-Resource-Type": "encoded_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 5: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/encoded/dGFyZ2V0X3Jlc291cmNlXzAwMQ==')
async def ctrl_5(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "encoded_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 6: url_aliases
@app.get('/adv3/v1/alias-primary')
async def vuln_6(x_actor: str | None = Header(None)):
    return JSONResponse(content={"secret": "alias_secret", "owner": "target_user"}, headers=hdr(x_actor, {"X-Resource-Type": "alias_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 6: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/alias-primary')
async def ctrl_6(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "alias_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 7: method_variation
@app.get('/adv3/v1/method-bypass')
async def vuln_7(x_actor: str | None = Header(None)):
    return JSONResponse(content={"data": "method_bypass_data", "owner": "target_user"}, headers=hdr(x_actor, {"X-Resource-Type": "method_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 7: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/method-bypass')
async def ctrl_7(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "method_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 8: header_based_authz
@app.get('/adv3/v1/header-protected')
async def vuln_8(x_actor: str | None = Header(None)):
    return JSONResponse(content={"data": "header_bypass", "owner": "target_user"}, headers=hdr(x_actor, {"X-Resource-Type": "header_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 8: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/header-protected')
async def ctrl_8(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "header_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 9: tenant_isolation_bypass
@app.get('/adv3/v1/tenant-bypass')
async def vuln_9(x_actor: str | None = Header(None)):
    return JSONResponse(content={"data": "cross_tenant", "tenant": "t2", "owner": "tenant2_user"}, headers=hdr(x_actor, {"X-Resource-Type": "tenant_record", "X-Resource-Owner": "tenant2_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 9: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/tenant-bypass')
async def ctrl_9(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "tenant_record", "X-Resource-Owner": "tenant2_user", "X-Authorization-Outcome": "denied"}))

# Vuln 10: privilege_escalation
@app.get('/adv3/v1/role-escalation')
async def vuln_10(x_actor: str | None = Header(None)):
    return JSONResponse(content={"role": "admin", "privileges": "all", "user": "actor_self"}, headers=hdr(x_actor, {"X-Resource-Type": "privilege_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 10: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/role-escalation')
async def ctrl_10(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "privilege_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 11: mass_assignment
@app.get('/adv3/v1/mass-assign')
async def vuln_11(x_actor: str | None = Header(None)):
    return JSONResponse(content={"id": "x", "role": "admin", "is_admin": True, "owner": "target_user"}, headers=hdr(x_actor, {"X-Resource-Type": "mass_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 11: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/mass-assign')
async def ctrl_11(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "mass_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 12: race_condition
@app.get('/adv3/v1/race-counter')
async def vuln_12(x_actor: str | None = Header(None)):
    return JSONResponse(content={"claimed": True, "remaining": 99, "counter": "decremented"}, headers=hdr(x_actor, {"X-Resource-Type": "race_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 12: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/race-counter')
async def ctrl_12(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "race_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 13: multi_step_chain
@app.get('/adv3/v1/multistep-token')
async def vuln_13(x_actor: str | None = Header(None)):
    return JSONResponse(content={"token": "stolen_token", "valid": True, "for_user": "target_user"}, headers=hdr(x_actor, {"X-Resource-Type": "token_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 13: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/multistep-token')
async def ctrl_13(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "token_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 14: stateful_side_effects
@app.get('/adv3/v1/stateful-side')
async def vuln_14(x_actor: str | None = Header(None)):
    return JSONResponse(content={"balance": 9999, "from": "other", "to": "attacker"}, headers=hdr(x_actor, {"X-Resource-Type": "financial_record", "X-Resource-Owner": "other_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 14: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/stateful-side')
async def ctrl_14(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "financial_record", "X-Resource-Owner": "other_user", "X-Authorization-Outcome": "denied"}))

# Vuln 15: random_status_codes
@app.get('/adv3/v1/random-status')
async def vuln_15(x_actor: str | None = Header(None)):
    return JSONResponse(content={"leaked": "data", "owner": "target_user"}, headers=hdr(x_actor, {"X-Resource-Type": "leak_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 15: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/random-status')
async def ctrl_15(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "leak_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 16: multistep_workflow
@app.get('/adv3/v1/workflow-approve')
async def vuln_16(x_actor: str | None = Header(None)):
    return JSONResponse(content={"status": "approved", "item": "target_user_item"}, headers=hdr(x_actor, {"X-Resource-Type": "workflow_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 16: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/workflow-approve')
async def ctrl_16(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "workflow_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 17: diff_body_same_auth
@app.get('/adv3/v1/diff-body-auth')
async def vuln_17(x_actor: str | None = Header(None)):
    return JSONResponse(content={"profile": "other_user", "email": "other@example.com"}, headers=hdr(x_actor, {"X-Resource-Type": "profile_record", "X-Resource-Owner": "other_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 17: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/diff-body-auth')
async def ctrl_17(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "profile_record", "X-Resource-Owner": "other_user", "X-Authorization-Outcome": "denied"}))

# Vuln 18: delayed_state_transitions
@app.get('/adv3/v1/delayed-state')
async def vuln_18(x_actor: str | None = Header(None)):
    return JSONResponse(content={"status": "completed", "owner": "target_user"}, headers=hdr(x_actor, {"X-Resource-Type": "state_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 18: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/delayed-state')
async def ctrl_18(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "state_record", "X-Resource-Owner": "target_user", "X-Authorization-Outcome": "denied"}))

# Vuln 19: deeply_nested_paths
@app.get('/adv3/v1/deep-path')
async def vuln_19(x_actor: str | None = Header(None)):
    return JSONResponse(content={"api_key": "sk-deep-12345", "owner": "svc_account"}, headers=hdr(x_actor, {"X-Resource-Type": "connector_record", "X-Resource-Owner": "svc_account", "X-Authorization-Outcome": "granted_full"}))

# Control for vuln 19: SAME resource_type/owner, but DENIED
@app.get('/patched/adv3/v1/deep-path')
async def ctrl_19(x_actor: str | None = Header(None)):
    return JSONResponse(status_code=403, content={"error": "forbidden"},
        headers=hdr(x_actor, {"X-Resource-Type": "connector_record", "X-Resource-Owner": "svc_account", "X-Authorization-Outcome": "denied"}))

# Clean 0: decoy_endpoints
@app.get('/adv3/v1/clean/decoy-admin-1')
async def clean_0(x_actor: str | None = Header(None)):
    return JSONResponse(content={"title": "Public Page 1"}, headers=hdr(x_actor, {"X-Resource-Type": "public_page", "X-Authorization-Outcome": "granted_full"}))

# Clean 1: decoy_endpoints
@app.get('/adv3/v1/clean/decoy-admin-2')
async def clean_1(x_actor: str | None = Header(None)):
    return JSONResponse(content={"title": "Public Page 2"}, headers=hdr(x_actor, {"X-Resource-Type": "public_page", "X-Authorization-Outcome": "granted_full"}))

# Clean 2: decoy_endpoints
@app.get('/adv3/v1/clean/decoy-admin-3')
async def clean_2(x_actor: str | None = Header(None)):
    return JSONResponse(content={"title": "Public Page 3"}, headers=hdr(x_actor, {"X-Resource-Type": "public_page", "X-Authorization-Outcome": "granted_full"}))

# Clean 3: misleading_headers
@app.get('/adv3/v1/clean/misleading-hdrs')
async def clean_3(x_actor: str | None = Header(None)):
    return JSONResponse(content={"public": "data"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 4: missing_security_headers
@app.get('/adv3/v1/clean/missing-hdrs')
async def clean_4(x_actor: str | None = Header(None)):
    return JSONResponse(content={"info": "public_info"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 5: reordered_json_fields
@app.get('/adv3/v1/clean/reordered-a')
async def clean_5(x_actor: str | None = Header(None)):
    return JSONResponse(content={"id": "a", "name": "b", "value": 42}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 6: reordered_json_fields
@app.get('/adv3/v1/clean/reordered-b')
async def clean_6(x_actor: str | None = Header(None)):
    return JSONResponse(content={"value": 42, "id": "a", "name": "b"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 7: dynamic_generated_links
@app.get('/adv3/v1/clean/dynamic-links')
async def clean_7(x_actor: str | None = Header(None)):
    return JSONResponse(content={"links": ["/a", "/b"]}, headers=hdr(x_actor, {"X-Resource-Type": "public_entry", "X-Authorization-Outcome": "granted_full"}))

# Clean 8: public_status_page
@app.get('/adv3/v1/clean/public-status')
async def clean_8(x_actor: str | None = Header(None)):
    return JSONResponse(content={"status": "operational"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 9: static_content
@app.get('/adv3/v1/clean/static-content')
async def clean_9(x_actor: str | None = Header(None)):
    return JSONResponse(content={"content": "static"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 10: health_check
@app.get('/adv3/v1/clean/health-check')
async def clean_10(x_actor: str | None = Header(None)):
    return JSONResponse(content={"status": "healthy"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 11: about_page
@app.get('/adv3/v1/clean/about-page')
async def clean_11(x_actor: str | None = Header(None)):
    return JSONResponse(content={"about": "info"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 12: version_info
@app.get('/adv3/v1/clean/version-info')
async def clean_12(x_actor: str | None = Header(None)):
    return JSONResponse(content={"version": "1.7.0"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 13: contact_form
@app.get('/adv3/v1/clean/contact-form')
async def clean_13(x_actor: str | None = Header(None)):
    return JSONResponse(content={"form": "public"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 14: terms_page
@app.get('/adv3/v1/clean/terms-page')
async def clean_14(x_actor: str | None = Header(None)):
    return JSONResponse(content={"terms": "public"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 15: privacy_policy
@app.get('/adv3/v1/clean/privacy-policy')
async def clean_15(x_actor: str | None = Header(None)):
    return JSONResponse(content={"privacy": "public"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 16: faq_page
@app.get('/adv3/v1/clean/faq-page')
async def clean_16(x_actor: str | None = Header(None)):
    return JSONResponse(content={"faq": "public"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 17: sitemap_page
@app.get('/adv3/v1/clean/sitemap')
async def clean_17(x_actor: str | None = Header(None)):
    return JSONResponse(content={"sitemap": "public"}, headers=hdr(x_actor, {"X-Resource-Type": "public_info", "X-Authorization-Outcome": "granted_full"}))

# Clean 18: public_auth_page
@app.get('/adv3/v1/clean/login-page')
async def clean_18(x_actor: str | None = Header(None)):
    return JSONResponse(content={"status": "login"}, headers=hdr(x_actor, {"X-Resource-Type": "public_auth", "X-Authorization-Outcome": "granted_full"}))

# Clean 19: public_auth_page
@app.get('/adv3/v1/clean/register-page')
async def clean_19(x_actor: str | None = Header(None)):
    return JSONResponse(content={"status": "register"}, headers=hdr(x_actor, {"X-Resource-Type": "public_auth", "X-Authorization-Outcome": "granted_full"}))

@app.get('/')
async def root(): return JSONResponse(content={'svc': 'adv3_v1.7', 'vuln': 20, 'clean': 20})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=9150, log_level='error')
