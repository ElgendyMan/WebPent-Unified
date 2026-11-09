# src/webpent/remediation/fix_templates.py
"""webpent.remediation.fix_templates

Fix templates: the concept, a bad example, a good example, and framework
variants where the fix differs by stack.

ADVISORY-ONLY reference text. Templates are keyed by ``VulnClass`` and are
attached to findings that already exist; nothing here executes, tests, or
re-runs against a target. The template's job is to make the fix reviewable:
a reviewer reads the concept, checks the applied diff against the good
example, and rejects fixes that re-implement the bad one.

Unmapped classes resolve to ``None``; callers must render an honest "no
template" instead of inventing fix advice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from webpent.models.findings import VulnClass
from webpent.remediation.patterns_db import get_pattern


@dataclass(frozen=True)
class FixTemplate:
    """Concept-level fix guidance for one class."""

    vuln_class: VulnClass
    concept: str
    bad_code: str
    good_code: str
    framework_variants: dict[str, tuple[str, str]] = field(
        default_factory=dict
    )


def _t(
    vuln_class: VulnClass,
    concept: str,
    bad_code: str,
    good_code: str,
    **variants: tuple[str, str],
) -> FixTemplate:
    return FixTemplate(
        vuln_class=vuln_class,
        concept=concept,
        bad_code=bad_code,
        good_code=good_code,
        framework_variants=dict(variants),
    )


_TEMPLATES: dict[VulnClass, FixTemplate] = {
    VulnClass.XSS: _t(
        VulnClass.XSS,
        "Encode at output, per context (HTML body, attribute, JS, URL); "
        "never build markup from strings on the client.",
        "el.innerHTML = userInput;",
        "el.textContent = userInput;",
        flask=("render_template with autoescaping; mark user data as "
               "never safe", "return render_template('p.html', data=v)"),
        django=("templates escape by default; remove |safe and marksafe "
                "uses on user data", "{{ user_value }}"),
    ),
    VulnClass.SQLI: _t(
        VulnClass.SQLI,
        "Parameterize every query; identifiers and sort directions come "
        "from server-side allowlists only.",
        "cursor.execute(\"SELECT * FROM t WHERE id = \" + uid)",
        "cursor.execute(\"SELECT * FROM t WHERE id = %s\", (uid,))",
        django=("ORM lookups or RawSQL with params",
                "Model.objects.filter(id=value)"),
        sqlalchemy=("bound parameters on text()", "text('... id = :id') "
                    ".bindparams(id=value)"),
    ),
    VulnClass.SSRF: _t(
        VulnClass.SSRF,
        "Allowlist destination hosts, resolve and validate the resolved "
        "address, disable redirect-following or re-validate per hop.",
        "requests.get(user_url)",
        "if urlparse(user_url).hostname not in ALLOWED_HOSTS:\n"
        "    raise Blocked()\n"
        "requests.get(user_url, allow_redirects=False)",
    ),
    VulnClass.LFI: _t(
        VulnClass.LFI,
        "Replace path-driven includes with an id-to-resource map; if a "
        "path is unavoidable, resolve and require containment.",
        "include($_GET['page'] . '.php');",
        "PAGES = ['home', 'about'];\n"
        "if (!in_array($_GET['page'], PAGES, true)) throw ...;",
    ),
    VulnClass.RFI: _t(
        VulnClass.RFI,
        "Remove the remote-include path entirely; local templates from "
        "a fixed directory only.",
        "include($_GET['tpl']);",
        "include(__DIR__ . '/templates/' . basename($_GET['tpl']) "
        ". '.php');",
    ),
    VulnClass.RCE: _t(
        VulnClass.RCE,
        "Remove the dynamic evaluation path; replace eval/exec with a "
        "lookup table of allowed operations.",
        "result = eval(user_expression)",
        "result = OPS[requested_op](a, b)  # OPS is a fixed dict",
    ),
    VulnClass.SSTI: _t(
        VulnClass.SSTI,
        "Pass user data as render variables, never as part of the "
        "template string.",
        "render_template_string(\"Hi \" + name)",
        "render_template_string(\"Hi {{ name }}\", name=name)",
    ),
    VulnClass.OPEN_REDIRECT: _t(
        VulnClass.OPEN_REDIRECT,
        "Validate the redirect target against a same-origin allowlist; "
        "fall back to a safe default.",
        "redirect(request.args['next'])",
        "redirect(target if _same_origin(target) else '/dashboard')",
    ),
    VulnClass.XXE: _t(
        VulnClass.XXE,
        "Disable entity resolution and network access on every XML "
        "parser; DTDs are not needed for data exchange.",
        "etree.parse(user_xml)",
        "etree.parse(user_xml, etree.XMLParser(resolve_entities=False, "
        "no_network=True))",
    ),
    VulnClass.CSRF: _t(
        VulnClass.CSRF,
        "Per-session CSRF token on every state-changing request, plus "
        "SameSite cookies as defense in depth.",
        "  state-changing handler with no token check  ",
        "validate_csrf(request.form['csrf_token']) before the state "
        "change",
        django=("CsrfViewMiddleware enabled and {% csrf_token %} in "
                "every form", "<form>{% csrf_token %}..."),
        spring=("enable CSRF protection and include the token in forms",
                "http.csrf(withDefaults())"),
    ),
    VulnClass.DESERIALIZATION: _t(
        VulnClass.DESERIALIZATION,
        "Replace executable serialization formats with data-only ones "
        "(JSON + schema); never deserialize untrusted bytes natively.",
        "obj = pickle.load(user_bytes)",
        "obj = json.loads(user_bytes)  # data, not objects",
    ),
    VulnClass.PATH_TRAVERSAL: _t(
        VulnClass.PATH_TRAVERSAL,
        "Resolve the joined path and require it to stay inside the "
        "base; prefer id-to-path indirection.",
        "open(os.path.join(base, name))",
        "target = (base / name).resolve()\n"
        "if not target.is_relative_to(base.resolve()): raise Blocked()",
    ),
    VulnClass.COMMAND_INJECTION: _t(
        VulnClass.COMMAND_INJECTION,
        "Never invoke a shell with request data; pass an argument "
        "vector with shell=False (or the equivalent).",
        "subprocess.run(f\"convert {f} out.png\", shell=True)",
        "subprocess.run(['convert', f, 'out.png'], shell=False, "
        "check=True)",
    ),
    VulnClass.NOSQL_INJECTION: _t(
        VulnClass.NOSQL_INJECTION,
        "Cast request fields to scalar types before they enter a "
        "query; build operators server-side only.",
        "db.users.find({'user': body['user']})",
        "db.users.find({'user': {'$eq': str(body['user'])}})",
    ),
    VulnClass.INFO_DISCLOSURE: _t(
        VulnClass.INFO_DISCLOSURE,
        "Return explicit field projections per audience; generic error "
        "bodies; secrets in configuration, never in responses.",
        "return jsonify(user.to_dict())",
        "return jsonify({'id': user.id, 'name': user.name})",
    ),
    VulnClass.RACE_CONDITION: _t(
        VulnClass.RACE_CONDITION,
        "Make the check-then-use atomic: row locks, transactions, or "
        "idempotency keys per logical operation.",
        "if account.balance >= price: account.balance -= price",
        "with db.transaction():\n"
        "    account = Account.lock(id)\n"
        "    if account.balance >= price: account.balance -= price",
    ),
    VulnClass.IDOR: _t(
        VulnClass.IDOR,
        "Derive object scope from the session on every read/write; the "
        "identifier alone never grants access.",
        "doc = db.documents.get(args['doc_id'])",
        "doc = db.documents.get(args['doc_id'])\n"
        "if doc.owner_id != current_user.id: raise Forbidden()",
        django=("querysets filtered by the requesting user",
                "Document.objects.filter(owner=user).get(id=..)"),
    ),
    VulnClass.AUTH_BYPASS: _t(
        VulnClass.AUTH_BYPASS,
        "Fail-closed authentication middleware on every route; remove "
        "magic headers, defaults, and debug paths from production.",
        "if headers.get('x-internal') == '1': return admin()",
        "user = authenticate(session)\nrequire_role(user, 'admin')\n"
        "return admin()",
    ),
    VulnClass.MASS_ASSIGNMENT: _t(
        VulnClass.MASS_ASSIGNMENT,
        "Bind an explicit allowlist of fields per endpoint; reject "
        "unknown fields loudly in non-production.",
        "User(**request.json)",
        "User(**{k: v for k, v in request.json.items() if k in FIELDS})",
        django=("ModelForm with explicit fields", "UserForm(data).save()"),
        rails=("Strong parameters", "params.require(:user).permit(:name, "
               ":email)"),
    ),
    VulnClass.REQUEST_SMUGGLING: _t(
        VulnClass.REQUEST_SMUGGLING,
        "One canonical parser per hop; reject ambiguous framing; keep "
        "proxy and backend HTTP implementations aligned.",
        "  frontend forwards requests with both CL and TE  ",
        "reject any request carrying both Content-Length and "
        "Transfer-Encoding at the edge",
    ),
    VulnClass.BRUTE_FORCE: _t(
        VulnClass.BRUTE_FORCE,
        "Progressive limits keyed by account and source, generic "
        "failure responses, exponential backoff.",
        "if check_password(u, p): login(u)",
        "if limiter.blocked(ip, u): raise TooManyAttempts()\n"
        "if check_password(u, p): login(u)",
    ),
    VulnClass.CAPTCHA: _t(
        VulnClass.CAPTCHA,
        "Server-issued single-use challenges bound to the session and "
        "expired on use; never trust a client-side score alone.",
        "if form['captcha_ok'] == 'true': proceed()",
        "if not challenge.verify_and_consume(session, form['token']):\n"
        "    raise Blocked()",
    ),
    VulnClass.WEAK_SESSION: _t(
        VulnClass.WEAK_SESSION,
        "Rotate identifiers on privilege changes, invalidate server-side "
        "on logout and credential change, high-entropy tokens only.",
        "session['uid'] = user.id",
        "session.regenerate()\nsession['uid'] = user.id",
    ),
    VulnClass.CSP: _t(
        VulnClass.CSP,
        "Nonce- or hash-based script policy, object-src 'none', no "
        "unsafe-inline; ship report-only first, then enforce.",
        "  no Content-Security-Policy header  ",
        "default-src 'self'; script-src 'self' 'nonce-...'; "
        "object-src 'none'",
    ),
    VulnClass.JAVASCRIPT: _t(
        VulnClass.JAVASCRIPT,
        "Use safe DOM APIs for untrusted data; validate postMessage "
        "origin; keep dangerous sinks out of client code paths.",
        "el.innerHTML = location.hash.slice(1)",
        "el.textContent = location.hash.slice(1)",
    ),
    VulnClass.CRYPTOGRAPHY: _t(
        VulnClass.CRYPTOGRAPHY,
        "Standard AEAD primitives, managed key rotation, fresh nonces; "
        "no custom crypto and no hardcoded keys.",
        "DES.new(key, DES.MODE_ECB)",
        "AES.new(key, AES.MODE_GCM, nonce=fresh_nonce)",
    ),
    VulnClass.API_ISSUE: _t(
        VulnClass.API_ISSUE,
        "Apply the web app's authorization and filtering policy to "
        "every API version through shared middleware; retire weak "
        "versions.",
        "  /api/v2/users/{id} without ownership filter  ",
        "same policy middleware enforced on all API versions",
    ),
    VulnClass.SUBDOMAIN_TAKEOVER: _t(
        VulnClass.SUBDOMAIN_TAKEOVER,
        "Reconcile DNS against live services on a schedule; remove "
        "dangling records; pin claimed services to the zone.",
        "  dangling CNAME to a deprovisioned service  ",
        "record removed, or service re-claimed and verified for this "
        "zone",
    ),
    VulnClass.CLOUD_STORAGE_EXPOSURE: _t(
        VulnClass.CLOUD_STORAGE_EXPOSURE,
        "Block public access at the account level, scope policies to "
        "explicit principals, isolate genuinely public assets.",
        "  policy: Principal=*, Action=s3:*  ",
        "account-level public-access block plus scoped read policies",
    ),
    VulnClass.JWT_WEAKNESS: _t(
        VulnClass.JWT_WEAKNESS,
        "Verify signatures with a pinned algorithm and proper key; "
        "never read claims from an unverified token.",
        "jwt.decode(token, options={'verify_signature': False})",
        "jwt.decode(token, key=PUBLIC_KEY, algorithms=['RS256'])",
    ),
    VulnClass.JWT_KEY_CONFUSION: _t(
        VulnClass.JWT_KEY_CONFUSION,
        "Pin the algorithm server-side per issuer; never accept the "
        "algorithm from the token at a shared call site.",
        "jwt.decode(token, key, algorithms=None)",
        "jwt.decode(token, key=PUBLIC_KEY, algorithms=['RS256'])",
    ),
    VulnClass.ELASTICSEARCH_SNAPSHOT_TRAVERSAL: _t(
        VulnClass.ELASTICSEARCH_SNAPSHOT_TRAVERSAL,
        "Enable authentication and authorization, bind to a private "
        "interface, scope snapshot roles to named repositories.",
        "  xpack.security disabled, bind 0.0.0.0  ",
        "auth enabled, private bind, snapshot roles scoped",
    ),
    VulnClass.XSLT_INJECTION: _t(
        VulnClass.XSLT_INJECTION,
        "Compile only allowlisted stylesheets; disable extension "
        "functions and document() resolution for user input paths.",
        "transform(xml, user_stylesheet)",
        "processor = XsltProcessor(extensions=[], resolve_documents="
        "False)\ntransform(xml, allowlisted_stylesheet)",
    ),
    # UM-DR-25: blind OOB + privilege-differential families.
    VulnClass.BLIND_SSRF: _t(
        VulnClass.BLIND_SSRF,
        "Allowlist outbound destinations at the HTTP client and "
        "never follow redirects for user-supplied URLs.",
        "fetch(url_from_request)",
        "if url.host not in OUTBOUND_ALLOWLIST:\n"
        "    raise BlockedDestination()\n"
        "fetch(url, allow_redirects=False)",
    ),
    VulnClass.XXE_OOB: _t(
        VulnClass.XXE_OOB,
        "Disable DTD processing and external entity resolution on "
        "every XML parse path.",
        "etree.fromstring(user_xml)",
        "parser = etree.XMLParser(load_dtd=False, resolve_entities="
        "False)\netree.fromstring(user_xml, parser)",
    ),
    VulnClass.BLIND_SQLI: _t(
        VulnClass.BLIND_SQLI,
        "Parameterize the query; never build SQL from request "
        "strings even when output is never reflected.",
        "cursor.execute('SELECT ... WHERE id=' + rid)",
        "cursor.execute('SELECT ... WHERE id=%s', (rid,))",
    ),
    VulnClass.PRIVILEGE_DIFFERENTIAL: _t(
        VulnClass.PRIVILEGE_DIFFERENTIAL,
        "Enforce the authorization decision on every read path, "
        "not only the routes the UI exposes.",
        "return repo.get(object_id)",
        "if not authorize(actor, object_id):\n"
        "    raise Forbidden()\n"
        "return repo.get(object_id)",
    ),

    # ULTIMATE PLAN 2026-10-27 (proposals 1/7).
    VulnClass.BUSINESS_LOGIC: _t(
        VulnClass.BUSINESS_LOGIC,
        "Re-derive every money and quota value server-side from "
        "pinned tables; the client sends intents, never totals.",
        "charge(payload.total)",
        "total = PRICES[payload.sku] * payload.qty\ncharge(total)",
    ),
    VulnClass.MULTI_STEP_AUTH_BYPASS: _t(
        VulnClass.MULTI_STEP_AUTH_BYPASS,
        "Model the flow as a server-side state machine; the session "
        "issues only from the terminal state, never from a stage's "
        "success alone.",
        "if stage1_ok: issue_session()",
        "state = flow.advance(stage1)\nif state.is_terminal: issue_session()",
    ),
    VulnClass.TENANT_ISOLATION: _t(
        VulnClass.TENANT_ISOLATION,
        "Put the tenant predicate in the data-access layer itself so "
        "no query can forget it.",
        "session.get(Invoice, id)",
        "session.get(Invoice, id, options=[with_tenant(user.tenant)])",
        sqlalchemy=("identity filter on every query",
                    "query.filter(Invoice.tenant_id == user.tenant_id)"),
    ),
    VulnClass.EXPLOIT_CHAIN: _t(
        VulnClass.EXPLOIT_CHAIN,
        "Fix each link at its own boundary, then re-score the chain: "
        "the cheapest link to break is usually the redirect or the "
        "leak.",
        "leave findings scored in isolation",
        "fix link N; retest the full chain; re-score severity",
    ),
    VulnClass.OAUTH: _t(
        VulnClass.OAUTH,
        "Verify signature, audience, and state at the decision point; "
        "a token's shape proves nothing.",
        "if token.count('.') == 2: accept()",
        "claims = verify_jwt(token, keys, audience)\ncheck_state(claims.state)",
    ),
    VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE: _t(
        VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE,
        "Disable introspection outside development; keep schema docs "
        "inside the team.",
        "GraphQL(schema=schema)",
        "GraphQL(schema=schema, introspection=False)",
        ariadne=("introspection disabled via config",
                 "if not DEV: introspection_disabled = True"),
    ),
    VulnClass.GRAPHQL_BATCHING_ABUSE: _t(
        VulnClass.GRAPHQL_BATCHING_ABUSE,
        "Cap accepted batch size at validation and make rate limits "
        "count operations, not requests.",
        "handle(any list of queries)",
        "if len(queries) > 10: reject()\nrate.count(len(queries))",
    ),
    VulnClass.GRAPHQL_FIELD_SUGGESTION_LEAK: _t(
        VulnClass.GRAPHQL_FIELD_SUGGESTION_LEAK,
        "Strip suggestion text from production validation errors.",
        'raise GraphQLError(f"Did you mean {near}?")',
        'raise GraphQLError("invalid field") if not DEV else suggest()',
    ),
    VulnClass.GRAPHQL_DEPTH_COMPLEXITY_DOS: _t(
        VulnClass.GRAPHQL_DEPTH_COMPLEXITY_DOS,
        "Reject over-deep or over-complex queries before any resolver "
        "runs.",
        "result = schema.execute(query)",
        "if depth(query) > 10: reject()\nresult = schema.execute(query)",
        graphql_core=("depth check in a validation rule",
                      "ValidationRule(depth_limit(10))"),
    ),
    VulnClass.PROTOTYPE_POLLUTION: _t(
        VulnClass.PROTOTYPE_POLLUTION,
        "Block __proto__ and constructor keys at the parser boundary "
        "and use a merge helper with built-in protection.",
        "merge({}, req.body)",
        "merge({}, safeParse(req.body))  # __proto__ stripped",
        lodash=("use _.merge with a sanitizer or lodash-es fixed "
                "versions", "_.merge({}, sanitize(body))"),
    ),
    VulnClass.OAUTH_MISCONFIGURATION: _t(
        VulnClass.OAUTH_MISCONFIGURATION,
        "Exact-match redirect URIs against the per-client "
        "registration; state is mandatory and single-use.",
        "if redirect_uri.startswith(registered): ok()",
        "if redirect_uri in registered_set: ok()\nrequire_state(flow)",
    ),
    VulnClass.CACHE_POISONING: _t(
        VulnClass.CACHE_POISONING,
        "Everything that shapes a cacheable response is either in the "
        "cache key or stripped before render.",
        "body = render(urlparse(request.headers['X-Forwarded-Host']))",
        "host = request.url.host  # unkeyed headers never reach render",
        varnish=("strip unkeyed headers in vcl_recv",
                 "unset req.http.X-Forwarded-Host;"),
    ),
    VulnClass.WEB_CACHE_DECEPTION: _t(
        VulnClass.WEB_CACHE_DECEPTION,
        "Authenticated responses are never cacheable, regardless of "
        "path suffix.",
        "cache_if_static_like(path)",
        "if request.isAuthenticated: header('Cache-Control', 'no-store')",
        nginx=("no-cache for authenticated locations",
               "location /account { proxy_hide_header Cache-Control; "
               "add_header Cache-Control no-store; }"),
    ),
}


def fix_template(vuln_class: VulnClass | str) -> FixTemplate | None:
    """Template for a class, or ``None`` when unmapped."""
    if isinstance(vuln_class, str):
        try:
            vuln_class = VulnClass(vuln_class)
        except ValueError:
            return None
    if get_pattern(vuln_class) is None:
        return None
    return _TEMPLATES[vuln_class]
