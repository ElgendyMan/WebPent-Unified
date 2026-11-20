# src/webpent/remediation/patterns_db.py
"""webpent.remediation.patterns_db

Security pattern database: every ``VulnClass`` mapped to its CWE entry,
a plain-language explanation, and bad/good code examples.

ADVISORY-ONLY: this is reference text attached to findings that already
exist. Nothing here executes, fetches, or promotes. The database is honest
about its edges: ``UNKNOWN`` (and any value outside the enum) resolves to
no pattern, and ``coverage()`` reports exactly which classes are mapped
rather than implying total coverage.

Severity defaults are the pattern's typical worst case, not a claim about
any specific finding; the finding's own severity always wins in reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from webpent.models.findings import Severity, VulnClass
from webpent.remediation._fields import as_vuln_class
from webpent.remediation.root_cause_mapper import RootCause, causes


@dataclass(frozen=True)
class SecurityPattern:
    """Reference pattern for one vulnerability class."""

    vuln_class: VulnClass
    cwe_id: str | None
    cwe_name: str
    simplified_name: str
    description: str
    default_severity: Severity
    bad_example: str
    good_example: str
    references: tuple[str, ...] = field(default_factory=tuple)

    @property
    def root_causes(self) -> tuple[RootCause, ...]:
        return causes(self.vuln_class) or ()


def _p(
    vuln_class: VulnClass,
    cwe_id: str | None,
    cwe_name: str,
    simplified_name: str,
    description: str,
    default_severity: Severity,
    bad_example: str,
    good_example: str,
    *references: str,
) -> SecurityPattern:
    return SecurityPattern(
        vuln_class=vuln_class,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        simplified_name=simplified_name,
        description=description,
        default_severity=default_severity,
        bad_example=bad_example,
        good_example=good_example,
        references=references,
    )


PATTERNS: dict[VulnClass, SecurityPattern] = {
    VulnClass.XSS: _p(
        VulnClass.XSS, "CWE-79",
        "Improper Neutralization of Input During Web Page Generation",
        "Script injection through reflected or stored data",
        "Attacker-controlled data reaches the page as markup or script "
        "instead of text, so the victim's browser executes it in the "
        "application's origin.",
        Severity.HIGH,
        "return f\"<div>Hello {request.args['name']}</div>\"",
        "from markupsafe import escape\n"
        "return f\"<div>Hello {escape(request.args['name'])}</div>\"",
        "https://cwe.mitre.org/data/definitions/79.html",
    ),
    VulnClass.SQLI: _p(
        VulnClass.SQLI, "CWE-89",
        "Improper Neutralization of Special Elements in an SQL Command",
        "SQL built by string concatenation",
        "Query text and attacker data are concatenated, so data is parsed "
        "as SQL. The fix is parameterized queries, never filtering.",
        Severity.CRITICAL,
        "cur.execute(\"SELECT * FROM users WHERE id = \" + uid)",
        "cur.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))",
        "https://cwe.mitre.org/data/definitions/89.html",
    ),
    VulnClass.SSRF: _p(
        VulnClass.SSRF, "CWE-918",
        "Server-Side Request Forgery",
        "Server fetches an attacker-chosen URL",
        "A URL the attacker controls is fetched by the server, reaching "
        "internal services, cloud metadata, or localhost that the "
        "attacker cannot touch directly.",
        Severity.HIGH,
        "body = requests.get(user_supplied_url).text",
        "allowed_hosts = fetch_allowlist()\n"
        "host = urlparse(user_supplied_url).hostname\n"
        "if host not in allowed_hosts or _is_ip(host):\n"
        "    raise BlockedHost(host)\n"
        "body = requests.get(user_supplied_url).text",
        "https://cwe.mitre.org/data/definitions/918.html",
    ),
    VulnClass.LFI: _p(
        VulnClass.LFI, "CWE-98",
        "Improper Control of Filename with an Include Path",
        "Server includes a file the attacker chooses",
        "A file path from the request drives an include/require, loading "
        "attacker-readable or attacker-uploaded files as code or data.",
        Severity.HIGH,
        "include($_GET['page'] . '.php');",
        "$whitelist = ['home', 'about', 'contact'];\n"
        "if (!in_array($_GET['page'], $whitelist, true)) { throw ... }\n"
        "include(__DIR__ . '/pages/' . $_GET['page'] . '.php');",
        "https://cwe.mitre.org/data/definitions/98.html",
    ),
    VulnClass.RFI: _p(
        VulnClass.RFI, "CWE-98",
        "Improper Control of Filename with a Remote Include Path",
        "Server includes a remote file the attacker hosts",
        "The include path accepts remote URLs, letting the attacker "
        "serve code the server executes. Treat as command injection "
        "until proven otherwise.",
        Severity.CRITICAL,
        "include($_GET['tpl']);",
        "if (!preg_match('#^/[a-z]+$#', $_GET['tpl'])) { throw ... }\n"
        "include(__DIR__ . '/templates/' . $_GET['tpl'] . '.php');",
        "https://cwe.mitre.org/data/definitions/98.html",
    ),
    VulnClass.RCE: _p(
        VulnClass.RCE, "CWE-94",
        "Improper Control of Code Generation",
        "Attacker input becomes executed code",
        "Untrusted data reaches an interpreter that runs it as code "
        "(eval, dynamic include, expression language, template engine). "
        "The only real fix is removing the dynamic evaluation path.",
        Severity.CRITICAL,
        "result = eval(user_expression)",
        "ALLOWED_OPS = {'add': operator.add, 'sub': operator.sub}\n"
        "result = ALLOWED_OPS[requested_op](a, b)",
        "https://cwe.mitre.org/data/definitions/94.html",
    ),
    VulnClass.SSTI: _p(
        VulnClass.SSTI, "CWE-1336",
        "Improper Neutralization of Special Elements in a Template Engine",
        "Template engine renders user data as template code",
        "User data is passed into the template engine as a template "
        "string instead of as a render variable, so template syntax "
        "becomes code.",
        Severity.CRITICAL,
        "render_template_string(\"Hello \" + request.args['name'])",
        "render_template_string(\"Hello {{ name }}\", "
        "name=request.args['name'])",
        "https://cwe.mitre.org/data/definitions/1336.html",
    ),
    VulnClass.OPEN_REDIRECT: _p(
        VulnClass.OPEN_REDIRECT, "CWE-601",
        "URL Redirection to Untrusted Site",
        "Redirect target taken from the request without an allowlist",
        "A redirect target from user input is followed verbatim, "
        "laundering phishing links through your trusted domain.",
        Severity.LOW,
        "return redirect(request.args['next'])",
        "target = request.args['next']\n"
        "if not _same_origin(target):\n"
        "    target = '/dashboard'\n"
        "return redirect(target)",
        "https://cwe.mitre.org/data/definitions/601.html",
    ),
    VulnClass.XXE: _p(
        VulnClass.XXE, "CWE-611",
        "Improper Restriction of XML External Entity Reference",
        "XML parser resolves external entities",
        "The XML parser resolves attacker-named external entities, "
        "reading local files or reaching internal endpoints.",
        Severity.HIGH,
        "doc = etree.parse(user_xml)",
        "parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
        "doc = etree.parse(user_xml, parser)",
        "https://cwe.mitre.org/data/definitions/611.html",
    ),
    VulnClass.CSRF: _p(
        VulnClass.CSRF, "CWE-352",
        "Cross-Site Request Forgery",
        "State-changing endpoint trusts the browser's ambient credentials",
        "A state-changing action has no per-request proof that the "
        "request came from the application's own pages.",
        Severity.MEDIUM,
        "@app.route('/email/change')\n"
        "def change_email():\n"
        "    ...  # cookie-authenticated, no token check",
        "@app.route('/email/change')\n"
        "def change_email():\n"
        "    validate_csrf_token(request.form['csrf_token'])\n"
        "    ...",
        "https://cwe.mitre.org/data/definitions/352.html",
    ),
    VulnClass.DESERIALIZATION: _p(
        VulnClass.DESERIALIZATION, "CWE-502",
        "Deserialization of Untrusted Data",
        "Attacker bytes become live objects",
        "A serializer that reconstructs executable object graphs reads "
        "attacker-controlled bytes, turning data into code execution.",
        Severity.CRITICAL,
        "state = pickle.load(request_body)",
        "state = json.loads(request_body)  # data only, never objects",
        "https://cwe.mitre.org/data/definitions/502.html",
    ),
    VulnClass.PATH_TRAVERSAL: _p(
        VulnClass.PATH_TRAVERSAL, "CWE-22",
        "Path Traversal",
        "File path escapes its intended directory",
        "A user-supplied path is joined onto a base directory without "
        "verifying the result stays inside it.",
        Severity.HIGH,
        "open(os.path.join('/srv/uploads', request.args['file']))",
        "base = Path('/srv/uploads').resolve()\n"
        "target = (base / request.args['file']).resolve()\n"
        "if not target.is_relative_to(base):\n"
        "    raise BlockedPath(request.args['file'])\n"
        "open(target)",
        "https://cwe.mitre.org/data/definitions/22.html",
    ),
    VulnClass.COMMAND_INJECTION: _p(
        VulnClass.COMMAND_INJECTION, "CWE-78",
        "Improper Neutralization of Special Elements in a Command",
        "User data reaches a shell",
        "User data is passed through a shell interpreter, so shell "
        "metacharacters become commands. The fix is to avoid the shell.",
        Severity.CRITICAL,
        "subprocess.run(f\"convert {user_file} out.png\", shell=True)",
        "subprocess.run(['convert', user_file, 'out.png'], shell=False, "
        "check=True)",
        "https://cwe.mitre.org/data/definitions/78.html",
    ),
    VulnClass.NOSQL_INJECTION: _p(
        VulnClass.NOSQL_INJECTION, "CWE-943",
        "Improper Neutralization in Data Query Logic",
        "Query operators injected into a NoSQL query",
        "Attacker data is merged into a document query as structure "
        "(operators like $gt, $ne) instead of values.",
        Severity.HIGH,
        "db.users.find({'user': request.json['user']})",
        "user = str(request.json['user'])  # scalar cast, never dict\n"
        "db.users.find({'user': {'$eq': user}})",
        "https://cwe.mitre.org/data/definitions/943.html",
    ),
    VulnClass.INFO_DISCLOSURE: _p(
        VulnClass.INFO_DISCLOSURE, "CWE-200",
        "Exposure of Sensitive Information",
        "Responses reveal more than the audience may see",
        "Error pages, headers, debug endpoints, or over-complete API "
        "responses hand out internals (stack traces, versions, other "
        "users' fields) to whoever asks.",
        Severity.MEDIUM,
        "return jsonify(User.query.get(user_id).to_dict())",
        "user = User.query.get(user_id)\n"
        "return jsonify({'id': user.id, 'name': user.name})",
        "https://cwe.mitre.org/data/definitions/200.html",
    ),
    VulnClass.RACE_CONDITION: _p(
        VulnClass.RACE_CONDITION, "CWE-362",
        "Concurrent Execution with Shared State",
        "Check-then-use without synchronization",
        "Two concurrent requests both pass the same check before either "
        "consumes the result (balance, coupon, email verification).",
        Severity.MEDIUM,
        "if account.balance >= price:\n"
        "    account.balance -= price",
        "with db.transaction():\n"
        "    account = Account.lock(id)  # SELECT ... FOR UPDATE\n"
        "    if account.balance >= price:\n"
        "        account.balance -= price",
        "https://cwe.mitre.org/data/definitions/362.html",
    ),
    VulnClass.IDOR: _p(
        VulnClass.IDOR, "CWE-639",
        "Authorization on a User-Controlled Key",
        "Object access checked by identifier, not by ownership",
        "The server trusts the object identifier in the request and "
        "never asks whether the caller owns (or may see) the object.",
        Severity.HIGH,
        "doc = db.documents.get(request.args['doc_id'])",
        "doc = db.documents.get(request.args['doc_id'])\n"
        "if doc.owner_id != current_user.id and not current_user.admin:\n"
        "    raise Forbidden()",
        "https://cwe.mitre.org/data/definitions/639.html",
    ),
    VulnClass.AUTH_BYPASS: _p(
        VulnClass.AUTH_BYPASS, "CWE-287",
        "Improper Authentication",
        "Authentication check skipped or satisfiable",
        "A path, header, default credential, or predictable token lets "
        "a caller reach an authenticated surface without authenticating.",
        Severity.CRITICAL,
        "if request.headers.get('x-internal') == '1':\n"
        "    return admin_panel()",
        "user = authenticate(session_token)  # fails closed\n"
        "require_role(user, 'admin')\n"
        "return admin_panel()",
        "https://cwe.mitre.org/data/definitions/287.html",
    ),
    VulnClass.MASS_ASSIGNMENT: _p(
        VulnClass.MASS_ASSIGNMENT, "CWE-915",
        "Improperly Controlled Modification of Dynamically Determined Attributes",
        "Request body bound straight onto a model",
        "The request payload is bound onto the model wholesale, so "
        "fields like is_admin or price can be set by the client.",
        Severity.MEDIUM,
        "user = User(**request.json); db.save(user)",
        "FIELDS = {'name', 'email'}\n"
        "user = User(**{k: v for k, v in request.json.items() "
        "if k in FIELDS})",
        "https://cwe.mitre.org/data/definitions/915.html",
    ),
    VulnClass.REQUEST_SMUGGLING: _p(
        VulnClass.REQUEST_SMUGGLING, "CWE-444",
        "Inconsistent Interpretation of HTTP Requests",
        "Two HTTP parsers disagree on where one request ends",
        "Frontend and backend disagree about request boundaries "
        "(Content-Length vs Transfer-Encoding), so one crafted request "
        "smuggles a second past controls.",
        Severity.HIGH,
        " proxies and backends left with differing HTTP parsing rules ",
        "normalize the chain: one parser per hop, reject ambiguous "
        "framing (CL+TE together), and align proxy/backend versions",
        "https://cwe.mitre.org/data/definitions/444.html",
    ),
    VulnClass.BRUTE_FORCE: _p(
        VulnClass.BRUTE_FORCE, "CWE-307",
        "Improper Restriction of Excessive Authentication Attempts",
        "No limit on repeated credential guesses",
        "Authentication endpoints accept unlimited attempts, so "
        "credentials can be guessed offline-speed.",
        Severity.MEDIUM,
        "if check_password(user, password): login(user)",
        "if login_limiter.blocked(request.remote_addr, user):\n"
        "    raise TooManyAttempts()\n"
        "if check_password(user, password): login(user)",
        "https://cwe.mitre.org/data/definitions/307.html",
    ),
    VulnClass.CAPTCHA: _p(
        VulnClass.CAPTCHA, "CWE-804",
        "Guessable CAPTCHA",
        "Automated-client check can be solved or skipped",
        "The human-verification step is predictable, reusable, or "
        "client-enforced, so automation passes it.",
        Severity.LOW,
        "if int(form['captcha_sum']) == expected: proceed()",
        "server-side one-time challenge tokens, verified once, expired "
        "on use, bound to the session",
        "https://cwe.mitre.org/data/definitions/804.html",
    ),
    VulnClass.WEAK_SESSION: _p(
        VulnClass.WEAK_SESSION, "CWE-384",
        "Session Fixation and Weak Session Handling",
        "Session identifiers predictable, fixed, or never invalidated",
        "Sessions survive credential changes, accept attacker-chosen "
        "identifiers, or use low-entropy tokens.",
        Severity.MEDIUM,
        "session['uid'] = user.id  # token never rotated",
        "session.regenerate()  # rotate on privilege change\n"
        "session['uid'] = user.id",
        "https://cwe.mitre.org/data/definitions/384.html",
    ),
    VulnClass.CSP: _p(
        VulnClass.CSP, "CWE-1021",
        "Improper Restriction of Rendered-Layer Navigation",
        "Missing or permissive Content-Security-Policy",
        "Without a real CSP, injected markup can load remote scripts "
        "and exfiltrate data with no additional exploit step.",
        Severity.MEDIUM,
        "  (no Content-Security-Policy header emitted)  ",
        "Content-Security-Policy: default-src 'self'; "
        "script-src 'self' 'nonce-...'; object-src 'none'",
        "https://cwe.mitre.org/data/definitions/1021.html",
    ),
    VulnClass.JAVASCRIPT: _p(
        VulnClass.JAVASCRIPT, "CWE-79",
        "Client-Side Data Handling Weakness",
        "Client-side sink consumes untrusted data",
        "Browser-side code passes attacker-controlled data into a "
        "dangerous sink (innerHTML, eval, postMessage handlers, DOM "
        "URLs) where the server-side fixes do not apply.",
        Severity.MEDIUM,
        "el.innerHTML = location.hash.slice(1);",
        "el.textContent = location.hash.slice(1);",
        "https://cwe.mitre.org/data/definitions/79.html",
    ),
    VulnClass.CRYPTOGRAPHY: _p(
        VulnClass.CRYPTOGRAPHY, "CWE-327",
        "Use of a Broken or Risky Cryptographic Algorithm",
        "Weak or misapplied cryptography",
        "A broken algorithm, hardcoded key, or misuse of a correct "
        "primitive (ECB mode, static IV, unauthenticated encryption) "
        "undermines the guarantee the crypto was chosen for.",
        Severity.HIGH,
        "cipher = DES.new(key, DES.MODE_ECB)",
        "cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # fresh nonce",
        "https://cwe.mitre.org/data/definitions/327.html",
    ),
    VulnClass.API_ISSUE: _p(
        VulnClass.API_ISSUE, "CWE-16",
        "API Misconfiguration",
        "API surface configured weaker than the web app",
        "Versioned or shadow API endpoints skip the controls the main "
        "application applies: auth, rate limits, object filtering, or "
        "verbose errors.",
        Severity.MEDIUM,
        "  /api/v2/users/{id} returns full records without ownership check  ",
        "apply the same authorization policy middleware to every API "
        "version, and disable undocumented versions",
        "https://cwe.mitre.org/data/definitions/16.html",
    ),
    VulnClass.SUBDOMAIN_TAKEOVER: _p(
        VulnClass.SUBDOMAIN_TAKEOVER, "CWE-350",
        "Trusting a Dangling Endpoint",
        "DNS points at unclaimed infrastructure",
        "A DNS record still points at service infrastructure nobody "
        "owns any more; whoever claims the service serves content on "
        "your subdomain.",
        Severity.HIGH,
        "  dangling CNAME: status.example.com -> inactive cloud slot  ",
        "remove the stale DNS record, or re-claim and pin the target "
        "service to this zone",
        "https://cwe.mitre.org/data/definitions/350.html",
    ),
    VulnClass.CLOUD_STORAGE_EXPOSURE: _p(
        VulnClass.CLOUD_STORAGE_EXPOSURE, "CWE-732",
        "Incorrect Permission Assignment on a Critical Resource",
        "Cloud bucket/listing open to anonymous access",
        "A storage bucket permits anonymous listing or reading, "
        "exposing everything stored there to anyone with the URL.",
        Severity.HIGH,
        "  bucket policy: Effect=Allow, Principal=*, Action=s3:*  ",
        "block public access at the account level, scope policies to "
        "specific principals, and keep only genuinely public assets "
        "in a dedicated bucket",
        "https://cwe.mitre.org/data/definitions/732.html",
    ),
    VulnClass.JWT_WEAKNESS: _p(
        VulnClass.JWT_WEAKNESS, "CWE-347",
        "Improper Verification of Cryptographic Signature",
        "JWT claims trusted without signature verification",
        "Tokens are decoded and their claims used without verifying "
        "the signature, or with algorithms accepted from the token "
        "itself.",
        Severity.CRITICAL,
        "claims = jwt.decode(token, options={'verify_signature': False})",
        "claims = jwt.decode(token, key=PUBLIC_KEY, "
        "algorithms=['RS256'])",
        "https://cwe.mitre.org/data/definitions/347.html",
    ),
    VulnClass.JWT_KEY_CONFUSION: _p(
        VulnClass.JWT_KEY_CONFUSION, "CWE-347",
        "Signature Verification With the Wrong Key Material",
        "Algorithm confusion between HMAC and asymmetric keys",
        "The verifier accepts both symmetric and asymmetric algorithms "
        "with the same call site, so a token signed with the public key "
        "as an HMAC secret verifies.",
        Severity.CRITICAL,
        "jwt.decode(token, key=SECRET_OR_PUBLIC_KEY, "
        "algorithms=None)  # accepts whatever the token says",
        "jwt.decode(token, key=PUBLIC_KEY, algorithms=['RS256'])  "
        "# algorithm pinned by the server, never by the token",
        "https://cwe.mitre.org/data/definitions/347.html",
    ),
    VulnClass.ELASTICSEARCH_SNAPSHOT_TRAVERSAL: _p(
        VulnClass.ELASTICSEARCH_SNAPSHOT_TRAVERSAL, "CWE-285",
        "Improper Authorization on Cluster Snapshot APIs",
        "Snapshot/repository APIs reachable without authorization",
        "Snapshot or repository endpoints accept unauthenticated "
        "requests, letting a caller enumerate, read, or restore "
        "cluster data.",
        Severity.HIGH,
        "  cluster bound to 0.0.0.0 with xpack.security disabled  ",
        "enable authentication and authorization on the cluster, bind "
        "to a private interface, and restrict snapshot repository "
        "access",
        "https://cwe.mitre.org/data/definitions/285.html",
    ),
    VulnClass.XSLT_INJECTION: _p(
        VulnClass.XSLT_INJECTION, "CWE-91",
        "Injection Through XSLT Stylesheets",
        "Attacker-controlled stylesheet is compiled and executed",
        "An XSLT processor compiles attacker-supplied stylesheets, and "
        "extension functions or document() access turn the transform "
        "into code execution or file read.",
        Severity.CRITICAL,
        "result = transform(source_xml, user_supplied_stylesheet)",
        "if not stylesheet_allowlisted(user_supplied_stylesheet):\n"
        "    raise BlockedStylesheet()\n"
        "processor = XsltProcessor(extensions=[], "
        "resolve_documents=False)\n"
        "result = transform(source_xml, user_supplied_stylesheet)",
        "https://cwe.mitre.org/data/definitions/91.html",
    ),
    # UM-DR-25 (red-team window): blind OOB + privilege-differential
    # families — merged classes finally first-class in the enum.
    VulnClass.BLIND_SSRF: _p(
        VulnClass.BLIND_SSRF, "CWE-918",
        "Blind Server-Side Request Forgery",
        "Server fetches an attacker-chosen destination with no "
        "response reflection",
        "The application fetches a URL derived from user input, "
        "and the only observable evidence is an out-of-band "
        "callback — internal services can be probed blind.",
        Severity.HIGH,
        "fetch(profile_url_from_request)",
        "if url.host not in OUTBOUND_ALLOWLIST:\n"
        "    raise BlockedDestination()\n"
        "fetch(url, allow_redirects=False)",
        "https://cwe.mitre.org/data/definitions/918.html",
    ),
    VulnClass.XXE_OOB: _p(
        VulnClass.XXE_OOB, "CWE-611",
        "XXE with Out-of-Band Exfiltration",
        "External entity resolution confirmed by callback",
        "The XML parser resolves external entities from "
        "attacker-supplied XML; the collaborator callback proves "
        "the resolution and the reachable channel.",
        Severity.HIGH,
        "etree.fromstring(user_xml)",
        "parser = etree.XMLParser(load_dtd=False, "
        "resolve_entities=False)\netree.fromstring(user_xml, "
        "parser)",
        "https://cwe.mitre.org/data/definitions/611.html",
    ),
    VulnClass.BLIND_SQLI: _p(
        VulnClass.BLIND_SQLI, "CWE-89",
        "Blind SQL Injection",
        "Query-layer execution without output reflection",
        "Attacker input executes in the SQL query layer; the "
        "response never reflects output, so execution is proven "
        "by delay or out-of-band signals.",
        Severity.CRITICAL,
        "cursor.execute('... WHERE id=' + rid)",
        "cursor.execute('... WHERE id=%s', (rid,))",
        "https://cwe.mitre.org/data/definitions/89.html",
    ),
    VulnClass.PRIVILEGE_DIFFERENTIAL: _p(
        VulnClass.PRIVILEGE_DIFFERENTIAL, "CWE-284",
        "Privilege Differential Access Control Break",
        "Low-privilege principal reads a proven-restricted "
        "resource",
        "An observed behavioral differential shows a "
        "low-privilege principal receiving a restricted resource "
        "that a blanket-restricted control proves they cannot "
        "reach — the authorization decision is not enforced on "
        "this path.",
        Severity.HIGH,
        "return repo.get(object_id)",
        "if not authorize(actor, object_id):\n"
        "    raise Forbidden()\n"
        "return repo.get(object_id)",
        "https://cwe.mitre.org/data/definitions/284.html",
    ),
    # UNKNOWN deliberately carries no CWE: an unclassified finding gets an
    # honest absence, never an invented mapping.

    # ------------------------------------------------------------------
    # ULTIMATE PLAN 2026-10-27 (proposals 1/7): the five donorC family
    # classes and the eight new deterministic detector classes.
    # ------------------------------------------------------------------
    VulnClass.BUSINESS_LOGIC: _p(
        VulnClass.BUSINESS_LOGIC, "CWE-840",
        "Business Logic Errors",
        "Business rules enforced nowhere in code",
        "The application applies a price, quota, discount, or workflow "
        "rule that exists only in documentation; the request path that "
        "enforces it trusts client-supplied totals or skips the state "
        "machine entirely.",
        Severity.HIGH,
        "charge(order.total_from_client)",
        "total = price_table[order.sku] * qty\ncharge(total)",
        "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
    ),
    VulnClass.MULTI_STEP_AUTH_BYPASS: _p(
        VulnClass.MULTI_STEP_AUTH_BYPASS, "CWE-287",
        "Improper Authentication",
        "Multi-step login completes without one of its steps",
        "A multi-stage authentication flow (password, OTP, device check) "
        "reaches the session-issue endpoint even when a stage was skipped "
        "or replayed; the flow's state machine has no completion proof.",
        Severity.CRITICAL,
        "issue_session(after=password_ok)",
        "issue_session(after=all_stages_verified)",
        "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
    ),
    VulnClass.TENANT_ISOLATION: _p(
        VulnClass.TENANT_ISOLATION, "CWE-284",
        "Improper Access Control",
        "Tenant boundary not enforced on data access",
        "A request authenticated as tenant A reads or writes tenant B's "
        "records because the object lookup filters by id alone and the "
        "tenant predicate exists only at the UI layer.",
        Severity.CRITICAL,
        "db.get(Invoice, id)",
        "db.get(Invoice, id, tenant=user.tenant)",
        "https://cheatsheetseries.owasp.org/cheatsheets/Multitenant_Security_Cheat_Sheet.html",
    ),
    VulnClass.EXPLOIT_CHAIN: _p(
        VulnClass.EXPLOIT_CHAIN, "CWE-680",
        "Injection of Unexpected Data into a Resource Used by a Downstream Component",
        "Individually-low findings chained into a high-impact path",
        "Two or more findings that look low-severity alone (an info "
        "disclosure, a weak redirect) compose into privilege escalation "
        "because each fixes the precondition the next one needs.",
        Severity.CRITICAL,
        "leak(token) + open_redirect(callback) -> account takeover",
        "fix each link: no secret in redirects, exact-match allowlists",
        "https://cwe.mitre.org/data/definitions/680.html",
    ),
    VulnClass.OAUTH: _p(
        VulnClass.OAUTH, "CWE-287",
        "Improper Authentication",
        "OAuth flow accepted without its proof artifacts",
        "An OAuth-protected decision (code exchange, scope grant) is "
        "made on the presence of a token shape rather than verified "
        "artifacts: signature, audience, and state are not all checked.",
        Severity.HIGH,
        "accept(token)  # any JWT-shaped string",
        "accept(verify_signature(token, aud, state))",
        "https://oauth.net/2/",
    ),
    VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE: _p(
        VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE, "CWE-200",
        "Exposure of Sensitive Information",
        "Production GraphQL schema exposed via introspection",
        "The production GraphQL endpoint answers __schema queries, "
        "handing attackers the full operation and type map — including "
        "fields that are not linked from any UI.",
        Severity.MEDIUM,
        "GraphQL(debug=True)  # introspection on",
        "GraphQL(introspection=False)  # production",
        "https://graphql.org/learn/introspection/",
    ),
    VulnClass.GRAPHQL_BATCHING_ABUSE: _p(
        VulnClass.GRAPHQL_BATCHING_ABUSE, "CWE-770",
        "Allocation of Resources Without Limits or Throttling",
        "Batched GraphQL queries bypass rate limits",
        "The endpoint accepts arrays of queries in one request; the "
        "per-request rate limit counts the batch as one unit, so an "
        "attacker multiplies effective request volume inside a single "
        "call.",
        Severity.MEDIUM,
        "POST /graphql  [{q1}, {q2}, ... {q5000}]",
        "max_query_batch_size = 10  # reject larger arrays",
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
    ),
    VulnClass.GRAPHQL_FIELD_SUGGESTION_LEAK: _p(
        VulnClass.GRAPHQL_FIELD_SUGGESTION_LEAK, "CWE-209",
        "Generation of Error Message Containing Sensitive Information",
        "GraphQL did-you-mean errors reveal hidden field names",
        "Validation errors echo the nearest known field name, letting "
        "attackers enumerate undocumented fields one typo at a time.",
        Severity.LOW,
        'errors: "Did you mean: internalAuditFlag?"',
        'errors: "invalid field"  # no suggestions in production',
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
    ),
    VulnClass.GRAPHQL_DEPTH_COMPLEXITY_DOS: _p(
        VulnClass.GRAPHQL_DEPTH_COMPLEXITY_DOS, "CWE-400",
        "Uncontrolled Resource Consumption",
        "Unbounded GraphQL query depth exhausts the resolver",
        "A deeply nested query fans out into exponential resolver work "
        "because no depth/complexity limit rejects it before execution.",
        Severity.MEDIUM,
        "execute(query)  # no depth check",
        "reject_if(depth(query) > 10 or complexity(query) > 1000)",
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#deprecation",
    ),
    VulnClass.PROTOTYPE_POLLUTION: _p(
        VulnClass.PROTOTYPE_POLLUTION, "CWE-1321",
        "Improperly Protected Modification of Object Prototype Attributes",
        "Unsafe merge lets input reach Object.prototype",
        "A recursive merge or path-set treats __proto__/constructor "
        "keys as data, letting input change the prototype every object "
        "inherits from — a polluted key then alters downstream logic.",
        Severity.HIGH,
        "deepMerge(target, req.body)",
        "deepMerge(target, sanitize(req.body))  # block __proto__/constructor",
        "https://github.com/nicknisi/prototype-pollution-examples",
        "https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html",
    ),
    VulnClass.OAUTH_MISCONFIGURATION: _p(
        VulnClass.OAUTH_MISCONFIGURATION, "CWE-601",
        "URL Redirection to Untrusted Site (Open Redirect)",
        "OAuth redirect_uri/state not strictly validated",
        "The authorization server accepts an attacker-shaped redirect_uri "
        "(absolute foreign host, protocol-relative, or a permissive "
        "prefix match) and issues codes without a validated state, so "
        "the flow can be completed by the attacker.",
        Severity.HIGH,
        "allow_prefix_match(redirect_uri)",
        "allow_exact_match(registered_redirect_uris[client_id])",
        "https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2",
    ),
    VulnClass.CACHE_POISONING: _p(
        VulnClass.CACHE_POISONING, "CWE-444",
        "Inconsistent Interpretation of HTTP Requests",
        "Unkeyed header input is cached and served to everyone",
        "The cache keys the response on the path but stores a body "
        "rendered from an unkeyed header (X-Forwarded-Host and friends), "
        "so one poisoned request is served to every later visitor.",
        Severity.HIGH,
        "cache(key=path)  # body rendered from X-Forwarded-Host",
        "cache(key=path); body=render(host_from_request_target)",
        "https://portswigger.net/research/practical-web-cache-poisoning",
    ),
    VulnClass.WEB_CACHE_DECEPTION: _p(
        VulnClass.WEB_CACHE_DECEPTION, "CWE-524",
        "Use of a Cache Without a Key",
        "Cacheable-looking path makes the cache store private content",
        "Requesting /account/settings.css (or any auto-extension path) "
        "makes a shared cache store the authenticated page's private "
        "body, which is then served unauthenticated to anyone.",
        Severity.HIGH,
        "cache_stores(/account/settings.css -> full account page)",
        "cache_bypass_for_authenticated_routes(); no extension-based "
        "cacheability",
        "https://portswigger.net/research/web-cache-deception",
    ),
    VulnClass.UNKNOWN: _p(
        VulnClass.UNKNOWN, None,
        "Unclassified Finding",
        "Class not recognized",
        "No pattern entry exists for this class. Guidance is withheld "
        "rather than invented; classify the finding first.",
        Severity.INFO,
        "", "", "",
    ),
}

_MAPPED = {
    cls for cls in PATTERNS
    if cls is not VulnClass.UNKNOWN and PATTERNS[cls].cwe_id
}


def get_pattern(vuln_class: VulnClass | str) -> SecurityPattern | None:
    """Pattern for a class, or ``None`` when the class has no CWE entry.

    UNKNOWN resolves to ``None``: callers must surface "no guidance"
    instead of rendering the empty placeholder as if it were advice.
    """
    if isinstance(vuln_class, str):
        try:
            vuln_class = VulnClass(vuln_class)
        except ValueError:
            return None
    pattern = PATTERNS.get(vuln_class)
    if pattern is None or pattern.cwe_id is None:
        return None
    return pattern


def pattern_for_finding(finding: dict[str, object]) -> SecurityPattern | None:
    """Pattern for a finding's ``vuln_class`` value, if it carries one.

    Accepts the string form or a ``VulnClass`` instance; UNKNOWN resolves
    to ``None`` like any unclassified value.
    """
    parsed = as_vuln_class(finding.get("vuln_class"))
    if parsed is None:
        return None
    return get_pattern(parsed)


def coverage() -> dict[str, int]:
    """Honest coverage report over the VulnClass vocabulary."""
    all_classes = set(VulnClass)
    return {
        "vocabulary_size": len(all_classes),
        "mapped": len(_MAPPED),
        "unmapped": len(all_classes - _MAPPED),
    }
