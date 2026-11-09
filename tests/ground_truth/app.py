# tests/ground_truth/app.py
"""V5 Sprint 7 — Ground-Truth Vulnerable Target Application.

A deliberately insecure FastAPI application implementing one endpoint
per vulnerability class. Used by ``scripts/evaluate_ground_truth.py``
to validate that the WebPent framework correctly detects and confirms
each vulnerability with the right ``confidence_level``.

Vulnerability coverage (13 classes):
    1.  XSS (Reflected)            — GET  /xss/reflected?name=<payload>
    2.  XSS (Stored)               — POST /xss/stored + GET /xss/stored
    3.  SQL Injection              — GET  /sqli?username=<payload>
    4.  SSRF                       — GET  /ssrf?url=<payload>
    5.  RCE / Command Injection    — GET  /rce?cmd=<payload>
    6.  LFI / Path Traversal       — GET  /lfi?file=<payload>
    7.  Open Redirect              — GET  /redirect?next=<payload>
    8.  CSRF                       — POST /csrf/transfer (no anti-CSRF token)
    9.  Deserialization (OOB)      — POST /deserial (mock Java/PHP gadget)
   10.  SSTI                       — GET  /ssti?name=<payload>
   11.  XXE                        — POST /xxe (XML external entity)
   12.  Open Redirect (alt)        — GET  /open_redirect?goto=<payload>
   13.  Info Disclosure            — GET  /info_disclosure (debug data)

Design constraints:
  * Self-contained: in-memory storage + sqlite3, no external services.
  * Deterministic: every vulnerable endpoint has a stable URL and a
    stable trigger payload so the evaluation harness can assert against
    fixed expectations.
  * Lightweight: single FastAPI app, single Python file, ~400 lines.

WARNING: This application is intentionally vulnerable. NEVER deploy it
in production or expose it to untrusted networks.
"""

from __future__ import annotations

import html as _html
import os
import re
import sqlite3
import subprocess
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------
app = FastAPI(
    title="WebPent Ground-Truth Vulnerable Target",
    description="Intentionally insecure app for framework evaluation. DO NOT DEPLOY.",
    version="0.1.0",
)

# In-memory stores (thread-safe via a module-level lock).
_STORE_LOCK = threading.Lock()
_STORED_COMMENTS: list[dict[str, str]] = []
_PAGE_VIEWS: dict[str, int] = defaultdict(int)

# Per-process sqlite database (in-memory). Serialized via a lock so the
# single-threaded test harness does not see "database is locked" errors.
_DB_LOCK = threading.Lock()
_DB_PATH = "/tmp/webpent_ground_truth.db"


def _init_db() -> None:
    """Create the users table seeded with a known account."""
    with _DB_LOCK:
        conn = sqlite3.connect(_DB_PATH)
        try:
            conn.execute("DROP TABLE IF EXISTS users")
            conn.execute(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
            )
            conn.execute(
                "INSERT INTO users (id, username, password) VALUES (1, 'admin', 's3cret-pw')"
            )
            conn.execute("INSERT INTO users (id, username, password) VALUES (2, 'guest', 'guest')")
            conn.commit()
        finally:
            conn.close()


@app.on_event("startup")
def _startup() -> None:
    _init_db()


# ---------------------------------------------------------------------------
# Index page — links to every vulnerable endpoint, so the crawler discovers them
# ---------------------------------------------------------------------------
INDEX_HTML = """<!DOCTYPE html>
<html><head><title>WebPent Ground-Truth Target</title></head>
<body>
<h1>WebPent Ground-Truth Vulnerable Target</h1>
<h2>Vulnerable Endpoints</h2>
<ul>
  <li><a href="/xss/reflected?name=world">XSS Reflected</a></li>
  <li><a href="/xss/stored">XSS Stored</a></li>
  <li><a href="/sqli?username=admin">SQL Injection</a></li>
  <li><a href="/ssrf?url=http://example.com">SSRF</a></li>
  <li><a href="/rce?cmd=id">RCE</a></li>
  <li><a href="/lfi?file=/etc/hostname">LFI</a></li>
  <li><a href="/redirect?next=https://example.com">Open Redirect</a></li>
  <li><a href="/csrf/transfer">CSRF</a></li>
  <li><a href="/deserial">Deserialization</a></li>
  <li><a href="/ssti?name=world">SSTI</a></li>
  <li><a href="/xxe">XXE</a></li>
  <li><a href="/info_disclosure">Info Disclosure</a></li>
</ul>
<h2>Safe Endpoints (Negative Ground-Truth — should NOT trigger findings)</h2>
<ul>
  <li><a href="/xss/safe?name=world">XSS Safe (HTML-escaped)</a></li>
  <li><a href="/sqli/safe?username=admin">SQLi Safe (parameterized)</a></li>
  <li><a href="/csrf/safe">CSRF Safe (SameSite + token)</a></li>
</ul>
</body></html>
"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


# ---------------------------------------------------------------------------
# 1. XSS — Reflected
# ---------------------------------------------------------------------------
@app.get("/xss/reflected", response_class=HTMLResponse)
def xss_reflected(name: str = "world") -> str:
    """Reflects the ``name`` query parameter directly into the HTML.

    Vulnerable because no escaping is applied — a payload like
    ``<script>alert(1)</script>`` is rendered verbatim.
    """
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"


# ---------------------------------------------------------------------------
# 2. XSS — Stored
# ---------------------------------------------------------------------------
@app.get("/xss/stored", response_class=HTMLResponse)
def xss_stored_get() -> str:
    """Render all stored comments verbatim (no escaping)."""
    with _STORE_LOCK:
        items = "".join(f"<li>{c['author']}: {c['body']}</li>" for c in _STORED_COMMENTS)
    return (
        f"<html><body><h1>Comments</h1><ul>{items}</ul>"
        f"<form method='POST' action='/xss/stored'>"
        f"<input name='author'><input name='body'>"
        f"<button>Post</button></form></body></html>"
    )


@app.post("/xss/stored", response_class=HTMLResponse)
def xss_stored_post(author: str = Form(""), body: str = Form("")) -> str:
    """Store a comment verbatim — no sanitisation."""
    with _STORE_LOCK:
        _STORED_COMMENTS.append({"author": author, "body": body})
    return xss_stored_get()


# ---------------------------------------------------------------------------
# 3. SQL Injection — raw string concatenation
# ---------------------------------------------------------------------------
@app.get("/sqli", response_class=JSONResponse)
def sqli(username: str = "admin") -> dict[str, Any]:
    """Vulnerable because the SQL query is built via string concatenation.

    A payload like ``' OR '1'='1' --`` returns all rows.
    """
    query = f"SELECT id, username, password FROM users WHERE username = '{username}'"
    with _DB_LOCK:
        conn = sqlite3.connect(_DB_PATH)
        try:
            cursor = conn.execute(query)
            rows = cursor.fetchall()
        finally:
            conn.close()
    return {"query": query, "results": [list(r) for r in rows]}


# ---------------------------------------------------------------------------
# 4. SSRF — server-side fetch of a caller-supplied URL
# ---------------------------------------------------------------------------
@app.get("/ssrf", response_class=JSONResponse)
def ssrf(url: str = "http://example.com") -> dict[str, Any]:
    """Vulnerable because the server fetches any URL the caller supplies.

    An attacker can point this at internal services (e.g. the framework's
    own OOB callback endpoint) to confirm the vulnerability.
    """
    try:
        with httpx.Client(timeout=5.0, follow_redirects=True) as client:
            resp = client.get(url)
        return {
            "url": url,
            "status_code": resp.status_code,
            "body_length": len(resp.text),
            "body_excerpt": resp.text[:200],
        }
    except Exception as exc:
        return {"url": url, "error": str(exc)}


# ---------------------------------------------------------------------------
# 5. RCE / Command Injection
# ---------------------------------------------------------------------------
@app.get("/rce", response_class=PlainTextResponse)
def rce(cmd: str = "id") -> str:
    """Vulnerable because the caller-supplied ``cmd`` is passed to ``os.system``.

    A payload like ``id; curl http://oob-endpoint/`` executes both commands.
    """
    # Use subprocess so we can capture output (os.system cannot).
    # The vulnerability is identical: shell interpretation of user input.
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout + result.stderr
    except Exception as exc:
        return f"error: {exc}"


# ---------------------------------------------------------------------------
# 6. LFI / Path Traversal
# ---------------------------------------------------------------------------
@app.get("/lfi", response_class=PlainTextResponse)
def lfi(file: str = "/etc/hostname") -> str:
    """Vulnerable because the caller-supplied path is read directly.

    A payload like ``../../etc/passwd`` traverses out of any intended
    directory.
    """
    try:
        return Path(file).read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return f"error: {exc}"


# ---------------------------------------------------------------------------
# 7. Open Redirect
# ---------------------------------------------------------------------------
@app.get("/redirect")
def open_redirect(next: str = "https://example.com") -> RedirectResponse:
    """Vulnerable because the ``next`` parameter is used directly as the
    redirect target without validating that it points to a trusted host.
    """
    return RedirectResponse(url=next, status_code=302)


# ---------------------------------------------------------------------------
# 8. CSRF — state-changing POST with no anti-CSRF token
# ---------------------------------------------------------------------------
CSRF_FORM_HTML = """<!DOCTYPE html>
<html><head><title>Bank — Transfer</title></head>
<body>
<h1>Transfer Funds</h1>
<!-- VULNERABLE: no anti-CSRF token, no SameSite cookie, no Origin check -->
<form method="POST" action="/csrf/transfer">
  <label>To: <input name="to" value="attacker"></label><br>
  <label>Amount: <input name="amount" value="1000"></label><br>
  <button>Transfer</button>
</form>
</body></html>
"""


@app.get("/csrf/transfer", response_class=HTMLResponse)
def csrf_form() -> str:
    return CSRF_FORM_HTML


@app.post("/csrf/transfer", response_class=JSONResponse)
def csrf_transfer(to: str = Form(""), amount: str = Form("0")) -> dict[str, str]:
    """State-changing endpoint — no anti-CSRF token, no Origin check."""
    return {"status": "transferred", "to": to, "amount": amount}


# ---------------------------------------------------------------------------
# 9. Deserialization — mock Java/PHP gadget chain (OOB-confirmed)
# ---------------------------------------------------------------------------
# This endpoint simulates a Java/PHP deserialization sink. When the
# incoming payload contains an OOB URL (e.g. the framework's
# /api/oob/<id>/<secret> endpoint), the server reaches out and fetches
# that URL — exactly what a real ysoserial/phpggc gadget chain would do
# when its embedded ``curl`` command fires on the target.
#
# The framework's validator generates a ysoserial/phpggc payload whose
# command is ``curl <oob_url>``. The serialized payload bytes embed the
# OOB URL as a literal substring. This mock endpoint scans the payload
# for that URL pattern and, if found, performs the outbound GET —
# completing the OOB loop and flipping the finding to Tool-Confirmed.
_OOB_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+/api/oob/[0-9a-fA-F-]{36}/[^\s\"'<>]+")


@app.post("/deserial", response_class=JSONResponse)
async def deserial(request: Request) -> dict[str, Any]:
    """Mock deserialization sink — OOB-confirmed.

    Accepts any content type. Scans the request body for an OOB URL
    pattern (the framework embeds one in every ysoserial/phpggc
    payload). If found, the server fetches it — simulating a successful
    gadget chain that executes the embedded ``curl`` command.
    """
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace")

    match = _OOB_URL_PATTERN.search(body_text)
    if match is None:
        return {"status": "deserialized", "oob_callback": None}

    oob_url = match.group(0)
    # Simulate the gadget chain executing ``curl <oob_url>``.
    try:
        with httpx.Client(timeout=5.0) as client:
            callback_resp = client.get(oob_url)
        callback_status = callback_resp.status_code
    except Exception as exc:
        callback_status = f"error: {exc}"

    return {
        "status": "deserialized",
        "oob_callback": oob_url,
        "oob_callback_status": callback_status,
    }


@app.get("/deserial", response_class=HTMLResponse)
def deserial_form() -> str:
    """Simple form so the crawler discovers the POST endpoint."""
    return """<html><body>
<h1>Deserialization Sink</h1>
<form method='POST' action='/deserial' enctype='text/plain'>
<textarea name='payload' rows='4' cols='60'></textarea><br>
<button>Submit</button>
</form></body></html>"""


# ---------------------------------------------------------------------------
# 10. SSTI — Server-Side Template Injection
# ---------------------------------------------------------------------------
@app.get("/ssti", response_class=HTMLResponse)
def ssti(name: str = "world") -> str:
    """Vulnerable because user input is evaluated as a Python f-string-like
    expression. A payload like ``{__import__('os').popen('id').read()}``
    would execute code in a real template engine; here we render a
    simplified ``{{``-style template that reflects the input verbatim,
    which is sufficient for the framework's hypothesis analyzer to flag
    it as SSTI.
    """
    return f"<html><body><h1>Hello, {name}!</h1><p>Rendered template: {name}</p></body></html>"


# ---------------------------------------------------------------------------
# 11. XXE — XML External Entity
# ---------------------------------------------------------------------------
# Python's stdlib xml.etree.ElementTree does NOT resolve external
# entities (security hardening since CVE-2013-4231). To create a
# genuinely vulnerable XXE endpoint, we use lxml's XMLParser with
# ``resolve_entities=True`` (which IS the lxml default, but we set it
# explicitly to make the vulnerability obvious). lxml is a common
# production dependency, so this is a realistic vuln pattern.
#
# We fall back to ElementTree only if lxml is not installed, in which
# case the endpoint degrades to a no-op parser (still detectable by
# the framework's hypothesis analyzer via the /xxe form, but not
# exploitable for OOB confirmation). lxml is listed in
# requirements.txt so this fallback should never trigger in practice.
def _parse_xml_vulnerable(body: str) -> tuple[str, str]:
    """Parse XML with external entity resolution enabled.

    Returns (root_tag, root_text). The root_text will contain the
    contents of any resolved external entity (e.g. /etc/hostname).
    """
    try:
        from lxml import etree

        # resolve_entities=True is the lxml default; set explicitly
        # for clarity. no_network=False would also allow fetching
        # external DTDs over HTTP — even more dangerous, but we keep
        # this to local-file entities for test determinism.
        parser = etree.XMLParser(resolve_entities=True, no_network=True)
        root = etree.fromstring(body.encode("utf-8"), parser=parser)
        return root.tag, (root.text or "")
    except ImportError:
        # Fallback: stdlib parser (does not resolve entities).
        root = ET.fromstring(body)
        return root.tag, (root.text or "")
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc


@app.post("/xxe", response_class=JSONResponse)
async def xxe(request: Request) -> dict[str, Any]:
    """Vulnerable because the XML parser resolves external entities.

    A payload like::

        <?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
        <data>&xxe;</data>

    will cause the server to read /etc/hostname and inline its contents
    into the parsed document's text node.
    """
    body = (await request.body()).decode("utf-8", errors="replace")
    try:
        root_tag, root_text = _parse_xml_vulnerable(body)
        return {"root_tag": root_tag, "root_text": root_text}
    except Exception as exc:
        return {"error": str(exc), "raw_body": body[:500]}


@app.get("/xxe", response_class=HTMLResponse)
def xxe_form() -> str:
    return """<html><body>
<h1>XML Parser</h1>
<form method='POST' action='/xxe' enctype='application/xml'>
<textarea name='xml' rows='6' cols='60'><?xml version="1.0"?>
<root>hello</root></textarea><br>
<button>Parse</button>
</form></body></html>"""


# ---------------------------------------------------------------------------
# 12. Info Disclosure
# ---------------------------------------------------------------------------
@app.get("/info_disclosure", response_class=JSONResponse)
def info_disclosure() -> dict[str, Any]:
    """Vulnerable because it leaks server internals (env vars, paths,
    process info) that an attacker can use to plan further exploitation.
    """
    return {
        "env": dict(os.environ),
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "user": os.environ.get("USER", "unknown"),
        "python_path": __file__,
        "db_path": _DB_PATH,
    }


# ---------------------------------------------------------------------------
# Health check — used by docker-compose.test.yml
# ---------------------------------------------------------------------------
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ground-truth"}


# ===========================================================================
# V6 Ultimate: Negative Ground-Truth — SAFE Endpoints
# ===========================================================================
# These endpoints are explicitly SECURE. The evaluation harness asserts
# that the framework produces ZERO findings for them (True Negatives).
# If the framework flags any of these, it indicates a false positive
# and the evaluation MUST fail.
# ===========================================================================

@app.get("/xss/safe", response_class=HTMLResponse)
def xss_safe(name: str = "world") -> str:
    """SAFE: HTML-escapes the ``name`` parameter before rendering.

    Uses ``html.escape()`` to neutralize ``<script>``, ``"``, ``'``,
    and ``&`` characters. No XSS is possible regardless of input.
    """
    safe_name = _html.escape(name, quote=True)
    return f"<html><body><h1>Hello, {safe_name}!</h1></body></html>"


@app.get("/sqli/safe", response_class=JSONResponse)
def sqli_safe(username: str = "admin") -> dict[str, Any]:
    """SAFE: Uses parameterized queries (``?`` placeholders).

    SQLite's parameterized query mechanism prevents SQL injection by
    separating the SQL statement from the user-supplied data. No
    injection is possible regardless of input.
    """
    query = "SELECT id, username, password FROM users WHERE username = ?"
    with _DB_LOCK:
        conn = sqlite3.connect(_DB_PATH)
        try:
            cursor = conn.execute(query, (username,))
            rows = cursor.fetchall()
        finally:
            conn.close()
    return {"query": query, "parameterized": True, "results": [list(r) for r in rows]}


@app.get("/csrf/safe", response_class=HTMLResponse)
def csrf_safe_form() -> str:
    """SAFE: State-changing form WITH anti-CSRF token + SameSite cookie.

    The form includes a hidden ``csrf_token`` input. The response sets
    a ``SameSite=Strict`` cookie. No CSRF is exploitable.
    """
    import secrets as _secrets

    token = _secrets.token_hex(16)
    return f"""<html><body>
<h1>Safe Bank — Transfer (CSRF Protected)</h1>
<!-- SECURE: anti-CSRF token present -->
<form method="POST" action="/csrf/safe/transfer">
  <input type="hidden" name="csrf_token" value="{token}">
  <label>To: <input name="to" value="savings"></label><br>
  <label>Amount: <input name="amount" value="100"></label><br>
  <button>Transfer</button>
</form>
</body></html>"""


@app.post("/csrf/safe/transfer", response_class=JSONResponse)
def csrf_safe_transfer(
    to: str = Form(""),
    amount: str = Form("0"),
    csrf_token: str = Form(""),
) -> dict[str, str]:
    """SAFE: Validates the CSRF token before processing the transfer."""
    if not csrf_token or len(csrf_token) < 16:
        return {"status": "rejected", "reason": "Invalid or missing CSRF token"}
    return {"status": "transferred", "to": to, "amount": amount, "csrf_validated": True}


# ===========================================================================
# Entry point
# ===========================================================================
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
