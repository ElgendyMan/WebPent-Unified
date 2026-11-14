"""Scenario lab app — operator workflow "URL + Credentials (+ Scope sometimes)".

A deliberately small multi-principal web app used to live-prove the
scenario contract end to end:

* **Session auth with a real HTML login form** the engine's Playwright
  flow can drive (``input[name='username']`` + ``input[type='password']``
  + ``button[type='submit']``). Failed logins re-render the sign-in page
  with an explicit "please sign in" indicator (fail-loud, not 200-ok).
* **Two resource principals** (user_a, user_b) plus an admin-only panel,
  so horizontal (A reading B's objects) and vertical (user hitting admin
  routes) access-control differentials are both exercisable.
* **One deliberately vulnerable IDOR endpoint** (``/api/invoices/{id}``):
  authenticated sessions can read ANY invoice — no ownership check.
  Safe control endpoint ``/api/invoices/mine`` is correctly enforced.
* **Auth-only vs anonymous surfaces** for the two-layer recon diff:
  ``/dashboard`` and ``/api/profile`` exist only behind a session.
* **Bounded business flows**: profile update + password change (the
  skip-step / repeat-step targets of the business-logic fuzzer).
* **A reflected-XSS parameter** for optional tool-first confirmation.

Everything is in-memory and deterministic; the app binds loopback only.
"""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="WebPent Scenario Lab")

# Accounts: username -> {password, email, owned_invoice_ids, role}
ACCOUNTS: dict[str, dict[str, Any]] = {
    "user_a": {
        "password": "alpha-pass-1",
        "email": "user_a@lab.internal",
        "owned_invoice_ids": [181],
        "role": "user",
    },
    "user_b": {
        "password": "beta-pass-2",
        "email": "user_b@lab.internal",
        "owned_invoice_ids": [182],
        "role": "user",
    },
    "admin": {
        "password": "admin-pass-9",
        "email": "admin@lab.internal",
        "owned_invoice_ids": [183],
        "role": "admin",
    },
}

# Invoice id -> record (181 = user_a's, 182 = user_b's, 183 = admin's).
INVOICES: dict[int, dict[str, Any]] = {
    181: {"id": 181, "owner": "user_a", "amount": "120.00", "iban": "LAB00A1"},
    182: {"id": 182, "owner": "user_b", "amount": "250.50", "iban": "LAB00B2"},
    183: {"id": 183, "owner": "admin", "amount": "990.00", "iban": "LAB00X9"},
}

SESSIONS: dict[str, str] = {}  # token -> username
SESSION_COOKIE = "sess"

LOGIN_PAGE = """<!doctype html>
<html><head><title>Scenario Lab Sign in</title></head>
<body>
  <h1>Scenario Lab</h1>
  <form method="post" action="/login">
    <input name="username" type="text" placeholder="username"/>
    <input name="password" type="password" placeholder="password"/>
    <button type="submit">Login</button>
  </form>
  {message}
</body></html>"""

DASHBOARD_PAGE = """<!doctype html>
<html><head><title>Dashboard</title></head>
<body>
  <h1>Dashboard for {username}</h1>
  <ul>
    <li><a href="/api/invoices/mine">My invoice (safe)</a></li>
    <li><a href="/api/invoices/181">Invoice 181</a></li>
    <li><a href="/api/invoices/182">Invoice 182</a></li>
    <li><a href="/api/invoices/183">Invoice 183</a></li>
  </ul>
  <p><a href="/profile">Profile</a> | <a href="/logout">Logout</a></p>
</body></html>"""

PROFILE_PAGE = """<!doctype html>
<html><head><title>Profile</title></head>
<body>
  <h1>Profile</h1>
  <form method="post" action="/profile/update">
    <input name="email" type="text" value="{email}"/>
    <button type="submit">Update email</button>
  </form>
  <form method="post" action="/password/change">
    <input name="current_password" type="password"/>
    <input name="new_password" type="password"/>
    <button type="submit">Change password</button>
  </form>
  <p><a href="/dashboard">Back</a></p>
</body></html>"""


def _current_user(request: Request) -> str | None:
    token = request.cookies.get(SESSION_COOKIE) or ""
    return SESSIONS.get(token)


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> Response:
    # Real apps redirect an authenticated visitor away from the login page.
    # The engine's session validator treats a login form on a post-login
    # fetch as a bounce indicator — so the lab must honour that contract.
    if _current_user(request):
        resp = Response(status_code=303)
        resp.headers["Location"] = "/dashboard"
        return resp
    return HTMLResponse(LOGIN_PAGE.format(message=""))


@app.get("/login", response_class=HTMLResponse)
def login_page() -> str:
    return LOGIN_PAGE.format(message="")


@app.post("/login")
def login(response: Response, username: str = Form(""), password: str = Form("")) -> Response:
    account = ACCOUNTS.get(username)
    if not account or account["password"] != password:
        # Fail-loud: 200 with the sign-in form + explicit indicator so the
        # engine's bounce heuristics (and honesty gates) see a login page.
        return HTMLResponse(LOGIN_PAGE.format(
            message="<p>Please sign in — invalid credentials.</p>"))
    token = secrets.token_hex(16)
    SESSIONS[token] = username
    resp = Response(status_code=303)
    resp.headers["Location"] = "/dashboard"
    resp.set_cookie(SESSION_COOKIE, token, httponly=True)
    return resp


@app.get("/logout")
def logout(response: Response) -> Response:
    resp = Response(status_code=303)
    resp.headers["Location"] = "/"
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request) -> Response:
    username = _current_user(request)
    if not username:
        return HTMLResponse(LOGIN_PAGE.format(
            message="<p>Please sign in to continue.</p>"), status_code=200)
    return HTMLResponse(DASHBOARD_PAGE.format(username=username))


@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request) -> Response:
    username = _current_user(request)
    if not username:
        return HTMLResponse(LOGIN_PAGE.format(
            message="<p>Please sign in to continue.</p>"), status_code=200)
    return HTMLResponse(PROFILE_PAGE.format(email=ACCOUNTS[username]["email"]))


@app.post("/profile/update")
def profile_update(request: Request, email: str = Form("")) -> JSONResponse:
    username = _current_user(request)
    if not username:
        return JSONResponse({"error": "please log in"}, status_code=401)
    ACCOUNTS[username]["email"] = email
    return JSONResponse({"ok": True, "username": username, "email": email})


@app.post("/password/change")
def password_change(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
) -> JSONResponse:
    username = _current_user(request)
    if not username:
        return JSONResponse({"error": "please log in"}, status_code=401)
    account = ACCOUNTS[username]
    if account["password"] != current_password or not new_password:
        return JSONResponse({"error": "password change rejected"}, status_code=400)
    account["password"] = new_password
    return JSONResponse({"ok": True})


@app.get("/api/profile")
def api_profile(request: Request) -> Response:
    username = _current_user(request)
    if not username:
        return JSONResponse({"error": "auth required"}, status_code=401)
    account = ACCOUNTS[username]
    return JSONResponse({
        "username": username, "email": account["email"], "role": account["role"],
    })


@app.get("/api/invoices/mine")
def api_invoices_mine(request: Request) -> Response:
    """SAFE control: correctly enforced to the session owner."""
    username = _current_user(request)
    if not username:
        return JSONResponse({"error": "auth required"}, status_code=401)
    owned = ACCOUNTS[username]["owned_invoice_ids"]
    return JSONResponse({"invoices": [INVOICES[i] for i in owned]})


@app.get("/api/invoices/{invoice_id}")
def api_invoice_by_id(request: Request, invoice_id: int) -> Response:
    """VULNERABLE (by design): session required, ownership NOT checked.

    Any authenticated principal can enumerate ANY invoice id — the exact
    "authenticated user reads /api/invoices/182 and gets user_b's data"
    scenario contract case. Anonymous callers get an explicit 401.
    """
    username = _current_user(request)
    if not username:
        return JSONResponse({"error": "auth required — please log in"},
                            status_code=401)
    record = INVOICES.get(invoice_id)
    if record is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(record)


@app.get("/admin/panel")
def admin_panel(request: Request) -> Response:
    username = _current_user(request)
    if not username:
        return HTMLResponse(LOGIN_PAGE.format(
            message="<p>Please sign in to continue.</p>"), status_code=200)
    if ACCOUNTS[username]["role"] != "admin":
        return JSONResponse({"error": "admin role required"}, status_code=403)
    return HTMLResponse("<html><body><h1>Admin panel</h1></body></html>")


@app.get("/search", response_class=HTMLResponse)
def search(q: str = "") -> str:
    # Reflected parameter — the XSS tool leg's target (bounded lab value).
    return f"<html><body><h1>Search</h1><p>Results for: {q}</p></body></html>"


@app.get("/public", response_class=HTMLResponse)
def public() -> str:
    return "<html><body><h1>Public area</h1><p>Anonymous-visible page.</p></body></html>"
