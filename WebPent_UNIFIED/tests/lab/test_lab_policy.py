# tests/lab/test_lab_policy.py
"""Sprint I-2, Part 1 — Lab target policy tests.

Asserts the exact lab scenario from the program spec:
  B reads INV-B-204  -> 200
  A reads INV-B-204  -> 403
  A reads INV-X-000  -> 403
  A reads INV-A-101  -> 200
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
)

from tests.lab.idor_lab_target import start_lab_server


@pytest.fixture(scope="module")
def lab_target():
    server, base_url = start_lab_server()
    yield base_url
    server.should_exit = True


def _get(base_url, path, x_user=None):
    import httpx
    headers = {}
    if x_user:
        headers["X-User"] = x_user
    return httpx.get(f"{base_url}{path}", headers=headers, follow_redirects=False)


class TestLabPolicy:
    def test_b_owns_204_reads_200(self, lab_target):
        r = _get(lab_target, "/api/invoices/INV-B-204", x_user="User_B")
        assert r.status_code == 200
        assert r.json()["owner"] == "User_B"

    def test_a_foreign_reads_b_204_forbidden(self, lab_target):
        r = _get(lab_target, "/api/invoices/INV-B-204", x_user="User_A")
        assert r.status_code == 403

    def test_a_reads_x000_forbidden(self, lab_target):
        r = _get(lab_target, "/api/invoices/INV-X-000", x_user="User_A")
        assert r.status_code == 403

    def test_a_reads_own_101_ok(self, lab_target):
        r = _get(lab_target, "/api/invoices/INV-A-101", x_user="User_A")
        assert r.status_code == 200
        assert r.json()["owner"] == "User_A"

    def test_login_issues_per_principal_tokens(self, lab_target):
        import httpx
        r_a = httpx.post(f"{lab_target}/api/login",
                         json={"username": "User_A", "password": "password_a"})
        assert r_a.status_code == 200
        assert r_a.json()["principal"] == "User_A"
        token_a = r_a.json()["token"]
        # Token authenticates as A.
        r = httpx.get(f"{lab_target}/api/invoices/INV-A-101",
                      headers={"Authorization": f"Bearer {token_a}"})
        assert r.status_code == 200
        # Wrong password rejected.
        r_bad = httpx.post(f"{lab_target}/api/login",
                           json={"username": "User_A", "password": "wrong"})
        assert r_bad.status_code == 401

    def test_unknown_invoice_404(self, lab_target):
        r = _get(lab_target, "/api/invoices/NO-SUCH", x_user="User_A")
        assert r.status_code == 404

    def test_unauthenticated_401(self, lab_target):
        r = _get(lab_target, "/api/invoices/INV-A-101")
        assert r.status_code == 401


class TestLabIdentityRoute:
    """RA-1 / U-2b: GET /api/invoices/me — the identity-discovery surface."""
    def test_me_returns_identity_for_user_a(self, lab_target):
        r = _get(lab_target, "/api/invoices/me", x_user="User_A")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == "User_A"
        assert body["principal"] == "User_A"
        assert body["role"] == "foreign-user"
    def test_me_returns_identity_for_user_b(self, lab_target):
        r = _get(lab_target, "/api/invoices/me", x_user="User_B")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == "User_B"
        assert body["principal"] == "User_B"
        assert body["role"] == "owner"
    def test_me_unauthenticated_401(self, lab_target):
        r = _get(lab_target, "/api/invoices/me")
        assert r.status_code == 401
    def test_me_not_captured_as_invoice_id(self, lab_target):
        r = _get(lab_target, "/api/invoices/me", x_user="User_A")
        assert r.status_code == 200, f"Route ordering bug: captured as invoice_id='me'"
        assert "principal" in r.json(), "Response from wrong route"
    def test_me_works_with_bearer_token(self, lab_target):
        import httpx
        r_login = httpx.post(f"{lab_target}/api/login", json={"username": "User_A", "password": "password_a"})
        assert r_login.status_code == 200
        token = r_login.json()["token"]
        r = httpx.get(f"{lab_target}/api/invoices/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["principal"] == "User_A"
