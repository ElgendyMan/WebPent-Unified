#!/usr/bin/env python3
"""Before/after behavioral comparison: original vs refactored validators.

Demonstrates:
  - Juice Shop regression: JSON format still CONFIRMS (no regression)
  - WebGoat generalization: HTML/plain-text formats now CONFIRM (were INCONCLUSIVE)
Run: PYTHONPATH=src python3 demo_refactor.py
"""

from __future__ import annotations

import importlib.util
import os
import sys

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")


def load_mod(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


orig = load_mod("/tmp/validators_orig.py", "validators_orig")
refac = load_mod("src/webpent/production/validators.py", "validators_refac")


def ev(status, body="", headers=None, **extra):
    d = {"status_code": status, "response_body": body, "headers": headers or {}}
    d.update(extra)
    return d


CASES = [
    # (name, validator_key, baseline, candidate, negative_control, expected_after)
    (
        "Juice Shop IDOR (JSON) — regression",
        "IDOR",
        ev(200, '{"id":1,"basketId":3,"email":"a@test.com"}'),
        ev(200, '{"id":1,"basketId":3,"email":"a@test.com"}'),
        ev(404, '{"error":"Not found"}'),
        "CONFIRMED",
    ),
    (
        "WebGoat IDOR (HTML w/ dynamic nonce) — generalization",
        "IDOR",
        ev(
            200,
            "<html><h1>Account #1001</h1><p>Balance: $250.00</p><span nonce='a1b2c3'></span></html>",
        ),
        ev(
            200,
            "<html><h1>Account #1001</h1><p>Balance: $250.00</p><span nonce='d4e5f6'></span></html>",
        ),
        ev(404, "<html><h1>Not Found</h1></html>"),
        "CONFIRMED",
    ),
    (
        "WebGoat IDOR (plain text) — generalization",
        "IDOR",
        ev(200, "RECORD id=777 owner=acme balance=1200.50 ref=ABC-1"),
        ev(200, "RECORD id=777 owner=acme balance=1200.50 ref=XYZ-9"),
        ev(403, "ERROR: record not found or access denied"),
        "CONFIRMED",
    ),
    (
        "WebGoat BOLA (XML object) — generalization",
        "BOLA",
        ev(200, "<xml><obj><id>55</id><name>doc.pdf</name></obj></xml>"),
        ev(200, "<xml><obj><id>55</id><name>doc.pdf</name></obj><ts>1</ts></xml>"),
        ev(404, "<xml><error>missing</error></xml>"),
        "CONFIRMED",
    ),
    (
        "XSS reflected in text/plain — generalization",
        "XSS",
        ev(200, "search results: none"),
        ev(
            200,
            "results for: <script>webpent_xss_9f8e7d()</script>",
            {"content-type": "text/plain"},
            payload="<script>webpent_xss_9f8e7d()</script>",
        ),
        ev(200, "results for: "),
        "CONFIRMED",
    ),
    (
        "SSRF single strong internal IP — generalization",
        "SSRF",
        ev(200, '{"fetched":"https://api.example.com/data"}'),
        ev(200, '{"fetched":"http://10.0.0.5/internal-api/users"}'),
        ev(400, "invalid url scheme"),
        "CONFIRMED",
    ),
    (
        "Info disclosure verbose 500 error — generalization",
        "INFO_DISCLOSURE",
        ev(200, '{"public":"data"}'),
        ev(
            500,
            "Internal Server Error. Exception in thread main: NullPointerException at com.example.App.handle (App.java:42). Stack trace: ...",
        ),
        ev(200, '{"ok":true}'),
        "CONFIRMED",
    ),
    (
        "Different resource — still INCONCLUSIVE (no false positive)",
        "IDOR",
        ev(200, "<html>Account #1001 balance 250</html>"),
        ev(200, "<html>Account #2002 balance 999</html>"),
        ev(404, "<html>not found</html>"),
        "INCONCLUSIVE",
    ),
    (
        "Foreign denied — still REFUTED",
        "IDOR",
        ev(200, "ok data"),
        ev(403, "forbidden"),
        ev(404, "nf"),
        "REFUTED",
    ),
]

print(f"{'CASE':<62} {'BEFORE':<14} {'AFTER':<14} {'EXPECTED':<12} {'MATCH'}")
print("-" * 110)
all_pass = True
for name, key, b, c, nc, expected in CASES:
    ro = orig.run_validator(key, baseline=b, candidate=c, negative_control=nc)
    rr = refac.run_validator(key, baseline=b, candidate=c, negative_control=nc)
    match = "OK" if rr.outcome.value == expected else "FAIL"
    if match == "FAIL":
        all_pass = False
    changed = " *" if ro.outcome.value != rr.outcome.value else ""
    print(f"{name:<62} {ro.outcome.value:<14} {rr.outcome.value:<14} {expected:<12} {match}{changed}")

print("-" * 110)
print("ALL AFTER-MATCHES EXPECTED:", all_pass)
print("(* = outcome changed by refactor (generalization gained))")
