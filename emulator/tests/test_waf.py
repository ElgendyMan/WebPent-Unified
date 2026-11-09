"""U-EMU-2 — WAF simulation tests (5 tests)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from conftest import emulator_stack_up, http_status
from waf_config import waf_problems

EMU_DIR = Path(__file__).resolve().parents[1]
MODSEC = (EMU_DIR / "configs" / "modsecurity.conf").read_text()


def test_sqli_blocked() -> None:
    assert "SecRuleEngine On" in MODSEC
    assert "deny,status:403" in MODSEC
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    url = "http://localhost:80/?id=1%20UNION%20SELECT%20NULL,null,null"
    assert http_status(url) == 403


def test_xss_blocked() -> None:
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    url = "http://localhost:80/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
    assert http_status(url) == 403


def test_normal_request_allowed() -> None:
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    assert http_status("http://localhost:80/") == 200


def test_ssrf_blocked() -> None:
    # CRS SSRF/SSRF-protection rules (930xxx/918xxx) ship via the include
    assert "owasp-crs/rules" in MODSEC
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    url = ("http://localhost:80/?url=http://169.254.169.254/latest/"
           "meta-data/")
    assert http_status(url) == 403


def test_paranoia_level_2() -> None:
    # value-aware: a behavioral mutation (2->1, On->DetectionOnly) fails here
    # even without Docker running (Round-3 finding F-7)
    assert waf_problems(MODSEC) == []
    compose = yaml.safe_load(
        (EMU_DIR / "docker-compose.yml").read_text())
    waf_env = compose["services"]["waf"]["environment"]
    if isinstance(waf_env, list):
        waf_env = dict(item.split("=", 1) for item in waf_env)
    assert waf_env["PARANOIA"] == "2"
