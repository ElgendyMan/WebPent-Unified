"""U-EMU-1 — Docker Compose setup tests (8 tests)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from conftest import docker_available, emulator_stack_up, http_status

EMU_DIR = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((EMU_DIR / "docker-compose.yml").read_text())


def env_of(service: str) -> dict[str, str]:
    """Compose `environment` may be a list or map; normalize to a dict."""
    raw = COMPOSE["services"][service].get("environment", {})
    if isinstance(raw, dict):
        return dict(raw)
    return dict(item.split("=", 1) for item in raw)


def test_compose_valid() -> None:
    services = COMPOSE["services"]
    for name in ("juice-shop", "dvwa", "custom-api", "waf", "rate-limiter",
                 "fail2ban", "monitoring"):
        assert name in services, f"{name} missing from compose"
    assert COMPOSE["networks"]["target_net"]["driver"] == "bridge"
    # the WAF fronts juice-shop and runs at paranoia 2
    waf_env = env_of("waf")
    assert waf_env["BACKEND"] == "http://juice-shop:3000"
    assert waf_env["PARANOIA"] == "2"


def test_all_services_start() -> None:
    if not (docker_available() and emulator_stack_up()):
        pytest.skip("needs the docker compose stack running")
    import subprocess
    result = subprocess.run(
        ["docker", "compose", "ps", "--format", "json", "--all"],
        cwd=EMU_DIR, capture_output=True, text=True, check=False)
    states = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(states) >= 7, f"expected 7 services, got {len(states)}"


def test_juice_shop_accessible() -> None:
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    assert http_status("http://localhost:3000/") == 200


def test_dvwa_accessible() -> None:
    if not (docker_available() and emulator_stack_up()):
        pytest.skip("needs the docker compose stack (DVWA is PHP + MySQL)")
    assert http_status("http://localhost:8080/") == 200


def test_custom_api_accessible() -> None:
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    assert http_status("http://localhost:9000/health") == 200


def test_waf_blocks_sqli() -> None:
    modsec = (EMU_DIR / "configs" / "modsecurity.conf").read_text()
    assert "SecRuleEngine On" in modsec
    assert "owasp-crs/rules" in modsec  # CRS (SQLi rules 94xxxx) included
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    assert http_status("http://localhost:80/?id=1%27+OR+%271%27=%271") == 403


def test_waf_blocks_xss() -> None:
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    url = "http://localhost:80/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    assert http_status(url) == 403


def test_rate_limiter_429() -> None:
    limits = (EMU_DIR / "configs" / "rate_limits.conf").read_text()
    assert "limit_req_status 429" in limits
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    statuses = [http_status("http://localhost:8000/api?q=i")
                for _ in range(30)]
    assert 429 in statuses
