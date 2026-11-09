"""Round-3 red-team fixes — emulator regression tests (F-6, F-7).

- F-6  every published port binds the loopback interface only: the
       emulator is a local training range and must never expose
       vulnerable services to the LAN (MEDIUM).
- F-7  the WAF configuration tests parse the config VALUES, so a
       behavioral mutation (paranoia 2->1, engine On->DetectionOnly)
       fails the suite even when Docker is not running (LOW).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from waf_config import waf_problems

EMU_DIR = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((EMU_DIR / "docker-compose.yml").read_text())
MODSEC = (EMU_DIR / "configs" / "modsecurity.conf").read_text()


# -- F-6: loopback-only binding ------------------------------------------------


def test_no_wildcard_host_port_in_compose() -> None:
    offenders: list[str] = []
    for service, config in COMPOSE["services"].items():
        for port in config.get("ports", []):
            host_part = str(port).split(":")[0]
            if not host_part.startswith("127.0.0.1"):
                offenders.append(f"{service}: {port}")
    assert not offenders, (
        "services must bind 127.0.0.1 only, found: " + ", ".join(offenders)
    )


def test_dashboard_and_api_bind_loopback() -> None:
    offenders: list[str] = []
    for rel in ("monitoring/dashboard.py", "apps/custom-api/app.py"):
        text = (EMU_DIR / rel).read_text(encoding="utf-8")
        if '"0.0.0.0"' in text or "'0.0.0.0'" in text:
            offenders.append(rel)
    assert not offenders, (
        "python servers must bind loopback only: " + ", ".join(offenders)
    )


# -- F-7: WAF config checks are value-aware and mutation-sensitive --------------


def test_waf_config_is_valid() -> None:
    assert waf_problems(MODSEC) == []


def test_paranoia_mutation_is_caught() -> None:
    mutated = MODSEC.replace("tx.paranoia_level=2", "tx.paranoia_level=1")
    assert mutated != MODSEC
    assert any("paranoia" in p for p in waf_problems(mutated))


def test_engine_off_mutation_is_caught() -> None:
    mutated = MODSEC.replace("SecRuleEngine On", "SecRuleEngine DetectionOnly")
    assert mutated != MODSEC
    assert any("SecRuleEngine" in p for p in waf_problems(mutated))


def test_compose_paranoia_env_matches_config() -> None:
    waf_env = COMPOSE["services"]["waf"]["environment"]
    if isinstance(waf_env, list):
        waf_env = dict(item.split("=", 1) for item in waf_env)
    assert waf_env.get("PARANOIA") == "2"
