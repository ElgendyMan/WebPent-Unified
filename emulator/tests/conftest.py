"""Fixtures for the emulator test suite.

The suite is split honestly: structural and log-analysis tests always
run (no Docker needed); anything that requires the live stack first
checks that Docker is present and the stack is reachable, and skips
with a clear reason otherwise.
"""

from __future__ import annotations

import socket
import sys
import urllib.request
from pathlib import Path

import pytest

EMU_DIR = Path(__file__).resolve().parents[1]
if str(EMU_DIR) not in sys.path:
    sys.path.insert(0, str(EMU_DIR))


def docker_available() -> bool:
    import shutil
    return shutil.which("docker") is not None


def port_open(port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def emulator_stack_up() -> bool:
    """True when the emulator's endpoints answer, by any deployment.

    The compose stack (docker) and a native deployment (same configs,
    real nginx/Apache-ModSecurity/fail2ban on the same ports) both
    satisfy this. The gate is "can we actually verify behavior", not
    "is a specific runtime installed".
    """
    return port_open(3000) and port_open(80) and port_open(8000)


def http_status(url: str, timeout: float = 5.0) -> int | None:
    """GET a local emulator URL, returning the status code (None on error)."""
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "emu-test"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


@pytest.fixture
def sample_logs(tmp_path: Path) -> Path:
    """A log directory shaped like monitoring/nginx-logs with real entries."""
    log_dir = tmp_path / "nginx-logs"
    log_dir.mkdir()
    (log_dir / "access.log").write_text(
        '10.0.0.1 - - [18/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" '
        '200 1234 "-" "emu/1"\n'
        '10.0.0.2 - - [18/Oct/2026:10:00:01 +0000] "GET /?id=1 HTTP/1.1" '
        '200 1234 "-" "emu/1"\n'
        '10.0.0.2 - - [18/Oct/2026:10:00:02 +0000] "GET /?id=1\' HTTP/1.1" '
        '403 0 "-" "emu/1"\n'
        '10.0.0.2 - - [18/Oct/2026:10:00:03 +0000] "GET /search HTTP/1.1" '
        '429 0 "-" "emu/1"\n'
        '10.0.0.2 - - [18/Oct/2026:10:00:04 +0000] "GET /search HTTP/1.1" '
        '429 0 "-" "emu/1"\n',
        encoding="utf-8")
    (log_dir / "error.log").write_text(
        '2026/10/18 10:00:03 [error] 7#7: *12 limiting requests, '
        'excess: 5.20 by zone "api", client: 10.0.0.2, '
        'server: _, request: "GET /search HTTP/1.1", host: "localhost"\n'
        '2026/10/18 10:00:04 [error] 7#7: *13 limiting requests, '
        'excess: 6.10 by zone "api", client: 10.0.0.2, '
        'server: _, request: "GET /search HTTP/1.1", host: "localhost"\n',
        encoding="utf-8")
    (log_dir / "modsec_audit.log").write_text(
        '[id "942100"] [msg "SQL Injection Attack Detected via libinjection"]'
        ' [uri "/?id=1%27"]\n'
        '[id "942100"] [msg "SQL Injection Attack Detected via libinjection"]'
        ' [uri "/?id=1%27%20OR%20%271"]\n'
        '[id "941160"] [msg "XSS Filter - Category 1: Script Tag Vector"]'
        ' [uri "/search?q=%3Cscript%3E"]\n',
        encoding="utf-8")
    (log_dir / "fail2ban.log").write_text(
        '2026-10-18 10:01:00,700 fail2ban.actions        [7]: NOTICE  '
        '[nginx-limit-req] Ban 10.0.0.2\n'
        '2026-10-18 10:06:00,812 fail2ban.actions        [7]: NOTICE  '
        '[nginx-limit-req] Unban 10.0.0.2\n',
        encoding="utf-8")
    return log_dir
