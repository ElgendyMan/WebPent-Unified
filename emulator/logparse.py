"""Log analysis for the emulator — one module shared by the analyze
script and the CLI. Parses the shared nginx access/error logs and the
fail2ban log into a structured attack report. No network, no shell.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_NGINX_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" '
    r'(?P<status>\d{3}) \d+')
_LIMIT_LINE = re.compile(
    r'limiting requests, excess: [\d.]+ by zone "(?P<zone>\w+)", '
    r'client: (?P<ip>\S+)')
_BAN_LINE = re.compile(
    r'(?P<time>\S+ \S+) \S+ fail2ban\.actions\s*\[(?P<jail>[^\]]+)\] '
    r'(?:NOTICE|Notice):\s+(?P<action>Ban|Unban) (?P<ip>\S+)')
_WAF_LINE = re.compile(
    r'\[id "(?P<rule_id>\d+)"\].*?\[msg "(?P<msg>[^"]*)"\].*?'
    r'(?:\[data "[^"]*"\].*?)?\[uri "(?P<uri>[^"]*)"\]', re.S)


@dataclass
class AttackReport:
    generated_at: str = ""
    total_requests: int = 0
    requests_per_ip: dict[str, int] = field(default_factory=dict)
    blocked_403: int = 0
    throttled_429: int = 0
    status_counts: dict[str, int] = field(default_factory=dict)
    top_attackers: list[tuple[str, int]] = field(default_factory=list)
    waf_triggers: int = 0
    waf_rules_hit: dict[str, int] = field(default_factory=dict)
    rate_limit_hits: int = 0
    ban_events: list[str] = field(default_factory=list)
    unban_events: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = ["# Emulator Attack Report", ""]
        lines.append(f"Total requests: {self.total_requests}")
        lines.append(f"Blocked (403): {self.blocked_403}")
        lines.append(f"Throttled (429): {self.throttled_429}")
        lines.append(f"WAF triggers: {self.waf_triggers}")
        lines.append(f"Rate-limit hits: {self.rate_limit_hits}")
        lines.append(f"Ban events: {len(self.ban_events)}")
        lines.append("")
        lines.append("## Top attackers")
        for ip, count in self.top_attackers[:5]:
            lines.append(f"- {ip}: {count} requests")
        if self.waf_rules_hit:
            lines.append("")
            lines.append("## WAF rules hit")
            for rule, count in sorted(self.waf_rules_hit.items()):
                lines.append(f"- rule {rule}: {count}x")
        if self.rate_limit_hits:
            lines.append("")
            lines.append("## Rate-limit zone hits")
            lines.append(f"- {self.rate_limit_hits} limit_req events")
        return "\n".join(lines) + "\n"


def parse_access_log(path: Path, report: AttackReport) -> None:
    if not path.is_file():
        return
    per_ip: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    for line in path.read_text(errors="replace").splitlines():
        match = _NGINX_LINE.match(line)
        if not match:
            continue
        per_ip[match["ip"]] += 1
        statuses[match["status"]] += 1
    report.total_requests = sum(per_ip.values())
    report.requests_per_ip = dict(per_ip)
    report.status_counts = dict(statuses)
    report.blocked_403 = statuses.get("403", 0)
    report.throttled_429 = statuses.get("429", 0)
    report.top_attackers = per_ip.most_common()


def parse_error_log(path: Path, report: AttackReport) -> None:
    if not path.is_file():
        return
    hits = 0
    for line in path.read_text(errors="replace").splitlines():
        if _LIMIT_LINE.search(line):
            hits += 1
    report.rate_limit_hits = hits


def parse_audit_log(path: Path, report: AttackReport) -> None:
    if not path.is_file():
        return
    text = path.read_text(errors="replace")
    report.waf_triggers = text.count("[id \"")
    for rule_id in re.findall(r'\[id "(\d+)"\]', text):
        report.waf_rules_hit[rule_id] = report.waf_rules_hit.get(rule_id, 0) + 1


def parse_fail2ban_log(path: Path, report: AttackReport) -> None:
    if not path.is_file():
        return
    for line in path.read_text(errors="replace").splitlines():
        match = _BAN_LINE.search(line)
        if not match:
            continue
        if match["action"] == "Ban":
            report.ban_events.append(line)
        else:
            report.unban_events.append(line)


def analyze(log_dir: Path) -> AttackReport:
    report = AttackReport()
    parse_access_log(log_dir / "access.log", report)
    parse_error_log(log_dir / "error.log", report)
    parse_audit_log(log_dir / "modsec_audit.log", report)
    parse_fail2ban_log(log_dir / "fail2ban.log", report)
    return report
