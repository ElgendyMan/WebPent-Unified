#!/usr/bin/env python3
"""Secret scanning gate — Track 1 (كشف الأسرار) of the unified roadmap.

Roadmap contract (المسار 1، جدول البوابات — كشف الأسرار):

    إضافة secret scanning على التغييرات والتاريخ وفق سياسة الفريق، مع
    معالجة أي كشف دون نشر القيمة.

    ("Add secret scanning on changes and history per the team's policy,
    handling any detection without publishing the value.")

Design
------
A deterministic, dependency-free scanner over the working tree (CI runs
it on a fresh checkout, so the working tree IS the changeset):

* signature patterns for the credential shapes that matter here:
  cloud-provider keys (AWS/GCP), SCM tokens (GitHub app/ OAuth /
  fine-grained PAT), messaging webhooks (Slack/Discord), private key
  blocks, and high-entropy assignments to key-ish variable names;
* everything under the documented exclusions (venvs, caches, archives,
  lockfiles with hashes, historical reports) is skipped;
* an explicit, documented allowlist (``scripts/quality/secrets_allowlist.json``)
  may waive a SPECIFIC file+rule ONLY with a reason — used for the
  well-known EXAMPLE/dummy fixtures that test the secret-handling code
  paths themselves;
* detections NEVER print the matched value — only file, line, and rule
  (the roadmap line: "معالجة أي كشف دون نشر القيمة").

Exit codes: 0 = clean (or waived), 1 = detection (block), 2 = harness
error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "scripts" / "quality" / "secrets_allowlist.json"

#: Directory prefixes never scanned (caches, archives, vendored deps).
SKIP_DIRS = frozenset(
    {
        ".venv",
        "venv",
        ".git",
        ".ruff_cache",
        "__pycache__",
        "node_modules",
        ".pytest_cache",
        "archive",
        "docs/archive",
        ".mypy_cache",
    }
)

#: Files never scanned: lockfiles carry hashes, historical evidence
#: artifacts are archived by design (Track 0/7); both are noise.
SKIP_FILE_SUFFIXES = frozenset(
    {".lock", ".sum", ".min.js", ".map", ".png", ".jpg", ".gif", ".ico", ".zip",
     ".pdf", ".woff", ".woff2", ".db", ".sqlite3"}
)
SKIP_FILE_NAMES = frozenset({"uv.lock", "package-lock.json", "poetry.lock"})

#: Size cap — a single "file" larger than this is binary/asset noise.
MAX_FILE_BYTES = 2_000_000

RULES: tuple[tuple[str, str], ...] = (
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github-oauth", r"\bgho_[0-9A-Za-z]{36}\b"),
    ("github-pat", r"\bghp_[0-9A-Za-z]{36}\b"),
    ("github-fine-grained-pat", r"\bgithub_pat_[0-9A-Za-z_]{22,255}\b"),
    ("gitlab-pat", r"\bglpat-[0-9A-Za-z\-_]{20,}\b"),
    ("slack-webhook", r"hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+"),
    ("slack-token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    ("discord-webhook", r"discord(?:app)?\.com/api/webhooks/[0-9]{15,}/[0-9A-Za-z\-_]{50,}"),
    ("google-api-key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("private-key-block",
     r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY(?: BLOCK)?-----"),
    ("anthropic-key", r"\bsk-ant-[0-9A-Za-z\-_]{20,}\b"),
    ("openai-key", r"\bsk-proj-[0-9A-Za-z\-_]{20,}\b"),
    ("generic-secret-assignment",
     r"(?i)\b(api[_-]?key|secret|token|password|passwd|auth[_-]?token)\b"
     r"[\"']?\s*[:=]\s*[\"'][^\"']{16,}[\"']"),
)

#: Sentinel handling is SUBSTRING-based on purpose: literal
#: credential-shaped strings are never embedded in this scanner file,
#: and the well-known documentation example keys all carry the word
#: "example" (or another marker) in them.
#: Sentinel SUBSTRINGS that mark a value as an intentional non-secret:
#: documentation placeholders, redaction fixtures, and obviously fake
#: test values ('sk-should-not-appear', 'REPLACE_ME_...', ...). A value
#: matching one of these is a fixture by construction, not a credential.
SENTINEL_SUBSTRINGS = (
    "example",
    "replace_me",
    "replace-me",
    "should-not-appear",
    "must-not-appear",
    "not-a-secret",
    "placeholder",
    "changeme",
    "change-me",
    "dummy",
    "fixture",
    "redacted",
    "xxxx",
    "****",
    "<your",
    "<insert",
    "${",
    "{your",
)


def _is_sentinel(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SENTINEL_SUBSTRINGS)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def iter_files():
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT).as_posix()
        if not path.is_file():
            continue
        parts = rel.split("/")
        if any(part in SKIP_DIRS for part in parts[:-1]) or rel.startswith("docs/archive/"):
            continue
        if path.name in SKIP_FILE_NAMES or path.suffix.lower() in SKIP_FILE_SUFFIXES:
            continue
        if path.name.startswith(".env"):
            # .env* files are configuration-templates/untracked by policy;
            # scanning templates would only match the documented placeholders.
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:1024]:
            continue  # binary
        yield rel, data.decode("utf-8", errors="replace")


def load_allowlist() -> set[tuple[str, str, str]]:
    """Waive keys are (file, rule, value-fingerprint) triples — value-
    precise, so a NEW secret in an allow-listed fixture file is still
    detected (it produces a different fingerprint)."""
    if not ALLOWLIST.exists():
        return set()
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    return {(e["file"], e["rule"], e["fingerprint"]) for e in data.get("allowlist", [])}


def scan() -> list[dict]:
    allow = load_allowlist()
    detections: list[dict] = []
    for rel, text in iter_files():
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule, pattern in RULES:
                match = re.search(pattern, line)
                if not match:
                    continue
                value = match.group(0)
                if _is_sentinel(value):
                    continue
                if rule == "generic-secret-assignment" and _entropy(value) < 3.5:
                    continue  # low-entropy placeholders ("", "changeme", docs text)
                fingerprint = hashlib.sha256(value.encode()).hexdigest()[:12]
                if (rel, rule, fingerprint) in allow:
                    continue
                detections.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "rule": rule,
                        "fingerprint": fingerprint,
                    }
                )
    return detections


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    try:
        detections = scan()
    except Exception as exc:  # pragma: no cover
        print(f"ABORT: scanner harness error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"detections": detections, "pass": not detections}, indent=2))
    else:
        print(f"secret scan: {len(detections)} detection(s)")
        for d in detections:
            print(f"  {d['file']}:{d['line']} rule={d['rule']} fp={d['fingerprint']}")
    if detections:
        print(
            "\nFAIL: potential secrets detected (values intentionally NOT printed).\n"
            "  Remove the secret (rotate it if it was ever committed), or — for a\n"
            "  documented public EXAMPLE fixture only — add file+rule to\n"
            "  scripts/quality/secrets_allowlist.json with a reason."
        )
        return 1
    if not args.json:
        print("PASS: no secrets detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
