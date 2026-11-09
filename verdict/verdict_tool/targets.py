"""U-VERDICT-3 — the Target Configuration Manager.

Targets are YAML files with a strict schema: scope in and out, policy
(automation flag, rate ceiling, safe harbor), output paths and metadata
including the legal-review flag. The manager validates hard: a target
without a completed legal review, without safe harbor, or carrying
credentials in the file is rejected before it can enter the campaign.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import yaml

PLATFORMS = ("hackerone", "bugcrowd", "yeswehack", "other")
SEVERITIES = ("critical", "high", "medium", "low", "info")

# keys that must never appear inside a target config
_FORBIDDEN_KEYS = re.compile(
    r"^\s*(password|passwd|secret|token|api[_-]?key|authorization|"
    r"private[_-]?key|cookie|session)\s*:",
    re.IGNORECASE | re.MULTILINE,
)
_ALLOWED_CREDENTIAL_KEYS = {"has_test_account", "notes"}


class TargetConfigError(ValueError):
    """Raised when a target config is invalid or duplicates an existing one."""


@dataclass
class Target:
    name: str
    platform: str
    program_url: str
    program_handle: str
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    excluded_methods: list[str] = field(default_factory=list)
    automation_allowed: bool = False
    max_rate_rps: float = 0.0
    safe_harbor: bool = False
    notes: str = ""
    run_dir: str = ""
    log_level: str = "INFO"
    added_at: str = ""
    reviewed_by: str = ""
    legal_review_completed: bool = False
    config_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _require_list(raw: Any, field_name: str, errors: list[str]) -> list[str]:
    if raw is None:
        raw = []
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        errors.append(f"{field_name} must be a list of strings")
        return []
    return raw


def target_from_yaml(path: Path) -> Target:
    """Parse and validate a target YAML file; raises on any error."""
    path = Path(path)
    if not path.is_file():
        raise TargetConfigError(f"target config not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise TargetConfigError(f"invalid YAML in {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise TargetConfigError(f"{path.name} must be a YAML mapping")

    errors: list[str] = []
    top = data.get("target")
    if not isinstance(top, dict):
        raise TargetConfigError(f"{path.name}: missing 'target' section")
    scope = data.get("scope") or {}
    if not isinstance(scope, dict):
        errors.append("'scope' must be a mapping")
        scope = {}
    policy = data.get("policy") or {}
    if not isinstance(policy, dict):
        errors.append("'policy' must be a mapping")
        policy = {}
    credentials = data.get("credentials") or {}
    if not isinstance(credentials, dict):
        errors.append("'credentials' must be a mapping")
        credentials = {}
    output = data.get("output") or {}
    if not isinstance(output, dict):
        errors.append("'output' must be a mapping")
        output = {}
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        errors.append("'metadata' must be a mapping")
        metadata = {}

    name = str(top.get("name") or "").strip()
    if not name:
        errors.append("target.name is required")
    platform = str(top.get("platform") or "").strip().lower()
    if platform not in PLATFORMS:
        errors.append(
            f"target.platform must be one of {PLATFORMS}, got {platform!r}"
        )
    program_url = str(top.get("program_url") or "").strip()
    if not program_url.startswith("https://"):
        errors.append("target.program_url must be an https:// URL")
    program_handle = str(top.get("program_handle") or "").strip()
    if not program_handle:
        errors.append("target.program_handle is required")

    in_scope = _require_list(scope.get("in_scope"), "scope.in_scope", errors)
    if not in_scope:
        errors.append("scope.in_scope must list at least one pattern")
    out_scope = _require_list(scope.get("out_of_scope"),
                              "scope.out_of_scope", errors)
    excluded = _require_list(scope.get("excluded_methods"),
                             "scope.excluded_methods", errors)

    if not isinstance(policy.get("automation_allowed"), bool):
        errors.append("policy.automation_allowed must be a boolean")
    automation = bool(policy.get("automation_allowed", False))
    rate = policy.get("max_rate_rps")
    if not isinstance(rate, (int, float)) or isinstance(rate, bool) \
            or rate <= 0:
        errors.append("policy.max_rate_rps must be a positive number")
    if policy.get("safe_harbor") is not True:
        errors.append(
            "policy.safe_harbor must be true: no safe harbor, no testing"
        )
    notes = str(policy.get("notes") or "")

    unknown_cred_keys = set(credentials) - _ALLOWED_CREDENTIAL_KEYS
    if unknown_cred_keys:
        errors.append(
            "credentials must not hold secrets; only "
            f"{sorted(_ALLOWED_CREDENTIAL_KEYS)} are allowed "
            f"(found {sorted(unknown_cred_keys)}); use .env outside the repo"
        )
    raw_text = path.read_text(encoding="utf-8")
    forbidden = _FORBIDDEN_KEYS.search(raw_text)
    if forbidden:
        errors.append(
            f"{path.name} contains a forbidden credential key near "
            f"{forbidden.group(0).strip()!r}; never store credentials in configs"
        )

    legal = metadata.get("legal_review_completed") is True
    if not legal:
        errors.append(
            "metadata.legal_review_completed must be true: "
            "no target without a completed legal review"
        )

    if errors:
        raise TargetConfigError(
            f"{path.name} failed validation:\n  - " + "\n  - ".join(errors)
        )

    return Target(
        name=name,
        platform=platform,
        program_url=program_url,
        program_handle=program_handle,
        in_scope=in_scope,
        out_of_scope=out_scope,
        excluded_methods=excluded,
        automation_allowed=automation,
        max_rate_rps=float(rate),
        safe_harbor=True,
        notes=notes,
        run_dir=str(output.get("run_dir") or f"runs/{path.stem}/"),
        log_level=str(output.get("log_level") or "INFO"),
        added_at=str(metadata.get("added_at") or ""),
        reviewed_by=str(metadata.get("reviewed_by") or ""),
        legal_review_completed=True,
        config_path=str(path),
    )


def _http_head(url: str, timeout: float = 5.0) -> int:
    """Single HEAD request; isolated here so tests can patch it."""
    request = Request(url, method="HEAD")  # noqa: S310 (operator-invoked)
    with urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.status


class TargetManager:
    """Loads, validates and lists target configs from a directory."""

    def __init__(self, targets_dir: Path | str) -> None:
        self.dir = Path(targets_dir)

    def add(self, yaml_path: Path | str) -> Target:
        """Validate a config and copy it into the targets directory."""
        source = Path(yaml_path)
        target = target_from_yaml(source)
        slug = re.sub(r"[^a-z0-9]+", "_", target.program_handle.lower()).strip("_")
        destination = self.dir / f"{slug or 'target'}.yaml"
        if destination.exists():
            raise TargetConfigError(
                f"duplicate target: {destination.name} already exists "
                "(same program handle)"
            )
        for existing in self.list():
            if existing.name == target.name:
                raise TargetConfigError(
                    f"duplicate target name: {target.name!r} already registered"
                )
        self.dir.mkdir(parents=True, exist_ok=True)
        destination.write_text(source.read_text(encoding="utf-8"),
                               encoding="utf-8")
        target.config_path = str(destination)
        return target

    def list(self) -> list[Target]:
        if not self.dir.is_dir():
            return []
        targets: list[Target] = []
        for path in sorted(self.dir.glob("*.yaml")):
            targets.append(target_from_yaml(path))
        return targets

    def get(self, name: str) -> Target:
        for target in self.list():
            if target.name == name or target.program_handle == name:
                return target
        raise TargetConfigError(
            f"unknown target {name!r}; registered: "
            f"{[t.name for t in self.list()]}"
        )

    @staticmethod
    def validate(target: Target) -> list[str]:
        """Re-validate a loaded target; returns a list of errors (empty = ok)."""
        errors: list[str] = []
        if not target.name:
            errors.append("name is empty")
        if target.platform not in PLATFORMS:
            errors.append(f"unknown platform {target.platform!r}")
        if not target.program_url.startswith("https://"):
            errors.append("program_url must be https")
        if not target.in_scope:
            errors.append("in_scope is empty")
        if not target.safe_harbor:
            errors.append("safe_harbor is not enabled")
        if target.max_rate_rps <= 0:
            errors.append("max_rate_rps must be positive")
        if not target.legal_review_completed:
            errors.append("legal review not completed")
        if target.automation_allowed and target.max_rate_rps > 50:
            errors.append("rate ceiling above 50 rps is outside policy")
        return errors

    @staticmethod
    def check_accessibility(target: Target) -> bool:
        """One HEAD request to the program URL; any failure means False."""
        try:
            return 200 <= _http_head(target.program_url) < 400
        except Exception:  # noqa: BLE001 — offline or blocked = not accessible
            return False

    @staticmethod
    def get_config_for_webpent(target: Target) -> dict[str, Any]:
        """Map a target onto the shape webpent's runner expects."""
        return {
            "target": {
                "name": target.name,
                "program_handle": target.program_handle,
            },
            "scope": {
                "in_scope": list(target.in_scope),
                "out_of_scope": list(target.out_of_scope),
                "excluded_methods": list(target.excluded_methods),
            },
            "policy": {
                "automation_allowed": target.automation_allowed,
                "max_rate_rps": target.max_rate_rps,
                "safe_harbor": target.safe_harbor,
            },
            "output": {
                "run_dir": target.run_dir,
                "log_level": target.log_level,
            },
        }


__all__ = ["PLATFORMS", "SEVERITIES", "Target", "TargetConfigError",
           "TargetManager", "target_from_yaml"]
