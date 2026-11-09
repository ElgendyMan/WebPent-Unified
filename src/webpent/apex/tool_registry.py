"""The Apex Predator — U-APEX-1, the Tool Registry (v87).

The apex layer orchestrates the world's vetted arsenal; it never
reimplements a tool (APEX-L-1). This module is the single source of truth
for which external tools exist, what they can do, and whether they are
present on PATH. Loading and querying this registry performs zero network
calls and zero subprocess launches: `verify_installed` is which(2) only
(APEX-L-2, APEX-L-9). Registration is advisory bookkeeping; execution
belongs to the sandbox (APEX-L-4) behind the scope guard (APEX-L-3).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PREAMBLE_LINE = (
    "advisory: apex orchestrates vetted tools and proposes plans only — "
    "the operator approves every execution; no finding is promoted here."
)

#: the nine declared tool categories (closed set)
CATEGORIES = (
    "recon",
    "crawling",
    "scanning",
    "fuzzing",
    "injection",
    "exploitation",
    "credentials",
    "analysis",
    "network",
)

REGISTRY_SPEEDS = ("fast", "medium", "slow")
REGISTRY_STEALTH = ("low", "medium", "high")

_REQUIRED_FIELDS = (
    "id",
    "name",
    "category",
    "binary",
    "install_command",
    "input_type",
    "output_format",
    "capabilities",
    "speed",
    "stealth",
    "vetted",
)


class UnknownToolError(KeyError):
    """Raised when a tool id is not in the registry."""


@dataclass(frozen=True)
class ToolSpec:
    """One vetted external tool (APEX-L-2)."""

    id: str
    name: str
    category: str
    binary: str
    install_command: str
    input_type: str
    output_format: str
    capabilities: tuple[str, ...]
    speed: str
    stealth: str
    vetted: bool
    version: str = ""
    requires_confirmation: bool = False

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "binary": self.binary,
            "install_command": self.install_command,
            "input_type": self.input_type,
            "output_format": self.output_format,
            "capabilities": list(self.capabilities),
            "speed": self.speed,
            "stealth": self.stealth,
            "vetted": self.vetted,
            "version": self.version,
            "requires_confirmation": self.requires_confirmation,
        }


@dataclass
class ToolRegistry:
    """Unified registry of external tools with their capabilities."""

    _tools: dict[str, ToolSpec] = field(default_factory=dict)

    # -- loading --------------------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> ToolRegistry:
        """Load the YAML registry. Missing file → FileNotFoundError; broken
        YAML or an invalid entry → ValueError (fail closed, never silent)."""
        if not path.is_file():
            raise FileNotFoundError(f"registry file not found: {path}")
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:  # pragma: no cover - message text only
            raise ValueError(f"broken registry yaml: {exc}") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("tools"), list):
            raise ValueError("registry yaml must map 'tools' to a list")
        registry = cls()
        for entry in raw["tools"]:
            spec = cls._spec_from_entry(entry)
            if spec.id in registry._tools:
                raise ValueError(f"duplicate tool id: {spec.id}")
            registry._tools[spec.id] = spec
        return registry

    @staticmethod
    def _spec_from_entry(entry: object) -> ToolSpec:
        if not isinstance(entry, dict):
            raise ValueError("registry entry must be a mapping")
        missing = [k for k in _REQUIRED_FIELDS if k not in entry]
        if missing:
            raise ValueError(f"registry entry missing fields: {missing}")
        if entry["category"] not in CATEGORIES:
            raise ValueError(f"unknown category: {entry['category']!r}")
        if entry["speed"] not in REGISTRY_SPEEDS:
            raise ValueError(f"unknown speed: {entry['speed']!r}")
        if entry["stealth"] not in REGISTRY_STEALTH:
            raise ValueError(f"unknown stealth: {entry['stealth']!r}")
        if not entry.get("vetted"):
            raise ValueError(f"tool {entry['id']!r} is not vetted (APEX-L-2)")
        if not entry["capabilities"]:
            raise ValueError(f"tool {entry['id']!r} declares no capabilities")
        return ToolSpec(
            id=str(entry["id"]),
            name=str(entry["name"]),
            category=str(entry["category"]),
            binary=str(entry["binary"]),
            install_command=str(entry["install_command"]),
            input_type=str(entry["input_type"]),
            output_format=str(entry["output_format"]),
            capabilities=tuple(str(c) for c in entry["capabilities"]),
            speed=str(entry["speed"]),
            stealth=str(entry["stealth"]),
            vetted=bool(entry["vetted"]),
            version=str(entry.get("version", "")),
            requires_confirmation=bool(entry.get("requires_confirmation", False)),
        )

    # -- queries ---------------------------------------------------------------

    def list_tools(self, category: str | None = None) -> list[ToolSpec]:
        tools = list(self._tools.values())
        if category is not None:
            tools = [t for t in tools if t.category == category]
        return sorted(tools, key=lambda t: t.id)

    def find_by_capability(self, capability: str) -> list[ToolSpec]:
        return sorted(
            (t for t in self._tools.values() if capability in t.capabilities),
            key=lambda t: (REGISTRY_SPEEDS.index(t.speed), t.id),
        )

    def find_by_speed(self, speed: str) -> list[ToolSpec]:
        if speed not in REGISTRY_SPEEDS:
            raise ValueError(f"unknown speed: {speed!r}")
        return sorted(
            (t for t in self._tools.values() if t.speed == speed),
            key=lambda t: t.id,
        )

    def get(self, tool_id: str) -> ToolSpec:
        try:
            return self._tools[tool_id]
        except KeyError as exc:
            raise UnknownToolError(tool_id) from exc

    def has(self, tool_id: str) -> bool:
        return tool_id in self._tools

    # -- presence ----------------------------------------------------------------

    def verify_installed(self, tool_id: str) -> bool:
        """True when the tool's binary is on PATH. which(2) only — this never
        executes anything and never touches the network (APEX-L-9)."""
        return shutil.which(self.get(tool_id).binary) is not None

    def installation_report(self) -> dict[str, bool]:
        return {t.id: self.verify_installed(t.id) for t in self.list_tools()}

    # -- summary -----------------------------------------------------------------

    def summary(self) -> dict:
        by_category: dict[str, int] = {}
        for tool in self._tools.values():
            by_category[tool.category] = by_category.get(tool.category, 0) + 1
        return {
            "total": len(self._tools),
            "vetted": sum(1 for t in self._tools.values() if t.vetted),
            "by_category": dict(sorted(by_category.items())),
        }
