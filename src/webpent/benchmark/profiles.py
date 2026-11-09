"""Offline benchmark target profiles and manifest helpers.

Profiles are declarations for injected deterministic fixtures only.  They are
not target URLs, scan instructions, or evidence that a live application was
qualified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from webpent.benchmark.qualification import GroundTruthCase, QualificationFixture

_MAX_CATEGORIES = 64
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class OfflineTargetProfile:
    """Bounded manifest describing an offline benchmark scenario."""

    profile_id: str
    display_name: str
    vulnerability_classes: tuple[str, ...] = ()
    scenario: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        profile_id = self.profile_id.strip().lower()
        if not _SAFE_ID.fullmatch(profile_id):
            raise ValueError("profile_id must be a lowercase safe identifier")
        if not self.display_name.strip():
            raise ValueError("display_name must not be empty")
        categories: list[str] = []
        seen: set[str] = set()
        for category in self.vulnerability_classes[:_MAX_CATEGORIES]:
            normalized = str(category).strip().lower()
            if normalized and normalized not in seen:
                seen.add(normalized)
                categories.append(normalized)
        object.__setattr__(self, "profile_id", profile_id)
        object.__setattr__(self, "display_name", self.display_name.strip()[:160])
        object.__setattr__(self, "vulnerability_classes", tuple(categories))
        object.__setattr__(self, "scenario", dict(self.scenario or {}))

    def as_fixture(self) -> QualificationFixture:
        """Return a fixture with no live URL and an explicit offline marker."""
        ground_truth = tuple(
            GroundTruthCase(
                case_id=f"{self.profile_id}:{category}",
                category=category,
                source="offline-manifest",
            )
            for category in self.vulnerability_classes
        )
        scenario = {
            "offline_only": True,
            "profile_id": self.profile_id,
            "display_name": self.display_name,
            **dict(self.scenario or {}),
        }
        return QualificationFixture(
            fixture_id=self.profile_id,
            target_ref=f"fixture://{self.profile_id}",
            ground_truth=ground_truth,
            scenario=scenario,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "display_name": self.display_name,
            "vulnerability_classes": list(self.vulnerability_classes),
            "scenario": dict(self.scenario or {}),
            "offline_only": True,
        }


def build_offline_target_profile(
    profile_id: str,
    display_name: str,
    vulnerability_classes: tuple[str, ...] | list[str] = (),
    *,
    scenario: dict[str, Any] | None = None,
) -> OfflineTargetProfile:
    """Create a bounded custom profile for a local deterministic fixture."""
    return OfflineTargetProfile(
        profile_id=profile_id,
        display_name=display_name,
        vulnerability_classes=tuple(vulnerability_classes),
        scenario=scenario,
    )


def default_offline_target_profiles() -> tuple[OfflineTargetProfile, ...]:
    """Return declared benchmark profiles; these do not execute or scan them."""
    return (
        OfflineTargetProfile(
            "juice-shop",
            "OWASP Juice Shop fixture",
            ("injection", "broken_access_control", "xss", "ssrf", "authentication"),
        ),
        OfflineTargetProfile(
            "dvwa",
            "Damn Vulnerable Web Application fixture",
            ("injection", "xss", "csrf", "authentication", "file_upload"),
        ),
        OfflineTargetProfile(
            "webgoat",
            "OWASP WebGoat fixture",
            ("injection", "broken_access_control", "authentication", "cryptography"),
        ),
        OfflineTargetProfile(
            "wapt-labs",
            "WAPT Labs fixture",
            ("xss", "ssrf", "injection", "broken_access_control", "business_logic"),
        ),
        OfflineTargetProfile(
            "custom",
            "Operator-declared custom fixture",
            (),
        ),
    )


__all__ = [
    "OfflineTargetProfile",
    "build_offline_target_profile",
    "default_offline_target_profiles",
]
