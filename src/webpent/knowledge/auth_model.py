"""Authorization knowledge facade with conservative unknown handling."""

from __future__ import annotations

from webpent.knowledge.target_knowledge import AuthorizationProfile, TargetKnowledgeModel


class AuthorizationModel:
    """Read-only identity and role observations."""

    def __init__(self, profiles: dict[str, AuthorizationProfile]) -> None:
        self.profiles = dict(profiles)

    @classmethod
    def from_target_knowledge(cls, model: TargetKnowledgeModel) -> AuthorizationModel:
        return cls(model.authorization_profiles)

    def get(self, identity_id: str) -> AuthorizationProfile | None:
        return self.profiles.get(identity_id)

    def known_roles(self, identity_id: str) -> tuple[str, ...]:
        profile = self.get(identity_id)
        return tuple(profile.role_names) if profile else ()

    def is_authorized(self, identity_id: str) -> bool:
        profile = self.get(identity_id)
        return bool(profile and profile.authorization_status == "authorized_observed")

    def as_dict(self) -> dict[str, dict[str, object]]:
        return {key: value.model_dump(mode="json") for key, value in self.profiles.items()}


__all__ = ["AuthorizationModel"]
