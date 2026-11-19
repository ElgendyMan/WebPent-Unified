"""OAuth / OIDC vulnerability family — passive analyzers (12 scenarios)."""
from .analyzer import OAuthSurfaceDetector
from .scenarios import OAUTH_SCENARIOS

__all__ = ["OAuthSurfaceDetector", "OAUTH_SCENARIOS"]
