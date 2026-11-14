from .authority import (
    CanonicalScopeError,
    ControlPlaneEgressPolicy,
    EngagementScopeAuthority,
    authority_for_target_only,
    authority_from_policy,
    authority_from_scope_file_spec,
)
from .enforcer import ScopeEnforcer
from .models import ScopeDecision, ScopeLimits, ScopePolicy, ScopeRule, ScopeStatus
from .parser import ScopeParseError, parse_scope_file, parse_scope_text
from .registry import GLOBAL_SCOPE_REGISTRY, ScopeRegistry
from .violations import ScopeViolation

__all__ = [
    "GLOBAL_SCOPE_REGISTRY",
    "CanonicalScopeError",
    "ControlPlaneEgressPolicy",
    "EngagementScopeAuthority",
    "ScopeDecision",
    "ScopeEnforcer",
    "ScopeLimits",
    "ScopeParseError",
    "ScopePolicy",
    "ScopeRegistry",
    "ScopeRule",
    "ScopeStatus",
    "ScopeViolation",
    "authority_for_target_only",
    "authority_from_policy",
    "authority_from_scope_file_spec",
    "parse_scope_file",
    "parse_scope_text",
]
