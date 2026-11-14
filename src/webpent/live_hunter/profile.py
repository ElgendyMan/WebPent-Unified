"""TEAM-1 V1 — Authorized-lab hunter profile. Frozen, fail-closed."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final

PROFILE_ID: Final[str] = "authorized-lab-qualification-v1"
PROFILE_VERSION: Final[str] = "1.0.0"

LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1"})

class HunterCapability(str, Enum):
    TARGET_UNDERSTANDING="target_understanding"; AUTHORIZATION_MATRIX="authorization_matrix"
    IDOR_ENUMERATION="idor_enumeration"; JS_INTELLIGENCE="js_intelligence"
    ATTACK_GRAPH="attack_graph"; SMART_CAMPAIGNS="smart_campaigns"
    CQA_STRICT_EVIDENCE="cqa_strict_evidence"; SECOND_PRINCIPAL="second_principal"
    LIVE_QUALIFICATION="live_qualification"; REPLAY_VERIFICATION="replay_verification"
    DECISION_LOG_REPLAN="decision_log_replan"

FORBIDDEN_CAPABILITIES: Final[frozenset[str]] = frozenset({
    "unrestricted_shell","arbitrary_subprocess","llm_confirmation","evidence_mutation",
    "bypass_causal_guard","bypass_tool_boundary","external_target_contact","destructive_actions"})

@dataclass(frozen=True)
class AuthorizedLabProfile:
    profile_id: str=PROFILE_ID; profile_version: str=PROFILE_VERSION
    authorized_targets: tuple=field(default_factory=tuple)
    engagement_id: str=""; operator_approval_at: str=""
    capabilities: tuple=tuple(HunterCapability); lab_fixture_mode: bool=False; knowledge_ready: bool=False
    def __post_init__(self):
        if not self.engagement_id or not self.engagement_id.strip(): raise ValueError("engagement_id required")
        if not self.operator_approval_at or not self.operator_approval_at.strip(): raise ValueError("operator_approval_at required")
        if not self.authorized_targets: raise ValueError("at least one authorized_target required")
        for cap in self.capabilities:
            if getattr(cap,"value",str(cap)) in FORBIDDEN_CAPABILITIES: raise ValueError(f"forbidden: {cap}")
        if not self.knowledge_ready: raise ValueError("knowledge_ready must be True")
    @property
    def enabled_capabilities(self): return tuple(sorted(getattr(c,"value",str(c)) for c in self.capabilities))
    def is_target_authorized(self, target_url):
        from urllib.parse import urlparse
        if not target_url: return False
        try: p=urlparse(target_url)
        except Exception: return False
        if p.scheme not in {"http","https"}: return False
        host=p.hostname or ""
        if not host: return False
        if host in LOOPBACK_HOSTS:
            return bool(self.lab_fixture_mode) and host in set(self.authorized_targets)
        return host in set(self.authorized_targets)
    def digest(self):
        return hashlib.sha256(json.dumps({"pid":self.profile_id,"pv":self.profile_version,
            "targets":sorted(self.authorized_targets),"eid":self.engagement_id,"oa":self.operator_approval_at,
            "caps":self.enabled_capabilities,"lfm":self.lab_fixture_mode,"kr":self.knowledge_ready},
            sort_keys=True,separators=(",",":")).encode()).hexdigest()

def build_authorized_lab_profile(*,engagement_id,operator_approval_at,authorized_targets,lab_fixture_mode=False,knowledge_ready=True):
    return AuthorizedLabProfile(engagement_id=engagement_id,operator_approval_at=operator_approval_at,
        authorized_targets=tuple(sorted(str(t).strip() for t in authorized_targets if str(t).strip())),
        lab_fixture_mode=bool(lab_fixture_mode),knowledge_ready=bool(knowledge_ready))

__all__=["PROFILE_ID","PROFILE_VERSION","HunterCapability","FORBIDDEN_CAPABILITIES","AuthorizedLabProfile","build_authorized_lab_profile"]
