"""TEAM-1 V1 Phase 9 — Uniform scope law. Preserved."""
from __future__ import annotations
import hashlib, json, re
from dataclasses import dataclass
from typing import Any
from webpent.live_hunter.profile import AuthorizedLabProfile

REGISTERED_TOOLS: frozenset[str]=frozenset({"sqlmap","sqlmap_post_exploit","dalfox","ffuf","nuclei","httpx","katana","subfinder","httpx_bounded"})
POISON_PATTERNS: tuple=tuple(re.compile(p,re.IGNORECASE) for p in [r"169\.254\.169\.254",r"metadata\.google\.internal",r"file://",r"gopher://",r"dict://",r"ftp://",r"--os-shell",r"--os-pwn",r"--sql-shell",r"--os-cmd",r"--priv-esc"])

@dataclass(frozen=True)
class ScopeDecision:
    tool_name:str; target_url:str; in_scope:bool; poison_detected:bool; poison_details:tuple; reason:str; scope_law_version:str="1.0"
    def digest(self): return hashlib.sha256(json.dumps({"t":self.tool_name,"u":self.target_url,"s":self.in_scope,"p":self.poison_detected,"r":self.reason},sort_keys=True,separators=(",",":")).encode()).hexdigest()

class ScopeLaw:
    def __init__(self,*,profile:AuthorizedLabProfile,engagement_id:str):
        self.profile=profile; self.engagement_id=engagement_id; self._decisions=[]
    @property
    def decisions(self): return tuple(self._decisions)
    @staticmethod
    def _detect(text):
        d=[p.pattern for p in POISON_PATTERNS if p.search(text)]; return (len(d)>0,tuple(d))
    def authorize_invocation(self,*,tool_name,target_url,arguments=()):
        if tool_name not in REGISTERED_TOOLS:
            d=ScopeDecision(tool_name,target_url,False,False,(),f"tool_not_registered:{tool_name}"); self._decisions.append(d); return d
        text=f"{target_url} "+(" ".join(str(a) for a in arguments) if isinstance(arguments,(list,tuple)) else str(arguments))
        poisoned,details=self._detect(text); in_scope=self.profile.is_target_authorized(target_url)
        # FV-1 (final verification pass): poison detection MUST deny, not merely
        # annotate. Previously a poisoned invocation whose target URL happened to
        # be in scope reported ``in_scope=True`` — any consumer honoring the
        # boolean alone would execute poisoned argv (e.g. ``--os-shell`` against
        # the in-scope target). Poison is a hard deny: fail closed regardless of
        # target scope verdict.
        if poisoned: d=ScopeDecision(tool_name,target_url,False,True,details,f"poisoned:{','.join(details)}")
        elif not in_scope: d=ScopeDecision(tool_name,target_url,False,False,(),f"out_of_scope:{target_url}")
        else: d=ScopeDecision(tool_name,target_url,True,False,(),"scope_law_passed")
        self._decisions.append(d); return d

__all__=["ScopeDecision","ScopeLaw","REGISTERED_TOOLS","POISON_PATTERNS"]
