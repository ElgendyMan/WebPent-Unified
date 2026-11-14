"""webpent.brain.blocked_path — U-12 S-2 The Blocked-Path Protocol."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
class ReasonClass(str, Enum):
    TRANSIENT="TRANSIENT"; AUTH_FAILURE="AUTH_FAILURE"; SCOPE_DENIAL="SCOPE_DENIAL"; EVIDENCE_INSUFFICIENT="EVIDENCE_INSUFFICIENT"; FABRIC_GAP="FABRIC_GAP"; BUDGET="BUDGET"; LLM_FAILURE="LLM_FAILURE"; UNEXPECTED_SHAPE="UNEXPECTED_SHAPE"
@dataclass
class BlockedRecord:
    stage: str; reason_class: ReasonClass; evidence: str
    alternatives_considered: list[dict[str,Any]] = field(default_factory=list)
    chosen_next: str|None = None; campaign_terminal_justification: str|None = None; lesson_proposal: str|None = None
    def is_valid(self): return len(self.alternatives_considered)>=2 or bool(self.campaign_terminal_justification)
    def to_dict(self): return {"stage":self.stage,"reason_class":self.reason_class.value,"evidence":self.evidence,"alternatives_considered":self.alternatives_considered,"chosen_next":self.chosen_next,"campaign_terminal_justification":self.campaign_terminal_justification,"lesson_proposal":self.lesson_proposal}
class BlockedPathProtocol:
    def __init__(self): self._records=[]
    def record_block(self,*,stage,reason_class,evidence,alternatives=None,chosen_next=None,terminal_justification=None,campaign_terminal_justification=None,lesson_proposal=None):
        rec=BlockedRecord(stage=stage,reason_class=reason_class,evidence=evidence,alternatives_considered=alternatives or [],chosen_next=chosen_next,campaign_terminal_justification=terminal_justification or campaign_terminal_justification,lesson_proposal=lesson_proposal)
        self._records.append(rec); return rec
    def get_records(self): return list(self._records)
    def check_invariant(self): return all(r.is_valid() for r in self._records)
    def check_no_dead_ends(self): return all(r.is_valid() for r in self._records)
    def check_no_blind_repeats(self, max_retries=3):
        from collections import Counter
        return all(c<=max_retries for c in Counter((r.stage,r.reason_class) for r in self._records).values())
