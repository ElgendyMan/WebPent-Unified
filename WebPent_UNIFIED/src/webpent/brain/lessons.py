"""webpent.brain.lessons — U-15 S-5 The Lessons Ledger."""
from __future__ import annotations
import time
from dataclasses import dataclass, field, asdict
from typing import Any
@dataclass
class Lesson:
    lesson_id:str; scope:str; statement:str
    evidence_refs:list[str]=field(default_factory=list); confidence:float=0.5
    proposed_by:str="system"; approved_by:str|None=None
    applied_runs:int=0; outcome_feedback:list[str]=field(default_factory=list)
    last_applied_run:int=0; created_at:float=field(default_factory=time.time)
    def is_approved(self): return self.approved_by is not None
    def to_dict(self): return asdict(self)
class LessonsLedger:
    DECAY_RATE=0.1; MINIMUM_INFLUENCE=0.0
    def __init__(self, store_path=None):
        self._lessons={}; self._current_run=0
    def record_lesson(self, lesson):
        if lesson.scope=="run": lesson.approved_by="auto"
        self._lessons[lesson.lesson_id]=lesson; return lesson
    def approve_lesson(self, lesson_id, approver):
        l=self._lessons.get(lesson_id)
        if not l: return False
        if l.scope=="beyond-lab" and approver!="owner": return False
        l.approved_by=approver; return True
    def retrieve_lessons(self,*,tech_stack="",family="",run_number=0):
        self._current_run=run_number; results=[]
        for l in self._lessons.values():
            if not l.is_approved(): continue
            if family and family.lower() not in l.statement.lower(): continue
            results.append(l)
        return results
    def get_influence(self, lesson, current_run):
        if not lesson.is_approved(): return 0.0
        runs_since=current_run-lesson.last_applied_run
        if runs_since<=0: return lesson.confidence
        return max(self.MINIMUM_INFLUENCE, lesson.confidence*((1-self.DECAY_RATE)**runs_since))
    def apply_lesson(self, lesson_id, run_number):
        l=self._lessons.get(lesson_id)
        if not l or not l.is_approved(): return False
        l.applied_runs+=1; l.last_applied_run=run_number; return True
    def get_all_lessons(self): return list(self._lessons.values())
    def is_advisory_only(self): return True
