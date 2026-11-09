"""webpent.brain.scorecard — U-17 The Mastery Scorecard.

EV-Calibration (``rank_outcome_correlation``) is the scheduler's honesty
metric: the Spearman rank correlation between the EV-implied priority
order (what the EV scheduler ranked first) and the observed outcome order
(what actually produced confirmed outcomes).  A scorecard whose
calibration column is hard-coded to 0.0 lies about whether the scheduler
is learning; the correlation is therefore COMPUTED from real inputs via
:meth:`ScorecardEmitter._compute_ev_correlation` (restored at C1(a) of
TC-2 — the v14 implementation's semantics, reconstructed from the
verifier's V14-V probe contract).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

LAB_DENOMINATORS={"juice_shop":116,"webgoat":69,"dvwa":76}
@dataclass
class ScorecardEmission:
    lab:str; cycle:int
    coverage:dict[str,Any]=field(default_factory=dict)
    honesty:dict[str,Any]=field(default_factory=dict)
    no_dead_ends:dict[str,Any]=field(default_factory=dict)
    efficiency:dict[str,Any]=field(default_factory=dict)
    ev_calibration:dict[str,Any]=field(default_factory=dict)
    def to_json(self): return json.dumps(asdict(self),indent=2,sort_keys=True)
class ScorecardEmitter:
    @staticmethod
    def _compute_ev_correlation(ev_ranked, ev_outcomes):
        """Spearman rank correlation between EV order and observed outcomes.

        ``ev_ranked``   — the EV scores in scheduler rank order (index 0 =
                          highest-priority hypothesis, as produced by
                          ``EVScheduler.rank``).
        ``ev_outcomes`` — the observed outcome value aligned to the SAME
                          hypothesis positions (e.g. 1.0 confirmed /
                          0.0 refuted-or-inconclusive, or any fractional
                          credit the caller recorded).

        Ties receive the average of their would-be ranks (standard
        Spearman average-rank method).  Returns 0.0 when either side is
        missing, empty, or misaligned — no observations means NO
        calibration claim, never an invented one.
        """
        if not ev_ranked or not ev_outcomes:
            return 0.0
        n = len(ev_ranked)
        if n != len(ev_outcomes) or n < 2:
            return 0.0
        try:
            ev_vals = [float(v) for v in ev_ranked]
            out_vals = [float(v) for v in ev_outcomes]
        except (TypeError, ValueError):
            return 0.0

        def _average_ranks(values):
            order = sorted(range(len(values)), key=lambda i: values[i])
            ranks = [0.0] * len(values)
            i = 0
            while i < len(order):
                j = i
                while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
                    j += 1
                avg = (i + j) / 2.0 + 1.0  # 1-based average rank for the tie block
                for k in range(i, j + 1):
                    ranks[order[k]] = avg
                i = j + 1
            return ranks

        ev_ranks = _average_ranks(ev_vals)
        out_ranks = _average_ranks(out_vals)
        d2 = sum((ev_ranks[i] - out_ranks[i]) ** 2 for i in range(n))
        denom = n * (n * n - 1)
        if denom == 0:
            return 0.0
        rho = 1.0 - (6.0 * d2) / denom
        return round(max(-1.0, min(1.0, rho)), 4)
    def emit(self,*,lab,cycle,full_chain_outcomes,applicable_items=None,false_positives=0,correct_refutations=0,total_refutations=0,explained_terminals=0,total_terminals=0,findings=0,cost_usd=0.0,total_requests=0,ev_ranked=None,ev_outcomes=None):
        denom=applicable_items or LAB_DENOMINATORS.get(lab,0)
        cov=full_chain_outcomes/denom if denom>0 else 0.0
        hon=1.0 if false_positives==0 else 0.0
        ref=correct_refutations/total_refutations if total_refutations>0 else 1.0
        nde=explained_terminals/total_terminals if total_terminals>0 else 1.0
        fpd=findings/cost_usd if cost_usd>0 else 0.0
        rpf=total_requests/findings if findings>0 else 0.0
        corr=self._compute_ev_correlation(ev_ranked,ev_outcomes)
        return ScorecardEmission(lab,cycle,{"full_chain_outcomes":full_chain_outcomes,"applicable":denom,"ratio":round(cov,4)},{"false_positives":false_positives,"ratio":hon,"refutation_rate":round(ref,4)},{"explained":explained_terminals,"total":total_terminals,"ratio":round(nde,4)},{"findings_per_dollar":round(fpd,6),"requests_per_finding":round(rpf,2)},{"rank_outcome_correlation":corr,"ev_input_count":len(ev_ranked) if ev_ranked else 0})
