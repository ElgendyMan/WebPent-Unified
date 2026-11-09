"""Campaign errors — typed, fail-closed, never silent.

Every refusal names the law that produced it (CAMPAIGN-L) so the trace
records WHY the machine stopped, not just THAT it stopped.
"""
from __future__ import annotations


class CampaignError(Exception):
    """Base class for every campaign-layer refusal."""


class InsufficientDataError(CampaignError):
    """L-1: no thesis can be built from the available evidence.

    The builder refuses to guess. A campaign built on thin evidence
    burns the budget confirming noise.
    """


class ThesisValidationError(CampaignError):
    """L-1: the thesis exists but does not meet the proceeding floor.

    Carries the list of failed checks on ``.errors`` — each names the
    failed requirement and its threshold.
    """

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("thesis validation failed: " + "; ".join(self.errors))


class CampaignNotApprovedError(CampaignError):
    """L-2: the operator has not approved this campaign.

    No request may leave the workshop until a human decision is
    recorded on the brief. The machine never self-approves.
    """


class InvalidModificationError(CampaignError):
    """L-2: the operator's modification references something unknown.

    A modification naming a phase that does not exist is a typo, not a
    decision — refuse rather than silently guess.
    """
