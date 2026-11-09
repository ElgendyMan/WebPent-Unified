"""Evidence Ledger contracts for reviewable, non-secret proof bundles."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive, sha256_text

LedgerStatus = Literal[
    "candidate",
    "inconclusive",
    "needs_human_review",
    "tool_confirmed",
]
CleanupStatus = Literal["pending", "complete", "failed", "not_applicable"]


class EvidenceLedgerEntry(BaseModel):
    """One bounded causal evidence bundle; raw payloads remain out of state."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    entry_id: str = Field(min_length=3, max_length=160)
    campaign_key: str = Field(min_length=1, max_length=120)
    vuln_class: str = Field(min_length=1, max_length=120)
    target: str = Field(min_length=1, max_length=1000)
    identity: str | None = Field(default=None, max_length=160)
    request_metadata: dict[str, Any] = Field(default_factory=dict)
    response_metadata: dict[str, Any] = Field(default_factory=dict)
    baseline: dict[str, Any] = Field(default_factory=dict)
    negative_control: dict[str, Any] = Field(default_factory=dict)
    oracle: dict[str, Any] = Field(default_factory=dict)
    oob_events: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    browser_events: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    evidence_hashes: dict[str, str] = Field(default_factory=dict, max_length=30)
    evidence_refs: list[str] = Field(default_factory=list, max_length=30)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    cleanup_status: CleanupStatus = "pending"
    status: LedgerStatus = "candidate"
    reason: str | None = Field(default=None, max_length=500)

    @field_validator(
        "target",
        "identity",
        "request_metadata",
        "response_metadata",
        "baseline",
        "negative_control",
        "oracle",
        "oob_events",
        "browser_events",
        "evidence_hashes",
        "evidence_refs",
        "reason",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean

    def content_digest(self) -> str:
        """Return a deterministic digest of the redacted causal bundle."""
        digest = sha256_text(
            {
                "campaign_key": self.campaign_key,
                "vuln_class": self.vuln_class,
                "target": self.target,
                "identity": self.identity,
                "request_metadata": self.request_metadata,
                "response_metadata": self.response_metadata,
                "baseline": self.baseline,
                "negative_control": self.negative_control,
                "oracle": self.oracle,
                "oob_events": self.oob_events,
                "browser_events": self.browser_events,
                "evidence_hashes": self.evidence_hashes,
                "evidence_refs": self.evidence_refs,
                "cleanup_status": self.cleanup_status,
                "status": self.status,
            }
        )
        return f"sha256:{digest}"


__all__ = ["CleanupStatus", "EvidenceLedgerEntry", "LedgerStatus"]
