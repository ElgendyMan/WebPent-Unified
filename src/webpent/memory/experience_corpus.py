"""webpent.memory.experience_corpus — campaign self-knowledge (ق4).

Every campaign already produces structural evidence artifacts (hunt
notes, graph traces, campaign summaries) — and then forgets them: the
RAG corpus (``docs/knowledge_pack``) holds only the static payload/WSTG
libraries, so campaign #100 starts knowing nothing about campaigns 1-99.

This module turns those artifacts into a bounded, redacted,
deduplicated EXPERIENCE CORPUS the retrieval layer can index:

  - sources: ``hunt_notes.md``, ``campaign_summary.json``,
    ``graph_trace.json`` under a campaign-artifact root;
  - REDACTION: URLs collapse to their origin, credential-shaped
    strings (tokens, passwords, api keys, bearer/jwt forms) are
    replaced with typed placeholders, and nothing longer than the
    per-document cap survives — the corpus carries structure, never
    secrets;
  - DEDUPE by content digest (the same lesson from two artifacts is
    stored once);
  - BOUNDS: per-document byte cap and a corpus document cap (oldest
    wins eviction by insertion order) so the corpus cannot grow
    unbounded;
  - SCOPING: every document carries ``client_id`` +
    ``engagement_id`` and retrieval is scoped the same way as the
    lessons ledger — no cross-engagement leakage;
  - RETRIEVAL: deterministic lexical scoring (no embeddings needed at
    this layer; the vector store can index the same JSONL upstream).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "ExperienceCorpus",
    "ExperienceDocument",
    "harvest_campaign_artifacts",
    "redact_text",
]

#: sources harvested from one campaign artifact directory
SOURCE_FILES = {
    "hunt_notes.md": "hunt_notes",
    "campaign_summary.json": "campaign_summary",
    "graph_trace.json": "graph_trace",
}

DEFAULT_DOC_CAP_BYTES = 8_192
DEFAULT_CORPUS_DOC_CAP = 500

_URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
_URL_ORIGIN_RE = re.compile(r"^(https?://[^/]+)")
_BEARER_RE = re.compile(
    r"(?i)\b(bearer|authorization)\s*[:=]?\s*([a-z0-9._~+/-]{12,})"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_TOKENISH_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|password|passwd|secret|credential)s?\b"
    r"\s*[:=]\s*([^\s,;\"']{6,})"
)
_HEX32_RE = re.compile(r"\b[0-9a-f]{32,}\b")


def redact_text(text: str) -> str:
    """Typed redaction of secret-shaped strings, structure kept."""
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)}=[REDACTED_TOKEN]", text)
    text = _TOKENISH_RE.sub(lambda m: f"{m.group(1)}=[REDACTED_VALUE]", text)
    def _collapse(match: "re.Match[str]") -> str:
        origin = _URL_ORIGIN_RE.match(match.group(0))
        return (
            origin.group(1) + "/[ORIGIN_PATH]"
            if origin else "[REDACTED_URL]"
        )

    text = _URL_RE.sub(_collapse, text)
    text = _HEX32_RE.sub("[REDACTED_HEX]", text)
    return text


@dataclass(frozen=True)
class ExperienceDocument:
    """One redacted, digest-identified experience record."""

    doc_id: str
    client_id: str
    engagement_id: str
    source: str
    kind: str
    digest: str
    text: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "client_id": self.client_id,
            "engagement_id": self.engagement_id,
            "source": self.source,
            "kind": self.kind,
            "digest": self.digest,
            "text": self.text,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExperienceDocument":
        return cls(
            doc_id=data["doc_id"],
            client_id=data["client_id"],
            engagement_id=data["engagement_id"],
            source=data["source"],
            kind=data["kind"],
            digest=data["digest"],
            text=data["text"],
            created_at=float(data["created_at"]),
        )


def harvest_campaign_artifacts(
    root: str | Path,
    *,
    client_id: str,
    engagement_id: str,
    created_at: float = 0.0,
    doc_cap_bytes: int = DEFAULT_DOC_CAP_BYTES,
) -> list[ExperienceDocument]:
    """Harvest the known artifact files from ONE campaign directory.

    Missing artifacts are skipped silently; unreadable ones too — the
    harvest is a best-effort enrichment, never a gate.
    """
    base = Path(root)
    documents: list[ExperienceDocument] = []
    for filename, kind in SOURCE_FILES.items():
        path = base / filename
        if not path.is_file():
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = redact_text(raw)[:doc_cap_bytes]
        if not text.strip():
            continue
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        documents.append(
            ExperienceDocument(
                doc_id=f"{kind}-{digest[:16]}",
                client_id=client_id,
                engagement_id=engagement_id,
                source=str(path),
                kind=kind,
                digest=digest,
                text=text,
                created_at=created_at,
            )
        )
    return documents


class ExperienceCorpus:
    """Bounded JSONL store of experience documents, engagement-scoped."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_documents: int = DEFAULT_CORPUS_DOC_CAP,
    ) -> None:
        self.path = Path(path)
        self.max_documents = max_documents
        self._docs: list[ExperienceDocument] = []
        self._by_digest: dict[str, ExperienceDocument] = {}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    doc = ExperienceDocument.from_dict(json.loads(line))
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue
                self._docs.append(doc)
                self._by_digest.setdefault(doc.digest, doc)

    def add(self, document: ExperienceDocument) -> bool:
        """Add one document; duplicates (by digest) are dropped.

        Returns True when stored. The corpus cap evicts by insertion
        order — the oldest experience makes room, never the newest.
        """
        if document.digest in self._by_digest:
            return False
        self._docs.append(document)
        self._by_digest[document.digest] = document
        while len(self._docs) > self.max_documents:
            evicted = self._docs.pop(0)
            if evicted.digest in self._by_digest and all(
                d.digest != evicted.digest
                for d in self._docs
            ):
                self._by_digest.pop(evicted.digest, None)
        self._flush()
        return True

    def add_documents(self, documents: list[ExperienceDocument]) -> int:
        return sum(1 for doc in documents if self.add(doc))

    def search(
        self,
        query: str,
        *,
        client_id: str,
        engagement_id: str,
        limit: int = 5,
    ) -> list[tuple[ExperienceDocument, float]]:
        """Deterministic lexical search, scoped to ONE engagement.

        Score = overlap of the query's terms with the document text,
        normalized by query length. No embeddings here — the vector
        store may index the same JSONL upstream; this retrieval keeps
        the module self-contained and its behavior reproducible.
        """
        terms = [
            term.lower()
            for term in re.findall(r"[a-z0-9_/.-]{3,}", query.lower())
        ]
        if not terms:
            return []
        scored: list[tuple[ExperienceDocument, float]] = []
        for doc in self._docs:
            if doc.client_id != client_id or (
                    doc.engagement_id != engagement_id):
                continue
            haystack = doc.text.lower()
            hits = sum(1 for term in terms if term in haystack)
            if hits:
                scored.append((doc, hits / len(terms)))
        scored.sort(key=lambda pair: (-pair[1], pair[0].doc_id))
        return scored[:limit]

    def __len__(self) -> int:
        return len(self._docs)

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".jsonl.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for doc in self._docs:
                fh.write(
                    json.dumps(doc.to_dict(), sort_keys=True) + "\n"
                )
        tmp.replace(self.path)
