"""ق4 — experience corpus contract tests.

Redaction, dedupe, bounds, engagement scoping, deterministic retrieval.
"""
from __future__ import annotations

import json

import pytest

from webpent.memory.experience_corpus import (
    ExperienceCorpus,
    ExperienceDocument,
    harvest_campaign_artifacts,
    redact_text,
)


# -- redaction ---------------------------------------------------------

def test_urls_collapse_to_origins():
    text = "crawled https://target.example.com/a/b/c?token=1 and stopped"
    out = redact_text(text)
    assert "target.example.com" in out
    assert "/a/b/c" not in out
    assert "[ORIGIN_PATH]" in out


def test_credentials_and_tokens_are_typed_placeholders():
    text = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxw"
        " api_key=supersecret123 password=hunter2 secret=abcdef0123456789"
    )
    out = redact_text(text)
    # the jwt is caught either as a JWT or as a bearer token — the
    # contract is that the raw material never survives
    assert "SflKxw" not in out and "eyJhbGciOiJIUzI1NiJ9" not in out
    assert "supersecret123" not in out
    assert "hunter2" not in out
    assert "abcdef0123456789" not in out


def test_long_hex_blobs_are_redacted():
    out = redact_text("digest be021a9c6f3b41d2a1d0a0c9f7b2e5d3aa11bb22")
    assert "be021a9c" not in out and "[REDACTED_HEX]" in out


# -- harvest ------------------------------------------------------------

def _write_campaign(root, summary=None, notes=None, trace=None):
    root.mkdir(parents=True, exist_ok=True)
    root.joinpath("campaign_summary.json").write_text(
        json.dumps(summary or {"campaign_id": "c1"}), encoding="utf-8")
    root.joinpath("hunt_notes.md").write_text(notes or "# notes",
                                              encoding="utf-8")
    root.joinpath("graph_trace.json").write_text(
        json.dumps(trace or {"nodes": []}), encoding="utf-8")


def test_harvest_reads_all_three_artifacts(tmp_path):
    root = tmp_path / "camp-1"
    _write_campaign(
        root,
        notes="# Hunt Notes\n\n- auth flow needs two ids",
    )
    docs = harvest_campaign_artifacts(
        root, client_id="client-a", engagement_id="eng-1",
        created_at=100.0)
    kinds = {doc.kind for doc in docs}
    assert kinds == {"hunt_notes", "campaign_summary", "graph_trace"}
    assert all(doc.engagement_id == "eng-1" for doc in docs)
    assert all(len(doc.digest) == 64 for doc in docs)


def test_harvest_skips_missing_and_bounded(tmp_path):
    root = tmp_path / "camp-2"
    root.mkdir(parents=True, exist_ok=True)
    root.joinpath("hunt_notes.md").write_text("x" * 50_000,
                                              encoding="utf-8")
    docs = harvest_campaign_artifacts(
        root, client_id="c", engagement_id="e", doc_cap_bytes=1_000)
    assert len(docs) == 1
    assert len(docs[0].text) <= 1_000


# -- corpus --------------------------------------------------------------

def _doc(doc_id="d1", digest=None, client="client-a", engagement="eng-1",
         text="the checkout flow needs two ids", created=100.0):
    return ExperienceDocument(
        doc_id=doc_id,
        client_id=client,
        engagement_id=engagement,
        source="hunt_notes.md",
        kind="hunt_notes",
        digest=digest or f"{doc_id:0<64}",
        text=text,
        created_at=created,
    )


def test_duplicates_by_digest_are_stored_once(tmp_path):
    corpus = ExperienceCorpus(tmp_path / "corpus.jsonl")
    assert corpus.add(_doc()) is True
    assert corpus.add(_doc()) is False
    assert len(corpus) == 1


def test_corpus_cap_evicts_oldest(tmp_path):
    corpus = ExperienceCorpus(tmp_path / "corpus.jsonl", max_documents=3)
    for i in range(5):
        corpus.add(_doc(doc_id=f"d{i}"))
    assert len(corpus) == 3
    ids = {doc.doc_id for doc, _ in corpus.search(
        "checkout", client_id="client-a", engagement_id="eng-1")}
    assert "d0" not in ids and "d1" not in ids


def test_search_is_scoped_and_deterministic(tmp_path):
    corpus = ExperienceCorpus(tmp_path / "corpus.jsonl")
    corpus.add(_doc(doc_id="d1", text="checkout flow needs two ids"))
    corpus.add(_doc(doc_id="d2", engagement="eng-2",
                    text="checkout needs two ids"))
    corpus.add(_doc(doc_id="d3", client="client-b",
                    text="checkout needs two ids"))
    hits = corpus.search("checkout ids", client_id="client-a",
                         engagement_id="eng-1")
    assert [doc.doc_id for doc, _ in hits] == ["d1"]
    again = corpus.search("checkout ids", client_id="client-a",
                          engagement_id="eng-1")
    assert hits == again  # deterministic


def test_corpus_round_trips_through_disk(tmp_path):
    path = tmp_path / "corpus.jsonl"
    corpus = ExperienceCorpus(path)
    corpus.add(_doc(doc_id="d1"))
    reopened = ExperienceCorpus(path)
    assert len(reopened) == 1
    assert reopened.search("checkout ids", client_id="client-a",
                           engagement_id="eng-1")[0][0].doc_id == "d1"


def test_tampered_corpus_lines_are_skipped_not_fatal(tmp_path):
    path = tmp_path / "corpus.jsonl"
    path.write_text(
        json.dumps(_doc().to_dict()) + "\n" + "{bad json\n",
        encoding="utf-8",
    )
    corpus = ExperienceCorpus(path)
    assert len(corpus) == 1
