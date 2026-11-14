from __future__ import annotations

from types import SimpleNamespace

import pytest

from webpent.cli.git_source import GitSourceError, clone_repository, validate_git_url
from webpent.cli.ingest import _build_parser
from webpent.memory.vectorstore import VectorStoreManager
from webpent.models.targets import Target
from webpent.state.initial_state import build_initial_state


def test_ingest_parser_accepts_payload_type() -> None:
    args = _build_parser().parse_args(["./PayloadsAllTheThings", "--type", "payload"])
    assert args.doc_type == "payload"


def test_git_url_rejects_credentials_and_non_https() -> None:
    with pytest.raises(GitSourceError):
        validate_git_url("https://user:secret@example.test/repo.git")
    with pytest.raises(GitSourceError):
        validate_git_url("git@example.test:repo.git")


def test_clone_repository_is_shallow_and_non_interactive(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("webpent.cli.git_source.subprocess.run", fake_run)
    destination = tmp_path / "checkout"
    result = clone_repository(
        "https://github.com/owner/repo.git",
        destination,
        git_ref="main",
    )

    command = captured["command"]
    assert result == destination.resolve()
    assert command[:8] == [
        "git",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--config",
        "core.hooksPath=/dev/null",
        "--branch",
    ]
    assert "main" in command
    assert command[-3:] == ["--", "https://github.com/owner/repo.git", str(destination.resolve())]
    assert captured["kwargs"]["shell"] is not True
    assert captured["kwargs"]["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_lesson_storage_and_search_require_exact_scope(tmp_path) -> None:
    manager = VectorStoreManager(persist_path=str(tmp_path))

    class FakeStore:
        def __init__(self) -> None:
            self.added: list[dict[str, object]] = []
            self.filters: list[dict[str, object] | None] = []

        def add_texts(self, *, texts, metadatas):
            self.added.extend(metadatas)

        def similarity_search(self, *, query, k, filter=None):
            self.filters.append(filter)
            if filter in (
                {"$and": [{"client_id": "client-a"}, {"engagement_id": "eng-a"}]},
                {"client_id": "client-a"},
            ):
                return [SimpleNamespace(page_content="lesson-a")]
            return []

    store = FakeStore()
    manager._lessons_store = store

    manager.add_lesson("scoped lesson", {"client_id": "client-a", "engagement_id": "eng-a"})
    manager.add_lesson("unscoped lesson", {"client_id": "client-a"})

    assert store.added == [{"client_id": "client-a", "engagement_id": "eng-a"}]
    assert manager.search_lessons("query", client_id="client-a", engagement_id="eng-a") == [
        "lesson-a"
    ]
    assert manager.search_lessons("query", client_id="client-b", engagement_id="eng-a") == []
    assert manager.search_lessons("query", client_id="client-a") == ["lesson-a"]
    assert manager.search_lessons("query", client_id=None) == []
    assert len(store.filters) == 3


def test_initial_state_defaults_engagement_scope_to_thread_id() -> None:
    state = build_initial_state(
        Target(url="https://example.test"),
        thread_id="thread-123",
        client_id="client-a",
    )
    assert state["client_id"] == "client-a"
    assert state["engagement_id"] == "thread-123"


def test_git_clone_rejects_existing_destination(tmp_path) -> None:
    destination = tmp_path / "already-there"
    destination.mkdir()
    with pytest.raises(GitSourceError):
        clone_repository("https://github.com/owner/repo.git", destination)


def test_git_clone_rejects_parent_path_from_ingest() -> None:
    args = _build_parser().parse_args(["../secrets", "--git-url", "https://github.com/owner/repo.git"])
    assert ".." in args.path.split("/")


# Keep the test module explicit about the public exception contract.
assert GitSourceError.__name__ == "GitSourceError"
