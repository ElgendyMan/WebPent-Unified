from __future__ import annotations

from webpent.memory.lessons import LessonsManager


def test_search_lessons_isolates_client_and_engagement(tmp_path) -> None:
    manager = LessonsManager(database_url=str(tmp_path / "lessons.db"))
    manager.save_lesson(
        "https://target-a.test",
        "lesson for client one engagement alpha",
        client_id="client-1",
        engagement_id="eng-alpha",
    )
    manager.save_lesson(
        "https://target-b.test",
        "lesson for client two engagement beta",
        client_id="client-2",
        engagement_id="eng-beta",
    )
    manager.save_lesson(
        "https://target-c.test",
        "lesson for client one engagement gamma",
        client_id="client-1",
        engagement_id="eng-gamma",
    )

    assert manager.search_lessons(
        "lesson",
        client_id="client-1",
        engagement_id="eng-alpha",
    ) == ["lesson for client one engagement alpha"]
    assert manager.search_lessons("lesson", client_id="client-1") == [
        "lesson for client one engagement gamma",
        "lesson for client one engagement alpha",
    ]
    assert manager.search_lessons(
        "lesson",
        client_id="client-1",
        engagement_id="eng-beta",
    ) == []


def test_search_lessons_fails_closed_without_complete_scope(tmp_path) -> None:
    manager = LessonsManager(database_url=str(tmp_path / "lessons.db"))
    manager.save_lesson(
        "https://target.test",
        "scoped lesson",
        client_id="client-1",
        engagement_id="eng-1",
    )

    assert manager.search_lessons("scoped", client_id=None, engagement_id="eng-1") == []
    assert manager.search_lessons("scoped", client_id="client-1", engagement_id=None) == [
        "scoped lesson"
    ]
    assert manager.search_lessons("scoped", client_id=None, engagement_id=None) == []


def test_legacy_save_remains_compatible_but_is_not_scoped(tmp_path) -> None:
    manager = LessonsManager(database_url=str(tmp_path / "lessons.db"))
    lesson_id = manager.save_lesson("https://target.test", "legacy lesson")

    assert lesson_id is not None
    lessons = manager.get_lessons()
    assert lessons[-1]["content"] == "legacy lesson"
    assert lessons[-1]["client_id"] is None
    assert manager.search_lessons(
        "legacy",
        client_id="client-1",
        engagement_id="eng-1",
    ) == []
