# src/webpent/memory/lessons.py
"""webpent.memory.lessons

Long-term memory store for the WebPent Framework V2.

While :mod:`webpent.memory.db` persists *per-engagement* findings, this
module persists *cross-engagement* knowledge that survives across runs:

  * **Lessons** — distilled takeaways from reflection phases (e.g.
    "Target's login form is vulnerable to time-based SQLi when
    single-quotes are doubled").
  * **Hypotheses** — working theories that proved fruitful on a prior
    target and may apply to similar targets in the future.

The manager follows the same thread-safe, short-lived-connection
pattern as V1's :class:`DatabaseManager`: writes are serialised by a
:class:`threading.Lock`, file-backed connections are opened per
operation, and in-memory databases reuse a single shared connection so
data persists across calls within a process.

V6 DX-Final — RAG Moderation:
    All lesson and hypothesis content is now passed through
    :func:`_sanitize_lesson_content` before persistence. This strips
    raw payloads, shell metacharacters, SQL/XSS injection strings, and
    other malicious content that an LLM might inadvertently echo back
    from the engagement transcript. Without this moderation, a single
    malicious target could pollute the cross-engagement RAG store with
    payloads that subsequent engagements would retrieve as "lessons",
    creating a cross-engagement pollution / prompt-infection vector.

Timestamp handling:
    All ``created_at`` values use timezone-aware UTC ISO-8601 strings
    (``datetime.now(timezone.utc).isoformat()``). The legacy
    ``datetime.utcnow()`` API is deprecated in Python 3.12+ and is
    avoided here for forward compatibility.
"""

from __future__ import annotations

import hashlib
import html
import re
import sqlite3
import threading
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from webpent.models.hypothesis import Hypothesis

# Default location for the long-term memory database. Hard-coded to
# match the path referenced by the graph orchestration layer; can be
# overridden by passing an explicit ``database_url`` to
# :class:`LessonsManager`.
_DEFAULT_LESSONS_DB_PATH = "./memory/global/lessons.db"


# ---------------------------------------------------------------------------
# V6 DX-Final — RAG Moderation: lesson content sanitiser
# ---------------------------------------------------------------------------
# Patterns that indicate raw payload / exploit material. Any lesson
# content matching one of these is considered unsafe to persist
# verbatim — the matched region is replaced with ``[REDACTED-PAYLOAD]``
# so the structural context of the lesson is preserved (e.g. "the
# endpoint was vulnerable to XSS via [REDACTED-PAYLOAD]") while the
# actual payload cannot be replayed by a future engagement's LLM.

# Shell command injection patterns: ``;``, ``|``, ``&&``, ``$()``,
# backticks, common shell builtins.
_SHELL_METACHAR_RE = re.compile(
    r"(?:;"
    r"|\|\|?"
    r"|&&?"
    r"|\$\([^)]*\)"
    r"|`[^`]*`"
    r"|\b(?:rm|cat|wget|curl|nc|bash|sh|python|perl|ruby)\s+-[a-zA-Z]"
    r")",
    re.IGNORECASE,
)

# SQL injection payloads: ``' OR '1'='1``, ``UNION SELECT``, ``--``,
# ``; DROP``, ``xp_cmdshell``, etc.
_SQL_INJECTION_RE = re.compile(
    r"(?:"
    r"'\s*(?:OR|AND)\s+'?1'?\s*=\s*'?1"  # ' OR '1'='1
    r"|UNION\s+(?:ALL\s+)?SELECT"
    r"|--\s*$"  # SQL comment at end of line
    r"|;\s*DROP\s+TABLE"
    r"|;\s*DELETE\s+FROM"
    r"|;\s*INSERT\s+INTO"
    r"|;\s*UPDATE\s+\w+\s+SET"
    r"|xp_cmdshell"
    r"|\bWAITFOR\s+DELAY\b"
    r"|\bSLEEP\s*\(\s*\d+\s*\)"
    r"|/\*.*?\*/"  # SQL inline comments
    r")",
    re.IGNORECASE,
)

# XSS payloads: ``<script>``, ``onerror=``, ``javascript:``, ``onload=``,
# ``<img src=x``, ``<svg onload``, etc.
_XSS_PAYLOAD_RE = re.compile(
    r"(?:"
    r"<\s*script[^>]*>"
    r"|</\s*script\s*>"
    r"|\bon\w+\s*=\s*['\"]?[^'\"\s>]+"  # onerror=, onload=, onclick=, ...
    r"|javascript\s*:"
    r"|<\s*img[^>]+src\s*=\s*['\"]?[^'\"\s>]+['\"]?[^>]*on\w+"
    r"|<\s*svg[^>]*on\w+"
    r"|<\s*iframe[^>]*>"
    r"|<\s*body[^>]*on\w+"
    r"|data\s*:\s*text/html"
    r")",
    re.IGNORECASE,
)

# Path traversal: ``../../``, ``..\\..\\``, ``/etc/passwd``,
# ``C:\Windows\system32``, etc.
_PATH_TRAVERSAL_RE = re.compile(
    r"(?:"
    r"\.\./"
    r"|\.\.\\"
    r"|/etc/passwd"
    r"|/etc/shadow"
    r"|/proc/self/environ"
    r"|C:\\Windows\\system32"
    r"|C:\\Windows\\win.ini"
    r"|\bfile:///"
    r")",
    re.IGNORECASE,
)

# SSRF / RCE callback URLs: ``http://attacker.com``, ``127.0.0.1:PORT``,
# ``http://169.254.169.254`` (AWS metadata), etc.
#
# V6 Absolute-Flawless P0 FIX (CISO + Red Team audit): The previous
# regex used a permissive character class that allowed a
# ``userinfo@host`` bypass — e.g. ``http://127.0.0.1:8000@evil.com/callback``
# was matched, but the captured host segment was ``127.0.0.1:8000@evil.com``
# which the redirection logic would interpret as ``evil.com`` after the
# ``@``, silently exfiltrating data to the attacker's domain while the
# regex thought it had caught an internal-host reference.
#
# The new pattern, mandated verbatim by the CISO, anchors the trusted
# hostname immediately after the ``://`` via a negative lookahead that
# requires the hostname to be followed by a path/port delimiter
# (``/`` or ``:``) or end-of-string. This closes the userinfo@host
# bypass because the lookahead now rejects ``127.0.0.1:8000@evil.com``
# outright (the segment after ``://`` is not one of the trusted
# hostnames followed by a delimiter). All other URL content (path,
# query, fragment) is captured by the ``[^\s\"'<>]+`` tail. The IPv6
# loopback ``[::1]:PORT`` form is retained as a separate alternative.
_SSRF_CALLBACK_RE = re.compile(
    r"(?:"
    r"https?://(?!(?:localhost|127\.0\.0\.1:8000|api:8000)(?:[/:]|$))[^\s\"'<>]+"
    r"|\[::1\]:\d+"
    r")",
    re.IGNORECASE,
)

# Deserialization / PHP object injection: ``O:N:"ClassName":...``,
# ``rO0ABX`` (Java serialized base64 prefix), ``__construct``.
_DESERIAL_PAYLOAD_RE = re.compile(
    r"(?:"
    r"O:\d+:\"[^\"]+\":\d+:"  # PHP serialized object
    r"|rO0ABX"  # Java serialized base64 prefix
    r"|__wakeup"
    r"|__destruct"
    r"|__toString"
    r")",
    re.IGNORECASE,
)

# SSTI: ``{{7*7}}``, ``${7*7}``, ``#{7*7}``, ``<%= 7*7 %>``.
_SSTI_PAYLOAD_RE = re.compile(
    r"(?:"
    r"\{\{[^}]+\}\}"
    r"|\$\{[^}]+\}"
    r"|\{#[^}]+#\}"
    r"|<%=[^%]+%>"
    r")",
)

# Combine all payload patterns into one tuple for sequential
# application. Order matters: we redact the most specific / dangerous
# patterns first so subsequent passes don't see partial fragments.
_ALL_PAYLOAD_PATTERNS: tuple[re.Pattern[str], ...] = (
    _SQL_INJECTION_RE,
    _XSS_PAYLOAD_RE,
    _SHELL_METACHAR_RE,
    _PATH_TRAVERSAL_RE,
    _SSRF_CALLBACK_RE,
    _DESERIAL_PAYLOAD_RE,
    _SSTI_PAYLOAD_RE,
)

# Hard cap on persisted lesson length. Even after sanitization, a
# multi-KB lesson is almost certainly a verbatim copy of tool output
# rather than a distilled takeaway — truncate to keep the RAG store
# searchable and to bound the impact of any missed payload.
_MAX_LESSON_LENGTH = 1024

# Hard floor — lessons shorter than this are almost certainly noise
# (e.g. "ok", "done") and would pollute semantic search results.
_MIN_LESSON_LENGTH = 8


def structural_sanitize(val: str) -> str:
    """V7 Sprint 1.1: Structural sanitization shared by both ingestion paths.

    Applies three transformations that are safe for BOTH the
    methodology corpus (where payloads should be redacted) and the
    payload corpus (where payloads must survive verbatim):

      1. **HTML-entity decode** (fixed-point, max 5 iterations) —
         defeats ``&lt;script&gt;`` obfuscation.
      2. **NFKC normalization** — collapses fullwidth / compatibility
         characters that could evade the redaction regex.
      3. **Zero-width / Unicode Tag character strip** — removes
         invisible characters that could break up tag names or
         payloads.

    This function does NOT redact payload content — it only normalizes
    the structure. The methodology corpus calls this then applies
    ``_sanitize_lesson_content``'s redaction step on top; the payload
    corpus calls this and stops, so payload strings like
    ``<script>alert(1)</script>`` survive verbatim for retrieval-time
    framing (Sprint 1.3).

    Extracting this into a public helper ensures a single enforcement
    point with no duplicated regex logic to drift out of sync between
    the two ingestion paths.
    """
    if not val or not isinstance(val, str):
        return ""

    # 1. Decode HTML entities (fixed-point, max 5 iterations).
    for _ in range(5):
        unescaped = html.unescape(val)
        if unescaped == val:
            break
        val = unescaped

    # 2. NFKC normalisation — collapses fullwidth / compatibility chars
    # that could evade the regex (e.g. fullwidth single-quote U+FF07).
    val = unicodedata.normalize("NFKC", val)

    # 3. Strip zero-width + Unicode Tag characters.
    val = re.sub(
        r"[\u200b-\u200f\u2028-\u202f\ufeff\U000e0000-\U000e007f]",
        "",
        val,
    )

    return val


def target_signature(target_url: str | None) -> str:
    """Return a stable, non-sensitive signature for a target URL."""
    normalized = str(target_url or "").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _sanitize_lesson_content(content: str) -> str:
    """V6 DX-Final: Sanitise lesson / hypothesis content before persistence.

    Strips raw payloads, shell metacharacters, SQL/XSS injection
    strings, and other malicious content that an LLM might inadvertently
    echo back from the engagement transcript. This is the RAG
    moderation step that prevents cross-engagement pollution — without
    it, a malicious target's response could be persisted as a "lesson"
    and later retrieved by a different engagement's LLM as context,
    effectively propagating the payload across engagements.

    The sanitiser:
      1. Decodes HTML entities (defeats ``&lt;script&gt;`` obfuscation).
      2. NFKC-normalises Unicode (defeats fullwidth / homoglyph tricks).
      3. Strips zero-width and Unicode Tag characters (U+E0000–U+E007F).
      4. Redacts any region matching a payload regex to
         ``[REDACTED-PAYLOAD]``.
      5. Truncates to ``_MAX_LESSON_LENGTH`` chars.
      6. Returns ``""`` if the result is shorter than
         ``_MIN_LESSON_LENGTH`` (the caller should skip persistence
         of empty lessons).
      7. All-redaction check — if the sanitised content consists ONLY
         of ``[REDACTED-PAYLOAD]`` tokens + whitespace + punctuation,
         the original lesson was a pure payload with no useful semantic
         content. Drop it entirely.

    Args:
        content: The raw lesson / hypothesis text from the LLM.

    Returns:
        The sanitised text, or ``""`` if the content was entirely
        payload / too short to be a useful lesson.
    """
    if not content or not isinstance(content, str):
        return ""

    val = content

    # V7 Sprint 1.1: Steps 1-3 (HTML decode + NFKC + zero-width strip)
    # are now delegated to the public ``structural_sanitize`` helper,
    # which is also called by the payload-corpus ingestion path. This
    # ensures a single enforcement point with no duplicated regex
    # logic to drift out of sync. The payload corpus uses
    # ``structural_sanitize`` WITHOUT the content-redaction step (step
    # 4 below) because payloads must survive verbatim — their
    # injection risk is handled at retrieval time (Sprint 1.3), not
    # ingestion time.
    val = structural_sanitize(val)

    # 4. Redact payload regions. Each pattern pass replaces matches
    # with ``[REDACTED-PAYLOAD]``; subsequent passes operate on the
    # already-redacted text, so a payload that uses multiple
    # obfuscation layers (e.g. SQLi wrapped in an SSTI template) is
    # fully neutralised.
    redaction_count = 0
    for pattern in _ALL_PAYLOAD_PATTERNS:
        val, n = pattern.subn("[REDACTED-PAYLOAD]", val)
        redaction_count += n

    # 5. Collapse runs of whitespace introduced by redaction.
    val = re.sub(r"\s{3,}", "  ", val).strip()

    # 6. Truncate to the hard cap.
    if len(val) > _MAX_LESSON_LENGTH:
        val = val[: _MAX_LESSON_LENGTH - 3] + "..."

    # 7. Floor check — if the result is too short, treat as noise.
    if len(val) < _MIN_LESSON_LENGTH:
        return ""

    # 8. All-redaction check — if the sanitised content consists ONLY
    # of ``[REDACTED-PAYLOAD]`` tokens + whitespace + punctuation,
    # the original lesson was a pure payload with no useful semantic
    # content. Drop it entirely so the RAG store doesn't fill up with
    # rows like ``[REDACTED-PAYLOAD]alert(1)[REDACTED-PAYLOAD]``.
    # We strip redaction tokens, whitespace, and common punctuation,
    # then check if anything meaningful remains.
    semantic_content = re.sub(
        r"\[REDACTED-PAYLOAD\]",
        "",
        val,
    )
    semantic_content = re.sub(
        r"[\s\.\,\;\:\!\?\-\(\)\[\]\{\}\"'<>/\\@#\$%\^&\*\+=\|~`]+", "", semantic_content
    )
    if len(semantic_content) < _MIN_LESSON_LENGTH:
        return ""

    if redaction_count > 0:
        # Lightweight logger — we don't have a per-lesson logger here
        # so use the module logger. Importing lazily to avoid circular
        # imports at module load time.
        import logging as _logging

        _logging.getLogger(__name__).info(
            "RAG moderation: redacted %d payload region(s) from lesson content before persistence.",
            redaction_count,
        )

    return val


def _resolve_db_path(database_url: str | None) -> Path:
    """Resolve a database URL or path to a :class:`Path`.

    Accepts either a bare filesystem path (preferred for V2) or a
    SQLAlchemy-style ``sqlite:///`` URL for backward compatibility with
    V1-style configuration.

    Args:
        database_url: Database URL or path. ``None`` falls back to the
            V2 default location.

    Returns:
        A :class:`pathlib.Path` pointing at the SQLite file. The string
        ``":memory:"`` is returned as-is for in-memory mode.
    """
    if database_url is None:
        # V9 FIX B-05: Anchor relative path to project root (same
        # fix as db.py:66-69) so different worker CWDs don't write
        # to different files.
        p = Path(_DEFAULT_LESSONS_DB_PATH)
        if not p.is_absolute():
            # Walk up from this file to find the project root
            # (the directory containing pyproject.toml).
            root = Path(__file__).resolve()
            for parent in root.parents:
                if (parent / "pyproject.toml").exists():
                    return parent / p
        return p

    if database_url == "sqlite://":
        return Path(":memory:")

    prefix = "sqlite:///"
    if database_url.startswith(prefix):
        return Path(database_url[len(prefix) :])

    return Path(database_url)


# SQL DDL for the lessons and hypotheses tables. Both share the same
# schema shape (UUID PK, target URL, free-form content, ISO-8601
# timestamp) so they can be queried with near-identical code.
_LESSONS_DDL = """
CREATE TABLE IF NOT EXISTS lessons (
    id            TEXT PRIMARY KEY,
    target_url    TEXT NOT NULL,
    content       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    client_id     TEXT,
    engagement_id TEXT
);
"""

_HYPOTHESES_DDL = """
CREATE TABLE IF NOT EXISTS hypotheses (
    id          TEXT PRIMARY KEY,
    target_url  TEXT NOT NULL,
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
"""

# V7 Cognitive Upgrade — Phase 1: Structured hypotheses table.
#
# The legacy ``hypotheses`` table (above) stores raw text strings tied
# to a target URL — no provenance, no status, no confidence, no parent
# reference. The new ``hypotheses_structured`` table supersedes it for
# all V7 code paths: each row is a full :class:`Hypothesis` model
# serialised to columns. The legacy table is left in place (not dropped)
# so historical rows persisted before the V7 upgrade remain queryable
# by the existing ``save_hypothesis`` / ``get_hypotheses`` text-mode
# API — backward compatibility, no data loss.
#
# Migration policy (per user choice during Phase 1 planning): use
# ``CREATE TABLE IF NOT EXISTS`` + ``ALTER TABLE ADD COLUMN`` guarded
# by ``PRAGMA table_info`` checks in :meth:`LessonsManager.init_db`,
# mirroring :meth:`DatabaseManager._init_db_legacy`. No Alembic
# migration is added for this change.
_HYPOTHESES_STRUCTURED_DDL = """
CREATE TABLE IF NOT EXISTS hypotheses_structured (
    id                    TEXT PRIMARY KEY,
    target_url            TEXT NOT NULL,
    statement             TEXT NOT NULL,
    vuln_class            TEXT NOT NULL DEFAULT 'unknown',
    status                TEXT NOT NULL DEFAULT 'unexplored',
    confidence_score      REAL NOT NULL DEFAULT 0.3,
    evidence_refs         TEXT NOT NULL DEFAULT '[]',
    origin                TEXT NOT NULL DEFAULT 'heuristic',
    origin_detail         TEXT NOT NULL DEFAULT '',
    estimated_cost        REAL,
    parent_hypothesis_id  TEXT,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);
"""

_HYPOTHESIS_STRUCTURED_INSERT = """
INSERT OR REPLACE INTO hypotheses_structured (
    id, target_url, statement, vuln_class, status, confidence_score,
    evidence_refs, origin, origin_detail, estimated_cost,
    parent_hypothesis_id, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_HYPOTHESIS_STRUCTURED_SELECT = """
SELECT id, target_url, statement, vuln_class, status, confidence_score,
       evidence_refs, origin, origin_detail, estimated_cost,
       parent_hypothesis_id, created_at, updated_at
FROM hypotheses_structured
ORDER BY created_at ASC;
"""

_LESSON_INSERT = """
INSERT INTO lessons (id, target_url, content, created_at, client_id, engagement_id)
VALUES (?, ?, ?, ?, ?, ?);
"""

_HYPOTHESIS_INSERT = """
INSERT INTO hypotheses (id, target_url, content, created_at)
VALUES (?, ?, ?, ?);
"""

_LESSON_SELECT = """
SELECT id, target_url, content, created_at, client_id, engagement_id
FROM lessons
ORDER BY created_at ASC;
"""

_HYPOTHESIS_SELECT = """
SELECT id, target_url, content, created_at
FROM hypotheses
ORDER BY created_at ASC;
"""

_STRUCTURED_LESSONS_DDL = """
CREATE TABLE IF NOT EXISTS lessons_structured (
    lesson_id TEXT PRIMARY KEY,
    lesson_type TEXT NOT NULL,
    route_pattern TEXT NOT NULL,
    parameter_name TEXT,
    family TEXT,
    target_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    boost_factor REAL,
    evidence_count INTEGER NOT NULL DEFAULT 1,
    confidence REAL NOT NULL DEFAULT 0.5,
    source_campaign_ids TEXT NOT NULL DEFAULT '[]',
    source_finding_ids TEXT NOT NULL DEFAULT '[]',
    client_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    UNIQUE(client_id, fingerprint)
);
"""

_STRUCTURED_LESSON_SELECT = """
SELECT lesson_id, lesson_type, route_pattern, parameter_name, family,
       target_type, reason, boost_factor, evidence_count, confidence,
       source_campaign_ids, source_finding_ids, client_id, created_at
FROM lessons_structured
"""


class LessonsManager:
    """Thread-safe SQLite manager for cross-engagement memory.

    The manager stores lessons and hypotheses that should survive
    across engagements, enabling the framework to learn from prior
    runs. Like :class:`webpent.memory.db.DatabaseManager`, it uses a
    per-operation connection for file-backed databases and a single
    shared connection for in-memory databases.

    The default database path is ``./memory/global/lessons.db``. This
    can be overridden by passing an explicit ``database_url`` to the
    constructor or by setting a value in :class:`Settings`.
    """

    def __init__(self, database_url: str | None = None) -> None:
        """Initialise the manager.

        Args:
            database_url: Optional override for the database URL. When
                ``None`` (default), the V2 default path
                (``./memory/global/lessons.db``) is used.
        """
        self._database_url = database_url
        self._write_lock = threading.Lock()
        self._initialised = False
        self._memory_conn: sqlite3.Connection | None = None

    # -- Connection management ----------------------------------------------
    def _db_path(self) -> Path:
        # V2 does not (yet) add a dedicated settings field for the
        # lessons DB path; fall back to the hard-coded default. When a
        # settings field is added later, swap this line for the
        # settings lookup.
        url = self._database_url or _DEFAULT_LESSONS_DB_PATH
        return _resolve_db_path(url)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a short-lived connection (file mode) or yield the shared
        persistent connection (in-memory mode).
        """
        path = self._db_path()

        if str(path) == ":memory:":
            # In-memory mode: reuse a single shared connection so data
            # persists across operations within the manager's lifetime.
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(
                    ":memory:",
                    isolation_level="",
                    check_same_thread=False,
                    timeout=30.0,
                )
                self._memory_conn.row_factory = sqlite3.Row
            try:
                yield self._memory_conn
            finally:
                # Intentionally do NOT close — connection is reused.
                pass
            return

        # File-backed mode: open a fresh connection per operation.
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(path),
            isolation_level="",
            check_same_thread=False,
            timeout=30.0,
        )
        conn.row_factory = sqlite3.Row
        # V9 FIX B-08: Enable WAL + busy_timeout (same as db.py:218-222)
        # to prevent "database is locked" under concurrent multi-worker
        # Celery writes.
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.OperationalError:
            pass
            # Intentionally suppressed — reviewed 2026-09-03
        try:
            yield conn
        finally:
            conn.close()

    # -- Schema -------------------------------------------------------------
    def init_db(self) -> None:
        """Create the ``lessons``, ``hypotheses``, and
        ``hypotheses_structured`` tables if absent.

        Safe to call multiple times. The schema flag prevents redundant
        DDL round-trips within a single manager instance.

        V7 Cognitive Upgrade — Phase 1: also creates the new
        ``hypotheses_structured`` table (full :class:`Hypothesis` shape,
        superseding the legacy bare-text ``hypotheses`` table for all
        V7 code paths). The legacy table is left in place so historical
        rows remain queryable via the existing text-mode API. Migration
        policy: ``CREATE TABLE IF NOT EXISTS`` only — no Alembic
        migration, mirroring :meth:`DatabaseManager._init_db_legacy`.
        """
        if self._initialised:
            return
        with self._write_lock:
            if self._initialised:
                return
            with self._connect() as conn:
                conn.execute(_LESSONS_DDL)
                conn.execute(_HYPOTHESES_DDL)
                # Add scope columns to databases created before the
                # client/engagement isolation contract. Legacy rows remain
                # unscoped and are therefore excluded from scoped retrieval.
                lesson_columns = {
                    str(row[1]) for row in conn.execute("PRAGMA table_info(lessons)")
                }
                for column in ("client_id", "engagement_id"):
                    if column not in lesson_columns:
                        conn.execute(f"ALTER TABLE lessons ADD COLUMN {column} TEXT")
                # V7 Cognitive Upgrade — Phase 1: structured hypotheses.
                conn.execute(_HYPOTHESES_STRUCTURED_DDL)
                # Learning-loop structured lessons are additive. Legacy lesson
                # rows remain queryable and are never implicitly copied into a
                # cross-client structured memory scope.
                conn.execute(_STRUCTURED_LESSONS_DDL)
                conn.commit()
            self._initialised = True

    # -- Lessons ------------------------------------------------------------
    def save_lesson(
        self,
        target_url: str,
        content: str,
        *,
        client_id: str | None = None,
        engagement_id: str | None = None,
    ) -> UUID | None:
        """Persist a single lesson with optional engagement scope.

        V6 DX-Final: ``content`` is passed through
        :func:`_sanitize_lesson_content` before persistence to strip
        raw payloads and malicious strings. If the sanitised content
        is empty (i.e. the entire lesson was a payload or too short
        to be useful), the lesson is skipped and ``None`` is returned
        — persisting an empty row would pollute the RAG store.

        Args:
            target_url: The target the lesson was learned against.
            content: The distilled takeaway text.
            client_id: Optional client/tenant scope.
            engagement_id: Optional engagement scope.

        Returns:
            The UUID assigned to the new lesson row, or ``None`` if
            the lesson was dropped by the moderation step.
        """
        self.init_db()
        # V6 DX-Final: RAG moderation — strip raw payloads / malicious
        # strings BEFORE persistence to prevent cross-engagement
        # pollution. See _sanitize_lesson_content for the full list
        # of redacted patterns.
        sanitized = _sanitize_lesson_content(content)
        if not sanitized:
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "RAG moderation: lesson dropped (content was entirely "
                "payload or too short after sanitization). Original "
                "preview: %r",
                (content[:80] if content else ""),
            )
            return None
        lesson_id = uuid4()
        with self._write_lock, self._connect() as conn:
            conn.execute(
                _LESSON_INSERT,
                (
                    str(lesson_id),
                    target_url,
                    sanitized,
                    datetime.now(timezone.utc).isoformat(),
                    str(client_id).strip() if client_id else None,
                    str(engagement_id).strip() if engagement_id else None,
                ),
            )
            conn.commit()
        return lesson_id

    def save_negative_lesson(
        self,
        *,
        target_url: str,
        vuln_class: str,
        failure_reason: str,
        hypothesis_id: str | None,
        client_id: str | None,
        engagement_id: str | None = None,
    ) -> UUID | None:
        """Persist a bounded, scoped lesson from a deterministic rejection.

        The caller supplies only a closed-set failure reason. The lesson is
        deliberately structured as plain text so existing retrieval paths can
        consume it, while the exact scoped row and content are deduplicated
        atomically. Missing client scope fails closed.
        """
        scoped_client = str(client_id or "").strip()
        if not scoped_client:
            return None
        scoped_engagement = str(engagement_id or "").strip() or None
        content = (
            "negative_lesson "
            f"target_signature {target_signature(target_url)} "
            f"vulnerability_class {str(vuln_class or 'unknown')[:80]} "
            f"failure_reason {str(failure_reason or 'unknown')[:80]} "
            f"hypothesis_id {str(hypothesis_id or 'unknown')[:120]}. "
            "Constraint avoid repeating this hypothesis until new causal evidence appears."
        )
        sanitized = _sanitize_lesson_content(content)
        if not sanitized:
            return None
        self.init_db()
        with self._write_lock, self._connect() as conn:
            existing = conn.execute(
                """
                SELECT id FROM lessons
                WHERE target_url = ? AND content = ? AND client_id = ?
                  AND (? IS NULL OR engagement_id = ?)
                LIMIT 1
                """,
                (
                    str(target_url or ""),
                    sanitized,
                    scoped_client,
                    scoped_engagement,
                    scoped_engagement,
                ),
            ).fetchone()
            if existing is not None:
                return UUID(str(existing[0]))
            lesson_id = uuid4()
            conn.execute(
                _LESSON_INSERT,
                (
                    str(lesson_id),
                    str(target_url or ""),
                    sanitized,
                    datetime.now(timezone.utc).isoformat(),
                    scoped_client,
                    scoped_engagement,
                ),
            )
            conn.commit()
        return lesson_id

    def get_lessons(self) -> list[dict]:
        """Return every persisted lesson, ordered by creation time.

        Returns:
            A list of dicts with keys ``id``, ``target_url``,
            ``content``, and ``created_at``.
        """
        self.init_db()
        with self._connect() as conn:
            cursor = conn.execute(_LESSON_SELECT)
            rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def search_lessons(
        self,
        query: str,
        *,
        client_id: str | None,
        engagement_id: str | None = None,
        limit: int = 5,
    ) -> list[str]:
        """Return lessons for one client, optionally limited to one engagement.

        ``client_id`` is mandatory and always forms the isolation boundary.
        ``engagement_id`` is an optional narrowing filter: when omitted, the
        query may reuse lessons from other engagements belonging to the same
        client, but it can never cross into another client. Missing client
        scope fails closed.
        """
        scoped_client = str(client_id or "").strip()
        scoped_engagement = str(engagement_id or "").strip()
        if not scoped_client:
            return []
        self.init_db()
        bounded_limit = max(1, min(int(limit), 50))
        needle = f"%{str(query or '').strip()}%"
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT content
                FROM lessons
                WHERE client_id = ?
                  AND (? IS NULL OR engagement_id = ?)
                  AND (content LIKE ? OR target_url LIKE ?)
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (
                    scoped_client,
                    scoped_engagement or None,
                    scoped_engagement or None,
                    needle,
                    needle,
                    bounded_limit,
                ),
            ).fetchall()
        return [str(row[0]) for row in rows]

    # -- Structured learning-loop lessons ----------------------------------
    def save_structured_lesson(self, lesson: object) -> str | None:
        """Persist one moderated, client-scoped structured lesson."""
        from webpent.memory.lesson_models import StructuredLesson

        if not isinstance(lesson, StructuredLesson) or not lesson.client_id:
            return None
        if not lesson.source_campaign_ids:
            return None
        self.init_db()
        import json as _json

        sanitized_reason = _sanitize_lesson_content(lesson.reason) or "structured lesson"
        row = lesson.as_dict()
        row["reason"] = sanitized_reason
        fingerprint = lesson.fingerprint()
        with self._write_lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT lesson_id FROM lessons_structured WHERE client_id=? AND fingerprint=?",
                (lesson.client_id, fingerprint),
            ).fetchone()
            if existing is not None:
                return str(existing[0])
            conn.execute(
                """INSERT INTO lessons_structured
                (lesson_id, lesson_type, route_pattern, parameter_name, family,
                 target_type, reason, boost_factor, evidence_count, confidence,
                 source_campaign_ids, source_finding_ids, client_id, created_at, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    row["lesson_id"], str(row["lesson_type"]), row["route_pattern"],
                    row["parameter_name"], row["family"], row["target_type"],
                    row["reason"][:500], row["boost_factor"], row["evidence_count"],
                    row["confidence"], _json.dumps(row["source_campaign_ids"][:50]),
                    _json.dumps(row["source_finding_ids"][:100]), row["client_id"],
                    row["created_at"], fingerprint,
                ),
            )
            conn.commit()
        return str(lesson.lesson_id)

    def get_structured_lessons(
        self, *, client_id: str | None, target_type: str | None = None,
        lesson_type: str | None = None, limit: int = 200,
    ) -> list[dict]:
        """Return only structured lessons belonging to the requested client."""
        scoped_client = str(client_id or "").strip()
        if not scoped_client:
            return []
        self.init_db()
        import json as _json

        clauses = ["client_id = ?"]
        params: list[object] = [scoped_client]
        if target_type:
            clauses.append("target_type = ?")
            params.append(str(target_type).strip()[:80])
        if lesson_type:
            clauses.append("lesson_type = ?")
            params.append(str(lesson_type).strip()[:40])
        bounded_limit = max(1, min(1000, int(limit)))
        sql = _STRUCTURED_LESSON_SELECT + " WHERE " + " AND ".join(clauses) + " ORDER BY created_at DESC LIMIT ?"
        params.append(bounded_limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        result: list[dict] = []
        for row in rows:
            item = dict(row)
            for key in ("source_campaign_ids", "source_finding_ids"):
                try:
                    item[key] = _json.loads(item.get(key) or "[]")
                except (TypeError, ValueError):
                    item[key] = []
            result.append(item)
        return result

    def search_structured_lessons(
        self, query: str = "", *, client_id: str | None,
        target_type: str | None = None, route_pattern: str | None = None,
        family: str | None = None, limit: int = 100,
    ) -> list[dict]:
        """Search structural lessons with client isolation enforced."""
        rows = self.get_structured_lessons(client_id=client_id, target_type=target_type, limit=limit)
        needle = str(query or "").strip().lower()
        route = str(route_pattern or "").strip()
        fam = str(family or "").strip().upper()
        return [
            item for item in rows
            if (not needle or needle in str(item.get("reason", "")).lower() or needle in str(item.get("route_pattern", "")).lower())
            and (not route or item.get("route_pattern") == route or item.get("route_pattern") == "/*")
            and (not fam or str(item.get("family") or "").upper() == fam)
        ][: max(1, min(1000, int(limit)))]

    def structured_lesson_summary(self, *, client_id: str | None) -> dict[str, object]:
        """Return bounded counts for dashboard/evidence projections."""
        rows = self.get_structured_lessons(client_id=client_id, limit=1000)
        by_type: dict[str, int] = {}
        by_family: dict[str, int] = {}
        for row in rows:
            typ = str(row.get("lesson_type") or "unknown")
            by_type[typ] = by_type.get(typ, 0) + 1
            fam = str(row.get("family") or "unknown")
            by_family[fam] = by_family.get(fam, 0) + 1
        return {"total": len(rows), "by_type": by_type, "by_family": by_family}

    # -- Hypotheses ---------------------------------------------------------
    def save_hypothesis(self, target_url: str, content: str) -> UUID | None:
        """Persist a single hypothesis.

        V6 DX-Final: ``content`` is passed through
        :func:`_sanitize_lesson_content` (the same moderation step used
        for lessons) to strip raw payloads and malicious strings. If
        the sanitised content is empty, the hypothesis is skipped and
        ``None`` is returned.

        Args:
            target_url: The target the hypothesis was formed against.
            content: The hypothesis text.

        Returns:
            The UUID assigned to the new hypothesis row, or ``None``
            if the hypothesis was dropped by the moderation step.
        """
        self.init_db()
        # V6 DX-Final: RAG moderation — same rationale as save_lesson.
        sanitized = _sanitize_lesson_content(content)
        if not sanitized:
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "RAG moderation: hypothesis dropped (content was "
                "entirely payload or too short after sanitization). "
                "Original preview: %r",
                (content[:80] if content else ""),
            )
            return None
        hypothesis_id = uuid4()
        with self._write_lock, self._connect() as conn:
            conn.execute(
                _HYPOTHESIS_INSERT,
                (
                    str(hypothesis_id),
                    target_url,
                    sanitized,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()
        return hypothesis_id

    def get_hypotheses(self) -> list[dict]:
        """Return every persisted hypothesis, ordered by creation time.

        Returns:
            A list of dicts with keys ``id``, ``target_url``,
            ``content``, and ``created_at``.
        """
        self.init_db()
        with self._connect() as conn:
            cursor = conn.execute(_HYPOTHESIS_SELECT)
            rows = cursor.fetchall()
        return [dict(row) for row in rows]

    # -- Structured Hypotheses (V7 Cognitive Upgrade — Phase 1) -------------
    def save_structured_hypothesis(self, hypothesis: Hypothesis) -> UUID:
        """Persist a full :class:`Hypothesis` to ``hypotheses_structured``.

        V7 Cognitive Upgrade — Phase 1: supersedes the legacy
        :meth:`save_hypothesis` text-mode API for all V7 code paths.
        Each row is a full Hypothesis model serialised to columns,
        preserving the lifecycle status, numeric confidence score,
        evidence refs, origin, parent-hypothesis reference, and
        timestamps — everything needed to reconstruct the decision
        trail from belief -> investigation -> finding.

        The ``statement`` field is passed through
        :func:`_sanitize_lesson_content` for defence-in-depth: even
        though a hypothesis statement is producer-controlled (the
        heuristic extractor or RAG pipeline), sanitising it on
        persistence closes the same cross-engagement pollution window
        already closed for lessons. If the sanitised statement is
        empty, the row is NOT persisted (returns ``None``) — a
        hypothesis with no statement after sanitisation is noise.

        Uses ``INSERT OR REPLACE`` so updating an existing hypothesis
        (e.g. status transition unexplored -> investigating) is a
        simple re-save, mirroring how :meth:`DatabaseManager.save_finding`
        handles Finding updates.

        Args:
            hypothesis: A populated :class:`Hypothesis` instance.

        Returns:
            The hypothesis's UUID, or ``None`` if the sanitised
            statement was empty and the row was dropped.
        """
        self.init_db()
        # Defensive sanitisation — see docstring rationale. Lazy import
        # to avoid a circular dependency at module load time.
        sanitized_statement = _sanitize_lesson_content(hypothesis.statement)
        if not sanitized_statement:
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "RAG moderation: structured hypothesis dropped "
                "(statement was entirely payload or too short after "
                "sanitization). Original preview: %r",
                (hypothesis.statement[:80] if hypothesis.statement else ""),
            )
            return None

        # Serialise evidence_refs (list[str]) and enums for SQLite.
        import json as _json

        evidence_refs_json = _json.dumps(list(hypothesis.evidence_refs or []))
        origin_value = (
            hypothesis.origin.value
            if hasattr(hypothesis.origin, "value")
            else str(hypothesis.origin)
        )
        vuln_class_value = (
            hypothesis.vuln_class.value
            if hasattr(hypothesis.vuln_class, "value")
            else str(hypothesis.vuln_class)
        )
        status_value = (
            hypothesis.status.value
            if hasattr(hypothesis.status, "value")
            else str(hypothesis.status)
        )

        with self._write_lock, self._connect() as conn:
            conn.execute(
                _HYPOTHESIS_STRUCTURED_INSERT,
                (
                    str(hypothesis.id),
                    hypothesis.target_url,
                    sanitized_statement,
                    vuln_class_value,
                    status_value,
                    float(hypothesis.confidence_score),
                    evidence_refs_json,
                    origin_value,
                    hypothesis.origin_detail or "",
                    (
                        float(hypothesis.estimated_cost)
                        if hypothesis.estimated_cost is not None
                        else None
                    ),
                    (
                        str(hypothesis.parent_hypothesis_id)
                        if hypothesis.parent_hypothesis_id is not None
                        else None
                    ),
                    hypothesis.created_at.isoformat()
                    if hasattr(hypothesis.created_at, "isoformat")
                    else str(hypothesis.created_at),
                    hypothesis.updated_at.isoformat()
                    if hasattr(hypothesis.updated_at, "isoformat")
                    else str(hypothesis.updated_at),
                ),
            )
            conn.commit()
        return hypothesis.id

    def get_structured_hypotheses(
        self,
        *,
        target_url: str | None = None,
        limit: int = 200,
    ) -> list[dict]:
        """Return persisted structured hypotheses, ordered by creation time.

        V7 Cognitive Upgrade — Phase 1: returns the full Hypothesis
        shape from ``hypotheses_structured`` (one dict per row, with
        all structured columns). Mirrors :meth:`get_hypotheses`'s
        return contract for the legacy text-mode table.

        POST-P0 Phase 2 (memory read-back): added optional
        ``target_url`` narrowing and a hard ``limit`` (clamped to
        [1, 200]) so repeat-run read-back retrieves only the target's
        own ledger instead of every row in the workspace database.
        Isolation model is unchanged: the manager itself is
        workspace-scoped (one DB file per target workspace); the
        ``target_url`` filter narrows within that workspace. Callers
        that need cross-target isolation must NOT pass a ``None``
        target when they intend target-scoped reads.

        Args:
            target_url: If given, only rows whose ``target_url`` matches
                exactly (string equality on the normalized str) are
                returned.
            limit: Maximum number of rows to return (clamped 1..200).

        Returns:
            A list of dicts with keys: ``id``, ``target_url``,
            ``statement``, ``vuln_class``, ``status``,
            ``confidence_score``, ``evidence_refs`` (parsed JSON list),
            ``origin``, ``origin_detail``, ``estimated_cost``,
            ``parent_hypothesis_id``, ``created_at``, ``updated_at``.
        """
        self.init_db()
        import json as _json

        try:
            bounded_limit = max(1, min(200, int(limit)))
        except (TypeError, ValueError):
            bounded_limit = 200
        scoped_target = str(target_url).strip() if target_url else None
        # Standalone SQL (not appended to _HYPOTHESIS_STRUCTURED_SELECT,
        # which already carries its own ORDER BY and trailing semicolon).
        sql = """
SELECT id, target_url, statement, vuln_class, status, confidence_score,
       evidence_refs, origin, origin_detail, estimated_cost,
       parent_hypothesis_id, created_at, updated_at
FROM hypotheses_structured
"""
        if scoped_target:
            sql += "WHERE target_url = ? "
            params: list[object] = [scoped_target, bounded_limit]
        else:
            params = [bounded_limit]
        sql += "ORDER BY created_at ASC LIMIT ?"
        with self._connect() as conn:
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
        results: list[dict] = []
        for row in rows:
            d = dict(row)
            # Parse evidence_refs JSON back to a list for caller convenience.
            raw_refs = d.get("evidence_refs") or "[]"
            try:
                d["evidence_refs"] = _json.loads(raw_refs)
            except (ValueError, TypeError):
                d["evidence_refs"] = []
            results.append(d)
        return results


# V9 FIX B-03: Process-wide singleton (same pattern as DatabaseManager).
# Without this, every LessonsManager() call creates a fresh instance with
# its own _write_lock and _initialised flag, defeating cross-caller
# serialisation. Both strategist and reflection construct LessonsManager()
# directly — they should use this singleton instead.
#
# V10 TARGET-ISOLATION FIX: the legacy singleton is retained for callers
# outside an active TargetWorkspace, while target-scoped calls use a manager
# cached by the workspace-local database URL. This prevents structured
# hypotheses and lessons from one target from landing in another target's
# SQLite file, including when the process previously initialised the legacy
# global database.
_LESSONS_SINGLETON: LessonsManager | None = None
_LESSONS_SINGLETONS: dict[str, LessonsManager] = {}
_LESSONS_SINGLETON_LOCK = threading.Lock()


def get_lessons_manager(database_url: str | None = None) -> LessonsManager:
    """Return a manager scoped to an explicit or active target database.

    Outside a target workspace, omitted URLs preserve the historical
    process-wide singleton semantics. During target-scoped execution, an
    omitted URL resolves to ``<workspace>/databases/lessons.sqlite3`` and is
    cached by its normalized SQLite URL, so each target/client/engagement
    namespace gets an independent manager and schema state.
    """
    global _LESSONS_SINGLETON
    resolved_url = database_url

    if resolved_url is None:
        try:
            from webpent.shared.target_workspace_context import (
                get_active_target_workspace,
            )

            workspace = get_active_target_workspace()
        except ImportError:
            workspace = None
        if workspace is not None:
            resolved_url = f"sqlite:///{workspace.databases_dir / 'lessons.sqlite3'}"

    if resolved_url is None:
        if _LESSONS_SINGLETON is None:
            with _LESSONS_SINGLETON_LOCK:
                if _LESSONS_SINGLETON is None:
                    _LESSONS_SINGLETON = LessonsManager()
        return _LESSONS_SINGLETON

    key = str(resolved_url)
    with _LESSONS_SINGLETON_LOCK:
        manager = _LESSONS_SINGLETONS.get(key)
        if manager is None:
            manager = LessonsManager(key)
            _LESSONS_SINGLETONS[key] = manager
        return manager
