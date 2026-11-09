# src/webpent/memory/vectorstore.py
"""webpent.memory.vectorstore

Chroma vector store manager for the WebPent Framework V3 RAG system.

Manages two Chroma collections:
  * ``webpent_lessons`` — lessons learned from reflection agent.
  * ``webpent_knowledge`` — external knowledge base (PDFs, Markdown)
    ingested via the ``webpent-ingest`` CLI.

V3 Phase 4 adds the knowledge collection for RAG-enriched prompts.

V6 Absolute-Flawless P0 FIX (CISO audit — Thread Safety):
    ``VectorStoreManager._get_store`` had a check-then-act race: two
    concurrent Celery worker threads could both observe
    ``self._lessons_store is None`` and both proceed to call
    ``_init_store(collection_name)``, racing on Chroma collection
    creation. Depending on timing, this either:
      * raised a DuplicateCollectionError from Chroma (crashing one
        thread's RAG retrieval), or
      * silently created two in-memory Chroma handles pointing at
        the same on-disk SQLite files, producing write corruption
        when both handles tried to add texts concurrently.

    A per-instance lock is now held for the duration of the
    check-then-init-then-cache sequence. The lock is per-instance
    (not class-level) because each ``VectorStoreManager`` instance
    owns its own ``_lessons_store`` / ``_knowledge_store`` handles —
    cross-instance locking would unnecessarily serialise independent
    managers. The file-level ``fcntl`` lock in ``_acquire_lock`` is
    preserved for cross-process safety (multiple Celery workers in
    separate OS processes); the threading lock adds intra-process
    safety on top.

V6 Titanium P0 FIX (CISO audit — Self-Deadlock):
    The previous fix used a plain ``threading.Lock()``. However,
    ``_get_store()`` acquires the lock, then calls ``_init_store()``,
    which calls ``_get_embeddings()``, which ALSO tries to acquire
    the same lock. ``threading.Lock`` is NOT reentrant — a thread
    holding it cannot acquire it again — so this caused a permanent
    deadlock the first time any RAG retrieval was attempted,
    freezing the entire Celery worker.

    The fix is to switch to ``threading.RLock()`` (reentrant lock).
    An RLock can be acquired multiple times by the SAME thread; each
    ``acquire`` must be matched by a ``release``, but the lock is
    only released to other threads once the holding thread's
    acquire-count drops to zero. This lets ``_get_store`` →
    ``_init_store`` → ``_get_embeddings`` all run under the same
    lock without deadlocking, while still serialising concurrent
    threads (thread B cannot enter ``_get_store`` until thread A's
    nested acquire/release sequence completes).

V6 Titanium P2 FIX (CISO audit — Singleton Anti-Pattern):
    ``VectorStoreManager`` was instantiated ad-hoc in every agent
    and CLI that needed RAG access (reflection, planner,
    hypothesis_analyzer, ingest). Each instantiation discarded the
    cached embeddings model (~5 seconds to load sentence-transformers)
    and the cached Chroma collection handles, degrading performance
    on every RAG retrieval. See :func:`get_vector_store_manager`
    for the process-wide singleton accessor; all callers have been
    migrated to use it.
"""

from __future__ import annotations

import contextlib
import logging
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _rag_available_for_current_context() -> bool:
    """Return whether this execution may touch the vector store."""
    try:
        from webpent.memory.embeddings import is_rag_enabled

        return is_rag_enabled()
    except Exception:
        # Preserve the existing fail-open behavior only when the guard itself
        # cannot be imported; persistent DISABLE_RAG is still enforced by the
        # embeddings factory on any attempted store initialization.
        return True


_DEFAULT_CHROMA_PATH = "./memory/global/chroma_db"
_DEFAULT_LESSONS_COLLECTION = "webpent_lessons"
_KNOWLEDGE_COLLECTION_NAME = "webpent_knowledge"

# V6 Ready-For-Kali P1 FIX (CISO audit — permanent RAG disablement):
# ``_get_embeddings`` used to cache a load failure in
# ``self._embeddings_error`` forever, with no retry. Since
# ``get_vector_store_manager()`` returns a process-wide singleton that
# lives for the entire Celery worker's uptime, a single TRANSIENT
# failure (a network blip during the first-run ~80MB model download, a
# momentary disk-full condition, a race with another process writing
# to the HuggingFace cache dir) permanently disabled RAG retrieval —
# lessons-learned and knowledge-base context — for that worker's
# entire remaining lifetime, recoverable only by restarting the
# process. This cooldown lets the manager retry after a bounded wait
# instead of giving up forever on one bad attempt.
_EMBEDDINGS_RETRY_COOLDOWN_SECONDS = 300.0


class VectorStoreManager:
    """Manager for the Chroma-backed vector stores."""

    def __init__(self, persist_path: str = _DEFAULT_CHROMA_PATH) -> None:
        self._persist_path = persist_path
        self._embeddings: Any | None = None
        self._embeddings_error: Exception | None = None
        self._embeddings_error_at: float | None = None
        self._lessons_store: Any | None = None
        self._knowledge_store: Any | None = None
        self._lessons_init_error: Exception | None = None
        self._knowledge_init_error: Exception | None = None
        # V6 Titanium P0: use RLock (reentrant) instead of Lock.
        # _get_store acquires the lock, then calls _init_store, which
        # calls _get_embeddings, which also acquires the lock. A plain
        # Lock would deadlock here because the same thread cannot
        # re-acquire a non-reentrant Lock it already holds. RLock
        # allows the same thread to acquire it multiple times; the
        # lock is only released to OTHER threads once the holding
        # thread's acquire-count drops to zero.
        self._init_lock = threading.RLock()

    def _get_embeddings(self) -> Any | None:
        # V6 Absolute-Flawless: embeddings init is also a check-then-act
        # race — guard it with the same lock. We hold the lock for the
        # whole init so a concurrent thread doesn't see a half-set
        # _embeddings attribute.
        with self._init_lock:
            if self._embeddings is not None:
                return self._embeddings
            if self._embeddings_error is not None:
                # V6 Ready-For-Kali P1 FIX: don't cache a load failure
                # forever. Retry after a bounded cooldown instead of
                # permanently disabling RAG for this (process-wide
                # singleton) instance's entire remaining lifetime.
                elapsed = time.monotonic() - (self._embeddings_error_at or 0.0)
                if elapsed < _EMBEDDINGS_RETRY_COOLDOWN_SECONDS:
                    return None
                logger.info(
                    "Embeddings load failed %.0fs ago (cooldown %.0fs "
                    "elapsed) — retrying instead of staying permanently "
                    "disabled.",
                    elapsed, _EMBEDDINGS_RETRY_COOLDOWN_SECONDS,
                )
                self._embeddings_error = None
                self._embeddings_error_at = None
            try:
                from webpent.memory.embeddings import get_embeddings
                self._embeddings = get_embeddings()
                return self._embeddings
            except Exception as exc:
                self._embeddings_error = exc
                self._embeddings_error_at = time.monotonic()
                logger.error(
                    "Failed to load embeddings model: %s. RAG will "
                    "return empty for the next %.0fs, then retry.",
                    exc, _EMBEDDINGS_RETRY_COOLDOWN_SECONDS,
                )
                return None

    def _get_store(self, collection_name: str) -> Any | None:
        # A cached Chroma handle must not bypass a scan-scoped `--no-llm`
        # decision.  Check before acquiring the lock or returning a cache hit.
        if not _rag_available_for_current_context():
            logger.info("RAG disabled for current context; skipping vector store access")
            return None

        # V6 Absolute-Flawless: hold the init lock for the entire
        # check-then-init-then-cache sequence so concurrent threads
        # cannot both observe ``is None`` and both call _init_store.
        # Once the store is cached, subsequent calls hit the fast
        # path (return self._lessons_store) under the lock with no
        # I/O — the lock is uncontended in the steady state.
        with self._init_lock:
            if collection_name == _DEFAULT_LESSONS_COLLECTION:
                if self._lessons_init_error is not None:
                    return None
                if self._lessons_store is not None:
                    return self._lessons_store
                store, err = self._init_store(collection_name)
                if err is not None:
                    self._lessons_init_error = err
                    return None
                self._lessons_store = store
                return store
            elif collection_name == _KNOWLEDGE_COLLECTION_NAME:
                if self._knowledge_init_error is not None:
                    return None
                if self._knowledge_store is not None:
                    return self._knowledge_store
                store, err = self._init_store(collection_name)
                if err is not None:
                    self._knowledge_init_error = err
                    return None
                self._knowledge_store = store
                return store
            else:
                logger.warning("Unknown collection: %s", collection_name)
                return None

    def _init_store(self, collection_name: str) -> tuple[Any | None, Exception | None]:
        try:
            from langchain_chroma import Chroma
            Path(self._persist_path).mkdir(parents=True, exist_ok=True)
            embeddings = self._get_embeddings()
            if embeddings is None:
                return None, RuntimeError("Embeddings unavailable")
            store = Chroma(
                collection_name=collection_name,
                embedding_function=embeddings,
                persist_directory=self._persist_path,
            )
            logger.info(
                "Chroma collection %r initialised at %s",
                collection_name, self._persist_path,
            )
            return store, None
        except Exception as exc:
            logger.error("Failed to initialise Chroma collection %r: %s", collection_name, exc)
            return None, exc

    def _acquire_lock(self) -> Any | None:
        lock_path = Path(self._persist_path) / ".write.lock"
        with contextlib.suppress(Exception):
            lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            lock_file = open(lock_path, "w")  # noqa: SIM115 — lock file must stay open
        except Exception as exc:
            logger.debug("Could not open lock file: %s", exc)
            return None
        try:
            import fcntl
            fcntl.flock(lock_file, fcntl.LOCK_EX)
        except ImportError:
            logger.debug("fcntl not available (Windows?) — no file lock")
        except Exception as exc:
            logger.debug("Could not acquire file lock: %s", exc)
        return lock_file

    def _release_lock(self, lock_file: Any) -> None:
        if lock_file is None:
            return
        with contextlib.suppress(Exception):
            import fcntl
            fcntl.flock(lock_file, fcntl.LOCK_UN)
        with contextlib.suppress(Exception):
            lock_file.close()

    # --- Lessons collection ---
    @staticmethod
    def _lesson_scope_filter(
        client_id: str | None,
        engagement_id: str | None,
        *,
        allow_engagementless: bool = False,
    ) -> dict[str, Any] | None:
        """Build a client-isolated lesson filter.

        Writes require both scope keys, while reads may omit engagement_id to
        reuse history across engagements for the same client. A missing client
        always returns ``None`` so unscoped or cross-client retrieval fails
        closed.
        """
        client = str(client_id or "").strip()
        engagement = str(engagement_id or "").strip()
        if not client:
            return None
        if not engagement:
            return {"client_id": client} if allow_engagementless else None
        return {
            "$and": [
                {"client_id": client},
                {"engagement_id": engagement},
            ]
        }

    def add_lesson(self, text: str, metadata: dict[str, Any]) -> None:
        if not text or not text.strip():
            return
        scope_filter = self._lesson_scope_filter(
            metadata.get("client_id"), metadata.get("engagement_id")
        )
        if scope_filter is None:
            logger.warning(
                "Refusing to persist lesson without client_id and engagement_id"
            )
            return
        store = self._get_store(_DEFAULT_LESSONS_COLLECTION)
        if store is None:
            return
        clean_metadata = {
            **metadata,
            "client_id": str(metadata["client_id"]).strip(),
            "engagement_id": str(metadata["engagement_id"]).strip(),
        }
        lock = self._acquire_lock()
        try:
            store.add_texts(texts=[text], metadatas=[clean_metadata])
        except Exception as exc:
            logger.warning("Failed to add lesson: %s", exc)
        finally:
            self._release_lock(lock)

    def search_lessons(
        self,
        query: str,
        k: int = 3,
        *,
        client_id: str | None = None,
        engagement_id: str | None = None,
    ) -> list[str]:
        """Search lessons for one client, optionally narrowed by engagement.

        A missing client returns no results. Omitting engagement_id reuses
        lessons across engagements of that same client; it never broadens the
        query to another client or to unscoped legacy rows.
        """
        if not query or not query.strip():
            return []
        scope_filter = self._lesson_scope_filter(
            client_id,
            engagement_id,
            allow_engagementless=True,
        )
        if scope_filter is None:
            logger.warning("Refusing unscoped lesson search: client_id is required")
            return []
        store = self._get_store(_DEFAULT_LESSONS_COLLECTION)
        if store is None:
            return []
        try:
            results = store.similarity_search(
                query=query,
                k=k,
                filter=scope_filter,
            )
            return [doc.page_content for doc in results]
        except Exception as exc:
            logger.warning("Failed to search lessons: %s", exc)
            return []

    # --- Knowledge collection ---
    def add_knowledge(self, text: str, metadata: dict[str, Any]) -> None:
        if not text or not text.strip():
            return
        store = self._get_store(_KNOWLEDGE_COLLECTION_NAME)
        if store is None:
            return
        lock = self._acquire_lock()
        try:
            store.add_texts(texts=[text], metadatas=[metadata])
        except Exception as exc:
            logger.warning("Failed to add knowledge: %s", exc)
        finally:
            self._release_lock(lock)

    def add_knowledge_batch(
        self,
        texts: list[str],
        metadatas: list[dict[str, Any]],
        doc_type: str = "report",
    ) -> int:
        """Add a batch of knowledge chunks with document type metadata.

        V3.5: Accepts a ``doc_type`` parameter which is injected into
        every metadata dict as ``{"type": doc_type}``. This enables
        filtered retrieval via ``search_knowledge(doc_type=...)``.

        Args:
            texts: List of text chunks to embed and store.
            metadatas: List of metadata dicts (one per text).
            doc_type: Document type tag (e.g., 'writeup', 'methodology').
                Defaults to 'report'.

        Returns:
            The number of chunks successfully added.
        """
        if not texts:
            return 0
        store = self._get_store(_KNOWLEDGE_COLLECTION_NAME)
        if store is None:
            return 0
        pairs = [
            (t, m if i < len(metadatas) else {})
            for i, (t, m) in enumerate(zip(texts, metadatas, strict=False))
            if t and t.strip()
        ]
        if not pairs:
            return 0
        clean_texts = [p[0] for p in pairs]
        # V3.5: Inject doc_type into every metadata dict.
        clean_metas = [{**p[1], "type": doc_type} for p in pairs]
        existing_source_ids: set[str] = set()
        source_ids = {
            str(meta.get("source_id", "")).strip()
            for meta in clean_metas
            if str(meta.get("source_id", "")).strip()
        }
        for source_id in source_ids:
            try:
                existing = store.get(where={"source_id": source_id})
                if existing and existing.get("ids"):
                    existing_source_ids.add(source_id)
            except Exception:
                # Older/in-memory store adapters may not implement ``get``.
                # They retain the historical additive behavior.
                logger.debug("Knowledge source dedupe lookup unavailable", exc_info=True)
        if existing_source_ids:
            pairs = [
                (text, meta) for text, meta in pairs
                if str(meta.get("source_id", "")).strip() not in existing_source_ids
            ]
            if not pairs:
                logger.info("All knowledge sources already present; skipping batch")
                return 0
            clean_texts = [p[0] for p in pairs]
            clean_metas = [{**p[1], "type": doc_type} for p in pairs]
        lock = self._acquire_lock()
        try:
            store.add_texts(texts=clean_texts, metadatas=clean_metas)
            logger.info(
                "Added %d knowledge chunk(s) (type=%s)", len(clean_texts), doc_type
            )
            return len(clean_texts)
        except Exception as exc:
            logger.warning("Failed to add knowledge batch: %s", exc)
            return 0
        finally:
            self._release_lock(lock)

    def search_knowledge(
        self,
        query: str,
        k: int = 3,
        doc_type: str | None = None,
        stack: str | None = None,
        family: str | None = None,
        route_pattern: str | None = None,
    ) -> list[str]:
        """Retrieve top-``k`` semantically similar knowledge chunks.

        V3.5: Accepts an optional ``doc_type`` filter. If provided, the
        ChromaDB ``where`` clause is used to restrict results to documents
        whose ``type`` metadata matches.

        V7 Sprint 1.4: Accepts an optional ``stack`` filter. If provided,
        results are restricted to documents whose ``stack`` metadata
        field matches the target's detected technology stack (e.g.,
        ``php``, ``java``, ``nodejs``, ``generic``). This enables
        tech-stack-aware payload retrieval — the recon phase
        fingerprints the target, then ``payload_generator`` calls
        ``search_knowledge(doc_type="payload", stack="php")`` to get
        PHP-relevant payloads only.

        Args:
            query: The search query.
            k: Maximum number of results. Defaults to 3.
            doc_type: Optional document type filter (e.g., 'writeup',
                'payload', 'methodology'). If ``None``, all document
                types are searched.
            stack: Optional technology-stack filter (e.g., 'php',
                'java', 'nodejs', 'generic'). If ``None``, all stacks
                are searched.

        Returns:
            A list of matching text chunks.
        """
        if not query or not query.strip():
            return []
        store = self._get_store(_KNOWLEDGE_COLLECTION_NAME)
        if store is None:
            return []
        try:
            kwargs: dict[str, Any] = {"query": query, "k": k}
            # V7 Sprint 1.4: build a combined ``where`` filter when
            # both ``doc_type`` and ``stack`` are specified. Chroma
            # supports ``$and`` for compound filters.
            filters: dict[str, Any] = {}
            if doc_type is not None:
                filters["type"] = doc_type
            if stack is not None:
                filters["stack"] = stack
            if family is not None:
                filters["family"] = str(family).upper()[:64]
            if route_pattern is not None:
                filters["route_pattern"] = str(route_pattern)[:240]
            if filters:
                if len(filters) == 1:
                    # Single filter — pass directly (Chroma's simplest form).
                    kwargs["filter"] = filters
                else:
                    # Multiple filters — use $and compound.
                    kwargs["filter"] = {
                        "$and": [
                            {key: value} for key, value in filters.items()
                        ]
                    }
            results = store.similarity_search(**kwargs)
            return [doc.page_content for doc in results]
        except Exception as exc:
            logger.warning("Failed to search knowledge: %s", exc)
            return []


# ===========================================================================
# V6 Titanium P2: Process-wide singleton accessor.
# ===========================================================================
# ``VectorStoreManager`` instantiation is expensive (~5 seconds to load
# the sentence-transformers embeddings model on first use, plus Chroma
# collection handle creation). Instantiating it ad-hoc in every agent
# and CLI call discarded the cache on every RAG retrieval, dominating
# the latency budget of the hypothesis_analyzer and reflection agents.
#
# The singleton is created on first call to :func:`get_vector_store_manager`
# and reused for the lifetime of the process. The underlying RLock in
# the manager handles thread-safe lazy init of the embeddings model
# and Chroma handles; this module-level singleton just ensures there's
# only ONE manager instance per process.
#
# A module-level lock guards the singleton creation itself so that two
# concurrent threads calling ``get_vector_store_manager()`` for the
# first time don't both create a manager (which would re-trigger the
# 5-second embeddings load and produce two competing Chroma handles).
_SINGLETON_LOCK = threading.Lock()
_SINGLETON_INSTANCE: VectorStoreManager | None = None
_SCOPED_INSTANCES: dict[str, VectorStoreManager] = {}


def get_vector_store_manager(
    persist_path: str | None = None,
) -> VectorStoreManager:
    """Return a manager scoped to an explicit or active target RAG path.

    Legacy callers outside a target workspace retain the original singleton.
    During target-scoped execution, omitted ``persist_path`` resolves to the
    active workspace's Chroma directory and is cached by path.
    """
    global _SINGLETON_INSTANCE
    resolved_path = persist_path
    if resolved_path is None:
        try:
            from webpent.shared.target_workspace_context import (
                get_active_target_workspace,
            )

            workspace = get_active_target_workspace()
        except ImportError:
            workspace = None
        if workspace is not None:
            resolved_path = str(workspace.chroma_path)
    if resolved_path is None:
        if _SINGLETON_INSTANCE is not None:
            return _SINGLETON_INSTANCE
        with _SINGLETON_LOCK:
            if _SINGLETON_INSTANCE is None:
                _SINGLETON_INSTANCE = VectorStoreManager()
                logger.debug(
                    "VectorStoreManager singleton created (id=%d).",
                    id(_SINGLETON_INSTANCE),
                )
        return _SINGLETON_INSTANCE
    key = str(Path(resolved_path).expanduser().resolve())
    with _SINGLETON_LOCK:
        manager = _SCOPED_INSTANCES.get(key)
        if manager is None:
            manager = VectorStoreManager(key)
            _SCOPED_INSTANCES[key] = manager
            logger.debug(
                "Target-scoped VectorStoreManager created (path=%s, id=%d).",
                key,
                id(manager),
            )
        return manager


def reset_vector_store_manager() -> None:
    """Reset the singleton (for tests / forced reconfiguration).

    Drops the cached singleton so the next call to
    :func:`get_vector_store_manager` creates a fresh instance. Mainly
    useful in tests that need to point at a different ``persist_path``
    or that want to force a cold-start of the embeddings model.
    """
    global _SINGLETON_INSTANCE
    with _SINGLETON_LOCK:
        _SINGLETON_INSTANCE = None
        _SCOPED_INSTANCES.clear()
