#!/usr/bin/env python3
"""V7 Knowledge Ingestion — reads from knowledge_sources.yaml.

V8 P0 B2 — explicit reliable operator path
==========================================

This script is the SINGLE documented operator entry point for
populating the WebPent knowledge base (ChromaDB vector store). The
ingestion flow is deliberately manual — WebPent does NOT auto-ingest
on startup, because:

  1. The knowledge corpus is large (PayloadsAllTheThings + SecLists
     + bug-bounty writeups) and ingestion is slow on first run.
  2. Operators may want to curate which paths are ingested (edit
     knowledge_sources.yaml first).
  3. Ingestion writes to ./memory/global/chroma_db/ which is a
     bind-mounted volume in Docker — auto-ingest on every container
     start would re-chunk and re-embed the same content, wasting
     API quota and disk.

OPERATOR COMMAND PATH (fresh environment -> populated knowledge)
----------------------------------------------------------------

  # 1. (optional) verify the pins in knowledge_sources.yaml are
  #    reachable BEFORE running the full ingestion. Exits non-zero
  #    if any (repo, commit, path) triple returns non-200.
  python scripts/ingest_payloads.py --verify-pins

  # 2. Run the full ingestion. Fetches every path in
  #    knowledge_sources.yaml, sanitizes, chunks, embeds, and
  #    persists to ./memory/global/chroma_db/.
  python scripts/ingest_payloads.py

  # 3. (alternative) ingest a single local file (PDF/MD/TXT) into
  #    the knowledge base, bypassing knowledge_sources.yaml.
  python scripts/ingest_payloads.py --ingest-file path/to/file.pdf \\
      --doc-type methodology

  # 4. (alternative) dry-run — fetches and logs every URL but does
  #    NOT persist. Useful for debugging path issues without
  #    spending embedding API quota.
  python scripts/ingest_payloads.py --dry-run

The equivalent Make targets are:
  make ingest-knowledge              # runs step 2
  make ingest-file file=...          # runs step 3
  make ingest-knowledge-verify       # runs step 1 (NEW in V8 P0 B2)

The knowledge_sources.yaml file pins every (repo, commit, path)
triple. The commit SHAs were verified reachable on 2026-07-31 as
part of V8 P0 B1. Operators who want to bump a repo to a newer
commit MUST re-verify the paths still exist at that commit (the
SecLists repo, for example, restructured its Fuzzing/XSS/ subdir
between 2024.4 and 2026.1).
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

logger = logging.getLogger("ingest_payloads")
_MANIFEST_PATH = Path(__file__).resolve().parents[1] / "knowledge_sources.yaml"


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError:
        logger.error("PyYAML not installed")
        sys.exit(1)
    if not path.is_file():
        logger.error("Manifest not found: %s", path)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        manifest = yaml.safe_load(f) or {}
    manifest["_base_dir"] = str(path.resolve().parent)
    return manifest


def _raw_url(repo: str, commit: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{commit}/{quote(path)}"


def _fetch(url: str, timeout: float = 30.0) -> str | None:
    try:
        from webpent.shared.http import make_safe_httpx_client

        factory = make_safe_httpx_client
    except ImportError:
        import httpx

        factory = httpx.Client
    try:
        with factory(timeout=timeout, follow_redirects=True) as c:
            r = c.get(url)
        if r.status_code == 200:
            return r.text
        logger.warning("HTTP %d: %s", r.status_code, url)
    except Exception as e:
        logger.warning("Fetch error: %s", e)
    return None


def _chunk(text: str, size: int, overlap: int) -> list[str]:
    if not text:
        return []
    if len(text) <= size:
        return [text]
    chunks, start = [], 0
    while start < len(text):
        chunks.append(text[start : start + size])
        if start + size >= len(text):
            break
        start = start + size - overlap
    return chunks


def _ingest_file(file_path: Path, doc_type: str, chunk_size: int, chunk_overlap: int) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from webpent.memory.lessons import _sanitize_lesson_content, structural_sanitize
    from webpent.memory.vectorstore import get_vector_store_manager

    mgr = get_vector_store_manager()
    ext = file_path.suffix.lower()
    if ext == ".pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(str(file_path))
            content = "\n".join(p.extract_text() or "" for p in reader.pages)
        except ImportError:
            logger.error("pypdf not installed")
            return 0
    elif ext in (".md", ".markdown", ".txt", ".text"):
        content = file_path.read_text(encoding="utf-8", errors="replace")
    else:
        logger.warning("Unsupported: %s", ext)
        return 0
    sanitized = (
        structural_sanitize(content) if doc_type == "payload" else _sanitize_lesson_content(content)
    )
    if not sanitized:
        return 0
    chunks = _chunk(sanitized, chunk_size, chunk_overlap)
    if not chunks:
        return 0
    metas = [
        {
            "type": doc_type,
            "category": "file_upload",
            "stack": "generic",
            "source_repo": "local",
            "source_path": str(file_path),
            "chunk_index": i,
            "total_chunks": len(chunks),
            "ingested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        for i in range(len(chunks))
    ]
    return mgr.add_knowledge_batch(texts=chunks, metadatas=metas, doc_type=doc_type)


def _ingest_manifest_content(
    *,
    content: str,
    manager: Any,
    doc_type: str,
    category: str,
    stack: str,
    metadata: dict[str, Any],
    chunk_size: int,
    chunk_overlap: int,
    structural_sanitize: Any,
    sanitize_text: Any,
) -> int:
    sanitized = structural_sanitize(content) if doc_type == "payload" else sanitize_text(content)
    if not sanitized:
        return 0
    chunks = _chunk(sanitized, chunk_size, chunk_overlap)
    if not chunks:
        return 0
    base_metadata = {
        "type": doc_type,
        "category": category,
        "stack": stack,
        **metadata,
    }
    metas = [
        {
            **base_metadata,
            "chunk_index": index,
            "total_chunks": len(chunks),
            "ingested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        for index in range(len(chunks))
    ]
    return manager.add_knowledge_batch(
        texts=chunks,
        metadatas=metas,
        doc_type=doc_type,
    )


def ingest_manifest(
    manifest: dict,
    *,
    chunk_size: int = 1000,
    chunk_overlap: int = 100,
    dry_run: bool = False,
) -> dict:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from webpent.memory.lessons import _sanitize_lesson_content, structural_sanitize
    from webpent.memory.vectorstore import get_vector_store_manager

    mgr = get_vector_store_manager()
    summary = {"fetched": 0, "ingested": 0, "failed": 0, "total_chunks": 0}
    base_dir = Path(str(manifest.get("_base_dir", Path.cwd())))
    for source in manifest.get("sources", []):
        source_kind = source.get("type", "git_repo")
        doc_type = source.get("doc_type", "report")
        if source_kind == "local_file":
            relative_path = Path(str(source.get("path", "")))
            if relative_path.is_absolute() or ".." in relative_path.parts:
                logger.error("Refusing local source outside manifest directory: %s", relative_path)
                summary["failed"] += 1
                continue
            file_path = (base_dir / relative_path).resolve()
            try:
                file_path.relative_to(base_dir.resolve())
            except ValueError:
                logger.error("Refusing local source outside manifest directory: %s", file_path)
                summary["failed"] += 1
                continue
            if dry_run:
                logger.info("[dry-run] %s", file_path)
                summary["fetched"] += 1
                continue
            if not file_path.is_file():
                logger.error("Local knowledge source not found: %s", file_path)
                summary["failed"] += 1
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                added = _ingest_manifest_content(
                    content=content,
                    manager=mgr,
                    doc_type=doc_type,
                    category=source.get("category", "uncategorized"),
                    stack=source.get("stack", "generic"),
                    metadata={
                        "source_file": str(file_path),
                        "source_path": str(relative_path),
                        "source_url": source.get("source_url", ""),
                        "source_id": source.get("source_id", str(relative_path)),
                        "title": source.get("title", file_path.name),
                        "license_note": source.get("license_note", ""),
                        "trust_note": source.get("trust_note", ""),
                    },
                    chunk_size=chunk_size,
                    chunk_overlap=chunk_overlap,
                    structural_sanitize=structural_sanitize,
                    sanitize_text=_sanitize_lesson_content,
                )
                summary["fetched"] += 1
                summary["ingested"] += int(added > 0)
                summary["total_chunks"] += added
            except Exception as exc:
                logger.error("Local knowledge ingestion failed for %s: %s", file_path, exc)
                summary["failed"] += 1
            continue

        repo = source.get("repo", "")
        commit = source.get("commit", "main")
        for pe in source.get("paths", []):
            path = pe.get("path", "") if isinstance(pe, dict) else pe
            category = (
                pe.get("category", "uncategorized") if isinstance(pe, dict) else "uncategorized"
            )
            stack = pe.get("stack", "generic") if isinstance(pe, dict) else "generic"
            url = _raw_url(repo, commit, path)
            if dry_run:
                logger.info("[dry-run] %s", url)
                summary["fetched"] += 1
                continue
            content = _fetch(url)
            if content is None:
                summary["failed"] += 1
                continue
            try:
                added = _ingest_manifest_content(
                    content=content,
                    manager=mgr,
                    doc_type=doc_type,
                    category=category,
                    stack=stack,
                    metadata={
                        "source_repo": repo,
                        "source_commit": commit,
                        "source_path": path,
                        "source_url": url,
                        "source_id": f"{repo}@{commit}:{path}",
                    },
                    chunk_size=chunk_size,
                    chunk_overlap=chunk_overlap,
                    structural_sanitize=structural_sanitize,
                    sanitize_text=_sanitize_lesson_content,
                )
                summary["fetched"] += 1
                summary["ingested"] += int(added > 0)
                summary["total_chunks"] += added
            except Exception as exc:
                logger.error("Persist failed for %s: %s", url, exc)
                summary["failed"] += 1
    return summary


def _verify_pins(manifest: dict) -> int:
    """V8 P0 B2: pre-flight pin verification.

    Iterates every (repo, commit, path) triple in the manifest, fetches
    it via raw.githubusercontent.com, and confirms HTTP 200 + non-empty
    body. Does NOT touch ChromaDB or the embedding API — pure network
    check. Returns the number of failed paths (0 = all reachable).
    """
    import urllib.error
    import urllib.request

    sources = manifest.get("sources") or []
    total, ok, fail = 0, 0, 0
    print(f"Verifying {len(sources)} source repo(s)...")
    base_dir = Path(str(manifest.get("_base_dir", Path.cwd())))
    for src in sources:
        if src.get("type") == "local_file":
            relative_path = Path(str(src.get("path", "")))
            total += 1
            candidate = (base_dir / relative_path).resolve()
            try:
                candidate.relative_to(base_dir.resolve())
                is_valid = candidate.is_file()
            except ValueError:
                is_valid = False
            if is_valid:
                ok += 1
                print(f"  OK    local  {relative_path}")
            else:
                fail += 1
                print(f"  FAIL  local  {relative_path}")
            continue
        repo = src.get("repo")
        commit = src.get("commit", "main")
        paths = src.get("paths") or []
        for pe in paths:
            path = pe.get("path", "") if isinstance(pe, dict) else pe
            total += 1
            url = _raw_url(repo, commit, path)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "ingest-pins-verify"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    body = resp.read()
                if resp.status == 200 and body:
                    ok += 1
                    print(f"  OK    {repo}@{commit[:8]}  {path}  ({len(body)} bytes)")
                else:
                    fail += 1
                    print(
                        f"  FAIL  {repo}@{commit[:8]}  {path}  "
                        f"(HTTP {resp.status}, {len(body)} bytes)"
                    )
            except urllib.error.HTTPError as exc:
                fail += 1
                print(f"  FAIL  {repo}@{commit[:8]}  {path}  (HTTP {exc.code})")
            except Exception as exc:
                fail += 1
                print(f"  FAIL  {repo}@{commit[:8]}  {path}  ({exc})")
    print(f"\n{'=' * 60}\nVerified: {total}  OK: {ok}  FAIL: {fail}\n{'=' * 60}")
    return fail


def main() -> int:
    p = argparse.ArgumentParser(description="V7 Knowledge Ingestion")
    p.add_argument("--manifest", default=None)
    p.add_argument("--chunk-size", type=int, default=1000)
    p.add_argument("--chunk-overlap", type=int, default=100)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--verify-pins",
        action="store_true",
        help="V8 P0 B2: pre-flight check that every (repo, commit, path) "
        "triple in the manifest is reachable. Does NOT persist.",
    )
    p.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    p.add_argument("--ingest-file", default=None)
    p.add_argument(
        "--doc-type",
        default="methodology",
        # POST-P0 Phase 10: playbook documents (skill_selector-retrievable).
        choices=["payload", "methodology", "repository", "report", "writeup", "scenario", "playbook"],
    )
    args = p.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    mp = Path(args.manifest) if args.manifest else _MANIFEST_PATH
    # --verify-pins works without ChromaDB and without the webpent package
    # installed — it's a pure network check on the manifest.
    if args.verify_pins:
        manifest = _load_manifest(mp)
        return 0 if _verify_pins(manifest) == 0 else 1
    if args.ingest_file:
        fp = Path(args.ingest_file)
        if not fp.is_file():
            logger.error("File not found")
            return 1
        added = _ingest_file(fp, args.doc_type, args.chunk_size, args.chunk_overlap)
        print(f"\nIngested {added} chunks from {fp}")
        return 0
    manifest = _load_manifest(mp)
    s = ingest_manifest(
        manifest, chunk_size=args.chunk_size, chunk_overlap=args.chunk_overlap, dry_run=args.dry_run
    )
    print(
        f"\n{'=' * 60}\nFetched: {s['fetched']}  Ingested: "
        f"{s['ingested']}  Failed: {s['failed']}  Chunks: {s['total_chunks']}\n"
        f"{'=' * 60}"
    )
    return 0 if s["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
