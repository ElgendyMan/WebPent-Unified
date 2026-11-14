# src/webpent/cli/ingest.py
"""webpent.cli.ingest

CLI tool to ingest external documents into the WebPent knowledge base.

Usage:
    webpent-ingest <path>              # ingest a file or directory
    webpent-ingest ./docs/methods.pdf
    webpent-ingest ./writeups/
    webpent-ingest ./PayloadsAllTheThings --type payload
"""

from __future__ import annotations

import argparse
import contextlib
import glob
import importlib
import logging
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from webpent.cli.git_source import GitSourceError, clone_repository
from webpent.memory.vectorstore import VectorStoreManager, get_vector_store_manager
from webpent.memory.writeup_parser import parse_file

logger = logging.getLogger("webpent.ingest")

_EXTENSION_LOADERS: dict[str, str] = {
    ".pdf": "langchain_community.document_loaders.PyPDFLoader",
    ".md": "langchain_community.document_loaders.UnstructuredMarkdownLoader",
    ".markdown": "langchain_community.document_loaders.UnstructuredMarkdownLoader",
    ".txt": "langchain_community.document_loaders.TextLoader",
    ".text": "langchain_community.document_loaders.TextLoader",
}


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webpent-ingest",
        description="Ingest documents into the WebPent RAG knowledge base.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help=(
            "Path to a file or directory to ingest. With --git-url, this is "
            "an optional path relative to the cloned repository."
        ),
    )
    parser.add_argument(
        "--git-url",
        help="Clone a public HTTPS Git repository before ingesting it.",
    )
    parser.add_argument(
        "--git-ref",
        help="Optional branch or tag to clone with --git-url.",
    )
    parser.add_argument(
        "--git-dir",
        help=(
            "Optional empty checkout directory. Without it, the clone uses a "
            "temporary directory removed after ingest."
        ),
    )
    parser.add_argument(
        "--chunk-size", type=int, default=1000, help="Chunk size (default: 1000)."
    )
    parser.add_argument(
        "--chunk-overlap", type=int, default=100, help="Chunk overlap (default: 100)."
    )
    parser.add_argument(
        "--type",
        dest="doc_type",
        choices=["writeup", "methodology", "report", "payload", "playbook"],
        default="report",
        help=(
            "Document type tag for RAG metadata "
            "(writeup, methodology, report, payload, playbook; default: report)."
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging.")
    parser.add_argument(
        "--writeup", action="append", default=[],
        help="Ingest a Markdown/text security writeup structurally (repeatable).",
    )
    parser.add_argument(
        "--cve", action="append", default=[],
        help="Ingest a CVE JSON file/directory structurally (repeatable).",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Use deterministic parsing only; never invoke an LLM during ingestion.",
    )
    return parser


def _load_file(file_path: Path) -> list[Any]:
    ext = file_path.suffix.lower()
    loader_path = _EXTENSION_LOADERS.get(ext)
    if loader_path is None:
        logger.warning("Unsupported file type: %s — skipping", file_path)
        return []
    module_path, class_name = loader_path.rsplit(".", 1)
    try:
        module = importlib.import_module(module_path)
        loader_cls = getattr(module, class_name)
    except (ImportError, AttributeError) as exc:  # noqa: BLE001
        logger.error("Could not import %s: %s", loader_path, exc)
        return []
    try:
        loader = loader_cls(str(file_path))
        return loader.load()
    except Exception as exc:
        logger.warning("Failed to load %s: %s", file_path, exc)
        return []


def _chunk_documents(documents: list[Any], chunk_size: int, chunk_overlap: int) -> list[Any]:
    try:
        from langchain_text_splitters import RecursiveCharacterTextSplitter
    except ImportError as exc:
        logger.error("Could not import RecursiveCharacterTextSplitter: %s", exc)
        return documents
    splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    return splitter.split_documents(documents)


def _ingest_file(
    file_path: Path,
    manager: VectorStoreManager,
    chunk_size: int,
    chunk_overlap: int,
    doc_type: str = "report",
) -> int:
    logger.info("Ingesting: %s (type=%s)", file_path, doc_type)
    documents = _load_file(file_path)
    if not documents:
        return 0
    chunks = _chunk_documents(documents, chunk_size, chunk_overlap)
    if not chunks:
        return 0
    texts = [chunk.page_content for chunk in chunks]
    metadatas = []
    for chunk in chunks:
        meta = dict(chunk.metadata) if hasattr(chunk, "metadata") else {}
        meta["source_file"] = str(file_path)
        meta["file_name"] = file_path.name
        metadatas.append(meta)
    added = manager.add_knowledge_batch(texts, metadatas, doc_type=doc_type)
    logger.info("Ingested %d/%d chunk(s) from %s", added, len(chunks), file_path)
    return added


def _collect_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        files: list[Path] = []
        for ext in _EXTENSION_LOADERS:
            files.extend(path.rglob(f"*{ext}"))
        return sorted(files)
    logger.error("Path does not exist: %s", path)
    return []


def _expand_sources(values: list[str], *, extensions: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for value in values:
        matches = [Path(item) for item in glob.glob(value, recursive=True)] or [Path(value)]
        for candidate in matches:
            if candidate.is_file() and (not extensions or candidate.suffix.lower() in extensions):
                files.append(candidate.resolve())
            elif candidate.is_dir():
                files.extend(sorted(item.resolve() for ext in extensions for item in candidate.rglob(f"*{ext}")))
    return list(dict.fromkeys(files))


def _ingest_structured_sources(args: argparse.Namespace, manager: VectorStoreManager) -> tuple[int, int]:
    """Parse writeups/CVEs into bounded metadata-only knowledge entries."""
    sources: list[tuple[Path, str]] = []
    sources.extend((path, "writeup") for path in _expand_sources(args.writeup, extensions=(".md", ".markdown", ".txt", ".text")))
    sources.extend((path, "cve") for path in _expand_sources(args.cve, extensions=(".json",)))
    total_entries = failed = 0
    for path, doc_type in sources:
        try:
            entries = parse_file(path, doc_type=doc_type, use_llm=not args.no_llm)
            texts = [str(entry.get("content") or "")[:1000] for entry in entries if entry.get("content")]
            metadata = [{key: value for key, value in entry.items() if key != "content"} for entry in entries if entry.get("content")]
            total_entries += manager.add_knowledge_batch(texts, metadata, doc_type=doc_type)
        except (OSError, ValueError, TypeError):
            logger.exception("Failed structured ingestion for %s", path)
            failed += 1
    return total_entries, failed


def _ingest_target(
    target_path: Path,
    args: argparse.Namespace,
    manager: VectorStoreManager,
) -> int:
    """Ingest one local target and return the process exit code."""
    if not target_path.exists():
        logger.error("Path does not exist: %s", target_path)
        return 1

    files = _collect_files(target_path)
    if not files:
        logger.error("No ingestible files found at %s", target_path)
        return 1

    logger.info("Found %d file(s) to ingest (type=%s)", len(files), args.doc_type)
    total_chunks = 0
    failed_files = 0
    for file_path in files:
        try:
            added = _ingest_file(
                file_path, manager, args.chunk_size, args.chunk_overlap, args.doc_type
            )
            total_chunks += added
            if added == 0:
                failed_files += 1
        except Exception as exc:
            logger.exception("Unexpected error ingesting %s: %s", file_path, exc)
            failed_files += 1

    logger.info(
        "Ingestion complete. %d chunk(s) added; %d file(s) failed.",
        total_chunks, failed_files,
    )
    return 0 if failed_files == 0 else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    if not args.path and not args.git_url and not args.writeup and not args.cve:
        parser.error("provide PATH, --git-url, --writeup, or --cve")
    if args.git_ref and not args.git_url:
        parser.error("--git-ref requires --git-url")
    if args.git_dir and not args.git_url:
        parser.error("--git-dir requires --git-url")

    # V6 Titanium P2: use the process-wide singleton. CLI invocations
    # are typically one-shot, but if the CLI is ever called from inside
    # a long-running process (e.g. a REPL), the singleton avoids
    # re-loading the embeddings model on every call.
    manager = get_vector_store_manager()

    structured_added, structured_failed = _ingest_structured_sources(args, manager)
    if structured_added or structured_failed:
        logger.info(
            "Structured ingestion complete. %d entry/chunk(s) added; %d source(s) failed.",
            structured_added, structured_failed,
        )
        if not args.path and not args.git_url:
            return 0 if structured_failed == 0 else 1

    if not args.git_url:
        return _ingest_target(Path(args.path).resolve(), args, manager)

    temporary_checkout = tempfile.TemporaryDirectory(prefix="webpent-ingest-")
    checkout_context = (
        contextlib.nullcontext(Path(args.git_dir).expanduser().resolve())
        if args.git_dir
        else contextlib.nullcontext(Path(temporary_checkout.name) / "checkout")
    )
    try:
        with checkout_context as destination:
            try:
                checkout = clone_repository(
                    args.git_url,
                    destination,
                    git_ref=args.git_ref,
                )
            except GitSourceError as exc:
                logger.error("Git source unavailable: %s", exc)
                return 1
            relative_path = Path(args.path) if args.path else Path(".")
            if relative_path.is_absolute() or ".." in relative_path.parts:
                logger.error("PATH must stay inside the cloned repository")
                return 1
            resolved_target = (checkout / relative_path).resolve()
            try:
                resolved_target.relative_to(checkout.resolve())
            except ValueError:
                logger.error("PATH resolves outside the cloned repository")
                return 1
            return _ingest_target(resolved_target, args, manager)
    finally:
        temporary_checkout.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
