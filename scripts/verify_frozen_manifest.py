#!/usr/bin/env python3
"""Fail-closed verification of WebPent's authoritative frozen-file manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

DEFAULT_MANIFEST = Path("docs/integration/WEBPENT_AUTHORITY_MANIFEST.json")


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("manifest_root_must_be_object")
    files = value.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("manifest_files_must_be_non_empty_object")
    return value


def verify(project_root: Path, manifest_path: Path) -> tuple[bool, list[str]]:
    errors: list[str] = []
    try:
        manifest = _load(manifest_path)
    except Exception as exc:
        return False, [f"manifest_load_error:{type(exc).__name__}:{exc}"]

    files = manifest["files"]
    if len(files) != len(set(files)):
        errors.append("duplicate_manifest_paths")
    for relative, expected in files.items():
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            errors.append(f"invalid_manifest_path:{relative!r}")
            continue
        if not isinstance(expected, str) or len(expected) != 64:
            errors.append(f"invalid_manifest_hash:{relative}")
            continue
        try:
            int(expected, 16)
        except ValueError:
            errors.append(f"invalid_manifest_hash:{relative}")
            continue
        path = project_root / relative
        if not path.is_file():
            errors.append(f"missing:{relative}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected.lower():
            errors.append(f"mismatch:{relative}:expected={expected[:16]}:actual={actual[:16]}")

    root = project_root.resolve()
    for relative in files:
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            errors.append(f"path_traversal:{relative}")
    return not errors, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    manifest = args.manifest if args.manifest.is_absolute() else args.project_root / args.manifest
    ok, errors = verify(args.project_root.resolve(), manifest.resolve())
    if ok:
        print(f"FROZEN MANIFEST: OK ({len(_load(manifest)['files'])} files)")
        return 0
    print("FROZEN MANIFEST: FAIL")
    for error in errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
