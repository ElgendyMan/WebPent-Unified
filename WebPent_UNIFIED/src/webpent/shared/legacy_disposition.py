# src/webpent/shared/legacy_disposition.py
"""webpent.shared.legacy_disposition — ق9 legacy unification (FEATURE_PROPOSALS ق9).

Proposal contract (ق9، WebPent_FEATURE_PROPOSALS.md):

    توحيد طبقة الـlegacy الناجية: بعد المرحلة 1 من خطة الإصلاح، جدولة
    «ترحيل مختار»: كل وحدة legacy إما تُستوعب في البنية الحالية (كما
    فعلنا مع ProposalOrderSelector) أو تُعلن مهجورة رسمياً وتُنقل
    للأرشيف — لا منطقة رمادية دائمة (قاعدة: إن لم تُستورد من أي كود
    نشط خلال إصدارين → أرشفة).

    ("Unify the surviving legacy layer: after Phase 1 of the fix plan,
    schedule a 'selective migration': every legacy module is either
    ABSORBED into the current architecture (as ProposalOrderSelector
    was) or formally declared deprecated and moved to the archive — no
    permanent gray zone. Rule: not imported by any active code for two
    releases ⇒ archive.")

New module, pure machinery:

* :func:`find_importers` — AST scan of the ACTIVE tree (src/ minus the
  module itself, minus tests/docs/archive) answering "who imports this
  module RIGHT NOW" — the absorption evidence.
* :class:`LegacyRegistry` — the two-release memory: a JSON file keyed
  by module recording ``imported_releases`` (every release in which the
  module was observed imported) so the gray-zone clock is RECORDED
  history, never recomputed folklore. Atomic writes; unknown-field
  refusal on load (fail-closed).
* :func:`classify` — the disposition pass over a declared legacy
  inventory. Exactly THREE outcomes, one per module, gray zone bounded:
    - ``absorbed`` — imported by active code in the current tree;
      the registry records the current release.
    - ``archive`` — no active importer AND the recorded history proves
      the module went unimported for ≥ ``grace_releases`` (default 2).
    - ``review`` — no active importer yet, but the two-release clock
      has not run out; the disposition REPORT carries the deadline
      (``deadline_release``) so the gray zone cannot become permanent.
* :func:`archive_plan` — the computed move targets
  (``docs/archive/<window>-legacy/<module>``) for every ``archive``
  disposition — the plan only; the actual move is an operator-reviewed
  script, never an import-time side effect.

No network, no filesystem mutation beyond the registry file the
operator names.
"""

from __future__ import annotations

import ast
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "LegacyRegistry",
    "LegacyDisposition",
    "find_importers",
    "classify",
    "archive_plan",
    "DISPOSITIONS",
]

DISPOSITIONS = ("absorbed", "archive", "review")

# Trees that NEVER count as active-code importers (tests prove
# behaviour, docs/archive are history).
_INACTIVE_DIR_NAMES = frozenset({"tests", "docs", "archive", "benchmarks", "scripts"})


def _module_variants(module: str) -> tuple[str, ...]:
    """The import name that references ``module``.

    Accepts dotted names (``webpent.shared.epss``) and repo-relative
    paths (``src/webpent/shared/epss.py``, ``shared/epss.py``). The
    dotted form is anchored at the ``webpent`` package root.

    M1-D fix (UM-DR-12): the tuple is EXACTLY ``(full_dotted_name,)`` —
    the previous parent-prefix variant (``webpent.shared`` for
    ``webpent.shared.cve_advisory``) joined the equality/prefix match
    set, so EVERY ``from webpent.shared import <anything>`` in the tree
    (~190 files) counted as an importer and the first documented ق9 run
    over the M0 dead clusters classified them all ``absorbed`` on
    fabricated evidence. Name completion (``from webpent import
    legacy_a`` / ``from webpent.shared import cve_advisory``) is handled
    by :func:`_imports_any`'s candidate check against the full name —
    no parent variant is needed.
    """
    cleaned = module.strip().strip("/\\")
    if not cleaned:
        return ()
    if cleaned.endswith(".py"):
        cleaned = cleaned[:-3]
    # dotted names and paths are the same vocabulary here: split on both
    parts = [p for p in cleaned.replace("\\", "/").replace(".", "/").split("/") if p]
    if "webpent" in parts:
        parts = parts[parts.index("webpent"):]
    if not parts or parts[0] != "webpent":
        return ()
    return (".".join(parts),)


def _is_active(path: Path) -> bool:
    return not (set(path.parts) & _INACTIVE_DIR_NAMES)


def find_importers(module: str, *, src_root: Path) -> list[str]:
    """Every ACTIVE source file that imports ``module`` (AST-accurate).

    ``src_root`` is the directory CONTAINING the ``webpent`` package
    (i.e. ``src/``). Relative imports are resolved against the
    importing file's package path. The module's own file is never its
    own importer; tests/docs/archive never count as importers.
    """
    variants = _module_variants(module)
    if not variants:
        return []
    root = Path(src_root)
    # the module's own file: src/<webpent/shared/epss>.py, or its
    # package __init__ when the last segment names a package. The FULL
    # dotted name (variants[0]) decides the self file — never a parent
    # prefix (the M1-D over-match fix: variants used to be sorted, so a
    # parent prefix could land first and make the module scan itself).
    primary_parts = variants[0].split(".")
    self_file = root.joinpath(*primary_parts[:-1], primary_parts[-1] + ".py")
    if not self_file.exists():
        self_file = root.joinpath(*primary_parts, "__init__.py")

    importers: list[str] = []
    for py_file in sorted(root.rglob("*.py")):
        if not _is_active(py_file):
            continue
        if py_file == self_file:
            continue
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError):
            continue
        if _imports_any(tree, py_file, variants, root):
            try:
                rel = str(py_file.relative_to(root.parent))
            except ValueError:
                rel = str(py_file)
            importers.append(rel)
    return importers


def _imports_any(tree: ast.AST, file_path: Path, variants: tuple[str, ...], root: Path) -> bool:
    # M1-D (UM-DR-12): variants[0] is the FULL dotted module name and the
    # ONLY equality/prefix variant. The old parent-prefix variants made
    # every ``from webpent.shared import <anything>`` an "importer".
    full_variants = (variants[0],)
    package_parts = tuple(file_path.parent.relative_to(root).parts) if root in file_path.parents else ()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if any(name == v or name.startswith(v + ".") for v in full_variants):
                    return True
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            level = node.level or 0
            if level:
                # relative: resolve against the file's package
                base = package_parts[: len(package_parts) - (level - 1)] if package_parts else ()
                resolved = ".".join([*base, module]) if module else ".".join(base)
            else:
                resolved = module
            if resolved:
                if any(resolved == v or resolved.startswith(v + ".") for v in full_variants):
                    return True
                # name completion: "from webpent import legacy_a" and
                # "from webpent.shared import cve_advisory" complete to the
                # full dotted name. The completed candidate must equal the
                # FULL name exactly — a different imported name proves
                # nothing ("from webpent.shared import differential_workflow"
                # is NOT an importer of cve_advisory).
                for alias in node.names:
                    if f"{resolved}.{alias.name}" == variants[0]:
                        return True
    return False


@dataclass
class LegacyDisposition:
    """One module's verdict — one of exactly three, never gray forever."""

    module: str
    disposition: str  # absorbed | archive | review
    importers: list[str] = field(default_factory=list)
    imported_releases: list[str] = field(default_factory=list)
    releases_since_import: int = 0
    deadline_release: str | None = None
    rule: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "disposition": self.disposition,
            "importers": list(self.importers),
            "imported_releases": list(self.imported_releases),
            "releases_since_import": self.releases_since_import,
            "deadline_release": self.deadline_release,
            "rule": self.rule,
        }


class LegacyRegistry:
    """JSON record of ``module -> [releases where imports were seen]``.

    The two-release clock runs on RECORDED history: ``classify`` records
    the current release for every module that still has an active
    importer, and the archive rule counts releases since the LAST
    recorded import. The file is written atomically and refuses unknown
    shapes on load.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._data: dict[str, list[str]] = {}
        if self._path.exists():
            self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"legacy_registry_unreadable: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("legacy_registry_shape_invalid")
        for module, releases in data.items():
            if not isinstance(module, str) or not isinstance(releases, list) or not all(
                isinstance(r, str) for r in releases
            ):
                raise ValueError(f"legacy_registry_entry_invalid: {module!r}")
        self._data = data

    def record_import(self, module: str, release: str) -> None:
        releases = self._data.setdefault(str(module), [])
        if release not in releases:
            releases.append(str(release))

    def imported_releases(self, module: str) -> list[str]:
        return list(self._data.get(str(module), []))

    def modules(self) -> list[str]:
        return sorted(self._data)

    def save(self) -> None:
        """Atomic write (tmp + rename); creates parent dirs."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self._data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        tmp.replace(self._path)

    @property
    def path(self) -> Path:
        return self._path


def classify(
    *,
    legacy_modules: Iterable[str],
    src_root: Path,
    releases: list[str],
    registry: LegacyRegistry,
    grace_releases: int = 2,
) -> list[LegacyDisposition]:
    """Run the disposition pass over the legacy inventory.

    ``releases`` is the ordered release lineage, oldest → newest; the
    LAST element is the current release. A module with an active
    importer NOW is ``absorbed`` (and the current release is recorded).
    A module without importers is ``archive`` when its recorded
    history shows no import for ≥ ``grace_releases`` releases,
    otherwise ``review`` with an explicit deadline release.
    """
    if not releases:
        raise ValueError("legacy_releases_lineage_required")
    current = releases[-1]
    index = {r: i for i, r in enumerate(releases)}
    if grace_releases < 1:
        raise ValueError("legacy_grace_releases_must_be_positive")

    dispositions: list[LegacyDisposition] = []
    for module in legacy_modules:
        module = str(module or "").strip()
        if not module:
            continue
        importers = find_importers(module, src_root=Path(src_root))
        if importers:
            registry.record_import(module, current)
            dispositions.append(
                LegacyDisposition(
                    module=module,
                    disposition="absorbed",
                    importers=importers,
                    imported_releases=registry.imported_releases(module),
                    rule="imported by active code in the current tree",
                )
            )
            continue

        recorded = registry.imported_releases(module)
        if recorded:
            last_seen = max(recorded, key=lambda r: index.get(r, -1))
            last_index = index.get(last_seen, -1)
            since = len(releases) - 1 - last_index if last_index >= 0 else len(releases) - 1
        else:
            # never recorded as imported: the clock starts at the first
            # release the registry observed the module at all — unknown
            # provenance counts from the CURRENT release (review, not a
            # surprise archive)
            since = 0
        if since >= grace_releases:
            dispositions.append(
                LegacyDisposition(
                    module=module,
                    disposition="archive",
                    imported_releases=recorded,
                    releases_since_import=since,
                    rule=f"no active importer for {since} releases (grace={grace_releases})",
                )
            )
        else:
            # The gray zone is BOUNDED: the deadline is the release at
            # which the two-release clock runs out. It may lie beyond
            # the supplied lineage, in which case it is projected by
            # incrementing the final numeric segment of the current
            # release (deterministic, documented, never a vague "TBD").
            releases_left = grace_releases - since
            deadline_index = (len(releases) - 1) + releases_left
            if deadline_index < len(releases):
                deadline = releases[deadline_index]
            else:
                deadline = _project_release(current, releases_left)
            dispositions.append(
                LegacyDisposition(
                    module=module,
                    disposition="review",
                    imported_releases=recorded,
                    releases_since_import=since,
                    deadline_release=deadline,
                    rule=(
                        f"no active importer for {since} release(s); "
                        f"archives after {grace_releases} (deadline: {deadline})"
                    ),
                )
            )
    return dispositions


def _project_release(release: str, steps: int) -> str:
    """Deterministic future-release projection: the FINAL numeric
    segment is bumped by ``steps`` (``0.35.0`` + 1 → ``0.35.1``).
    Non-numeric tails fall back to a ``+N`` suffix rather than guessing
    a versioning scheme — the deadline stays concrete either way."""
    match = re.match(r"^(.*?)(\d+)$", str(release))
    if match is None:
        return f"{release}+{steps}"
    return f"{match.group(1)}{int(match.group(2)) + steps}"


def archive_plan(dispositions: Iterable[LegacyDisposition], *, window: str) -> list[dict[str, Any]]:
    """Computed move targets for every ``archive`` disposition.

    The plan ONLY: ``docs/archive/<window>-legacy/<module path>``. The
    actual move stays an operator-reviewed step (no import-time side
    effects, no silent deletions).
    """
    plan: list[dict[str, Any]] = []
    for disposition in dispositions:
        if disposition.disposition != "archive":
            continue
        raw = disposition.module.strip().strip("/\\")
        if raw.endswith(".py") or "/" in raw:
            source = raw if raw.startswith("src/") else f"src/{raw}"
        else:
            source = f"src/{raw.replace('.', '/')}"
            if not source.endswith(".py"):
                source += ".py"
        plan.append(
            {
                "module": disposition.module,
                "source": source,
                "destination": f"docs/archive/{window}-legacy/{source}",
                "rule": disposition.rule,
                "imported_releases": list(disposition.imported_releases),
            }
        )
    return plan
