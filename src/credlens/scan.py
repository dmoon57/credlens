"""Shared source-tree walker (docs/specs/hosted-scan.md §No-network boundary).

This is the ONE place a directory of source files becomes (relpath, Finding) pairs.
It is deliberately network-free and side-effect-free: it takes a local root path and
reads only the files under it. The eval harness and the hosted scan both call it, so
the published precision/recall numbers describe exactly the hosted code.

Symlinks are never followed (`lstat`, `is_symlink` guard) — extraction jails already
reject link members (spec T3), and this is the defence-in-depth second check the spec
requires of the walker itself. On the pinned corpus (no symlinks) this is identical to
the previous `is_file()` walk, so it is a pure refactor for eval.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from credlens.detectors.base import Finding

# Source extensions the detectors understand. Kept here as the single owner of
# scan surface; the coverage manifest reports what was in/out of this set.
SCAN_SUFFIXES = {".ts", ".js", ".mjs", ".cts", ".mts", ".py"}


@dataclass
class Coverage:
    """What a scan actually looked at — so 'no findings' can't be read as 'clean'."""

    status: str = "complete"  # complete | partial
    languages: set[str] = field(default_factory=set)
    files_seen: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    deadline_hit: bool = False
    skipped: dict[str, int] = field(default_factory=dict)  # reason -> count

    def _skip(self, reason: str) -> None:
        self.files_skipped += 1
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


@dataclass
class ScanResult:
    findings: list[tuple[str, Finding]]
    coverage: Coverage


_LANG_BY_SUFFIX = {
    ".ts": "typescript", ".cts": "typescript", ".mts": "typescript",
    ".js": "javascript", ".mjs": "javascript",
    ".py": "python",
}


def iter_source_files(root: Path):
    """Yield (relpath, path) for scannable, non-symlink regular files under root.

    Deterministic order; symlinks (file or dir) are never traversed or yielded.
    """
    root = Path(root)
    for path in sorted(root.rglob("*")):
        if path.is_symlink():  # never follow — defence in depth over the extract jail
            continue
        if path.suffix not in SCAN_SUFFIXES or not path.is_file():
            continue
        yield path.relative_to(root).as_posix(), path


def scan_tree(
    root: Path,
    detectors,
    *,
    max_file_bytes: int | None = None,
    on_file=None,
) -> ScanResult:
    """Run detectors over every scannable file under root.

    `max_file_bytes` skips oversized files (hosted path); None = no cap (eval path).
    `on_file(rel)` is called before each file is read — the hosted worker uses it to
    emit a progress marker so the parent can enforce a per-file stall deadline.
    Per-file parse exceptions are contained (counted as `parse_error`), never raised.
    """
    cov = Coverage()
    out: list[tuple[str, Finding]] = []
    for rel, path in iter_source_files(root):
        cov.files_seen += 1
        if on_file is not None:
            on_file(rel)
        if max_file_bytes is not None:
            try:
                if path.stat().st_size > max_file_bytes:
                    cov._skip("over_size")
                    continue
            except OSError:
                cov._skip("parse_error")
                continue
        try:
            text = path.read_text(errors="replace")
            found = list(_scan_one(detectors, rel, text))
        except Exception:  # noqa: BLE001 — one bad file never sinks the scan
            cov._skip("parse_error")
            continue
        cov.files_scanned += 1
        lang = _LANG_BY_SUFFIX.get(path.suffix)
        if lang:
            cov.languages.add(lang)
        out.extend(found)
    if cov.files_skipped:
        cov.status = "partial"
    return ScanResult(findings=out, coverage=cov)


def _scan_one(detectors, rel: str, text: str):
    for detector in detectors:
        for f in detector.scan_text(rel, text):
            yield rel, f
