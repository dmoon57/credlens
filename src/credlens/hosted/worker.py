"""The scan worker (docs/specs/hosted-scan.md §Isolation).

Runs as a subprocess in its own process group with a scrubbed environment. It is the
only place hostile bytes are inflated, parsed by tar, and parsed by tree-sitter. It
emits a progress marker to stderr before each file so the parent can enforce a per-file
stall deadline, and writes exactly one length-prefixed result frame to stdout on success.

Exit protocol (the parent's coarse channel; stdout frame is the fine one):
  0  success  — a valid {records, coverage} frame on stdout
  2  rejected — stderr ends with "REJECT <reason>" (extract/parse rejection: too_large_*,
                unsafe_member, corrupt, not_gzip, member_too_large, …)
  *  anything else (incl. a SIGKILL from the parent) → the parent treats it as scan_failed
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from credlens.detectors import CredentialDetector, LeastPrivDetector
from credlens.hosted.extract import ExtractError, safe_extract
from credlens.hosted.frame import write_frame
from credlens.hosted.limits import Limits
from credlens.scan import scan_tree

PROGRESS_PREFIX = "P "
REJECT_PREFIX = "REJECT "


def _coverage_dict(cov) -> dict:
    return {
        "status": cov.status,
        "languages": sorted(cov.languages),
        "files_seen": cov.files_seen,
        "files_scanned": cov.files_scanned,
        "files_skipped": cov.files_skipped,
        "deadline_hit": cov.deadline_hit,
        "skipped": [{"reason": r, "count": n} for r, n in sorted(cov.skipped.items())],
    }


def build_frame(tarball_path: Path, dest: Path, limits: Limits, *, on_file=None) -> dict:
    """Extract + scan; return the success-frame dict. Raises ExtractError on rejection.

    Detectors are constructed fresh here (per-request instances — the concurrency
    guarantee holds regardless of the platform fluid setting).
    """
    with open(tarball_path, "rb") as raw:
        safe_extract(raw, dest, limits)
    detectors = [CredentialDetector(), LeastPrivDetector()]
    result = scan_tree(dest, detectors, max_file_bytes=limits.max_file_bytes, on_file=on_file)
    records = [
        {
            "file": rel,
            "line": f.line,
            "lens": f.lens,
            "kind": f.kind,
            "message": f.message,
            "confidence": f.confidence,
        }
        for rel, f in result.findings
    ]
    return {"records": records, "coverage": _coverage_dict(result.coverage)}


def _emit_progress(rel: str) -> None:
    # one line per file so the parent can reset its per-file stall timer
    sys.stderr.write(PROGRESS_PREFIX + rel[:512] + "\n")
    sys.stderr.flush()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    tarball_path = Path(argv[0])
    dest = Path(argv[1])
    limits = Limits(**json.loads(argv[2])) if len(argv) > 2 and argv[2] else Limits()
    try:
        frame = build_frame(tarball_path, dest, limits, on_file=_emit_progress)
    except ExtractError as e:
        sys.stderr.write(REJECT_PREFIX + e.reason + "\n")
        sys.stderr.flush()
        return 2
    write_frame(sys.stdout.buffer, frame)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
