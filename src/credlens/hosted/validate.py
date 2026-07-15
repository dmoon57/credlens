"""Parent-boundary validation of the worker frame (docs/specs/hosted-scan.md).

The worker is inside the hostile-byte blast radius, so nothing it returns is trusted:
the parent validates the frame against the closed contract in
docs/specs/hosted-scan-schema.json BEFORE assembling any response. Hand-rolled rather
than via `jsonschema` because the hosted surface adds ZERO new runtime dependencies —
so this stays in lockstep with the schema file, guarded by test_validate_matches_schema.
"""

from __future__ import annotations

_LENSES = {"credential", "capability"}
_KINDS = {"finding", "inventory"}
_CONFIDENCE = {"low", "medium", "high"}
_SKIP_REASONS = {"unsupported_ext", "over_size", "parse_error", "deadline", "binary"}
_COVERAGE_STATUS = {"complete", "partial"}
_LANGUAGES = {"javascript", "typescript", "python"}

MAX_RECORDS = 2000        # worker frame cap (records array); response caps are tighter
MAX_FILE_LEN = 512
MAX_MESSAGE_LEN = 2000


class ParentBoundaryError(Exception):
    """Worker frame violated the closed contract — treat as scan_failed."""


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise ParentBoundaryError(msg)


def _bytelen(s: str) -> int:
    return len(s.encode("utf-8", "replace"))


def _record(r) -> dict:
    _need(isinstance(r, dict), "record not an object")
    _need(set(r) == {"file", "line", "lens", "kind", "message", "confidence"},
          f"record keys {sorted(r)} != contract")
    _need(isinstance(r["file"], str) and _bytelen(r["file"]) <= MAX_FILE_LEN, "bad file")
    _need(isinstance(r["line"], int) and 1 <= r["line"] <= 100_000_000, "bad line")
    _need(r["lens"] in _LENSES, "bad lens")
    _need(r["kind"] in _KINDS, "bad kind")
    _need(isinstance(r["message"], str) and _bytelen(r["message"]) <= MAX_MESSAGE_LEN, "bad message")
    _need(r["confidence"] in _CONFIDENCE, "bad confidence")
    return r


def _coverage(c) -> dict:
    _need(isinstance(c, dict), "coverage not an object")
    allowed = {"status", "languages", "files_seen", "files_scanned",
               "files_skipped", "deadline_hit", "skipped"}
    _need(set(c) <= allowed, f"coverage extra keys {set(c) - allowed}")
    for k in ("status", "languages", "files_seen", "files_scanned", "files_skipped", "skipped"):
        _need(k in c, f"coverage missing {k}")
    _need(c["status"] in _COVERAGE_STATUS, "bad coverage status")
    _need(isinstance(c["languages"], list) and len(c["languages"]) <= 16
          and all(x in _LANGUAGES for x in c["languages"]), "bad languages")
    for k in ("files_seen", "files_scanned", "files_skipped"):
        _need(isinstance(c[k], int) and 0 <= c[k] <= 5000, f"bad {k}")
    if "deadline_hit" in c:
        _need(isinstance(c["deadline_hit"], bool), "bad deadline_hit")
    _need(isinstance(c["skipped"], list) and len(c["skipped"]) <= 200, "bad skipped")
    for s in c["skipped"]:
        _need(isinstance(s, dict) and set(s) == {"reason", "count"}, "bad skip entry")
        _need(s["reason"] in _SKIP_REASONS, "bad skip reason")
        _need(isinstance(s["count"], int) and s["count"] >= 1, "bad skip count")
    return c


def validate_worker_frame(obj) -> dict:
    """Return the validated {records, coverage} frame, or raise ParentBoundaryError."""
    _need(isinstance(obj, dict), "frame not an object")
    _need(set(obj) == {"records", "coverage"}, f"frame keys {sorted(obj)} != contract")
    records = obj["records"]
    _need(isinstance(records, list) and len(records) <= MAX_RECORDS,
          f"records not a list or over {MAX_RECORDS}")
    for r in records:
        _record(r)
    _coverage(obj["coverage"])
    return obj
