"""Hosted redaction + response assembly (docs/specs/hosted-scan.md §Result policy).

A finding's `message`/`file` are arbitrary strings from the scanned repo, and least-priv
messages embed raw repo values — so before any 200 body leaves the parent, every
repository-derived string is scrubbed of token-shaped and high-entropy substrings
(reusing the credential detector's own shape rules). Service-generated metadata
(`repo`, `digest`, `scanned_at`, `schema`, counts) is attached AFTER redaction and is
never passed through it, so redaction can't eat its own bookkeeping. Combined
findings+inventory caps (r3 #6) are then enforced deterministically.
"""

from __future__ import annotations

import math
import re

from credlens.detectors.credential import TOKEN_SHAPES

# combined findings+inventory population caps (spec T12)
MAX_PER_FILE = 100
MAX_TOTAL = 1000
MAX_FIELD_BYTES = 2000

# candidate high-entropy run: >=20 chars of secret-ish alphabet
_HIGH_ENTROPY = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_ENTROPY_BITS = 3.5


def _shannon_bits(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact_string(s: str) -> str:
    if not s:
        return s
    for label, pat in TOKEN_SHAPES:
        s = pat.sub(f"[REDACTED:{label}]", s)

    def _maybe(m: re.Match) -> str:
        run = m.group(0)
        return "[REDACTED:high-entropy]" if _shannon_bits(run) >= _ENTROPY_BITS else run

    s = _HIGH_ENTROPY.sub(_maybe, s)
    if len(s.encode("utf-8", "replace")) > MAX_FIELD_BYTES:
        s = s.encode("utf-8", "replace")[:MAX_FIELD_BYTES].decode("utf-8", "ignore")
    return s


def _redact_record(r: dict) -> dict:
    return {**r, "file": redact_string(r["file"]), "message": redact_string(r["message"])}


def _apply_caps(records: list[dict]):
    """Deterministic combined per-file + total caps; returns (kept, omitted_by_kind)."""
    kept: list[dict] = []
    per_file: dict[str, int] = {}
    omitted = {"finding": 0, "inventory": 0}
    for r in records:
        f = r["file"]
        if len(kept) >= MAX_TOTAL or per_file.get(f, 0) >= MAX_PER_FILE:
            omitted[r["kind"]] = omitted.get(r["kind"], 0) + 1
            continue
        per_file[f] = per_file.get(f, 0) + 1
        kept.append(r)
    return kept, omitted


def assemble_response(frame: dict, *, repo: str, digest: str, scanned_at: str) -> dict:
    """Build the validated-shape 200 body from a worker frame. Redaction happens on the
    repo-derived record fields BEFORE service metadata is attached; caps come last."""
    redacted = [_redact_record(r) for r in frame["records"]]
    kept, omitted = _apply_caps(redacted)
    findings = [r for r in kept if r["kind"] == "finding"]
    inventory = [r for r in kept if r["kind"] == "inventory"]
    truncated = None
    if omitted["finding"] or omitted["inventory"]:
        truncated = {
            "findings_omitted": omitted["finding"],
            "inventory_omitted": omitted["inventory"],
            "reason": "total_cap" if len(kept) >= MAX_TOTAL else "per_file_cap",
        }
    return {
        "schema": 1,
        "repo": repo,
        "digest": digest,
        "scanned_at": scanned_at,
        "coverage": frame["coverage"],
        "findings": findings,
        "inventory": inventory,
        "truncated": truncated,
    }
