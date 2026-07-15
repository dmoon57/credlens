"""Redaction-boundary tests (docs/specs/hosted-scan.md §Result policy).

The security property: no repository-derived secret material reaches a response body,
and service-generated metadata (digest, scanned_at) survives redaction intact.
"""

from __future__ import annotations

from credlens.hosted.redact import (
    MAX_PER_FILE,
    MAX_TOTAL,
    assemble_response,
    redact_string,
)


def _fake(*parts: str) -> str:
    """Assemble a clearly-fake fixture token from short parts so no complete
    secret-shaped literal ever appears in source (belt to the .gitleaks.toml
    allowlist). The runtime string still matches credlens's shape/entropy rules."""
    return "".join(parts)


def _rec(file="repo/a.js", line=1, lens="credential", kind="finding", message="msg", confidence="high"):
    return {"file": file, "line": line, "lens": lens, "kind": kind,
            "message": message, "confidence": confidence}


def _cov(status="complete"):
    return {"status": status, "languages": ["javascript"], "files_seen": 1,
            "files_scanned": 1, "files_skipped": 0, "deadline_hit": False, "skipped": []}


# Fixture tokens are defanged twice per repo convention: a FAKE marker AND structurally
# invalid as real credentials, while still matching credlens's own shape/entropy rules.
def test_known_token_shapes_redacted():
    gh = _fake("ghp_", "FAKE", "0123456789ABCDEF")
    slack = _fake("xoxb-", "FAKE", "1234567890abcd")
    aws = _fake("AKIA", "FAKE", "0123456789XY")
    assert "ghp_" not in redact_string(f"leak {gh} here")
    assert "xoxb-" not in redact_string(f"slack {slack} set")
    assert "AKIA" not in redact_string(f"aws {aws} key")


def test_high_entropy_run_redacted_but_prose_kept():
    secret = _fake("EXAMPLEZm9vYmFy", "BaSE64abcDEFgh", "IJKLmn0pq")  # no real provider prefix
    out = redact_string(f"token is {secret} in config")
    assert secret not in out
    assert "[REDACTED" in out
    # ordinary prose (low entropy, short words) is untouched
    assert redact_string("the quick brown fox jumps") == "the quick brown fox jumps"


def test_planted_token_never_in_response_including_oauth_scope_value():
    # a live-shaped token planted in a least-priv inventory message (raw repo value)
    token = _fake("ghp_", "FAKEBCDEFGHIJKL", "MNOP0123456789xyz")
    frame = {
        "records": [
            _rec(kind="inventory", lens="capability",
                 message=f"OAuth scope declares access with credential {token}"),
            _rec(file=f"repo/{token}.js", message="secret reaches a sink"),
        ],
        "coverage": _cov(),
    }
    body = assemble_response(frame, repo="o/r", digest="a" * 64, scanned_at="2026-07-14T23:00Z")
    blob = str(body)
    assert token not in blob


def test_service_metadata_exempt_from_redaction():
    digest = "deadbeef" * 8  # 64 hex chars — high-entropy shaped, must survive
    frame = {"records": [], "coverage": _cov()}
    body = assemble_response(frame, repo="o/r", digest=digest, scanned_at="2026-07-14T23:00Z")
    assert body["digest"] == digest
    assert body["repo"] == "o/r"
    assert body["schema"] == 1


def test_combined_caps_split_and_truncate():
    # 150 records on one file: per-file cap (100 combined) trips
    recs = [_rec(line=i + 1, kind="finding" if i % 2 == 0 else "inventory") for i in range(150)]
    frame = {"records": recs, "coverage": _cov()}
    body = assemble_response(frame, repo="o/r", digest="a" * 64, scanned_at="t")
    kept = len(body["findings"]) + len(body["inventory"])
    assert kept == MAX_PER_FILE
    assert body["truncated"]["reason"] == "per_file_cap"
    assert body["truncated"]["findings_omitted"] + body["truncated"]["inventory_omitted"] == 50


def test_total_cap_across_many_files():
    recs = [_rec(file=f"repo/f{i}.js", line=1) for i in range(MAX_TOTAL + 25)]
    frame = {"records": recs, "coverage": _cov()}
    body = assemble_response(frame, repo="o/r", digest="a" * 64, scanned_at="t")
    assert len(body["findings"]) == MAX_TOTAL
    assert body["truncated"]["reason"] == "total_cap"
    assert body["truncated"]["findings_omitted"] == 25
