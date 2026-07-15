"""Parent-boundary validation tests + a drift guard vs the JSON schema file.

The hand-rolled validator (zero runtime deps) must stay in lockstep with
docs/specs/hosted-scan-schema.json — test_enums_match_schema fails if either drifts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from credlens.hosted import validate as v
from credlens.hosted.validate import ParentBoundaryError, validate_worker_frame

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "docs/specs/hosted-scan-schema.json").read_text()
)


def _rec(**kw):
    base = {"file": "a.js", "line": 1, "lens": "credential", "kind": "finding",
            "message": "m", "confidence": "high"}
    base.update(kw)
    return base


def _cov(**kw):
    base = {"status": "complete", "languages": ["javascript"], "files_seen": 1,
            "files_scanned": 1, "files_skipped": 0, "deadline_hit": False, "skipped": []}
    base.update(kw)
    return base


def _frame(records=None, coverage=None):
    return {"records": records if records is not None else [_rec()],
            "coverage": coverage if coverage is not None else _cov()}


def test_valid_frame_accepted():
    assert validate_worker_frame(_frame()) == _frame()


@pytest.mark.parametrize("mutate", [
    lambda f: f.update({"extra": 1}) or f,
    lambda f: f["records"][0].update({"lens": "bogus"}) or f,
    lambda f: f["records"][0].update({"kind": "bogus"}) or f,
    lambda f: f["records"][0].update({"line": 0}) or f,
    lambda f: f["records"][0].update({"surprise": 1}) or f,
    lambda f: f["records"][0].update({"message": "x" * 5000}) or f,
    lambda f: f.update({"coverage": _cov(status="bogus")}) or f,
    lambda f: f.update({"coverage": _cov(languages=["cobol"])}) or f,
    lambda f: f.update({"records": [_rec()] * 3000}) or f,
])
def test_hostile_frames_rejected(mutate):
    with pytest.raises(ParentBoundaryError):
        validate_worker_frame(mutate(_frame()))


def test_enums_match_schema():
    """Guard: the validator's enum sets equal the schema file's — neither may drift."""
    defs = _SCHEMA["$defs"]
    assert v._LENSES == set(defs["lens"]["enum"])
    assert v._KINDS == set(defs["kind"]["enum"])
    assert v._CONFIDENCE == set(defs["confidence"]["enum"])
    skip_reason_enum = defs["coverage"]["properties"]["skipped"]["items"]["properties"]["reason"]["enum"]
    assert v._SKIP_REASONS == set(skip_reason_enum)
    lang_enum = defs["coverage"]["properties"]["languages"]["items"]["enum"]
    assert v._LANGUAGES == set(lang_enum)
    assert v._COVERAGE_STATUS == set(defs["coverage"]["properties"]["status"]["enum"])
