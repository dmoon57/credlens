"""Adversarial tests for the streaming, metered tar extractor.

Written in isolation from the implementation (repo working agreement): these
fixtures must not be shaped around whatever `safe_extract` happens to do —
only around the documented contract (`ExtractError.reason` codes) and the
threat model in docs/specs/hosted-scan.md (T2/T3).
"""

from __future__ import annotations

import io
import pathlib

import pytest

from credlens.hosted.extract import ExtractError, safe_extract
from credlens.hosted.limits import Limits

from . import tars


def _make_dest(tmp_path: pathlib.Path) -> pathlib.Path:
    dest = tmp_path / "dest"
    dest.mkdir()
    return dest


def _assert_nothing_escaped(tmp_path: pathlib.Path, dest: pathlib.Path) -> None:
    """The real security property: after any hostile extraction attempt,
    nothing was written outside `dest` (no siblings appeared under the
    tmp_path that contains it)."""
    siblings = [p for p in tmp_path.iterdir() if p != dest]
    assert siblings == [], f"unexpected paths escaped dest: {siblings}"


def test_benign_extracts_all_files_and_nothing_escapes(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.benign_tar())

    stats = safe_extract(raw, dest)

    assert stats.files_written == 3
    assert (dest / "repo" / "index.ts").read_bytes() == b"export const ok = true;\n"
    assert (dest / "repo" / "main.py").read_bytes() == b"print('hello')\n"
    assert (dest / "repo" / "util.ts").read_bytes() == b"export function noop() {}\n"
    assert stats.bytes_written == sum(
        len(p.read_bytes())
        for p in [
            dest / "repo" / "index.ts",
            dest / "repo" / "main.py",
            dest / "repo" / "util.ts",
        ]
    )
    _assert_nothing_escaped(tmp_path, dest)


def test_traversal_member_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.traversal_tar())

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "unsafe_member"
    _assert_nothing_escaped(tmp_path, dest)


def test_absolute_path_member_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.absolute_path_tar())

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "unsafe_member"
    _assert_nothing_escaped(tmp_path, dest)


def test_symlink_escape_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.symlink_tar())

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "unsafe_member"
    _assert_nothing_escaped(tmp_path, dest)


def test_internal_symlink_rejected(tmp_path):
    """Every symlink is rejected, even one that would resolve inside dest."""
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.internal_symlink_tar())

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "unsafe_member"
    _assert_nothing_escaped(tmp_path, dest)


def test_hardlink_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.hardlink_tar())

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "unsafe_member"
    _assert_nothing_escaped(tmp_path, dest)


def test_device_member_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.device_tar())

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "unsafe_member"
    _assert_nothing_escaped(tmp_path, dest)


def test_gzip_bomb_trips_decompressed_cap(tmp_path):
    dest = _make_dest(tmp_path)
    # max_file_bytes raised above the bomb's own size so the per-member cap
    # can't fire first — isolates the running decompressed-total cap.
    limits = Limits(max_decompressed=10 * 1024 * 1024, max_file_bytes=50 * 1024 * 1024)
    raw = io.BytesIO(tars.gzip_bomb_tar(total_size=20 * 1024 * 1024))

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest, limits)

    assert ei.value.reason == "too_large_decompressed"
    _assert_nothing_escaped(tmp_path, dest)


def test_too_many_files_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    limits = Limits(max_files=100)
    raw = io.BytesIO(tars.many_files_tar(150))

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest, limits)

    assert ei.value.reason == "too_many_files"
    _assert_nothing_escaped(tmp_path, dest)


def test_oversize_member_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    limits = Limits(max_file_bytes=1024)
    raw = io.BytesIO(tars.oversize_member_tar(size=2048))

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest, limits)

    assert ei.value.reason == "member_too_large"
    _assert_nothing_escaped(tmp_path, dest)


def test_duplicate_path_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.duplicate_path_tar())

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "duplicate_path"
    _assert_nothing_escaped(tmp_path, dest)


def test_long_name_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.long_name_tar(name_len=600))

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "name_too_long"
    _assert_nothing_escaped(tmp_path, dest)


def test_not_gzip_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.not_gzip_bytes())

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "not_gzip"
    _assert_nothing_escaped(tmp_path, dest)


def test_truncated_gzip_rejected(tmp_path):
    dest = _make_dest(tmp_path)
    raw = io.BytesIO(tars.truncated_gzip_tar())

    with pytest.raises(ExtractError) as ei:
        safe_extract(raw, dest)

    assert ei.value.reason == "corrupt"
    _assert_nothing_escaped(tmp_path, dest)
