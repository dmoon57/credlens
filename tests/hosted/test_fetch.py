"""Identifier-parse + fetch tests (docs/specs/hosted-scan.md T1/T11).

The parser is the SSRF boundary, so it gets hostile inputs; the fetcher is exercised
with an injected opener (no real network) covering the codeload status matrix.
"""

from __future__ import annotations

import io
import urllib.error

import pytest

from credlens.hosted.fetch import (
    CODELOAD_HOST,
    FetchError,
    codeload_url,
    fetch_tarball,
    parse_repo,
)
from credlens.hosted.limits import Limits


@pytest.mark.parametrize("s,owner,repo", [
    ("torvalds/linux", "torvalds", "linux"),
    ("https://github.com/torvalds/linux", "torvalds", "linux"),
    ("a/b.c-d_e", "a", "b.c-d_e"),
    ("  torvalds/linux\n", "torvalds", "linux"),  # surrounding whitespace is stripped
])
def test_parse_accepts_valid(s, owner, repo):
    assert parse_repo(s) == (owner, repo)


@pytest.mark.parametrize("s", [
    "",
    "onlyowner",
    "owner/repo/extra",
    "../etc/passwd",
    "owner/..",
    "owner/.",
    "git://github.com/o/r",
    "file:///etc/passwd",
    "https://github.com:22/o/r",
    "https://user@github.com/o/r",
    "https://github.com/o/r?x=1",
    "https://github.com/o/r#frag",
    "https://evil.com/o/r",
    "https://codeload.github.com/o/r",
    "оwner/repo",           # cyrillic 'о' — unicode confusable
    "owner/re\npo",         # embedded newline (survives strip) must be rejected
    "own er/repo",
])
def test_parse_rejects_hostile(s):
    with pytest.raises(FetchError):
        parse_repo(s)


def test_codeload_url_is_pinned_host():
    url = codeload_url("torvalds", "linux")
    assert url == f"https://{CODELOAD_HOST}/torvalds/linux/tar.gz/HEAD"


# --- fetch with an injected opener ---

class _Resp(io.BytesIO):
    def __init__(self, data, status=200):
        super().__init__(data)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class _Opener:
    def __init__(self, resp=None, error=None):
        self._resp = resp
        self._error = error
        self.opened = []

    def open(self, url, timeout=None):
        self.opened.append(url)
        if self._error:
            raise self._error
        return self._resp


def test_fetch_happy_writes_gzip(tmp_path):
    gzip_bytes = b"\x1f\x8b" + b"rest-of-a-tarball"
    opener = _Opener(resp=_Resp(gzip_bytes))
    dest = tmp_path / "repo.tgz"
    fetch_tarball("o", "r", dest, opener=opener)
    assert dest.read_bytes() == gzip_bytes
    assert opener.opened == [f"https://{CODELOAD_HOST}/o/r/tar.gz/HEAD"]


def test_fetch_404_is_not_found(tmp_path):
    err = urllib.error.HTTPError("u", 404, "nf", {}, None)
    with pytest.raises(FetchError) as ei:
        fetch_tarball("o", "r", tmp_path / "x.tgz", opener=_Opener(error=err))
    assert ei.value.reason == "not_found"


def test_fetch_redirect_refused_is_not_found(tmp_path):
    # a refused redirect surfaces as HTTPError 301 through _NoRedirect
    err = urllib.error.HTTPError("u", 301, "moved", {}, None)
    with pytest.raises(FetchError) as ei:
        fetch_tarball("o", "r", tmp_path / "x.tgz", opener=_Opener(error=err))
    assert ei.value.reason == "not_found"


def test_fetch_500_is_upstream_unsupported(tmp_path):
    err = urllib.error.HTTPError("u", 500, "err", {}, None)
    with pytest.raises(FetchError) as ei:
        fetch_tarball("o", "r", tmp_path / "x.tgz", opener=_Opener(error=err))
    assert ei.value.reason == "upstream_unsupported"


def test_fetch_200_non_gzip_is_upstream_unsupported(tmp_path):
    opener = _Opener(resp=_Resp(b"<html>not a tarball</html>"))
    with pytest.raises(FetchError) as ei:
        fetch_tarball("o", "r", tmp_path / "x.tgz", opener=opener)
    assert ei.value.reason == "upstream_unsupported"


def test_fetch_oversize_is_too_large(tmp_path):
    big = b"\x1f\x8b" + b"A" * (5 * 1024)
    opener = _Opener(resp=_Resp(big))
    with pytest.raises(FetchError) as ei:
        fetch_tarball("o", "r", tmp_path / "x.tgz", opener=opener, limits=Limits(max_compressed=1024))
    assert ei.value.reason == "too_large_compressed"
