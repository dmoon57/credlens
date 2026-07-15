"""Repo-identifier parsing + codeload tarball fetch (docs/specs/hosted-scan.md T1/T11).

The user string is PARSED, never fetched: a strict ASCII full-match yields owner/repo,
and the download URL is rebuilt from those components against a pinned host. The opener
refuses redirects and ignores environment proxies, so the fetcher can only ever address
codeload.github.com — the whole SSRF class is closed structurally. Fetch is the parent's
job (it holds the network); the scan worker only ever sees a local tarball file.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from pathlib import Path

from credlens.hosted.limits import Limits

CODELOAD_HOST = "codeload.github.com"
_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
_REPO = r"[A-Za-z0-9._-]{1,100}"
_SHORT = re.compile(rf"({_OWNER})/({_REPO})", re.ASCII)
_URL = re.compile(rf"https://github\.com/({_OWNER})/({_REPO})", re.ASCII)
_CHUNK = 64 * 1024


class FetchError(Exception):
    """Fetch rejected. .reason ∈ {bad_request, not_found, upstream_unsupported,
    too_large_compressed}."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # any 3xx surfaces as HTTPError — redirects are refused (T1)


def parse_repo(s: str) -> tuple[str, str]:
    """Accept `owner/repo` or `https://github.com/owner/repo`; reject everything else.

    ASCII-only full match rejects unicode confusables, `.`/`..`, ports, userinfo, query,
    and fragments by construction.
    """
    s = (s or "").strip()
    m = _SHORT.fullmatch(s) or _URL.fullmatch(s)
    if not m:
        raise FetchError("bad_request")
    owner, repo = m.group(1), m.group(2)
    if repo in (".", ".."):
        raise FetchError("bad_request")
    return owner, repo


def codeload_url(owner: str, repo: str) -> str:
    return f"https://{CODELOAD_HOST}/{owner}/{repo}/tar.gz/HEAD"


def _default_opener():
    return urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


def fetch_tarball(
    owner: str,
    repo: str,
    dest_path: Path,
    *,
    limits: Limits = Limits(),
    opener=None,
    timeout: float = 15.0,
) -> None:
    """Stream the pinned-host tarball to dest_path, capped at max_compressed bytes.

    Requires HTTP 200 + gzip magic; a 3xx (redirect refused) or 404 → not_found; any
    other status or a non-gzip body → upstream_unsupported; over-cap → too_large_compressed.
    """
    opener = opener or _default_opener()
    url = codeload_url(owner, repo)
    try:
        resp = opener.open(url, timeout=timeout)
    except urllib.error.HTTPError as e:
        raise FetchError("not_found" if e.code in (301, 302, 303, 307, 308, 404, 410, 451)
                         else "upstream_unsupported") from None
    except urllib.error.URLError as e:
        raise FetchError("upstream_unsupported") from e

    with resp:
        if getattr(resp, "status", 200) != 200:
            raise FetchError("upstream_unsupported")
        total = 0
        first = b""
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "wb") as out:
            while True:
                chunk = resp.read(_CHUNK)
                if not chunk:
                    break
                if not first:
                    first = chunk[:2]
                total += len(chunk)
                if total > limits.max_compressed:
                    raise FetchError("too_large_compressed")
                out.write(chunk)
        if first[:2] != b"\x1f\x8b":
            raise FetchError("upstream_unsupported")  # 200 but not a gzip tarball
