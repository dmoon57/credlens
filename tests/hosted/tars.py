"""Pure-stdlib builders for adversarial (and one benign) gzip'd tarballs.

Every function returns raw gzipped tar bytes (as `bytes`), built entirely in
memory via `tarfile`/`gzip`/`io`. These are adversarial *fixtures* only — no
implementation code is imported or exercised here. Members are constructed by
hand via `tarfile.TarInfo` so we can author shapes (symlinks, hardlinks,
device nodes, traversal/absolute names) that `tarfile.add()` from real
filesystem paths would refuse to create.
"""

from __future__ import annotations

import io
import tarfile


def _new_writer(buf: io.BytesIO) -> tarfile.TarFile:
    # PAX format so overlong names/links round-trip without truncation.
    return tarfile.open(fileobj=buf, mode="w|gz", format=tarfile.PAX_FORMAT)


def _add_file(tf: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.REGTYPE
    info.size = len(content)
    tf.addfile(info, io.BytesIO(content))


def _add_link(tf: tarfile.TarFile, name: str, linkname: str, link_type: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = link_type
    info.linkname = linkname
    info.size = 0
    tf.addfile(info)


def _add_device(tf: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.CHRTYPE
    info.devmajor = 1
    info.devminor = 5
    info.size = 0
    tf.addfile(info)


class _ZeroStream:
    """A read-only file-like yielding `size` zero bytes, without ever
    materializing the whole thing in memory (tarfile reads it in small
    chunks via .read(n))."""

    def __init__(self, size: int) -> None:
        self._left = size

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self._left
        n = min(n, self._left)
        self._left -= n
        return b"\0" * n


def benign_tar() -> bytes:
    """3 small regular files under a subdir — the happy path."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        _add_file(tf, "repo/index.ts", b"export const ok = true;\n")
        _add_file(tf, "repo/main.py", b"print('hello')\n")
        _add_file(tf, "repo/util.ts", b"export function noop() {}\n")
    return buf.getvalue()


def traversal_tar() -> bytes:
    """A member named `../escape.js` — classic path traversal."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        _add_file(tf, "../escape.js", b"console.log('escaped');\n")
    return buf.getvalue()


def absolute_path_tar() -> bytes:
    """A member with an absolute path name."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        _add_file(tf, "/etc/evil.js", b"console.log('evil');\n")
    return buf.getvalue()


def symlink_tar() -> bytes:
    """A symlink member pointing outside dest."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        _add_link(tf, "repo/link_out", "../../../etc/passwd", tarfile.SYMTYPE)
    return buf.getvalue()


def internal_symlink_tar() -> bytes:
    """A symlink member pointing to a sibling that would resolve inside
    dest — still rejected per the "every symlink" policy (T3)."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        _add_file(tf, "repo/target.txt", b"hi\n")
        _add_link(tf, "repo/link_in", "target.txt", tarfile.SYMTYPE)
    return buf.getvalue()


def hardlink_tar() -> bytes:
    """A hardlink member."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        _add_file(tf, "repo/a.txt", b"hi\n")
        _add_link(tf, "repo/b.txt", "a.txt", tarfile.LNKTYPE)
    return buf.getvalue()


def device_tar() -> bytes:
    """A character-device member."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        _add_device(tf, "repo/dev_evil")
    return buf.getvalue()


def gzip_bomb_tar(total_size: int = 200 * 1024 * 1024) -> bytes:
    """A single member whose declared+actual content is `total_size` bytes
    of a repeating (highly compressible) byte, streamed in without holding
    the whole thing in RAM. Compressed output stays tiny since it's all
    zeros. Placed as the (only, hence first) member so the decompressed
    counter must trip while extracting it."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        info = tarfile.TarInfo(name="repo/bomb.bin")
        info.type = tarfile.REGTYPE
        info.size = total_size
        tf.addfile(info, _ZeroStream(total_size))
    return buf.getvalue()


def many_files_tar(n: int) -> bytes:
    """`n` tiny regular files — for use with a small custom `max_files`."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        for i in range(n):
            _add_file(tf, f"repo/f{i}.txt", b"x")
    return buf.getvalue()


def oversize_member_tar(size: int = 2048) -> bytes:
    """One regular file of `size` bytes — pair with a small `max_file_bytes`
    (e.g. 1024) so it exceeds the per-file cap."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        _add_file(tf, "repo/big.bin", b"A" * size)
    return buf.getvalue()


def duplicate_path_tar() -> bytes:
    """Two regular members that resolve to the same destination path."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        _add_file(tf, "repo/dup.txt", b"first\n")
        _add_file(tf, "repo/dup.txt", b"second\n")
    return buf.getvalue()


def long_name_tar(name_len: int = 600) -> bytes:
    """A member whose name length exceeds `max_name_len` (default 512)."""
    buf = io.BytesIO()
    with _new_writer(buf) as tf:
        name = "repo/" + ("a" * name_len) + ".txt"
        _add_file(tf, name, b"hi\n")
    return buf.getvalue()


def not_gzip_bytes() -> bytes:
    """Raw bytes that aren't gzip at all (no gzip magic)."""
    return b"this is definitely not a gzip stream, obviously\n" * 4


def truncated_gzip_tar() -> bytes:
    """A valid gzip'd tar with the tail bytes chopped off."""
    full = benign_tar()
    return full[: len(full) // 2]
