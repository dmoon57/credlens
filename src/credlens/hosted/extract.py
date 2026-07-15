"""Streamed, metered tar extraction (docs/specs/hosted-scan.md T2/T3).

The one place hostile GitHub-tarball bytes are unpacked. Everything is streamed and
metered so a bomb is caught at the decompression boundary, never after the fact:

    raw gzip stream
      -> _Counter(max_compressed)        # bytes off the wire
      -> gzip.GzipFile                    # inflate
      -> _Counter(max_decompressed)       # inflated bytes — the bomb backstop
      -> tarfile.open(mode="r|")          # forward-only streaming, never getmembers()

Only directories and regular files are ever written. Symlinks, hardlinks, devices,
absolute paths, and `..` escapes are rejected outright (data_filter alone permits
inside-destination links, so this is a stricter hand-rolled policy). Any cap breach
or hostile member raises ExtractError(reason) — the caller extracts into a throwaway
tmpdir, so partial output on raise is fine.
"""

from __future__ import annotations

import gzip
import os
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from credlens.hosted.limits import Limits

_CHUNK = 64 * 1024


class ExtractError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass
class ExtractStats:
    files_written: int
    bytes_written: int


class _Counter:
    """A read()-only passthrough that trips ExtractError(reason) past a byte cap."""

    def __init__(self, fileobj, cap: int, reason: str):
        self._f = fileobj
        self._cap = cap
        self._reason = reason
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._f.read(size)
        self.total += len(chunk)
        if self.total > self._cap:
            raise ExtractError(self._reason)
        return chunk


def _safe_target(dest: Path, name: str) -> Path | None:
    """Resolve a member name under dest lexically; None if absolute or escaping."""
    if not name or name.startswith("/") or os.path.isabs(name) or "\x00" in name:
        return None
    dest_s = os.path.normpath(str(dest))
    target = os.path.normpath(os.path.join(dest_s, name))
    if target != dest_s and not target.startswith(dest_s + os.sep):
        return None
    return Path(target)


def safe_extract(raw_stream, dest: Path, limits: Limits = Limits()) -> ExtractStats:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest  # already the jail root; members validated lexically against it

    compressed = _Counter(raw_stream, limits.max_compressed, "too_large_compressed")
    files_written = 0
    bytes_written = 0
    seen_files: set[str] = set()
    member_count = 0

    try:
        gz = gzip.GzipFile(fileobj=compressed, mode="rb")
        decompressed = _Counter(gz, limits.max_decompressed, "too_large_decompressed")
        with tarfile.open(fileobj=decompressed, mode="r|") as tar:
            for member in tar:
                member_count += 1
                if member_count > limits.max_files:
                    raise ExtractError("too_many_files")
                if len(member.name) > limits.max_name_len:
                    raise ExtractError("name_too_long")
                # only directories and regular files may exist; everything else is hostile
                if not (member.isdir() or member.isreg()):
                    raise ExtractError("unsafe_member")
                target = _safe_target(dest_resolved, member.name)
                if target is None:
                    raise ExtractError("unsafe_member")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                # regular file
                if member.size > limits.max_file_bytes:
                    raise ExtractError("member_too_large")
                key = str(target)
                if key in seen_files:
                    raise ExtractError("duplicate_path")
                seen_files.add(key)
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tar.extractfile(member)
                if src is None:
                    raise ExtractError("unsafe_member")
                written = 0
                with open(target, "wb") as out:
                    while True:
                        chunk = src.read(_CHUNK)
                        if not chunk:
                            break
                        written += len(chunk)
                        bytes_written += len(chunk)
                        if bytes_written > limits.max_written:
                            raise ExtractError("too_large_written")
                        out.write(chunk)
                files_written += 1
    except ExtractError:
        raise
    except gzip.BadGzipFile:
        raise ExtractError("not_gzip") from None
    except (EOFError, zlib.error, tarfile.ReadError, tarfile.StreamError, OSError) as e:
        raise ExtractError("corrupt") from e

    return ExtractStats(files_written=files_written, bytes_written=bytes_written)
