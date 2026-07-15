"""Length-prefixed worker→parent framing (docs/specs/hosted-scan.md §Parent-boundary).

A dead or hostile worker must never make the parent allocate unbounded memory, so the
result crosses the pipe as a 4-byte big-endian length + JSON body, and the parent
refuses any length over the frame cap *before* reading the body.
"""

from __future__ import annotations

import json
import struct

FRAME_CAP = 2 * 1024 * 1024  # 2 MiB — parent-enforced (spec T12)
_HEADER = struct.Struct(">I")


class FrameError(Exception):
    """Frame missing, truncated, over-cap, or not valid JSON."""


def write_frame(fileobj, obj) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    fileobj.write(_HEADER.pack(len(body)))
    fileobj.write(body)
    fileobj.flush()


def read_frame(fileobj, cap: int = FRAME_CAP):
    header = _read_exactly(fileobj, _HEADER.size)
    if header is None:
        raise FrameError("no frame (worker produced no output)")
    (length,) = _HEADER.unpack(header)
    if length > cap:
        raise FrameError(f"frame length {length} exceeds cap {cap}")
    body = _read_exactly(fileobj, length)
    if body is None:
        raise FrameError("frame truncated")
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        raise FrameError(f"frame not valid JSON: {e}") from e


def _read_exactly(fileobj, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = fileobj.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
