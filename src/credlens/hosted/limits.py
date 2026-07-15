"""Extraction / scan caps (docs/specs/hosted-scan.md §Interface & limits).

One frozen dataclass so tests can dial caps down for fast, low-memory adversarial
runs while production uses the defaults. Numbers mirror the spec's limits table.
"""

from __future__ import annotations

from dataclasses import dataclass

_MB = 1024 * 1024


@dataclass(frozen=True)
class Limits:
    max_compressed: int = 30 * _MB       # raw gzip bytes off the wire
    max_decompressed: int = 150 * _MB    # total inflated tar bytes (bomb backstop)
    max_written: int = 100 * _MB         # total bytes written to disk
    max_files: int = 5000                # member count
    max_file_bytes: int = 1 * _MB        # per regular file
    max_name_len: int = 512              # member name length
