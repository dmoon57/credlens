"""Parent-side scan orchestration (docs/specs/hosted-scan.md §Isolation).

Spawns the scan worker in its own process group with a scrubbed environment, watches
its stderr progress stream to enforce a per-file stall deadline plus a whole-scan
deadline, and on any deadline or failure SIGKILLs the entire group (so a hung native
parser or a spawned grandchild can't survive). On clean success it reads the single
length-prefixed stdout frame and validates it at the parent boundary before returning.

A native worker death or a stall-kill yields ScanFailed; an extract/parse rejection
yields ScanRejected(reason) — the handler maps those to distinct HTTP outcomes.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from credlens.hosted.frame import FrameError, read_frame
from credlens.hosted.limits import Limits
from credlens.hosted.validate import ParentBoundaryError, validate_worker_frame
from credlens.hosted.worker import PROGRESS_PREFIX, REJECT_PREFIX


@dataclass(frozen=True)
class Deadlines:
    per_file_s: float = 5.0     # max stall between progress markers
    total_s: float = 45.0       # whole-scan wall clock
    poll_s: float = 0.05


class ScanFailed(Exception):
    """Worker died, stalled, or returned an invalid frame — HTTP 500 scan_failed."""


class ScanRejected(Exception):
    """Worker rejected the archive; .reason is the extract/parse short code."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass
class _Watch:
    last_progress: float
    reject_reason: str | None = None


def _drain_stderr(pipe, watch: _Watch, lock: threading.Lock) -> None:
    for raw in iter(pipe.readline, b""):
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith(PROGRESS_PREFIX):
            with lock:
                watch.last_progress = time.monotonic()
        elif line.startswith(REJECT_PREFIX):
            with lock:
                watch.reject_reason = line[len(REJECT_PREFIX):].strip()


def scan_tarball(
    tarball_path: Path,
    dest: Path,
    *,
    limits: Limits = Limits(),
    deadlines: Deadlines = Deadlines(),
    worker_cmd: list[str] | None = None,
) -> dict:
    """Run the scan worker over a local tarball; return the validated frame dict.

    `worker_cmd` overrides the subprocess argv (tests inject hanging/crashing workers);
    the tarball path, dest, and limits JSON are always appended as the final three args.
    """
    args = [json.dumps({k: getattr(limits, k) for k in limits.__dataclass_fields__})]
    cmd = (worker_cmd or [sys.executable, "-m", "credlens.hosted.worker"]) + [
        str(tarball_path), str(dest), *args
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,   # own process group → killpg takes descendants too
        env={"PATH": os.environ.get("PATH", "")},  # scrubbed: no tokens, no proxy vars
    )
    watch = _Watch(last_progress=time.monotonic())
    lock = threading.Lock()
    drainer = threading.Thread(target=_drain_stderr, args=(proc.stderr, watch, lock), daemon=True)
    drainer.start()

    start = time.monotonic()
    killed_reason: str | None = None
    while proc.poll() is None:
        now = time.monotonic()
        with lock:
            stalled = (now - watch.last_progress) > deadlines.per_file_s
        if now - start > deadlines.total_s:
            killed_reason = "total_deadline"
        elif stalled:
            killed_reason = "stall_deadline"
        if killed_reason:
            _kill_group(proc)
            break
        time.sleep(deadlines.poll_s)

    rc = proc.wait()
    frame_bytes = proc.stdout.read() if proc.stdout else b""
    drainer.join(timeout=1.0)

    if killed_reason is not None:
        raise ScanFailed(killed_reason)
    if rc == 2 or watch.reject_reason is not None:
        raise ScanRejected(watch.reject_reason or "rejected")
    if rc != 0:
        raise ScanFailed(f"worker exit {rc}")
    try:
        import io
        frame = read_frame(io.BytesIO(frame_bytes))
        return validate_worker_frame(frame)
    except (FrameError, ParentBoundaryError) as e:
        raise ScanFailed(f"bad frame: {e}") from e


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
