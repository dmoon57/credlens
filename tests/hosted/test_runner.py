"""Worker-isolation tests (docs/specs/hosted-scan.md §Isolation, §Verification).

Proves the parent-side guarantees against injected hostile/broken workers: a hang is
killed at the stall deadline and takes its whole process group (grandchildren) with it;
a native death fails the scan; an over-cap or malformed frame is rejected at the parent
boundary; an extract rejection surfaces distinctly; and the happy path scans end to end.
"""

from __future__ import annotations

import gzip
import io
import os
import sys
import tarfile
import time
from pathlib import Path

import pytest

from credlens.hosted.limits import Limits
from credlens.hosted.runner import (
    Deadlines,
    ScanFailed,
    ScanRejected,
    scan_tarball,
)


def _gztar(files: list[tuple[str, bytes]]) -> io.BytesIO:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as t:
        for name, data in files:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    comp = io.BytesIO()
    with gzip.GzipFile(fileobj=comp, mode="wb") as g:
        g.write(raw.getvalue())
    comp.seek(0)
    return comp


def _write_tarball(tmp_path: Path, files: list[tuple[str, bytes]]) -> Path:
    p = tmp_path / "repo.tgz"
    p.write_bytes(_gztar(files).getvalue())
    return p


def _dest(tmp_path: Path) -> Path:
    return tmp_path / "scan"


# --- injected worker scripts (bypass the real worker to simulate failure modes) ---

_HANG = """
import sys, time, subprocess
pidfile = sys.argv[-1]  # we append it ourselves below via worker_cmd
sys.stderr.write("P start\\n"); sys.stderr.flush()
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
open(pidfile, "w").write(str(child.pid))
time.sleep(300)
"""

_CRASH = "import os; os._exit(139)"

_OVERSIZE_FRAME = (
    "import sys, struct; b=b'x'*(3*1024*1024);"
    "sys.stdout.buffer.write(struct.pack('>I', len(b))+b); sys.stdout.buffer.flush()"
)

_GARBAGE_FRAME = (
    "import sys, struct; b=b'not json at all';"
    "sys.stdout.buffer.write(struct.pack('>I', len(b))+b); sys.stdout.buffer.flush()"
)


def test_happy_path_scans_end_to_end(tmp_path):
    leak = b"const k = process.env.SECRET_KEY;\nconsole.log(k);\n"
    tb = _write_tarball(tmp_path, [("repo/index.js", leak), ("repo/ok.ts", b"export const x=1;\n")])
    frame = scan_tarball(tb, _dest(tmp_path))
    findings = [r for r in frame["records"] if r["kind"] == "finding"]
    assert any(r["lens"] == "credential" and r["file"] == "repo/index.js" for r in findings)
    assert frame["coverage"]["files_scanned"] == 2
    assert frame["coverage"]["status"] == "complete"


def test_hang_is_stall_killed_with_whole_group(tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    # worker_cmd's trailing args become the worker's argv; _HANG reads argv[-1] as the pidfile,
    # but scan_tarball appends (tarball, dest, limits-json) after our args — so put pidfile last-1?
    # simpler: bake the pidfile path into the script via a format, not argv.
    script = _HANG.replace("sys.argv[-1]", repr(str(pidfile)))
    tb = _write_tarball(tmp_path, [("r/a.js", b"x")])
    cmd = [sys.executable, "-c", script]
    t0 = time.monotonic()
    with pytest.raises(ScanFailed):
        scan_tarball(tb, _dest(tmp_path), worker_cmd=cmd,
                     deadlines=Deadlines(per_file_s=1.0, total_s=30, poll_s=0.05))
    assert time.monotonic() - t0 < 10  # killed promptly, not after 300s
    # the spawned grandchild must have died with the process group
    time.sleep(0.4)
    child_pid = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_total_deadline_kills(tmp_path):
    # a worker that keeps emitting progress (never stalls) must still hit the total deadline
    script = (
        "import sys,time\n"
        "while True:\n"
        "    sys.stderr.write('P tick\\n'); sys.stderr.flush(); time.sleep(0.1)\n"
    )
    tb = _write_tarball(tmp_path, [("r/a.js", b"x")])
    with pytest.raises(ScanFailed):
        scan_tarball(tb, _dest(tmp_path), worker_cmd=[sys.executable, "-c", script],
                     deadlines=Deadlines(per_file_s=5.0, total_s=1.0, poll_s=0.05))


def test_native_death_is_scan_failed(tmp_path):
    tb = _write_tarball(tmp_path, [("r/a.js", b"x")])
    with pytest.raises(ScanFailed):
        scan_tarball(tb, _dest(tmp_path), worker_cmd=[sys.executable, "-c", _CRASH])


def test_oversize_frame_rejected(tmp_path):
    tb = _write_tarball(tmp_path, [("r/a.js", b"x")])
    with pytest.raises(ScanFailed):
        scan_tarball(tb, _dest(tmp_path), worker_cmd=[sys.executable, "-c", _OVERSIZE_FRAME])


def test_garbage_frame_rejected(tmp_path):
    tb = _write_tarball(tmp_path, [("r/a.js", b"x")])
    with pytest.raises(ScanFailed):
        scan_tarball(tb, _dest(tmp_path), worker_cmd=[sys.executable, "-c", _GARBAGE_FRAME])


def test_extract_rejection_surfaces_distinctly(tmp_path):
    tb = _write_tarball(tmp_path, [(f"r/f{i}.js", b"x") for i in range(6)])
    with pytest.raises(ScanRejected) as ei:
        scan_tarball(tb, _dest(tmp_path), limits=Limits(max_files=3))
    assert ei.value.reason == "too_many_files"
