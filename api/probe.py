"""Milestone 3.2a runtime probe (docs/specs/hosted-scan.md).

Proves, on the actual Vercel Python runtime, everything the hosted scan design leans on:
pinned tree-sitter wheels import and parse; a hanging worker subprocess (with descendants)
dies to a process-group kill; /tmp create/write/cleanup works; and codeload's observed
behavior matches the T11 acceptance matrix (?matrix=1).

Token-gated (PROBE_TOKEN env, constant-time compare) so the deployment denies
unauthenticated callers even independently of Vercel Deployment Protection.
Probe-only code: deleted when 3.3 lands the real api/scan.py.
"""

from __future__ import annotations

import hmac
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler

CODELOAD_CASES = {
    # case -> (owner, repo) — statuses are OBSERVED and reported; the acceptance
    # matrix in the spec decides what each observation maps to.
    "normal": ("dmoon57", "credlens"),
    "nonexistent": ("dmoon57", "definitely-not-a-repo-x7k2q9"),
    "renamed": ("nodejs", "io.js"),
    "huge": ("torvalds", "linux"),
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # every 3xx surfaces as HTTPError — the spec refuses redirects


def _check_wheels() -> dict:
    import tree_sitter
    import tree_sitter_javascript
    import tree_sitter_python
    import tree_sitter_typescript

    out = {"tree_sitter": tree_sitter.__version__}
    snippets = {
        "javascript": (tree_sitter_javascript.language(), b"const k = process.env.KEY;"),
        "typescript": (
            tree_sitter_typescript.language_typescript(),
            b"const k: string = process.env.KEY!;",
        ),
        "python": (tree_sitter_python.language(), b"import os\nk = os.environ['KEY']\n"),
    }
    for name, (lang, src) in snippets.items():
        parser = tree_sitter.Parser(tree_sitter.Language(lang))
        tree = parser.parse(src)
        out[name] = {"root": tree.root_node.type, "children": tree.root_node.child_count}
    return out


def _check_worker_kill() -> dict:
    # a worker that spawns its own child, then hangs — group kill must take both
    code = (
        "import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(300)']);"
        "time.sleep(300)"
    )
    t0 = time.monotonic()
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)  # let the grandchild spawn
    pgid = os.getpgid(proc.pid)
    os.killpg(pgid, signal.SIGKILL)
    rc = proc.wait(timeout=10)
    elapsed = time.monotonic() - t0
    # after a group SIGKILL nothing in the group should still be signalable
    survivors = True
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        survivors = False
    return {
        "returncode": rc,
        "elapsed_s": round(elapsed, 3),
        "group_survivors": survivors,
        "own_session": pgid == proc.pid,
    }


def _check_tmp() -> dict:
    d = tempfile.mkdtemp(prefix="credlens-probe-")
    try:
        payload = os.urandom(1024) * 1024  # 1 MiB
        p = os.path.join(d, "blob")
        with open(p, "wb") as f:
            f.write(payload)
        with open(p, "rb") as f:
            ok = f.read() == payload
        usage = shutil.disk_usage(tempfile.gettempdir())
        return {
            "dir": d,
            "roundtrip_1mib": ok,
            "tmp_free_mb": usage.free // (1024 * 1024),
        }
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _check_runtime() -> dict:
    return {
        "python": sys.version.split()[0],
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
        "vercel_region": os.environ.get("VERCEL_REGION"),
        "vercel_env": os.environ.get("VERCEL_ENV"),
    }


def _check_codeload_matrix() -> dict:
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
    results = {}
    for case, (owner, repo) in CODELOAD_CASES.items():
        url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"
        entry: dict = {}
        try:
            with opener.open(url, timeout=8) as resp:
                magic = resp.read(2)
                entry["status"] = resp.status
                entry["gzip_magic"] = magic == b"\x1f\x8b"
        except urllib.error.HTTPError as e:  # includes refused redirects
            entry["status"] = e.code
            entry["location"] = "github" if "github" in (e.headers.get("Location") or "") else None
        except Exception as e:  # noqa: BLE001 — probe reports, never raises
            entry["error"] = type(e).__name__
        results[case] = entry
    return results


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        expected = os.environ.get("PROBE_TOKEN", "")
        got = self.headers.get("X-Probe-Token", "")
        if not expected or not hmac.compare_digest(expected, got):
            self._respond(403, {"error": "forbidden"})
            return

        report: dict = {"probe": "3.2a", "checks": {}}
        checks = {
            "wheels": _check_wheels,
            "worker_kill": _check_worker_kill,
            "tmp": _check_tmp,
            "runtime": _check_runtime,
        }
        if "matrix=1" in (self.path or ""):
            checks["codeload_matrix"] = _check_codeload_matrix
        for name, fn in checks.items():
            try:
                report["checks"][name] = {"ok": True, "result": fn()}
            except Exception as e:  # noqa: BLE001 — a failing check is the finding
                report["checks"][name] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        self._respond(200, report)

    def _respond(self, status: int, body: dict):
        data = json.dumps(body, indent=1).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # keep function logs terse
        pass
