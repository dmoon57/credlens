#!/usr/bin/env python3
"""Assemble the pinned eval corpus into corpus/servers/ (see corpus/manifest.json).

Layout (nested by source — the name `git` exists in both source repos):

    corpus/servers/<source>/<server>/...
    corpus/servers/local/synthetic-control/...

Fetch order per source: shallow SHA fetch from the upstream repo, then the mirror
tarball on the credlens release (archived repos rot — the mirror is the fallback of
record). After assembly the tree hash is verified against manifest tree_sha256;
run with --write-hash to (re)record it when the manifest changes.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "corpus" / "manifest.json"
DEST = REPO_ROOT / "corpus" / "servers"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def fetch_source_git(url: str, sha: str, workdir: Path) -> Path:
    """Shallow-fetch a single SHA (GitHub allows reachable-SHA fetches)."""
    clone = workdir / "repo"
    clone.mkdir()
    run(["git", "init", "-q"], cwd=clone)
    run(["git", "remote", "add", "origin", url], cwd=clone)
    run(["git", "fetch", "-q", "--depth", "1", "origin", sha], cwd=clone)
    run(["git", "checkout", "-q", sha], cwd=clone)
    return clone


def fetch_source_mirror(mirror: str, workdir: Path) -> Path:
    """Download and unpack the release-asset mirror tarball (contains src/)."""
    dest = workdir / "repo"
    dest.mkdir()
    with urllib.request.urlopen(mirror, timeout=120) as resp:
        data = resp.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(dest, filter="data")
    return dest


def tree_sha256(root: Path) -> str:
    """Content hash over the assembled corpus: sorted relpath + per-file sha256."""
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        h.update(rel.encode())
        h.update(b"\0")
        h.update(hashlib.sha256(path.read_bytes()).hexdigest().encode())
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-hash", action="store_true",
                        help="record the assembled tree hash into the manifest")
    parser.add_argument("--mirror-only", action="store_true",
                        help="skip upstream git, fetch from release mirrors only")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text())

    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True)

    for source in manifest["sources"]:
        name, url, sha, mirror = source["name"], source["url"], source["sha"], source["mirror"]
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            clone = None
            if not args.mirror_only:
                try:
                    clone = fetch_source_git(url, sha, workdir)
                    print(f"[fetch] {name} @ {sha[:7]} (git)")
                except subprocess.CalledProcessError as e:
                    print(f"[fetch] {name}: git fetch failed ({e}); trying mirror", file=sys.stderr)
            if clone is None:
                clone = fetch_source_mirror(mirror, workdir)
                print(f"[fetch] {name} @ {sha[:7]} (mirror)")
            for server in source["servers"]:
                src = clone / "src" / server
                if not src.is_dir():
                    print(f"ERROR: {name}:src/{server} missing", file=sys.stderr)
                    return 1
                shutil.copytree(src, DEST / name / server)

    for local in manifest["local"]:
        shutil.copytree(REPO_ROOT / local["path"], DEST / "local" / local["name"])
        print(f"[fetch] local/{local['name']} (in-repo)")

    actual = tree_sha256(DEST)
    expected = manifest.get("tree_sha256")
    if args.write_hash:
        manifest["tree_sha256"] = actual
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"[hash] recorded {actual}")
    elif expected is None:
        print("ERROR: manifest has no tree_sha256 — run with --write-hash first", file=sys.stderr)
        return 1
    elif actual != expected:
        print(f"ERROR: corpus tree hash mismatch\n  expected {expected}\n  actual   {actual}",
              file=sys.stderr)
        return 1
    else:
        print(f"[hash] verified {actual}")

    n_servers = sum(len(s["servers"]) for s in manifest["sources"]) + len(manifest["local"])
    print(f"[done] {n_servers} servers assembled at {DEST.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
