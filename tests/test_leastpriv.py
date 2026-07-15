"""Least-privilege inventory detector (Move 2.3).

Everything it emits is inventory (never a finding), so it can never move precision.
The load-bearing behaviors: it distinguishes a caller-controlled Authorization value
(confused-deputy) from a server sending its OWN configured token, and tags scope breadth.
"""

from pathlib import Path

import pytest

from credlens.detectors import LeastPrivDetector
from credlens.detectors.base import LENS_CAPABILITY

DET = LeastPrivDetector()
REPO = Path(__file__).resolve().parent.parent
SERVERS = REPO / "corpus" / "servers"


def _msgs(code):
    return [f.message for f in DET.scan_text("t.ts", code)]


def _kinds(code):
    return {f.kind for f in DET.scan_text("t.ts", code)}


def test_everything_is_inventory_never_a_finding():
    code = 'const t = process.env.API_KEY;\nexec("rm -rf /");\nfetch("https://x");'
    kinds = _kinds(code)
    assert kinds <= {"inventory"}
    assert all(f.lens == LENS_CAPABILITY for f in DET.scan_text("t.ts", code))


def test_confused_deputy_flagged_when_caller_controlled():
    code = ('export async function proxy(userToken: string) {\n'
            '  return fetch("https://api.example.com", '
            '{ headers: { Authorization: `Bearer ${userToken}` } });\n}')
    assert any("confused-deputy" in m for m in _msgs(code))


def test_own_configured_token_is_not_passthrough():
    code = ('const TOKEN = process.env.GITHUB_TOKEN;\n'
            'export async function api() {\n'
            '  return fetch("https://api.github.com", '
            '{ headers: { Authorization: `Bearer ${TOKEN}` } });\n}')
    assert not any("confused-deputy" in m for m in _msgs(code))


def test_scope_breadth_tagging():
    narrow = 'const a = new google.auth.GoogleAuth({ scopes: ["https://x/auth/drive.readonly"] });'
    broad = 'const a = new google.auth.GoogleAuth({ scopes: ["https://x/auth/drive", "admin.write"] });'
    assert any("narrow" in m for m in _msgs(narrow))
    assert any("broad" in m for m in _msgs(broad))


def test_categories_aggregate_once_per_file():
    code = 'fetch("a");\nfetch("b");\nfetch("c");'  # three fetches, one outbound-network item
    outbound = [m for m in _msgs(code) if "outbound network" in m]
    assert len(outbound) == 1


@pytest.mark.skipif(not SERVERS.exists(), reason="corpus not assembled (make corpus)")
def test_real_servers_emit_zero_findings():
    """The whole point: the inventory pass never asserts misbehavior on real code."""
    for path in SERVERS.rglob("*.ts"):
        rel = path.relative_to(SERVERS).as_posix()
        if rel.startswith("local/"):
            continue
        for f in DET.scan_text(rel, path.read_text(errors="replace")):
            assert f.kind == "inventory", f"{rel}:{f.line} emitted a {f.kind}"
