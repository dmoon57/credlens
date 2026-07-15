"""The credential lens vs the four-FP-class fixtures (authored in isolation).

These are the Move 2.1 fixtures: the detector must stay silent on the three
false-positive classes (name-not-value, window-overshoot, path-not-secret) and fire
on the aliased must-catch. expected.json carries the ground truth (with reasons).
"""

import json
from pathlib import Path

import pytest

from credlens.detectors import CredentialDetector
from credlens.detectors.base import LENS_CREDENTIAL

FX = Path(__file__).resolve().parent / "fixtures" / "credential"
EXPECTED = json.loads((FX / "expected.json").read_text())["fixtures"]
DETECTOR = CredentialDetector()


def _run(fixture):
    text = (FX / fixture["file"]).read_text()
    out = [f for f in DETECTOR.scan_text(fixture["file"], text) if f.lens == LENS_CREDENTIAL]
    findings = sorted((f.line for f in out if f.kind == "finding"))
    inventory = sorted((f.line for f in out if f.kind == "inventory"))
    return findings, inventory


@pytest.mark.parametrize("fixture", EXPECTED, ids=[f["file"] for f in EXPECTED])
def test_fixture_findings_match_ground_truth(fixture):
    findings, inventory = _run(fixture)
    want_findings = sorted(e["line"] for e in fixture.get("expect_findings", []))
    want_inventory = sorted(e["line"] for e in fixture.get("expect_inventory", []))
    assert findings == want_findings, f"{fixture['file']}: {fixture.get('reason', '')}"
    if "expect_inventory" in fixture:
        assert inventory == want_inventory, fixture["file"]


def test_the_three_fp_classes_emit_no_findings():
    """The headline precision guarantee: the FP classes produce zero findings."""
    fp_classes = {"name-not-value", "window-overshoot", "path-not-secret"}
    for fixture in EXPECTED:
        if fixture["class"] in fp_classes:
            findings, _ = _run(fixture)
            assert findings == [], f"{fixture['file']} regressed a false positive"
