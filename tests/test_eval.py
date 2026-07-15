"""Tests for the eval harness: gate logic (no corpus needed) + full run (guarded)."""

import json
from pathlib import Path

import pytest

from credlens import eval as ev
from credlens.detectors import BaselineDetector

REPO = Path(__file__).resolve().parent.parent
HAS_CORPUS = (REPO / "corpus" / "servers").exists()
HAS_MUTATIONS = (REPO / "corpus" / "mutations").exists()


def test_gate_fails_when_metric_below_floor(tmp_path, monkeypatch):
    floor = {"mutation_recall_holdout": 0.50, "mutation_precision": 0.90}
    fp = tmp_path / "floor.json"
    fp.write_text(json.dumps(floor))
    monkeypatch.setattr(ev, "FLOOR", fp)
    regressed = {
        "real_servers": {"available": True, "precision": 0.0},
        "mutations": {"available": True,
                      "recall": {"holdout": {"recall": 0.20}},
                      "precision": 0.88},
    }
    assert ev._gate(regressed) == 1


def test_gate_passes_when_metrics_meet_floor(tmp_path, monkeypatch):
    floor = {"mutation_recall_holdout": 0.50, "mutation_precision": 0.90}
    fp = tmp_path / "floor.json"
    fp.write_text(json.dumps(floor))
    monkeypatch.setattr(ev, "FLOOR", fp)
    ok = {
        "real_servers": {"available": True, "precision": 0.0},
        "mutations": {"available": True,
                      "recall": {"holdout": {"recall": 0.55}},
                      "precision": 0.92},
    }
    assert ev._gate(ok) == 0


@pytest.mark.skipif(not (HAS_CORPUS and HAS_MUTATIONS),
                    reason="corpus/mutations not assembled (make corpus && make mutations)")
def test_baseline_reproduces_poc_story():
    results = ev.evaluate(BaselineDetector())
    # the POC lesson, as a measured invariant: the naïve baseline has zero precision
    # on real servers (it emits name-not-value / window-overshoot false positives)
    assert results["real_servers"]["precision"] == 0.0
    assert results["real_servers"]["false_positive"] > 0
    # the documented intra-file-taint known-miss: cross-function-hop is not caught
    assert results["mutations"]["by_class"]["cross-function-hop"]["recall"] == 0.0
    # hardcoded token shapes are trivially caught
    assert results["mutations"]["by_class"]["hardcoded-token"]["recall"] == 1.0
