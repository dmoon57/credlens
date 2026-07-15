"""Consistency checks for corpus/labels.json against the POC findings and the corpus."""

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LABELS = json.loads((REPO / "corpus" / "labels.json").read_text())
FINDINGS = json.loads((REPO / "docs" / "research" / "poc" / "findings.json").read_text())
CORPUS = REPO / "corpus" / "servers"

VALID_LABELS = {"true-positive", "false-positive", "inventory"}


def test_every_poc_finding_is_labeled_exactly_once():
    n_findings = sum(len(s["findings"]) for s in FINDINGS["servers"])
    assert len(LABELS["labels"]) == n_findings
    ids = [entry["id"] for entry in LABELS["labels"]]
    assert len(ids) == len(set(ids))


def test_labels_and_reasons_are_valid():
    codes = set(LABELS["reason_codes"])
    for entry in LABELS["labels"]:
        assert entry["label"] in VALID_LABELS, entry["id"]
        assert entry["reason"] in codes, entry["id"]
        assert entry["note"], entry["id"]


def test_counts_block_matches_labels():
    for label in VALID_LABELS:
        actual = sum(1 for e in LABELS["labels"] if e["label"] == label)
        assert LABELS["counts"][label] == actual


def test_inventory_is_never_a_tp_fp_category_confusion():
    """ADR-0002: capability surface entries are inventory; asserted misbehavior is tp/fp."""
    for entry in LABELS["labels"]:
        if entry["label"] == "true-positive":
            assert entry["source"] == "local", f"{entry['id']}: only planted synthetic attacks are TP in this corpus"


@pytest.mark.skipif(not CORPUS.exists(), reason="corpus not assembled (run `make corpus`)")
def test_anchors_resolve_in_pinned_corpus():
    for entry in LABELS["labels"]:
        path = CORPUS / entry["source"] / entry["server"] / entry["file"]
        assert path.is_file(), f"{entry['id']}: {path} missing"
        n_lines = len(path.read_text(errors="replace").splitlines())
        assert 0 < entry["line"] <= n_lines, f"{entry['id']}: line {entry['line']} out of range"
