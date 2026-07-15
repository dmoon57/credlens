"""Detector interface and the Finding type.

A detector reads a source file's text and returns Findings. Per ADR-0002 a Finding
is either an asserted misbehavior (`kind="finding"`, precision-gated and scored) or
a factual capability/permission surface (`kind="inventory"`, never counted TP/FP).
The eval harness measures detectors through this interface, so swapping the engine
(ADR-0001) never touches the scorer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

# lenses the harness knows how to score
LENS_CREDENTIAL = "credential"
LENS_CAPABILITY = "capability"


@dataclass(frozen=True)
class Finding:
    file: str          # path relative to the scan root
    line: int          # 1-based
    lens: str          # LENS_CREDENTIAL | LENS_CAPABILITY | ...
    kind: str          # "finding" (asserted misbehavior) | "inventory" (surface)
    message: str
    confidence: str = "medium"  # low | medium | high


class Detector(Protocol):
    name: str

    def scan_text(self, path: str, text: str) -> list[Finding]:
        """Return findings for one file's text."""
        ...
