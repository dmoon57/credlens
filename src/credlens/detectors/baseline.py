"""Baseline credential detector — the POC's naïve heuristic, ported and measured.

This is deliberately the pre-AST version: line-based regex + a proximity window,
carrying the exact weakness the spike found (it flags the env-var NAME appearing in
a "please set X" error string as if the VALUE leaked). It exists so the eval harness
has an honest baseline to reproduce the POC result and so Phase 2's AST+taint lens
can be shown to beat it on the same corpus — not because it is good.

Do NOT harden this file. The credential lens (ADR-0001 engine) is a separate module.
"""

from __future__ import annotations

import re

from .base import LENS_CREDENTIAL, Finding

# env var names that look secret-ish (value is sensitive)
SECRET_NAME = re.compile(r"[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*")
# names that are pointers, not secrets — the POC still (wrongly) treats some as secret
PATHY = re.compile(r".*(PATH|FILE|DIR)$")

# hardcoded token shapes (structural; real detectors validate, the baseline does not)
TOKEN_SHAPES = [
    ("github token", re.compile(r"ghp_[A-Za-z0-9]{16,}")),
    ("slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("aws access key", re.compile(r"AKIA[A-Z0-9]{12,}")),
]

# env read into a variable: `const X = process.env.NAME` / `let`/ destructure
ENV_ASSIGN = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*process\.env\.(\w+)")
ENV_DESTRUCT = re.compile(r"(?:const|let|var)\s*\{\s*(\w+)\s*\}\s*=\s*process\.env")
ENV_INLINE = re.compile(r"process\.env\.(\w+)")

# sink calls: logging + outbound + file write (the POC's sink set)
SINK = re.compile(r"\b(console\.(?:log|error|warn|info)|logger\.\w+|fetch|fs\.writeFile\w*)\b")

WINDOW = 8  # lines after an env read to look for a sink (the POC's proximity window)


class BaselineDetector:
    name = "baseline"

    def scan_text(self, path: str, text: str) -> list[Finding]:
        lines = text.splitlines()
        findings: list[Finding] = []

        # 1. hardcoded token shapes
        for i, line in enumerate(lines, 1):
            for label, pat in TOKEN_SHAPES:
                if pat.search(line):
                    findings.append(Finding(path, i, LENS_CREDENTIAL, "finding",
                                            f"Possible hardcoded {label}", "high"))

        # 2. env-secret value reaching a sink within a proximity window.
        #    NOTE the POC bug reproduced here: the taint is by variable-NAME token
        #    match, so a sink line merely *mentioning* the name (even as a string
        #    literal in an error message) trips it — the name-not-value false positive.
        tainted: list[tuple[str, int]] = []  # (var-or-name token, line seen)
        for i, line in enumerate(lines, 1):
            m = ENV_ASSIGN.search(line)
            if m and SECRET_NAME.fullmatch(m.group(2)) and not PATHY.match(m.group(2)):
                tainted.append((m.group(1), i))
                tainted.append((m.group(2), i))  # the POC also tracks the raw name
            md = ENV_DESTRUCT.search(line)
            if md and SECRET_NAME.fullmatch(md.group(1)) and not PATHY.match(md.group(1)):
                tainted.append((md.group(1), i))
            mi = ENV_INLINE.search(line)
            if mi and SECRET_NAME.fullmatch(mi.group(1)) and not PATHY.match(mi.group(1)):
                if SINK.search(line):  # direct: console.log(process.env.SECRET)
                    findings.append(Finding(path, i, LENS_CREDENTIAL, "finding",
                                            f"Secret value ({mi.group(1)}) reaches a sink", "high"))

        for i, line in enumerate(lines, 1):
            if not SINK.search(line):
                continue
            for tok, seen in tainted:
                if seen <= i <= seen + WINDOW and re.search(rf"\b{re.escape(tok)}\b", line):
                    findings.append(Finding(path, i, LENS_CREDENTIAL, "finding",
                                            f"Secret value ({tok}) may reach a sink", "high"))
                    break

        return findings
