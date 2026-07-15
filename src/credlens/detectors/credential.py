"""Credential lens — AST intra-file def-use taint (ADR-0001 tree-sitter engine).

Answers: does a secret VALUE reach an observable sink within one file? Taint lives on
value BINDINGS, never on the env-var NAME as a token — which is exactly what kills the
POC's name-not-value / window-overshoot false positives (a string literal that mentions
a secret name is not tainted; `return` is not a sink). Spec: docs/specs/credential-lens.md.

v1 is intra-file: taint does not cross function boundaries (the cross-function-hop
mutation class exists to measure that documented miss). Python is not yet analyzed
(TS/JS only) — a documented shallow-coverage known-miss.
"""

from __future__ import annotations

import re

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

from .base import LENS_CREDENTIAL, Finding

SECRET_NAME = re.compile(r"[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*")
PATHY = re.compile(r".*(PATH|FILE|DIR)$")

TOKEN_SHAPES = [
    ("github token", re.compile(r"ghp_[A-Za-z0-9]{16,}")),
    ("slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("aws access key", re.compile(r"AKIA[A-Z0-9]{12,}")),
]

LOG_METHODS = {"log", "error", "warn", "info", "debug", "trace"}
LOG_OBJECTS = {"console", "logger", "log"}
SUBPROCESS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
FS_WRITES = {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "write"}

_TS = Language(tsts.language_typescript())
_TSX = Language(tsts.language_tsx())
_JS = Language(tsjs.language())

_LANG_BY_SUFFIX = {
    ".ts": _TS, ".mts": _TS, ".cts": _TS,
    ".tsx": _TSX,
    ".js": _JS, ".mjs": _JS, ".cjs": _JS, ".jsx": _JS,
}


def _lang_for(path: str) -> Language | None:
    for suf, lang in _LANG_BY_SUFFIX.items():
        if path.endswith(suf):
            return lang
    return None


class CredentialDetector:
    name = "credential"

    def scan_text(self, path: str, text: str) -> list[Finding]:
        lang = _lang_for(path)
        if lang is None:
            return []  # Python + others: documented v1 known-miss
        src = text.encode("utf-8", "replace")
        tree = Parser(lang).parse(src)
        self._src = src
        findings: list[Finding] = []

        # 1. hardcoded token literals: the presence IS the finding (at the literal line)
        token_lines: set[int] = set()
        for node, label in self._iter_token_literals(tree.root_node):
            line = node.start_point[0] + 1
            token_lines.add(line)
            findings.append(Finding(path, line, LENS_CREDENTIAL, "finding",
                                    f"Hardcoded {label}", "high"))

        # 2. taint: bindings whose value derives from a secret source
        tainted = self._collect_tainted(tree.root_node)

        # 3. sinks. A secret reaching a log / file-write / subprocess arg is an
        #    unambiguous leak → finding. A secret in an OUTBOUND request is ambiguous
        #    (sending an API key to its own API is the key's intended use) → inventory;
        #    telling legitimate auth from exfiltration needs destination-taint analysis
        #    (is the host caller-controlled?), a documented v2 refinement.
        for call in self._iter_calls(tree.root_node):
            kind, args = self._classify_sink(call)
            if kind is None:
                continue
            if any(self._expr_tainted(a, tainted) for a in args):
                line = call.start_point[0] + 1
                if kind == "finding" and line in token_lines:
                    continue  # already reported as a hardcoded token on this line
                msg = ("Secret value reaches a sink" if kind == "finding"
                       else "Secret value sent in an outbound request "
                             "(verify the destination is the intended API)")
                conf = "high" if kind == "finding" else "medium"
                findings.append(Finding(path, line, LENS_CREDENTIAL, kind, msg, conf))
        return findings

    # --- text helpers ----------------------------------------------------------

    def _text(self, node: Node) -> str:
        return self._src[node.start_byte:node.end_byte].decode("utf-8", "replace")

    # --- sources ---------------------------------------------------------------

    def _is_secret_env(self, node: Node) -> bool:
        """member_expression `process.env.NAME` with a secret-shaped, non-path NAME."""
        if node.type != "member_expression":
            return False
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or prop is None or self._text(obj) != "process.env":
            return False
        name = self._text(prop)
        return bool(SECRET_NAME.fullmatch(name)) and not PATHY.match(name)

    def _is_token_literal(self, node: Node) -> tuple[bool, str]:
        if node.type in ("string", "template_string"):
            t = self._text(node)
            for label, pat in TOKEN_SHAPES:
                if pat.search(t):
                    return True, label
        return False, ""

    def _iter_token_literals(self, root: Node):
        stack = [root]
        while stack:
            n = stack.pop()
            ok, label = self._is_token_literal(n)
            if ok:
                yield n, label
            stack.extend(n.children)

    # --- taint collection (fixpoint over declarations) -------------------------

    def _collect_tainted(self, root: Node) -> set[str]:
        declarators: list[tuple[str, Node]] = []  # (bound name, value node)
        destructured_env: list[str] = []
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "variable_declarator":
                name_node = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                if name_node is not None and value is not None:
                    if name_node.type == "identifier":
                        declarators.append((self._text(name_node), value))
                    elif name_node.type == "object_pattern" and self._reads_process_env(value):
                        # const { SECRET } = process.env  /  const { SECRET: alias } = process.env
                        # taint the BOUND local name, gated on the source property name.
                        for src_key, bound in self._object_pattern_bindings(name_node):
                            if SECRET_NAME.fullmatch(src_key) and not PATHY.match(src_key):
                                destructured_env.append(bound)
            stack.extend(n.children)

        tainted: set[str] = set(destructured_env)
        # fixpoint: a binding is tainted if its value is a tainted expression
        changed = True
        while changed:
            changed = False
            for name, value in declarators:
                if name not in tainted and self._expr_tainted(value, tainted):
                    tainted.add(name)
                    changed = True
        return tainted

    def _reads_process_env(self, node: Node) -> bool:
        return node.type == "member_expression" and self._text(node) == "process.env" or \
            self._text(node) == "process.env"

    def _object_pattern_bindings(self, pattern: Node) -> list[tuple[str, str]]:
        """Return (source property name, bound local name) for each destructured field.

        `{ X }`      → ("X", "X");  `{ X: y }` → ("X", "y")."""
        out = []
        for child in pattern.children:
            if child.type == "shorthand_property_identifier_pattern":
                name = self._text(child)
                out.append((name, name))
            elif child.type == "pair_pattern":
                k = child.child_by_field_name("key")
                v = child.child_by_field_name("value")
                if k is not None and v is not None:
                    out.append((self._text(k), self._text(v)))
        return out

    # --- tainted-expression test ----------------------------------------------

    def _expr_tainted(self, node: Node, tainted: set[str]) -> bool:
        """True if the expression carries a secret value. String literals are NEVER
        tainted on account of their text — only bindings, env reads, token literals."""
        if node is None:
            return False
        t = node.type
        if t == "identifier":
            return self._text(node) in tainted
        if t == "member_expression":
            if self._is_secret_env(node):
                return True
            # x.foo where x is tainted (a secret object's member is still sensitive)
            obj = node.child_by_field_name("object")
            return self._expr_tainted(obj, tainted) if obj is not None else False
        if t in ("string", "template_string"):
            ok, _ = self._is_token_literal(node)
            if ok:
                return True
            # a template string is tainted if a substitution is tainted
            if t == "template_string":
                return any(self._expr_tainted(sub, tainted)
                           for c in node.children if c.type == "template_substitution"
                           for sub in c.children if sub.is_named)
            return False
        # transparent wrappers / compound expressions: tainted if any child is
        if t in ("non_null_expression", "parenthesized_expression", "as_expression",
                 "binary_expression", "template_substitution", "await_expression",
                 "sequence_expression", "ternary_expression", "satisfies_expression"):
            return any(self._expr_tainted(c, tainted) for c in node.children if c.is_named)
        # container literals: a secret nested in a headers/body object or an array leaks
        if t in ("object", "array"):
            return any(self._expr_tainted(c, tainted) for c in node.children if c.is_named)
        if t == "pair":
            val = node.child_by_field_name("value")  # value side only, never the key
            return self._expr_tainted(val, tainted)
        # pass-through calls (JSON.stringify(secret), String(secret), encodeURIComponent…):
        # the secret flows through the wrapper into the result.
        if t == "call_expression":
            argnode = node.child_by_field_name("arguments")
            if argnode is not None:
                return any(self._expr_tainted(c, tainted) for c in argnode.children if c.is_named)
            return False
        return False

    # --- sinks -----------------------------------------------------------------

    def _iter_calls(self, root: Node):
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "call_expression":
                yield n
            stack.extend(n.children)

    def _classify_sink(self, call: Node) -> tuple[str | None, list[Node]]:
        """Classify a call site: ('finding'|'inventory'|None, sink-arg exprs).

        'finding' = an unambiguous leak sink (log / file-write / subprocess).
        'inventory' = an outbound request (ambiguous auth-vs-exfil; ADR-0002)."""
        fn = call.child_by_field_name("function")
        args = call.child_by_field_name("arguments")
        if fn is None or args is None:
            return None, []
        arg_exprs = [c for c in args.children if c.is_named]

        if fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            prop = fn.child_by_field_name("property")
            oname = self._text(obj) if obj is not None else ""
            pname = self._text(prop) if prop is not None else ""
            if pname in LOG_METHODS and (oname in LOG_OBJECTS or oname.endswith("ogger")):
                return "finding", arg_exprs
            if pname in FS_WRITES:
                return "finding", arg_exprs[1:2]  # the content arg, not the path
            if pname in SUBPROCESS:
                return "finding", arg_exprs
            return None, []

        if fn.type == "identifier":
            name = self._text(fn)
            if name == "fetch":
                sinks = arg_exprs[0:1]  # the URL
                if len(arg_exprs) >= 2:
                    sinks += self._fetch_option_values(arg_exprs[1])  # headers/body
                return "inventory", sinks
            if name in SUBPROCESS:
                return "finding", arg_exprs
        return None, []

    def _fetch_option_values(self, options: Node) -> list[Node]:
        """From a fetch options object, the `headers` and `body` property values."""
        if options.type != "object":
            return []
        out = []
        for pair in options.children:
            if pair.type != "pair":
                continue
            key = pair.child_by_field_name("key")
            val = pair.child_by_field_name("value")
            if key is not None and val is not None and self._text(key).strip("\"'") in ("headers", "body"):
                out.append(val)
        return out
