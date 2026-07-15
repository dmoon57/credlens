"""Least-privilege inventory (Move 2.3) — the factual permission surface.

Everything here is `kind="inventory"` (ADR-0002): a capability/permission surface a
reviewer wants, never an asserted misbehavior. It is never counted TP/FP and never
affects precision. One item per category per file. Spec: docs/specs/credential-lens.md.

The one shape that IS a real concern — token-passthrough / confused-deputy — is still
emitted as inventory in v1 (framed "verify", not asserted): a caller-controlled value
used as an Authorization credential on an outbound request. A server sending its OWN
configured token (github/gitlab) is legitimate and is NOT flagged.
"""

from __future__ import annotations

import re

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

from .base import LENS_CAPABILITY, Finding

_TS = Language(tsts.language_typescript())
_TSX = Language(tsts.language_tsx())
_JS = Language(tsjs.language())
_LANG_BY_SUFFIX = {
    ".ts": _TS, ".mts": _TS, ".cts": _TS, ".tsx": _TSX,
    ".js": _JS, ".mjs": _JS, ".cjs": _JS, ".jsx": _JS,
}

NARROW_SCOPE = re.compile(r"(readonly|\.read\b|/read$|\bread\b)", re.I)
BROAD_SCOPE = re.compile(r"(admin|write|full|\*|manage|\.all\b)", re.I)

NET_TRANSPORTS = {"SSEServerTransport", "StreamableHTTPServerTransport"}
FS_WRITE = {"writeFile", "writeFileSync", "appendFile", "appendFileSync"}
FS_DELETE = {"unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync"}
SUBPROCESS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"}
AUTH_HEADER_KEYS = {"authorization", "x-api-key", "x-auth-token", "proxy-authorization"}


def _lang_for(path: str) -> Language | None:
    for suf, lang in _LANG_BY_SUFFIX.items():
        if path.endswith(suf):
            return lang
    return None


class LeastPrivDetector:
    name = "leastpriv"

    def scan_text(self, path: str, text: str) -> list[Finding]:
        lang = _lang_for(path)
        if lang is None:
            return []
        self._src = text.encode("utf-8", "replace")
        tree = Parser(lang).parse(self._src)
        root = tree.root_node

        # aggregate one item per category; keep the first line seen
        items: dict[str, tuple[int, str]] = {}

        def add(cat: str, line: int, msg: str):
            if cat not in items:
                items[cat] = (line, msg)

        for node in self._walk(root):
            t = node.type
            if t == "new_expression":
                cls = self._new_class_name(node)
                if cls in NET_TRANSPORTS:
                    add(f"transport:{cls}", node.start_point[0] + 1,
                        f"Network-exposed transport ({cls}) — verify authentication/authorization")
            elif t == "call_expression":
                self._scan_call(node, add)
            elif t == "pair":
                self._scan_scopes(node, add)

        return [Finding(path, line, LENS_CAPABILITY, "inventory", msg, "low")
                for _, (line, msg) in sorted(items.items(), key=lambda kv: kv[1][0])]

    # --- walkers ---------------------------------------------------------------

    def _walk(self, root: Node):
        stack = [root]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(n.children)

    def _text(self, node: Node) -> str:
        return self._src[node.start_byte:node.end_byte].decode("utf-8", "replace")

    def _new_class_name(self, node: Node) -> str:
        c = node.child_by_field_name("constructor")
        if c is None:
            return ""
        if c.type == "member_expression":
            prop = c.child_by_field_name("property")
            return self._text(prop) if prop is not None else ""
        return self._text(c)

    def _scan_call(self, call: Node, add) -> None:
        fn = call.child_by_field_name("function")
        line = call.start_point[0] + 1
        if fn is None:
            return
        if fn.type == "identifier":
            name = self._text(fn)
            if name == "fetch":
                add("capability:outbound-network", line, "Makes outbound network requests")
                self._scan_passthrough(call, add)
            elif name in SUBPROCESS:
                add("capability:process-exec", line, "Executes subprocesses")
            elif name in ("eval", "Function"):
                add("capability:dynamic-eval", line, "Uses dynamic code evaluation")
            elif name in ("express", "createServer"):
                add("transport:http-server", line,
                    "HTTP server — verify authentication/authorization")
        elif fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            pname = self._text(prop) if prop is not None else ""
            if pname in FS_WRITE:
                add("capability:fs-write", line, "Writes to the filesystem")
            elif pname in FS_DELETE:
                add("capability:fs-delete", line, "Deletes filesystem entries")
            elif pname in SUBPROCESS:
                add("capability:process-exec", line, "Executes subprocesses")

    def _scan_scopes(self, pair: Node, add) -> None:
        key = pair.child_by_field_name("key")
        val = pair.child_by_field_name("value")
        if key is None or val is None or self._text(key).strip("\"'") != "scopes":
            return
        if val.type != "array":
            return
        scopes = [self._text(c).strip("\"'`") for c in val.children
                  if c.type in ("string", "template_string")]
        if not scopes:
            return
        broad = [s for s in scopes if BROAD_SCOPE.search(s) and not NARROW_SCOPE.search(s)]
        breadth = "broad" if broad else "narrow"
        add("oauth-scope", pair.start_point[0] + 1,
            f"OAuth scopes declared ({breadth}): {', '.join(scopes)}")

    def _scan_passthrough(self, call: Node, add) -> None:
        """A caller-controlled value used as an Authorization credential = confused-deputy.

        Caller-controlled = the value traces to a parameter of an enclosing function.
        A server's own env/const token is NOT caller-controlled and is not flagged."""
        args = call.child_by_field_name("arguments")
        if args is None:
            return
        arg_exprs = [c for c in args.children if c.is_named]
        if len(arg_exprs) < 2 or arg_exprs[1].type != "object":
            return
        header_val = self._auth_header_value(arg_exprs[1])
        if header_val is None:
            return
        params = self._enclosing_params(call)
        if any(self._references_param(header_val, params)):
            add("token-passthrough", call.start_point[0] + 1,
                "Caller-controlled value used as an outbound Authorization credential "
                "(confused-deputy — verify the token is not attacker-supplied)")

    def _auth_header_value(self, options: Node) -> Node | None:
        for pair in options.children:
            if pair.type != "pair":
                continue
            k = pair.child_by_field_name("key")
            v = pair.child_by_field_name("value")
            if k is not None and v is not None and self._text(k).strip("\"'").lower() == "headers":
                if v.type == "object":
                    for hp in v.children:
                        if hp.type != "pair":
                            continue
                        hk = hp.child_by_field_name("key")
                        hv = hp.child_by_field_name("value")
                        if hk is not None and hv is not None and \
                                self._text(hk).strip("\"'").lower() in AUTH_HEADER_KEYS:
                            return hv
        return None

    def _enclosing_params(self, node: Node) -> set[str]:
        params: set[str] = set()
        cur = node.parent
        while cur is not None:
            if cur.type in ("function_declaration", "function_expression",
                            "arrow_function", "method_definition", "function"):
                pnode = cur.child_by_field_name("parameters")
                if pnode is not None:
                    for p in pnode.children:
                        params.update(self._param_names(p))
            cur = cur.parent
        return params

    def _param_names(self, node: Node) -> list[str]:
        if node.type == "identifier":
            return [self._text(node)]
        names = []
        for c in node.children:
            if c.type == "identifier":
                names.append(self._text(c))
            elif c.type in ("required_parameter", "optional_parameter", "object_pattern"):
                names.extend(self._param_names(c))
        return names

    def _references_param(self, node: Node, params: set[str]):
        for n in self._walk(node):
            if n.type == "identifier" and self._text(n) in params:
                yield True
