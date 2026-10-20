"""
Package-level dataflow rules for npm / JavaScript, the JS counterpart of
dataflow_rules.py (same labels, same rule names).

tree-sitter parse only; nothing is executed. Flow-insensitive def-use taint
per top-level function (nested closures belong to their outermost function,
since npm payloads live in callbacks), plus:
  - callback parameters inherit labels: http.get(u, res => ...),
    fetch(u).then(r => ...), res.on("data", chunk => ...)
  - package.json install hooks (preinstall / install / postinstall) are the
    install-time entry points: the command string itself is checked, and
    any file it runs with `node x.js` counts as install-time code

Labels: NET, ENV_BULK, HOSTINFO, HOSTID, CRED_FILE, DECODED, NETFILE
Rules:  remote_code_exec, remote_cmd_exec, decoded_exec, exfil_env_bulk,
        exfil_cred_file, exfil_hostinfo, exfil_hostid, download_exec,
        shell_download, install_script_download, url_dependency (metadata)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

import tree_sitter as ts
import tree_sitter_javascript as tsjs

from dataflow_rules import _SHELL_DOWNLOAD  # same shell-downloader regex as Python

NET, ENV_BULK, HOSTINFO, HOSTID, CRED_FILE, DECODED, NETFILE = (
    "NET", "ENV_BULK", "HOSTINFO", "HOSTID", "CRED_FILE", "DECODED", "NETFILE")
EMPTY: frozenset[str] = frozenset()

_PARSER = ts.Parser(ts.Language(tsjs.language()))

# callee text -> network fetch
_NET_FETCH = re.compile(
    r"^(fetch|axios(\.(get|post|put|request|patch))?|got(\.(get|post))?|needle|superagent(\.\w+)?|"
    r"(https?|https?Module|node_https?)\.(get|request)|request(\.(get|post))?|undici\.(fetch|request))$")
_NET_SEND = re.compile(
    r"^(fetch|axios(\.(post|put|patch|request))?|got\.(post|put)|needle|"
    r"(https?|https?Module)\.request|\w*req\w*\.(write|end)|dns\.(lookup|resolve\w*)|"
    r"(sock|socket|client)\.(write|send))$")
_DNS = re.compile(r"^dns\.(lookup|resolve\w*)$")
_CMD = re.compile(r"^((child_process|cp|childProcess|\w*cp)\.)?(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)$")
_CODE = re.compile(r"^(eval|Function|vm\.(runInNewContext|runInThisContext|runInContext|compileFunction))$")
_HOSTINFO = re.compile(r"^(os|\w*os\w*)\.(hostname|userInfo|platform|networkInterfaces|type|release)$")
_HOSTID = re.compile(r"^(os|\w*os\w*)\.(hostname|userInfo)$")
_CRED = re.compile(
    r"(\.npmrc|\.ssh|id_rsa|id_ed25519|\.aws|\.azure|\.kube|\.docker|\.netrc|\.git-credentials|"
    r"\.gnupg|Login Data|Cookies|Local Storage|leveldb|discord|wallet|keychain|\.config/gcloud|"
    r"exodus|metamask|\.pypirc)", re.I)
_DECODE = re.compile(r"^(atob|zlib\.\w+Sync|zlib\.(inflate|gunzip|unzip)\w*|Buffer\.from|decodeURIComponent|unescape)$")
_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")


@dataclass
class Finding:
    rule: str
    func: str
    line: int


def _txt(src: bytes, n) -> str:
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def _callee(src: bytes, call) -> str:
    f = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    if f is None:
        return ""
    t = _txt(src, f)
    t = re.sub(r"^require\((['\"])([\w/:-]+)\1\)", lambda m: m.group(2).split(":")[-1].split("/")[0], t)
    return re.sub(r"\s+", "", t)[:80]


def _args(call):
    a = call.child_by_field_name("arguments")
    return [c for c in a.named_children] if a is not None else []


def _is_fn(n) -> bool:
    return n.type in ("arrow_function", "function_expression", "function", "generator_function")


def _params(fn) -> list[str]:
    p = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
    if p is None:
        return []
    if p.type == "identifier":
        return [p]
    out = []
    for c in p.named_children:
        if c.type == "identifier":
            out.append(c)
        elif c.type in ("assignment_pattern",) and c.child_by_field_name("left") is not None:
            out.append(c.child_by_field_name("left"))
    return out


class _Scope:
    def __init__(self, src: bytes, root, name: str):
        self.src, self.root, self.name = src, root, name
        self.env: dict[str, frozenset[str]] = {}
        self.nodes = list(self._walk(root))

    def _walk(self, n):
        stack = [n]
        while stack:
            cur = stack.pop()
            yield cur
            stack.extend(reversed(cur.children))

    def t(self, n) -> str:
        return _txt(self.src, n)

    # ── labels ───────────────────────────────────────────────────────────────
    def labels(self, n, depth: int = 0) -> frozenset[str]:
        if n is None or depth > 60:
            return EMPTY
        ty = n.type
        if _is_fn(n):
            return EMPTY
        if ty == "identifier":
            return self.env.get(self.t(n), EMPTY)
        if ty == "member_expression":
            full = re.sub(r"\s+", "", self.t(n))
            if full in self.env:
                return self.env[full]
            if full == "process.env":
                parent = n.parent
                # process.env.FOO is a specific var; bare process.env is the whole env
                if parent is None or parent.type != "member_expression" or \
                        parent.child_by_field_name("object") != n:
                    if not (parent is not None and parent.type == "subscript_expression"):
                        return frozenset({ENV_BULK})
                return EMPTY
            return self.labels(n.child_by_field_name("object"), depth + 1)
        if ty in ("call_expression", "new_expression"):
            return self._call_labels(n, depth)
        if ty in ("string", "template_string"):
            out = set()
            s = self.t(n)
            if _CRED.search(s) and re.search(r"[\\/~]|^['\"`]\.", s):
                out.add("_CRED_PATH")
            for c in n.named_children:
                if c.type == "template_substitution":
                    out |= self.labels(c, depth + 1)
            return frozenset(out)
        out: set[str] = set()
        for c in n.named_children:
            out |= self.labels(c, depth + 1)
        return frozenset(out)

    def _call_labels(self, call, depth: int) -> frozenset[str]:
        name = _callee(self.src, call)
        args = _args(call)
        out: set[str] = set()
        for a in args:
            out |= self.labels(a, depth + 1)
        f = call.child_by_field_name("function")
        if f is not None and f.type == "member_expression":
            out |= self.labels(f.child_by_field_name("object"), depth + 1)
        if _NET_FETCH.match(name):
            out.add(NET)
        if _HOSTINFO.match(name):
            out.add(HOSTINFO)
        if _HOSTID.match(name):
            out.add(HOSTID)
        if _DECODE.match(name):
            if name != "Buffer.from" or any(re.search(r"['\"](base64|hex|base64url)['\"]", self.t(a))
                                            for a in args[1:2]):
                out.add(DECODED)
        if "_CRED_PATH" in out and re.search(r"readFile(Sync)?$|\.read$", name):
            out.add(CRED_FILE)
        if name in ("JSON.stringify", "Object.assign", "Object.entries") and any(
                re.sub(r"\s+", "", self.t(a)) == "process.env" for a in args):
            out.add(ENV_BULK)
        return frozenset(out)

    # ── fixed point ──────────────────────────────────────────────────────────
    def _assign(self, key: str, lab: frozenset[str]) -> bool:
        lab = lab - {"_CRED_PATH"} if "_CRED_PATH" in lab and len(lab) > 1 else lab
        if not key or not lab:
            return False
        old = self.env.get(key, EMPTY)
        if lab <= old:
            return False
        self.env[key] = old | lab
        return True

    def solve(self):
        for _ in range(6):
            changed = False
            for n in self.nodes:
                ty = n.type
                if ty == "variable_declarator":
                    name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
                    if name is not None and val is not None:
                        lab = self.labels(val)
                        if name.type == "identifier":
                            changed |= self._assign(self.t(name), lab)
                        else:  # destructuring: every bound name gets the labels
                            for c in self._walk(name):
                                if c.type in ("identifier", "shorthand_property_identifier_pattern"):
                                    changed |= self._assign(self.t(c), lab)
                elif ty in ("assignment_expression", "augmented_assignment_expression"):
                    left = n.child_by_field_name("left")
                    if left is not None:
                        changed |= self._assign(re.sub(r"\s+", "", self.t(left)),
                                                self.labels(n.child_by_field_name("right")))
                elif ty in ("call_expression",):
                    changed |= self._callbacks(n)
                    changed |= self._writes(n)
            if not changed:
                break

    def _callbacks(self, call) -> bool:
        """Callback params inherit the labels of the call / its receiver."""
        name = _callee(self.src, call)
        f = call.child_by_field_name("function")
        recv = self.labels(f.child_by_field_name("object")) if f is not None and f.type == "member_expression" else EMPTY
        lab = set(recv)
        if _NET_FETCH.match(name):
            lab.add(NET)
        method = name.rsplit(".", 1)[-1]
        if not lab or not (method in ("then", "on", "once", "get", "request") or _NET_FETCH.match(name)):
            return False
        changed = False
        for a in _args(call):
            if _is_fn(a):
                for p in _params(a):
                    changed |= self._assign(self.t(p), frozenset(lab & {NET, DECODED}))
        return changed

    def _writes(self, call) -> bool:
        """fs.writeFileSync(p, netData) / x.pipe(fs.createWriteStream(p)) mark p NETFILE."""
        name = _callee(self.src, call)
        args = _args(call)
        if re.search(r"writeFile(Sync)?$", name) and len(args) > 1 and NET in self.labels(args[1]):
            return self._assign(re.sub(r"\s+", "", self.t(args[0])), frozenset({NETFILE}))
        if name.endswith(".pipe") and args and args[0].type == "call_expression" and \
                _callee(self.src, args[0]).endswith("createWriteStream"):
            f = call.child_by_field_name("function")
            if f is not None and NET in self.labels(f.child_by_field_name("object")):
                inner = _args(args[0])
                if inner:
                    return self._assign(re.sub(r"\s+", "", self.t(inner[0])), frozenset({NETFILE}))
        return False

    # ── findings ─────────────────────────────────────────────────────────────
    def findings(self) -> list[Finding]:
        out = []
        for n in self.nodes:
            if n.type not in ("call_expression", "new_expression"):
                continue
            name = _callee(self.src, n)
            args = _args(n)
            lab: set[str] = set()
            for a in args:
                lab |= self.labels(a)
                if re.sub(r"\s+", "", self.t(a)) in self.env:
                    lab |= self.env[re.sub(r"\s+", "", self.t(a))]
            line = n.start_point[0] + 1
            if _CODE.match(name) or (n.type == "new_expression" and name == "Function"):
                if NET in lab:
                    out.append(Finding("remote_code_exec", self.name, line))
                elif DECODED in lab:
                    out.append(Finding("decoded_exec", self.name, line))
            if _CMD.match(name):
                if NET in lab:
                    out.append(Finding("remote_cmd_exec", self.name, line))
                if NETFILE in lab:
                    out.append(Finding("download_exec", self.name, line))
                consts = " ".join(self.t(c) for a in args for c in self._walk(a)
                                  if c.type in ("string_fragment", "template_string"))
                if consts and _SHELL_DOWNLOAD.search(consts) and \
                        not re.match(r"\s*(git|npm|npx|pnpm|yarn|node)\b", consts):
                    out.append(Finding("shell_download", self.name, line))
            if name == "require" and NETFILE in lab:
                out.append(Finding("download_exec", self.name, line))
            if _NET_SEND.match(name) or (_NET_FETCH.match(name) and len(args) > 1):
                for l, rule in ((ENV_BULK, "exfil_env_bulk"), (CRED_FILE, "exfil_cred_file"),
                                (HOSTINFO, "exfil_hostinfo")):
                    if l in lab:
                        out.append(Finding(rule, self.name, line))
            if HOSTID in lab and (_NET_FETCH.match(name) or
                                  (_DNS.match(name) and args and args[0].type in ("template_string", "binary_expression"))):
                out.append(Finding("exfil_hostid", self.name, line))
        return out


def _scopes(src: bytes, tree):
    """Top-level functions (with their nested closures) plus the rest of the program."""
    root = tree.root_node
    top_fns, rest = [], []
    for c in root.named_children:
        node = c
        if c.type == "export_statement" and c.named_children:
            node = c.named_children[0]
        if node.type in ("function_declaration", "generator_function_declaration", "class_declaration"):
            nm = node.child_by_field_name("name")
            top_fns.append((_txt(src, nm) if nm is not None else "<fn>", node))
        else:
            rest.append(c)
    yield "<module>", rest
    for nm, node in top_fns:
        yield nm, [node]


class _Multi(_Scope):
    def __init__(self, src, roots, name):
        self.src, self.name = src, name
        self.env = {}
        self.nodes = [x for r in roots for x in self._walk(r)]


def analyze_file(src_text: str) -> list[Finding]:
    src = src_text.encode("utf-8", "replace")
    tree = _PARSER.parse(src)
    out = []
    for name, roots in _scopes(src, tree):
        sc = _Multi(src, roots, name)
        sc.solve()
        out += sc.findings()
    return out


def url_dependencies(package_json: str) -> list[Finding]:
    """Dependencies installed straight from an http(s) tarball, bypassing the registry.
    Dependency-only droppers ship an empty index.js and put the payload here."""
    try:
        pj = json.loads(package_json)
    except ValueError:
        return []
    out = []
    for sec in ("dependencies", "optionalDependencies", "peerDependencies"):
        for dep, spec in (pj.get(sec) or {}).items():
            if isinstance(spec, str) and re.match(r"https?://", spec):
                out.append(Finding("url_dependency", f"{sec}:{dep}", 0))
    return out


def install_hooks(package_json: str) -> tuple[list[str], list[Finding]]:
    """Files run by install hooks, and findings on the hook commands themselves."""
    try:
        scripts = (json.loads(package_json).get("scripts") or {})
    except (ValueError, AttributeError):
        return [], []
    files, found = [], []
    for hook in _INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str):
            continue
        if hook == "prepare" and not re.search(r"\bnode\b|curl|wget", cmd):
            continue  # prepare usually runs a build
        files += re.findall(r"\bnode\s+(?:-\S+\s+)*([\w./-]+\.(?:c|m)?js)\b", cmd)
        if _SHELL_DOWNLOAD.search(cmd) or re.search(r"\bnode\s+-e\b.*(Buffer\.from|atob|eval|child_process)", cmd):
            found.append(Finding("install_script_download", hook, 0))
    return files, found
