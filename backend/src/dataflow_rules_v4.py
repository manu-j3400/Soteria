"""
Package-level dataflow rules for install/import-time malware.

A small def-use taint pass over the Python AST (no CFG, no execution):
values get labels as they flow through assignments, calls and returns,
and a finding fires when a labeled value reaches a sink.

Labels (sources)
  NET        bytes/objects that came back from a network call
  ENV_BULK   the whole environment (dict(os.environ), os.environ.copy() ...)
  HOSTINFO   hostname / username / OS fingerprint
  CRED_FILE  contents of a credential file (~/.ssh, .aws, browser stores ...)
  DECODED    output of base64 / zlib / marshal / hex decoders

Findings (label -> sink)
  remote_code_exec   NET reaches exec/eval/compile/__import__
  remote_cmd_exec    NET reaches subprocess / os.system
  decoded_exec       DECODED (without NET) reaches exec/eval/compile
  exfil_env_bulk     ENV_BULK reaches a network send
  exfil_cred_file    CRED_FILE reaches a network send
  exfil_hostinfo     HOSTINFO reaches a network send
  download_exec      a file written from NET data is then executed
  shell_download     a shell/subprocess command string downloads or runs an
                     encoded/hidden payload (powershell -enc, curl|sh, certutil,
                     /dev/tcp, nc -e, base64 -d | sh, cloud metadata, curl $(hostname))
  reverse_shell      socket fds dup2'd onto stdio, or pty.spawn of a shell
  exfil_hostid       hostname/username reaches a GET URL / params or a DNS lookup

Flow-insensitive within a function (fixed point over assignments), plus one
level across the package: a function whose return value carries labels makes
every call to it (matched by bare name) carry them too.

v4 (this module; dataflow_rules.py is v3, frozen for the held-out run) adds
parameter-aware taint: when a call site passes labeled values into a package
function, the callee is re-analyzed with those parameters pre-labeled
(context-sensitive by label set, memoized, up to depth 2) and findings are
reported inside the callee, with the caller in Finding.via. Callees resolve
the same way as return values (unique, non-generic name; f(...) or
self.f(...)), with one opt-in exception: a generic name like `send` resolves
when it is called as a bare name in the module that defines it at top level
and that module doesn't import the name. Such findings carry loose=True.

Only exfiltration-source labels cross into parameters by default (ENV_BULK,
CRED_FILE, HOSTINFO, HOSTID and credential paths). Pushing NET / NETFILE /
DECODED down as well (param_labels=ALL_PARAM_LABELS) found nothing new on the
Datadog set but took eval-week strong flags from 143 to 350: dev tools and
self-updaters pass response fields into their own subprocess helpers.

Specific secrets (os.getenv("OPENAI_API_KEY")) are deliberately not a source:
SDKs sending their own API key to their own API were the largest
false-positive bucket in the PyPI run.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

NET, ENV_BULK, HOSTINFO, CRED_FILE, DECODED = "NET", "ENV_BULK", "HOSTINFO", "CRED_FILE", "DECODED"
NETFILE = "NETFILE"  # a path whose contents came from the network
HOSTID = "HOSTID"    # hostname / username only (subset of HOSTINFO)
EMPTY: frozenset[str] = frozenset()

# Receivers we trust to be network clients. Short or generic names (r, s, client,
# pool, conn, request) are mostly dicts, DB pools or Flask's incoming request.
_NET_BASES = {"requests", "httpx", "urllib3", "aiohttp", "session", "sess", "sock", "socket", "urllib"}
_NET_FETCH = {"get", "post", "put", "patch", "request", "urlopen", "recv", "recvfrom", "recv_into",
              "read_url", "fetch"}
_NET_SEND = {"post", "put", "patch", "request", "urlopen", "send", "sendall", "sendto",
             "sendmail", "send_message"}
_DECODERS = {"b64decode", "b32decode", "b16decode", "b85decode", "a85decode", "urlsafe_b64decode",
             "decodebytes", "decompress", "fromhex", "unhexlify", "a2b_hex", "a2b_base64",
             "decrypt", "loads"}  # loads: marshal/pickle; json.loads propagates without DECODED
_CODE_EXEC = {"exec", "eval", "compile", "__import__"}
_CMD_EXEC = {"system", "popen", "Popen", "run", "call", "check_call", "check_output",
             "getoutput", "getstatusoutput", "startfile", "execv", "execve", "execl", "spawnv"}
_CMD_BASES = {"os", "subprocess", "commands", "pty"}
# bare-name calls that are commands no matter where they were imported from;
# run/call/execv only count when imported from subprocess/os (see _cmd_imports)
_CMD_BARE = {"system", "popen", "Popen", "check_output", "check_call", "getoutput",
             "getstatusoutput", "startfile"}
# helper names too generic to resolve across a package by name alone
_GENERIC_NAMES = {"run", "get", "post", "put", "call", "read", "open", "send", "request", "fetch",
                  "load", "loads", "main", "execute", "invoke", "handle", "process", "query",
                  "decode", "parse", "resolve", "start", "exec", "eval", "compile", "write"}
_SHELL_DOWNLOAD = re.compile(
    r"(-enc(odedcommand)?\s+[a-z0-9+/=]{24,}|invoke-webrequest|\biwr\s|downloadstring|"
    r"downloadfile|invoke-expression|\biex\b|certutil|bitsadmin|mshta|"
    r"\b(curl|wget)\b[^|;&]*https?://[^|;&]*(\||;|&&)\s*(ba|z)?sh\b|"
    r"\b(curl|wget)\b[^\n]*https?://[^\n]*\.(exe|sh|ps1|bat|bin|dll|scr|vbs)\b|"
    r"start\s+[^\n]*\.exe|/dev/tcp/|\bnc\b[^\n]*\s-e\s|\bncat\b[^\n]*-e\s|"
    r"base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh\b|metadata\.google\.internal|169\.254\.169\.254|"
    r"\b(curl|wget)\b[^\n]*\$\(?\s*(hostname|whoami|id|uname|pwd)|"
    r"\b(curl|wget)\b[^\n]*\$\{?(github_token|aws_|npm_token|pypi_token))", re.I)
_HOSTID = {"gethostname", "getfqdn", "getuser", "getlogin"}
_DNS = {"gethostbyname", "gethostbyname_ex", "getaddrinfo", "resolve", "query"}
_EXEC_FILE = {"startfile", "execv", "execve", "execl", "spawnv"} | _CMD_EXEC
_HOSTINFO = {"gethostname", "getfqdn", "getuser", "getlogin", "node", "uname", "platform",
             "getnode", "gethostbyname"}
_CRED_PATH = re.compile(
    r"(\.ssh|id_rsa|id_ed25519|\.aws|\.azure|\.kube|\.docker|\.netrc|\.npmrc|\.pypirc|"
    r"\.git-credentials|\.gnupg|login data|cookies|local storage|leveldb|wallet|"
    r"keychain|\.config/gcloud|discord|telegram desktop|exodus|metamask)", re.I)


@dataclass
class Finding:
    rule: str
    func: str
    line: int
    via: str = ""        # v4: caller whose arguments made this fire ("" = intrinsic)
    loose: bool = False  # v4: reached through a same-module generic-name callee
    origin: str = ""     # v4: file of the outermost caller (for install-time attribution)


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    return ".".join(reversed(parts))


def _call_name(call: ast.Call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _key(target: ast.AST) -> str | None:
    if isinstance(target, (ast.Name, ast.Attribute)):
        return _dotted(target)
    if isinstance(target, ast.Subscript):
        return _key(target.value)
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        return "const:" + target.value  # literal paths, e.g. urlretrieve(u, "/tmp/x")
    return None


def _is_environ(node: ast.AST) -> bool:
    return _dotted(node) == "os.environ"


class _FunctionTaint:
    """Labels for one function body (or a module's top-level statements)."""

    def __init__(self, body: list[ast.stmt], returns: dict[str, frozenset[str]],
                 cmd_names: frozenset[str] = EMPTY,
                 init_env: dict[str, frozenset[str]] | None = None):
        self.body = body
        self.returns = returns          # package-wide: function name -> return labels
        self.cmd_names = cmd_names      # names imported from subprocess / os in this module
        self.env: dict[str, frozenset[str]] = dict(init_env or {})  # v4: pre-labeled params
        self.file_alias: dict[str, ast.expr] = {}   # with open(p) as f  ->  f: p

    # ── expression labels ────────────────────────────────────────────────────
    def labels(self, node: ast.AST | None) -> frozenset[str]:
        if node is None:
            return EMPTY
        if isinstance(node, (ast.Name, ast.Attribute)):
            k = _dotted(node)
            if k in self.env:
                return self.env[k]
            if isinstance(node, ast.Attribute):
                return self.labels(node.value)
            return EMPTY
        if isinstance(node, ast.Subscript):
            return self.labels(node.value)
        if isinstance(node, ast.Call):
            return self._call_labels(node)
        if isinstance(node, ast.Await):
            return self.labels(node.value)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and "const:" + node.value in self.env:
                return self.env["const:" + node.value]
            if isinstance(node.value, str) and _CRED_PATH.search(node.value) and \
                    re.search(r"[\\/~]|^\.", node.value):
                return frozenset({"_CRED_PATH"})
            return EMPTY
        out: set[str] = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr) or isinstance(child, (ast.keyword, ast.comprehension,
                                                                  ast.FormattedValue)):
                out |= self.labels(child) if not isinstance(child, ast.keyword) else self.labels(child.value)
        return frozenset(out)

    def _args_labels(self, call: ast.Call) -> frozenset[str]:
        out: set[str] = set()
        for a in call.args:
            out |= self.labels(a)
        for kw in call.keywords:
            out |= self.labels(kw.value)
        return frozenset(out)

    def _call_labels(self, call: ast.Call) -> frozenset[str]:
        name = _call_name(call)
        dotted = _dotted(call.func)
        base = dotted.split(".")[0].lower() if "." in dotted else ""
        args = self._args_labels(call)
        recv = self.labels(call.func.value) if isinstance(call.func, ast.Attribute) else EMPTY
        out = set(args) | set(recv)

        if name in {"urlopen", "urlretrieve"} or (name in _NET_FETCH and base in _NET_BASES):
            out.add(NET)
        # resolve package helpers only for f(...) / self.f(...) / cls.f(...)
        if name in self.returns and (isinstance(call.func, ast.Name) or base in {"self", "cls"}):
            out |= self.returns[name]
        if name in _DECODERS and not dotted.startswith("json."):
            out.add(DECODED)
        if name in _HOSTINFO and base in {"socket", "getpass", "os", "platform", "uuid", ""}:
            out.add(HOSTINFO)
            if name in _HOSTID:
                out.add(HOSTID)
        # "".join(map(chr, [...])), bytes([...]).decode(), codecs.decode(x, "rot13")
        if name == "join" and any(isinstance(n, ast.Name) and n.id == "chr" for n in ast.walk(call)):
            out.add(DECODED)
        if name == "bytes" and call.args and isinstance(call.args[0], (ast.List, ast.ListComp, ast.Tuple)):
            out.add(DECODED)
        if name == "decode" and dotted.startswith("codecs.") and any(
                isinstance(a, ast.Constant) and str(a.value).lower().startswith("rot") for a in call.args):
            out.add(DECODED)
        if (name in {"dict", "copy", "items", "dumps", "str", "repr"} and
                (any(_is_environ(a) for a in call.args) or
                 (isinstance(call.func, ast.Attribute) and _is_environ(call.func.value)))):
            out.add(ENV_BULK)
        # open("~/.ssh/id_rsa").read() / Path(...).read_text()
        if "_CRED_PATH" in out and name in {"read", "read_text", "read_bytes", "readlines", "open"}:
            out.add(CRED_FILE)
        return frozenset(out)

    # ── statement walk ───────────────────────────────────────────────────────
    def _assign(self, target: ast.AST, labels: frozenset[str]) -> bool:
        if isinstance(target, (ast.Tuple, ast.List)):
            return any([self._assign(t, labels) for t in target.elts])
        if isinstance(target, ast.Starred):
            return self._assign(target.value, labels)
        k = _key(target)
        if k is None or not labels:
            return False
        old = self.env.get(k, EMPTY)
        if labels <= old:
            return False
        self.env[k] = old | labels
        return True

    def _stmts(self):
        for stmt in self.body:
            for node in ast.walk(stmt):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)) \
                        and node is not stmt:
                    continue
                yield node

    def solve(self) -> None:
        for _ in range(6):
            changed = False
            for node in self._stmts():
                if isinstance(node, ast.Assign):
                    lab = self.labels(node.value)
                    for t in node.targets:
                        changed |= self._assign(t, lab)
                elif isinstance(node, (ast.AugAssign, ast.AnnAssign)) and node.value is not None:
                    changed |= self._assign(node.target, self.labels(node.value))
                elif isinstance(node, ast.NamedExpr):
                    changed |= self._assign(node.target, self.labels(node.value))
                elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                    changed |= self._assign(node.target, self.labels(node.iter))
                elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                    changed |= self._assign(node.optional_vars, self.labels(node.context_expr))
                    ce = node.context_expr
                    if isinstance(ce, ast.Call) and _call_name(ce) == "open" and ce.args:
                        k = _key(node.optional_vars)
                        if k:
                            self.file_alias[k] = ce.args[0]
                elif isinstance(node, ast.Call) and _call_name(node) == "urlretrieve" and len(node.args) > 1:
                    changed |= self._assign(node.args[1], frozenset({NETFILE}))
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                        node.func.attr in {"write", "write_bytes", "write_text"} and \
                        NET in self._args_labels(node):
                    # open(p, "wb").write(r.content) / Path(p).write_bytes(...) / f.write(...)
                    tgt = node.func.value
                    if isinstance(tgt, ast.Call) and tgt.args:
                        changed |= self._assign(tgt.args[0], frozenset({NETFILE}))
                    else:
                        changed |= self._assign(tgt, frozenset({NETFILE}))
                        for alias, path in self.file_alias.items():
                            if alias == _key(tgt):
                                changed |= self._assign(path, frozenset({NETFILE}))
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                        node.func.attr in {"write", "append", "update", "extend", "add"}:
                    # buf.write(data) / payload.update(os.environ) taint the receiver
                    changed |= self._assign(node.func.value, self._args_labels(node))
            if not changed:
                break

    def return_labels(self) -> frozenset[str]:
        out: set[str] = set()
        for node in self._stmts():
            if isinstance(node, (ast.Return, ast.Yield)) and node.value is not None:
                out |= self.labels(node.value)
        return frozenset(out) - {"_CRED_PATH", NETFILE}

    def _glued_to_domain(self, arg: ast.AST) -> bool:
        """arg builds a hostname out of a host-id value plus a literal domain."""
        if isinstance(arg, (ast.Name, ast.Attribute)):
            return False
        return any(isinstance(c, ast.Constant) and isinstance(c.value, str) and "." in c.value
                   for c in ast.walk(arg))

    def _bare_cmd(self, call: ast.Call) -> bool:
        return isinstance(call.func, ast.Name) and (call.func.id in _CMD_BARE or call.func.id in self.cmd_names)

    def exec_aliases(self) -> set[str]:
        """Names bound to exec/eval: `e = exec`, `_ = eval('eval')`, `x = getattr(builtins, 'exec')`."""
        names = set(_CODE_EXEC)
        aliasable = {"exec", "eval"}  # __import__/compile get wrapped legitimately (import hooks, tests)
        for node in self._stmts():
            if not isinstance(node, ast.Assign):
                continue
            v = node.value
            hit = (isinstance(v, ast.Name) and v.id in aliasable) or (
                isinstance(v, ast.Call) and any(isinstance(a, ast.Constant) and a.value in aliasable
                                                for a in v.args))
            if hit:
                names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        return names

    def findings(self, func: str) -> list[Finding]:
        found = []
        execs = self.exec_aliases()
        has_dup2_fileno = has_socket = False
        for node in self._stmts():
            if isinstance(node, ast.Call):
                n = _call_name(node)
                if n == "dup2" and "fileno" in ast.unparse(node):
                    has_dup2_fileno = True
                if n in {"socket", "create_connection", "connect"}:
                    has_socket = True
                if n == "spawn" and _dotted(node.func).startswith("pty") and \
                        re.search(r"/bin/(ba|z)?sh\b", ast.unparse(node)):
                    found.append(Finding("reverse_shell", func, node.lineno))
        if has_dup2_fileno and has_socket:
            found.append(Finding("reverse_shell", func, getattr(self.body[0], "lineno", 0) if self.body else 0))
        for node in self._stmts():
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            dotted = _dotted(node.func)
            base = dotted.split(".")[0].lower() if "." in dotted else ""
            args = self._args_labels(node)
            line = getattr(node, "lineno", 0)
            if isinstance(node.func, ast.Name) and name in execs:
                if NET in args:
                    found.append(Finding("remote_code_exec", func, line))
                elif DECODED in args or name not in _CODE_EXEC:
                    # calling exec/eval through an alias is obfuscation in itself
                    found.append(Finding("decoded_exec", func, line))
            elif name in _CMD_EXEC and (base in _CMD_BASES or self._bare_cmd(node)):
                if NET in args:
                    found.append(Finding("remote_cmd_exec", func, line))
                consts = " ".join(c.value for a in node.args for c in ast.walk(a)
                                  if isinstance(c, ast.Constant) and isinstance(c.value, str))
                if consts and _SHELL_DOWNLOAD.search(consts) and \
                        not re.match(r"\s*(git|pip|python|cmake|make|conda|npm)\b", consts):
                    found.append(Finding("shell_download", func, line))
            if name in _EXEC_FILE and NETFILE in args and (base in _CMD_BASES or self._bare_cmd(node)):
                found.append(Finding("download_exec", func, line))
            if name in _NET_SEND and (base in _NET_BASES or name == "urlopen"):
                for lab, rule in ((ENV_BULK, "exfil_env_bulk"), (CRED_FILE, "exfil_cred_file"),
                                  (HOSTINFO, "exfil_hostinfo")):
                    if lab in args:
                        found.append(Finding(rule, func, line))
            # hostname/username smuggled out in a GET URL / params, or as a DNS label
            if name == "get" and base in _NET_BASES and HOSTID in args:
                found.append(Finding("exfil_hostid", func, line))
            elif name in _DNS and HOSTID in args and node.args and self._glued_to_domain(node.args[0]):
                # gethostbyname(gethostname()) is the usual "what's my LAN IP" idiom
                found.append(Finding("exfil_hostid", func, line))
        return found


_Def = ast.FunctionDef | ast.AsyncFunctionDef


def _scopes(tree: ast.Module):
    """(name, body, def node or None) for the module top level and every function / method."""
    top = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    yield "<module>", top, None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node.body, node


def _cmd_imports(tree: ast.Module) -> frozenset[str]:
    """Local names bound by `from subprocess import run` / `from os import system`."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in _CMD_BASES:
            names |= {a.asname or a.name for a in node.names if a.name in _EXEC_FILE}
    return frozenset(names)


def _imported_names(tree: ast.Module) -> frozenset[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names |= {(a.asname or a.name).split(".")[0] for a in node.names}
    return frozenset(names)


EXFIL_PARAM_LABELS = frozenset({ENV_BULK, CRED_FILE, HOSTINFO, HOSTID, "_CRED_PATH"})
ALL_PARAM_LABELS = EXFIL_PARAM_LABELS | {NET, NETFILE, DECODED}

Binding = frozenset  # frozenset[tuple[str, frozenset[str]]]: (param name, labels)


def _bind(ft: _FunctionTaint, call: ast.Call, fdef: _Def, via_self: bool,
          keep: frozenset[str] = ALL_PARAM_LABELS) -> Binding | None:
    """Labels each parameter of fdef receives at this call site (None: arity mismatch)."""
    a = fdef.args
    params = [p.arg for p in a.posonlyargs + a.args]
    static = any(_dotted(d) == "staticmethod" for d in fdef.decorator_list)
    if via_self and not static:
        params = params[1:]
    elif not via_self and params and params[0] in {"self", "cls"}:
        return None
    kwonly = [p.arg for p in a.kwonlyargs]
    vararg = a.vararg.arg if a.vararg else None
    kwarg = a.kwarg.arg if a.kwarg else None
    out: dict[str, set[str]] = {}

    def put(p: str | None, lab: frozenset[str]) -> None:
        lab = lab & keep
        if p and lab:
            out.setdefault(p, set()).update(lab)

    for i, arg in enumerate(call.args):
        lab = ft.labels(arg)
        if isinstance(arg, ast.Starred):
            for p in params[i:]:
                put(p, lab)
            put(vararg, lab)
            break
        put(params[i] if i < len(params) else vararg, lab)
    for kw in call.keywords:
        lab = ft.labels(kw.value)
        if kw.arg is None:          # **kwargs at the call site
            for p in params + kwonly:
                put(p, lab)
            put(kwarg, lab)
        elif kw.arg in params or kw.arg in kwonly:
            put(kw.arg, lab)
        else:
            put(kwarg, lab)
    return frozenset((p, frozenset(lab)) for p, lab in out.items())


def analyze_package(modules: list[tuple[str, ast.Module]], max_depth: int = 2,
                    local_generic: bool = True, max_contexts: int = 400,
                    param_labels: frozenset[str] = EXFIL_PARAM_LABELS) -> list[tuple[str, Finding]]:
    """modules: (rel_path, parsed tree). Returns (rel_path, Finding) pairs.

    max_depth: how many call levels parameter labels are pushed down (0 = v3 behaviour).
    local_generic: allow same-module bare calls to generic names (send, post ...)
    as parameter-propagation targets; those findings have loose=True.
    max_contexts: cap on callee re-analyses per package.
    param_labels: which labels may cross from arguments into parameters.
    """
    cmd = {rel: _cmd_imports(tree) for rel, tree in modules}
    scopes = [(rel, name, body, node) for rel, tree in modules for name, body, node in _scopes(tree)]
    n_defs: dict[str, int] = {}
    for _, name, _, _ in scopes:
        n_defs[name] = n_defs.get(name, 0) + 1
    returns: dict[str, frozenset[str]] = {}
    # two rounds so helper -> helper -> caller chains resolve; only names defined
    # once in the package and not generic, since resolution is by bare name
    for _ in range(2):
        for rel, name, body, _ in scopes:
            if name == "<module>" or n_defs[name] > 1 or name in _GENERIC_NAMES:
                continue
            ft = _FunctionTaint(body, returns, cmd[rel])
            ft.solve()
            lab = ft.return_labels()
            if lab:
                returns[name] = returns.get(name, EMPTY) | lab

    # parameter-propagation targets
    defs: dict[str, tuple[str, _Def]] = {}
    for rel, name, _, node in scopes:
        if node is not None and n_defs[name] == 1 and name not in _GENERIC_NAMES:
            defs[name] = (rel, node)
    local: dict[tuple[str, str], _Def] = {}
    if local_generic:
        for rel, tree in modules:
            imported = _imported_names(tree)
            top = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and n.name in _GENERIC_NAMES and n.name not in imported]
            counts: dict[str, int] = {}
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    counts[n.name] = counts.get(n.name, 0) + 1
            for n in top:
                if counts[n.name] == 1:
                    local[(rel, n.name)] = n

    def resolve(call: ast.Call, rel: str) -> tuple[str, _Def, bool, bool] | None:
        """-> (callee rel, def, via_self, loose)"""
        name = _call_name(call)
        if isinstance(call.func, ast.Name):
            via_self = False
        elif isinstance(call.func, ast.Attribute) and _dotted(call.func.value) in {"self", "cls"}:
            via_self = True
        else:
            return None
        if name in defs:
            return defs[name][0], defs[name][1], via_self, False
        if not via_self and (rel, name) in local:
            return rel, local[(rel, name)], False, True
        return None

    def labeled_calls(ft: _FunctionTaint, rel: str):
        for node in ft._stmts():
            if isinstance(node, ast.Call) and (node.args or node.keywords):
                r = resolve(node, rel)
                if r is None:
                    continue
                b = _bind(ft, node, r[1], r[2], param_labels)
                if b:
                    yield r[0], r[1], b, r[3]

    out: list[tuple[str, Finding]] = []
    seen: set[tuple[str, str, int]] = set()
    pending = []
    for rel, name, body, _ in scopes:
        ft = _FunctionTaint(body, returns, cmd[rel])
        ft.solve()
        for f in ft.findings(name):
            out.append((rel, f))
            seen.add((rel, f.rule, f.line))
        if max_depth > 0:
            for crel, fdef, b, loose in labeled_calls(ft, rel):
                pending.append((crel, fdef, b, name, loose, rel))

    memo: set[tuple[str, int, Binding]] = set()

    def run_ctx(crel: str, fdef: _Def, b: Binding, via: str, loose: bool, origin: str,
                depth: int) -> None:
        key = (crel, fdef.lineno, b)
        if key in memo or len(memo) >= max_contexts:
            return
        memo.add(key)
        ft = _FunctionTaint(fdef.body, returns, cmd[crel], init_env=dict(b))
        ft.solve()
        for f in ft.findings(fdef.name):
            if (crel, f.rule, f.line) not in seen:
                seen.add((crel, f.rule, f.line))
                f.via, f.loose, f.origin = via, loose, origin
                out.append((crel, f))
        if depth < max_depth:
            for nrel, ndef, nb, nloose in labeled_calls(ft, crel):
                run_ctx(nrel, ndef, nb, fdef.name, loose or nloose, origin, depth + 1)

    for crel, fdef, b, via, loose, origin in pending:
        run_ctx(crel, fdef, b, via, loose, origin, 1)
    return out
