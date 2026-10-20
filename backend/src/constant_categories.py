"""
Coarse categories of the constants the normalizer would otherwise hide.

Renaming-invariance stays: identifiers are still normalized. But the things
that separate a binary fetcher from a dropper live in literal values (where
a URL points, where a file lands, which env vars get read), so we keep a
bucketed summary of them instead of throwing them away.

Must run on the raw (un-normalized) AST. Every feature is prefixed cc_ so
models trained with them can be detected by feature name.
"""
from __future__ import annotations

import ast
import ipaddress
import re
from urllib.parse import urlparse

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)

# where legit installers usually fetch prebuilt binaries / data from
_ARTIFACT_HOSTS = (
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "pypi.org", "pythonhosted.org", "huggingface.co", "readthedocs.io",
    "amazonaws.com", "storage.googleapis.com", "blob.core.windows.net",
    "sourceforge.net", "anaconda.org", "npmjs.org", "crates.io",
)
# hosts that show up again and again in PyPI malware for exfil / staging
_EXFIL_HOSTS = (
    "discord.com/api/webhooks", "discordapp.com/api/webhooks", "api.telegram.org",
    "pastebin.com", "paste.ee", "hastebin", "transfer.sh", "ngrok", "webhook.site",
    "requestbin", "pipedream.net", "interact.sh", "oast.", "burpcollaborator",
    "trycloudflare.com", "glitch.me", "replit.dev", "anonfiles", "gofile.io",
    "ipinfo.io", "ip-api.com", "api.ipify.org", "checkip.",
)
_BINARY_EXT = (".exe", ".dll", ".so", ".dylib", ".bin", ".sh", ".ps1", ".bat",
               ".vbs", ".msi", ".zip", ".tar.gz", ".tgz", ".jar", ".scr")

_OUTSIDE_PKG_PATHS = re.compile(
    r"(^/tmp\b|^/var/tmp|^/dev/shm|%temp%|%appdata%|appdata[\\/]|\\startup\\|start menu\\programs\\startup|"
    r"^/etc/|launchagents|launchdaemons|\.bashrc|\.zshrc|\.profile\b|\.config/autostart|"
    r"/usr/local/bin|/usr/bin|crontab|system32|\\windows\\)", re.I)
_CREDENTIAL_PATHS = re.compile(
    r"(\.ssh\b|id_rsa|\.aws[\\/]|credentials|login data|cookies|local storage|leveldb|"
    r"\.git-credentials|\.npmrc|\.pypirc|\.netrc|wallet|keychain|discord[\\/]|"
    r"\.docker/config|kube/config|\.gnupg|exodus|metamask)", re.I)

_SECRET_ENV = re.compile(r"(TOKEN|SECRET|PASSW|API_?KEY|PRIVATE|CREDENTIAL|AWS_|WEBHOOK|SESSION)", re.I)
_BUILD_ENV = re.compile(
    r"^(CC|CXX|LD|AR|CFLAGS|CXXFLAGS|LDFLAGS|CPPFLAGS|PATH|HOME|USER|CI|TMPDIR|TEMP|TMP|"
    r"LANG|TERM|SHELL|PWD|VIRTUAL_ENV|CONDA_PREFIX|MACOSX_DEPLOYMENT_TARGET|"
    r"PYTHON\w*|PIP_\w*|SETUPTOOLS_\w*|\w*_VERSION|\w*_HOME|\w*_DIR|\w*_PATH|\w*_ROOT|"
    r"\w*_DEBUG|\w*_BUILD\w*|\w*_ARCH|\w*_PLATFORM|NO_COLOR|FORCE_COLOR|XDG_\w+|"
    r"GITHUB_ACTIONS|READTHEDOCS|\w*_LOG_LEVEL|\w*_NO_\w+|\w*_DISABLE\w*|\w*_SKIP\w*)$", re.I)

_DECODERS = {"b64decode", "b32decode", "b85decode", "a85decode", "urlsafe_b64decode",
             "decompress", "loads", "fromhex", "unhexlify", "decode"}
_EXECUTORS = {"exec", "eval", "compile", "__import__"}

_OBF_NAME = re.compile(r"^(_0x[0-9a-f]+|[Il1]{6,}|[O0]{6,}|_{3,}\w*|[a-zA-Z]\d{4,})$")

FEATURES = [
    "cc_url_raw_ip", "cc_url_artifact_host", "cc_url_exfil_host", "cc_url_other",
    "cc_url_binary_ext", "cc_path_outside_pkg", "cc_path_credential", "cc_path_pkg_relative",
    "cc_env_secret", "cc_env_build", "cc_env_other", "cc_env_bulk",
    "cc_platform_check", "cc_hash_verify", "cc_chmod_exec", "cc_decode_exec",
    "cc_obfuscator_marker", "cc_obf_name_ratio", "cc_network_call", "cc_download_then_run",
]


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _env_key(node: ast.AST) -> tuple[str | None, bool]:
    """If node reads an env var, return (key or None, is_env_access)."""
    if isinstance(node, ast.Subscript) and _dotted(node.value).endswith("environ"):
        return _const_str(node.slice), True
    if isinstance(node, ast.Call):
        d = _dotted(node.func)
        if d.endswith(("getenv", "environ.get", "environ.setdefault", "environ.pop")):
            return (_const_str(node.args[0]) if node.args else None), True
    return None, False


def constant_categories(tree: ast.AST) -> dict[str, float]:
    f = dict.fromkeys(FEATURES, 0.0)
    names, obf_names = 0, 0
    has_download = has_run = False

    for node in ast.walk(tree):
        s = _const_str(node)
        if s is not None:
            for url in _URL_RE.findall(s):
                low = url.lower()
                try:
                    parsed = urlparse(low)
                    host = parsed.hostname or ""
                except ValueError:  # e.g. "Invalid IPv6 URL"
                    f["cc_url_other"] += 1
                    continue
                try:
                    ip = ipaddress.ip_address(host)
                    if ip.is_global:  # loopback / LAN addresses are normal in tests and dev servers
                        f["cc_url_raw_ip"] += 1
                except ValueError:
                    if any(h in low for h in _EXFIL_HOSTS):
                        f["cc_url_exfil_host"] += 1
                    elif any(host == h or host.endswith("." + h) for h in _ARTIFACT_HOSTS):
                        f["cc_url_artifact_host"] += 1
                    else:
                        f["cc_url_other"] += 1
                if parsed.path.endswith(_BINARY_EXT):
                    f["cc_url_binary_ext"] += 1
            if not s.startswith(("http://", "https://")) and len(s) < 300:
                if _OUTSIDE_PKG_PATHS.search(s):
                    f["cc_path_outside_pkg"] += 1
                # only path-like strings, so a dict key "credentials" doesn't count
                if _CREDENTIAL_PATHS.search(s) and re.search(r"[\\/]|^~|^\.", s):
                    f["cc_path_credential"] += 1
            if "pyarmor" in s.lower() or "__pyarmor__" in s:
                f["cc_obfuscator_marker"] = 1

        elif isinstance(node, ast.Name):
            names += 1
            if _OBF_NAME.match(node.id):
                obf_names += 1
            if node.id == "__file__":
                f["cc_path_pkg_relative"] += 1
            if node.id.startswith("__pyarmor"):
                f["cc_obfuscator_marker"] = 1

        key, is_env = _env_key(node)
        if is_env:
            if key is None:
                f["cc_env_other"] += 1
            elif _SECRET_ENV.search(key):
                f["cc_env_secret"] += 1
            elif _BUILD_ENV.match(key):
                f["cc_env_build"] += 1
            else:
                f["cc_env_other"] += 1

        if isinstance(node, ast.Call):
            name = _call_name(node)
            dotted = _dotted(node.func)
            # whole environment serialized / copied out
            if any(isinstance(a, ast.Attribute) and a.attr == "environ" or
                   (isinstance(a, ast.Name) and a.id == "environ") for a in node.args) \
                    and name in {"dumps", "dict", "str", "repr", "post", "put", "send", "write", "urlencode"}:
                f["cc_env_bulk"] += 1
            if dotted in {"platform.machine", "platform.system", "platform.architecture",
                          "platform.processor", "sysconfig.get_platform"}:
                f["cc_platform_check"] += 1
            if dotted.startswith("hashlib.") or name in {"sha256", "sha512", "hexdigest", "compare_digest"}:
                f["cc_hash_verify"] += 1
            if name == "chmod":
                f["cc_chmod_exec"] += 1
            if name in {"urlopen", "urlretrieve", "get", "post", "request", "Request",
                        "download", "download_file", "create_connection", "connect"} and \
                    (dotted.split(".")[0] in {"urllib", "request", "requests", "httpx", "urllib3",
                                              "http", "socket", "aiohttp", "s"} or name in {"urlopen", "urlretrieve"}):
                f["cc_network_call"] += 1
                has_download = True
            if name in _EXECUTORS or dotted in {"os.system", "os.popen", "os.startfile",
                                                "subprocess.Popen", "subprocess.run",
                                                "subprocess.call", "subprocess.check_call",
                                                "subprocess.check_output", "os.execv", "os.execl"}:
                has_run = True
                for arg in node.args:
                    for sub in ast.walk(arg):
                        if isinstance(sub, ast.Call) and _call_name(sub) in _DECODERS:
                            f["cc_decode_exec"] += 1
                            break

    f["cc_obf_name_ratio"] = round(obf_names / names, 3) if names else 0.0
    f["cc_download_then_run"] = float(has_download and has_run)
    return f
