"""
Feature extraction for the PyPI eval, kept identical to training.

extractor_AST.py runs its CSV pipeline at import time, so instead of importing
it we parse its source, keep only imports / constant assignments / function
defs, and exec that. This way get_Node_Counts is the exact training code.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from normalizer_AST import codeNormalizer  # noqa: E402


def _load_get_node_counts():
    tree = ast.parse((SRC / "extractor_AST.py").read_text())
    keep = [n for n in tree.body
            if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))
            or (isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
                and getattr(n.value.func, "id", None) == "frozenset")]
    ns: dict = {}
    exec(compile(ast.Module(body=keep, type_ignores=[]), "extractor_AST.py", "exec"), ns)
    return ns["get_Node_Counts"]


get_Node_Counts = _load_get_node_counts()

INSTALL_TIME_NAMES = {"setup.py", "conftest.py", "hatch_build.py", "build.py",
                      "_build.py", "build_ext.py", "pdm_build.py", "__main__.py"}


def is_install_time(rel_path: str) -> bool:
    """setup.py and build hooks run at install; a top-level package
    __init__.py runs at first import."""
    parts = Path(rel_path).parts
    name = parts[-1]
    if name in INSTALL_TIME_NAMES:
        return True
    # sdist layout: <dist>-<ver>/<pkg>/__init__.py  (depth 3) or src/<pkg>/__init__.py
    return name == "__init__.py" and (len(parts) <= 3 or (len(parts) == 4 and parts[1] == "src"))


MAX_SOURCE_BYTES = 1_000_000


def read_jsonl(path: Path) -> list[dict]:
    """Parse a JSONL file, skipping a half-written last line (the live
    collector appends to manifest.jsonl while other scripts read it)."""
    import json
    out = []
    for line in Path(path).read_text().splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def pack_code(src: str) -> str:
    """Store code snippets zlib+base64 encoded. Snippets from malicious
    packages are real malware, and antivirus quarantines any plaintext file
    that contains them, including our whole units.jsonl."""
    import base64
    import zlib
    return base64.b64encode(zlib.compress(src.encode("utf-8", "replace"))).decode("ascii")


def unpack_code(blob: str) -> str:
    import base64
    import zlib
    if not blob:
        return ""
    return zlib.decompress(base64.b64decode(blob)).decode("utf-8", "replace")


def iter_sources(root: Path, rec: dict):
    """Yield (rel_path, source_text | None) for every .py file of a record.

    Records with "zip" point at an encrypted Datadog sample: members are
    decrypted in memory only, so plaintext malware never touches disk.
    Records with "path" point at a directory of extracted PyPI files.
    None means the file was too big to parse.
    """
    if rec.get("zip"):
        import zipfile
        with zipfile.ZipFile(root / rec["zip"]) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".py"):
                    continue
                if info.file_size > MAX_SOURCE_BYTES:
                    yield info.filename, None
                    continue
                yield info.filename, zf.read(info, pwd=b"infected").decode("utf-8", "replace")
        return
    pkg_dir = root / rec["path"]
    for f in sorted(pkg_dir.rglob("*.py")):
        rel = str(f.relative_to(pkg_dir))
        try:
            if f.stat().st_size > MAX_SOURCE_BYTES:
                yield rel, None
                continue
            yield rel, f.read_text(errors="replace")
        except FileNotFoundError:  # removed by antivirus mid-scan
            continue


def split_units(source: str):
    """Yield (unit_name, ast.Module, lineno) in the shape the model was trained on.

    Training samples were single top-level functions (median ~550 chars).
    We score every function and method on its own, plus one 'module-level'
    unit holding the top-level statements that are not defs or classes,
    which is where most setup.py / dropper logic lives.
    """
    tree = ast.parse(source)
    residue = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, ast.Module(body=[node], type_ignores=[]), node.lineno
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{node.name}.{sub.name}", ast.Module(body=[sub], type_ignores=[]), sub.lineno
        else:
            residue.append(node)
    if residue:
        yield "<module>", ast.Module(body=residue, type_ignores=[]), residue[0].lineno


def unit_features(mod: ast.Module) -> tuple[dict, str, str]:
    """Return (feature dict, raw unit source, normalized unit source)."""
    raw = ast.unparse(mod)
    normalized = ast.unparse(codeNormalizer().visit(ast.parse(raw)))
    counts = get_Node_Counts(normalized)
    if isinstance(counts, Exception):
        raise counts
    return counts, raw, normalized
