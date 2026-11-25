"""Every process spawn goes through ``gateway.py`` (design guide section 14).

``find_violations`` is the checker; the first group of tests proves it fails on offending code,
the last one runs it over the real tree.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "gatectl"
GATEWAY = SRC / "gateway.py"

BANNED_MODULES = {"subprocess", "_posixsubprocess", "pty"}
BANNED_OS = {
    "system",
    "popen",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    *(f"spawn{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    *(f"exec{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
}
DYNAMIC_IMPORTERS = {"__import__", "import_module"}


def find_violations(source: str, filename: str = "<src>") -> list[str]:
    """Return one message per spawn-capable import or call in ``source``."""
    tree = ast.parse(source, filename)
    found: list[str] = []
    os_names: set[str] = set()  # local names bound to the ``os`` module
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in BANNED_MODULES:
                    found.append(f"{filename}:{node.lineno}: import {alias.name}")
                if alias.name == "os":
                    os_names.add(alias.asname or "os")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if node.level == 0 and root in BANNED_MODULES:
                found.append(f"{filename}:{node.lineno}: from {node.module} import ...")
            if node.level == 0 and root == "os":
                for alias in node.names:
                    if alias.name in BANNED_OS:
                        found.append(f"{filename}:{node.lineno}: from os import {alias.name}")
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name in DYNAMIC_IMPORTERS and node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                    found.append(f"{filename}:{node.lineno}: dynamic import with a computed name")
                elif arg.value.split(".")[0] in BANNED_MODULES | {"os"}:
                    found.append(f"{filename}:{node.lineno}: dynamic import of {arg.value}")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in os_names
            and node.attr in BANNED_OS
        ):
            found.append(f"{filename}:{node.lineno}: os.{node.attr}")
    return found


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess",
        "import subprocess as sp",
        "import subprocess.something",
        "from subprocess import run",
        "from subprocess import Popen as P",
        "import os\nos.system('x')",
        "import os\nos.popen('x')",
        "import os\nos.spawnv(0, 'x', [])",
        "import os as o\no.spawnlp(0, 'x')",
        "import os\nos.posix_spawn('x', [], {})",
        "import os\nos.execv('x', [])",
        "import os\nos.fork()",
        "from os import system",
        "from os import popen as p",
        "from os import spawnvp",
        "import pty",
        "import _posixsubprocess",
        "__import__('subprocess')",
        "import importlib\nimportlib.import_module('subprocess')",
        "import importlib\nimportlib.import_module('os')",
        "__import__('sub' + 'process')",
        "def f():\n    import subprocess\n",
        "try:\n    from subprocess import run\nexcept ImportError:\n    pass\n",
    ],
)
def test_checker_flags_spawning_code(source: str) -> None:
    assert find_violations(source), source


@pytest.mark.parametrize(
    "source",
    [
        "",
        "import os\nos.getpid()\nos.path.join('a', 'b')",
        "import os\nos.environ.get('HOME')",
        "from os import path, getpid",
        "import sys\nsys.exit(0)",
        "from gatectl.gateway import Gateway",
        "from . import subprocess_helpers",
        "subprocess = 3\nsystem = 4",
        "x = 'subprocess'",
    ],
)
def test_checker_passes_innocent_code(source: str) -> None:
    assert find_violations(source) == []


def test_checker_reports_file_and_line() -> None:
    (msg,) = find_violations("x = 1\nimport subprocess\n", "pkg/mod.py")
    assert msg.startswith("pkg/mod.py:2:")


def scan_tree(root: Path, exempt: Path) -> list[str]:
    """Violations in every ``.py`` file under ``root`` except the one ``exempt`` file."""
    found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if path != exempt:
            found += find_violations(path.read_text(encoding="utf-8"), str(path.relative_to(root)))
    return found


def test_tree_has_no_spawn_outside_the_gateway() -> None:
    assert len(list(SRC.rglob("*.py"))) > 1, "no source files found: the test would be vacuous"
    assert GATEWAY.is_file()
    assert scan_tree(SRC, GATEWAY) == []


def test_gateway_is_exempt_and_really_spawns() -> None:
    # The exemption is not vacuous: the gateway is where the spawn lives.
    assert find_violations(GATEWAY.read_text(encoding="utf-8"))


def test_tree_scan_fails_on_a_module_that_imports_subprocess(tmp_path: Path) -> None:
    (tmp_path / "gateway.py").write_text("import subprocess\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("import subprocess\n", encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "gateway.py").write_text("import subprocess\n", encoding="utf-8")
    found = scan_tree(tmp_path, tmp_path / "gateway.py")
    # The top-level gateway is exempt; bad.py and a gateway.py in a subpackage are not.
    assert len(found) == 2
    assert any(f.startswith("bad.py:") for f in found)
    assert any(f.startswith("sub/gateway.py:") for f in found)
