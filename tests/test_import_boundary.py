"""Every process spawn and process signal goes through ``gateway.py`` (design guide section 14).

``find_violations`` is the checker; the first group of tests proves it fails on offending code,
the last one runs it over the real tree.

Limits of a static checker: it cannot catch ``getattr`` with a computed name on a module it does
not know is ``os``, ``sys.modules`` tricks, ``open('/proc/...')`` style indirection, or code
loaded from data. It bans the dynamic-import and ``eval``/``exec``/``compile`` entry points so
those routes need a visible, flagged name first. Only ``src/gatectl/**/*.py`` is scanned (tests
and scripts are out of scope), with ``gateway.py`` itself exempt.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "gatectl"
GATEWAY = SRC / "gateway.py"

# Modules (and their submodules) nothing but the gateway may import.
BANNED_MODULES = {
    "subprocess",
    "_posixsubprocess",
    "pty",
    "multiprocessing",
    "ctypes",
    "asyncio.subprocess",
    "concurrent.futures.process",
}
# Modules whose attributes are the os API (``posix`` is what ``os`` re-exports on POSIX).
OS_LIKE = {"os", "posix"}
BANNED_OS = {
    "system",
    "popen",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "kill",
    "killpg",
    "pidfd_open",
    *(f"spawn{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    *(f"exec{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
}
# Names that spawn wherever they come from (``asyncio.create_subprocess_exec``, ...).
BANNED_NAMES = {"create_subprocess_exec", "create_subprocess_shell", "ProcessPoolExecutor"}
# Any reference to these is a violation: they load modules by a name the checker cannot see.
DYNAMIC_IMPORTERS = {"__import__", "import_module"}
BANNED_CALLS = {"eval", "exec", "compile"}


def _banned_module(name: str) -> bool:
    return any(name == m or name.startswith(m + ".") for m in BANNED_MODULES)


def find_violations(source: str, filename: str = "<src>") -> list[str]:
    """Return one message per spawn-capable import, call or reference in ``source``."""
    tree = ast.parse(source, filename)
    found: list[str] = []
    os_names: set[str] = set()  # local names bound to the ``os`` (or ``posix``) module

    def flag(node: ast.AST, what: str) -> None:
        found.append(f"{filename}:{getattr(node, 'lineno', 0)}: {what}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _banned_module(alias.name):
                    flag(node, f"import {alias.name}")
                first = alias.name.split(".")[0]
                if first in OS_LIKE:
                    # ``import os.path`` binds ``os``; ``import os.path as p`` binds only ``p``.
                    if alias.asname is None:
                        os_names.add(first)
                    elif alias.name in OS_LIKE:
                        os_names.add(alias.asname)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            module = node.module or ""
            if _banned_module(module):
                flag(node, f"from {module} import ...")
            for alias in node.names:
                name = alias.name
                if _banned_module(f"{module}.{name}"):
                    flag(node, f"from {module} import {name}")
                if name in BANNED_NAMES | DYNAMIC_IMPORTERS:
                    flag(node, f"from {module} import {name}")
                if name == "*" and module in OS_LIKE | {"importlib"}:
                    flag(node, f"from {module} import *")
                if module in OS_LIKE and name in BANNED_OS:
                    flag(node, f"from {module} import {name}")

    attribute_bases = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr in BANNED_NAMES | DYNAMIC_IMPORTERS:
                flag(node, f"reference to {node.attr}")
            elif (
                isinstance(node.value, ast.Name)
                and node.value.id in os_names
                and node.attr in BANNED_OS
            ):
                flag(node, f"os.{node.attr}")
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in BANNED_NAMES | DYNAMIC_IMPORTERS:
                flag(node, f"reference to {node.id}")
            elif node.id in os_names and id(node) not in attribute_bases:
                # ``o = os``, ``getattr(os, ...)``, ``[os]``: the module escapes the checker.
                flag(node, f"{node.id} used as a value")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in BANNED_CALLS
        ):
            flag(node, f"call to {node.func.id}")
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
        # round 1: bypasses
        "import os.path\nos.system('x')",
        "import os.path as p\nimport os\nos.system('x')",
        "from os import *",
        "from posix import *",
        "import posix\nposix.system('x')",
        "import posix as px\npx.fork()",
        "from posix import system",
        "import multiprocessing",
        "from multiprocessing import Process",
        "import ctypes",
        "from ctypes import CDLL",
        "import asyncio.subprocess",
        "from asyncio import subprocess",
        "from asyncio.subprocess import PIPE",
        "import concurrent.futures.process",
        "from concurrent.futures import process",
        "from concurrent.futures import ProcessPoolExecutor",
        "import asyncio\nasyncio.create_subprocess_exec('x')",
        "import asyncio\nasyncio.create_subprocess_shell('x')",
        "from asyncio import create_subprocess_exec",
        "import concurrent.futures as cf\ncf.ProcessPoolExecutor()",
        "from importlib import import_module",
        "from importlib import import_module as im\nim('subprocess')",
        "from importlib import *",
        "x = __import__\nx('subprocess')",
        "__import__(name='subprocess')",
        "import importlib\nimportlib.import_module(name='subprocess')",
        "import importlib\nf = importlib.import_module",
        "import os\ngetattr(os, 'sys' + 'tem')('x')",
        "import os\no = os\no.system('x')",
        "import os\nf = [os]",
        "eval('1')",
        "exec('import subprocess')",
        "compile('x', 'f', 'exec')",
        "import os\nos.kill(1, 9)",
        "import os\nos.killpg(1, 9)",
        "import os\nos.pidfd_open(1)",
        "from os import kill",
        "from os import killpg as kp",
        "from os import pidfd_open",
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
        "import os.path as p\np.join('a', 'b')",
        "import os.path\nos.path.join('a', 'b')",
        "import os\nos.getpid()\nos.environ['A'] = 'b'",
        "import importlib\nimportlib.invalidate_caches()",
        "import asyncio\nasyncio.sleep(1)",
        "import concurrent.futures\nconcurrent.futures.ThreadPoolExecutor()",
        "def compile_it(): pass\ncompile_it()",
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
