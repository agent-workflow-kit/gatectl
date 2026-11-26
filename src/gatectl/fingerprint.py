"""The policy fingerprint (interface.md, Fingerprint).

``fingerprint`` is ``sha256:`` plus the SHA-256 of the canonical JSON of a policy's **effective
definition** for a scope: a normalized form with every default filled in, so spelling a default
explicitly changes nothing, plus the hashes of the files the checks depend on.

Computing it never fails and never depends on the working directory. A file that cannot be
read (or that changes while it is read) contributes the fixed marker ``unreadable``. Files are
opened without blocking, only when they are regular files, and are streamed up to a cap: a
file over the cap contributes its size and modification time instead of its content. The
deadline is checked before each file; once it has passed every remaining file contributes the
marker. Only absolute paths are ever opened.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import time
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from typing import Any

from gatectl.config import LoadedConfig
from gatectl.config_models import AgentCheck, Policy, RuleCheck, ScriptCheck, SharedConfig
from gatectl.inputhash import canonical_input
from gatectl.scope import Scope, resolve_effective

UNREADABLE = "unreadable"
FILE_CAP = 1024 * 1024
INSTRUCTION_CAP = 64 * 1024
_CHUNK = 64 * 1024
# The permission profile used when neither the check nor the ``agent:`` block names one.
# The file is plugin/permission-profile.json, a copy of claude-session's built-in `review` profile;
# a drift test (tests/test_bundled_plugin.py) pins it.
BUNDLED_PROFILE = "permission-profile.json"

_ABSENT = (errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.ENAMETOOLONG)


def bundled_plugin_dir() -> str:
    """The bundled plugin directory: package data when installed, else ``plugin/`` of a checkout."""
    packaged = resources.files("gatectl") / "plugin"
    if packaged.is_dir():
        return str(packaged)
    return str(Path(__file__).resolve().parents[2] / "plugin")


class _Files:
    """Hash files for one fingerprint computation, under one deadline."""

    def __init__(self, deadline: float | None, monotonic: Callable[[], float]) -> None:
        self._deadline = deadline
        self._monotonic = monotonic

    def _expired(self) -> bool:
        return self._deadline is not None and self._monotonic() >= self._deadline

    def hash(
        self, path: str, *, cap: int = FILE_CAP, over: str = "stat", optional: bool = False
    ) -> Any:
        """The contribution of one file.

        A hex digest; ``{"size", "mtime_ns"}`` for a file over ``cap`` (``over="stat"``) or the
        marker (``over="unreadable"``); the marker for anything that cannot be read, or changed
        while it was read; ``None`` for an ``optional`` file that is absent or not a regular file.
        """
        try:
            data = self._load(path, cap, over, optional)
        except (OSError, ValueError):
            return UNREADABLE
        if isinstance(data, bytes):
            return hashlib.sha256(data).hexdigest()
        return data

    def _load(self, path: str, cap: int, over: str, optional: bool) -> Any:
        """The file's bytes, read twice and equal both times (else the marker), or the
        non-content contribution of ``hash`` (marker, ``None``, size and mtime)."""
        if self._expired():
            return UNREADABLE  # checked once per file, not per pass
        first = self._pass(path, cap, over, optional)
        if not isinstance(first, bytes):
            return first
        second = self._pass(path, cap, over, optional)
        return first if second == first else UNREADABLE  # rewritten between the passes

    def _pass(self, path: str, cap: int, over: str, optional: bool) -> Any:
        if not path.startswith("/"):
            return UNREADABLE
        gone = None if optional else UNREADABLE
        try:
            before = os.stat(path)
        except OSError as exc:
            return gone if exc.errno in _ABSENT else UNREADABLE
        if not stat.S_ISREG(before.st_mode):
            return gone  # never opened: a FIFO or device could block or have effects
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                return UNREADABLE  # swapped between the stat and the open
            if opened.st_size > cap:
                if over == "unreadable":
                    return UNREADABLE
                return {"size": opened.st_size, "mtime_ns": opened.st_mtime_ns}
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, _CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > cap:
                    return UNREADABLE  # grew while being read
                chunks.append(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        # ctime cannot be set from user space, so a same-size rewrite that restores mtime shows
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) or total != after.st_size:
            return UNREADABLE  # changed while being read
        return b"".join(chunks)

    def plugin_name(self, directory: str) -> str | None:
        """The ``name`` in ``<directory>/.claude-plugin/plugin.json``, or None.

        Read like every hashed file, up to ``FILE_CAP``; a larger file cannot identify its plugin.
        """
        path = f"{directory}/.claude-plugin/plugin.json"
        try:
            data = self._load(path, FILE_CAP, "unreadable", False)
            if not isinstance(data, bytes):
                return None
            name = json.loads(data).get("name")
        except (OSError, ValueError, AttributeError, RecursionError):
            return None
        return name if isinstance(name, str) else None


def plugin_name_of(directory: str) -> str | None:
    """The plugin's ``name`` (``.claude-plugin/plugin.json``, read like every hashed file)."""
    return _Files(None, time.monotonic).plugin_name(directory)


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _plugin_dirs(shared: SharedConfig, bundled: str) -> list[str]:
    return [bundled, *shared.agent.plugin_dirs]


def _skill_files(
    files: _Files, skill: str, directories: list[str], index: dict[str, str | None]
) -> dict[str, Any]:
    """The hashes of the skill's ``SKILL.md`` and its plugin's ``plugin.json``."""
    plugin, _, name = skill.partition(":")
    for directory in directories:
        if directory not in index:
            index[directory] = files.plugin_name(directory)
    found = next((d for d in directories if index[d] == plugin), None)
    if found is None:
        return {"skill_md": UNREADABLE, "plugin_json": UNREADABLE}
    return {
        "skill_md": files.hash(f"{found}/skills/{name}/SKILL.md"),
        "plugin_json": files.hash(f"{found}/.claude-plugin/plugin.json"),
    }


def _script(check: ScriptCheck, shared: SharedConfig, files: _Files) -> dict[str, Any]:
    allowed = sorted({*shared.defaults.script_env_allow, *(check.env_allow or [])})
    return {
        "name": check.name,
        "type": "script",
        "argv": list(check.argv),
        "env_allow": allowed,
        "argv_files": [
            files.hash(a, optional=True) if a.startswith("/") else None for a in check.argv
        ],
    }


def _rule(check: RuleCheck) -> dict[str, Any]:
    return {
        "name": check.name,
        "type": "rule",
        "when": [c.model_dump(mode="json") for c in check.when],
        "then": check.then,
        "else": check.else_,
    }


def _agent(
    check: AgentCheck,
    shared: SharedConfig,
    files: _Files,
    bundled: str,
    index: dict[str, str | None],
) -> dict[str, Any]:
    block = shared.agent

    def pick(own: Any, inherited: Any) -> Any:
        return inherited if own is None else own

    skill = pick(check.skill, block.skill)
    profile = pick(check.permission_profile, block.permission_profile)
    if check.instruction_file is not None:
        # todo(#22): the prompt writer must read instruction_file once and use the same bytes as
        # the fingerprint (definition() returns only the digest)
        instruction = files.hash(check.instruction_file, cap=INSTRUCTION_CAP, over="unreadable")
    else:
        instruction = _text_sha256(check.instruction or "")
    out: dict[str, Any] = {"name": check.name, "type": "agent"}
    if check.instruction is not None:
        out["instruction"] = check.instruction
    if check.instruction_file is not None:
        out["instruction_file"] = check.instruction_file
    out.update(
        {
            "instruction_sha256": instruction,
            "skill": skill,
            "skill_files": _skill_files(files, skill, _plugin_dirs(shared, bundled), index),
            "model": pick(check.model, block.model),
            "threshold": float(pick(check.threshold, block.threshold)),
            "sandbox": pick(check.sandbox, block.sandbox),
            "setting_sources": sorted(set(pick(check.setting_sources, block.setting_sources))),
            "env_allowlist": sorted(set(pick(check.env_allowlist, block.env_allowlist))),
            "permission_profile": {
                "path": profile,
                "sha256": files.hash(
                    profile if profile is not None else f"{bundled}/{BUNDLED_PROFILE}",
                    over="stat",
                ),
            },
        }
    )
    return out


def definition(
    name: str,
    policy: Policy,
    shared: SharedConfig,
    *,
    bundled_plugin: str | None = None,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """The normalized effective definition that ``fingerprint`` hashes.

    ``deadline`` is an absolute ``monotonic`` time; the files not yet hashed when it passes
    contribute the marker. ``bundled_plugin`` is the bundled plugin directory (default: the
    package's own).
    """
    files = _Files(deadline, monotonic)
    bundled = bundled_plugin if bundled_plugin is not None else bundled_plugin_dir()
    index: dict[str, str | None] = {}
    decl = policy.input
    result: dict[str, Any] = {
        "policy": name,
        "input": {
            "require": list(decl.require) if decl else [],
            "types": dict(decl.types) if decl else {},
            "ignore": list(decl.ignore) if decl else [],
        },
    }
    if policy.applies_when is not None:
        result["applies_when"] = [c.model_dump(mode="json") for c in policy.applies_when]
    checks: list[dict[str, Any]] = []
    for check in policy.checks:
        if isinstance(check, ScriptCheck):
            checks.append(_script(check, shared, files))
        elif isinstance(check, RuleCheck):
            checks.append(_rule(check))
        else:
            checks.append(_agent(check, shared, files, bundled, index))
    result["checks"] = checks
    return result


def fingerprint(
    name: str,
    policy: Policy,
    shared: SharedConfig,
    *,
    bundled_plugin: str | None = None,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """``sha256:`` plus the SHA-256 of the canonical JSON of the effective definition."""
    text = canonical_input(
        definition(
            name,
            policy,
            shared,
            bundled_plugin=bundled_plugin,
            deadline=deadline,
            monotonic=monotonic,
        )
    )
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def fingerprint_for(
    config: LoadedConfig,
    name: str,
    scope: Scope,
    *,
    bundled_plugin: str | None = None,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """The fingerprint of policy ``name`` as effective for ``scope`` (its override applied).

    An unknown policy or an invalid policy or override is the config error of
    ``resolve_effective`` (exit 2); the file reads themselves never fail.
    """
    effective = resolve_effective(config, name, scope)
    return fingerprint(
        name,
        effective.policy,
        config.shared,
        bundled_plugin=bundled_plugin,
        deadline=deadline,
        monotonic=monotonic,
    )
