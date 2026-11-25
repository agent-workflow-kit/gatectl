"""``gatectl validate``: lint the whole config eagerly (interface.md, validate).

The load already validates the shared part, every policy and every override on its own
(``gatectl.config``); this module lists those problems and adds what load never does: it
resolves binaries, files, skills and plugins, judges each agent check's resolved safety
settings and deadline, and compares the config with ``state.db``.

Everything printed is built from closed codes, fixed message text and config *keys*: no config
value (an argv element, a path, a skill name, a model) is ever echoed, because config text is
untrusted (interface.md, Untrusted text). Files are inspected, never executed, and read only
as far as needed (a regular file, opened without blocking, a size check); ``state.db`` is
opened read-only and never created.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

from gatectl import audit, ids
from gatectl.config import (
    ConfigProblem,
    LoadedConfig,
    load_config,
    problem_path,
    resolve_session_cmd,
)
from gatectl.config_models import AgentCheck, ScriptCheck
from gatectl.context import Context, Result
from gatectl.errors import ConfigInvalidError, InternalError
from gatectl.fingerprint import INSTRUCTION_CAP, bundled_plugin_dir, plugin_name_of
from gatectl.sanitize import sanitize

MAX_REPORTED = 500  # problems and warnings are each cut here (a 1 MiB config can name many)
LAUNCH_OVERHEAD = timedelta(seconds=5)  # start, status and forget (interface.md, Deadline)
PLACEHOLDERS = (".claude", ".mcp.json", "CLAUDE.md", "CLAUDE.local.md")
_DB_VM_STEPS = 5_000_000  # a hostile database cannot keep a read busy longer than this

Path_ = tuple[str | int, ...]


# --- the collected report -----------------------------------------------------------------------


@dataclass
class Report:
    problems: list[ConfigProblem] = field(default_factory=list)
    warnings: list[ConfigProblem] = field(default_factory=list)
    session_cmd: str | None = None  # the resolved first element, when found
    session_cmd_known: bool = True  # False when the config did not parse (nothing was resolved)


class _Out:
    """Collects problems and warnings: no duplicates, at most ``MAX_REPORTED`` of each."""

    def __init__(self) -> None:
        self.report = Report()
        self._seen: set[tuple[str, str, str, str]] = set()

    def _add(self, kind: str, target: list[ConfigProblem], item: ConfigProblem) -> None:
        key = (kind, item.code, item.path, item.message)
        if key in self._seen or len(target) >= MAX_REPORTED:
            return
        self._seen.add(key)
        target.append(item)

    def problem(self, code: str, path: Path_ | str, message: str) -> None:
        self.add_problem(ConfigProblem(code, _p(path), message))

    def add_problem(self, item: ConfigProblem) -> None:
        self._add("problem", self.report.problems, item)

    def warning(self, code: str, path: Path_ | str, message: str) -> None:
        self._add("warning", self.report.warnings, ConfigProblem(code, _p(path), message))


def _p(path: Path_ | str) -> str:
    return path if isinstance(path, str) else problem_path(*path)


# --- file inspection -----------------------------------------------------------------------------


def _regular_file(path: str, cap: int | None) -> bool:
    """A regular file this process can open for reading (a link is followed), of at most ``cap``.

    Never blocks and never reads a FIFO or device: the type is checked before and after an
    ``O_NONBLOCK`` open, and the file is the same one both times.
    """
    try:
        before = os.stat(path)
        if not stat.S_ISREG(before.st_mode):
            return False
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
    except (OSError, ValueError):
        return False
    try:
        opened = os.fstat(fd)
    except OSError:
        return False
    finally:
        os.close(fd)
    if not stat.S_ISREG(opened.st_mode):
        return False
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        return False
    return cap is None or opened.st_size <= cap


def _executable_file(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode) and os.access(path, os.X_OK)
    except (OSError, ValueError):
        return False


def _is_dir(path: str) -> bool:
    try:
        return stat.S_ISDIR(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def _missing_placeholders(directory: str) -> list[str]:
    missing = []
    for name in PLACEHOLDERS:
        target = f"{directory}/{name}"
        ok = _is_dir(target) if name == ".claude" else _regular_file(target, None)
        if not ok:
            missing.append(name + "/" if name == ".claude" else name)
    return missing


# --- plugins -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Plugin:
    directory: str
    origin: Path_  # the config key that names the directory (``("agent",)`` for the bundled one)


def _index_plugins(shared_dirs: Sequence[str], bundled: str, out: _Out) -> dict[str, _Plugin]:
    """Plugins by name: the bundled one, then each ``agent.plugin_dirs`` entry in order.

    A directory with no readable name is ``plugin_not_found``; a name already taken is an
    ``invalid_value`` (interface.md, Skill and plugin). The bundled plugin is reported only when
    something uses it.
    """
    index: dict[str, _Plugin] = {}
    name = plugin_name_of(bundled)
    if name is not None:
        index[name] = _Plugin(bundled, ("agent",))
    for i, directory in enumerate(shared_dirs):
        origin: Path_ = ("agent", "plugin_dirs", i)
        found = plugin_name_of(directory)
        if found is None:
            out.problem(
                "plugin_not_found",
                origin,
                "no plugin: .claude-plugin/plugin.json is missing, too large or has no name",
            )
        elif found in index:
            out.problem("invalid_value", origin, "another plugin directory has the same name")
        else:
            index[found] = _Plugin(directory, origin)
    return index


# --- state.db ------------------------------------------------------------------------------------


def _non_empty_file(path: Path) -> bool:
    try:
        info = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_size > 0


def _open_regular(path: Path) -> int | None:
    """A descriptor for ``path`` when it is a regular file (a link is followed), else ``None``.

    The open never blocks (``O_NONBLOCK``), so a FIFO swapped in for the file cannot hang it; the
    type is read from the descriptor, not from a separate ``stat`` of the path.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
    except (OSError, ValueError):
        return None
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            return fd
    except OSError:
        pass
    os.close(fd)
    return None


def _wal_has_content(path: Path) -> bool:
    return _non_empty_file(path.with_name(path.name + "-wal"))


class _CannotReadSafely(Exception):
    """The database cannot be read without writing next to it: it is skipped, not judged."""


def _connect(path: Path) -> tuple[sqlite3.Connection, int | None] | None:
    """Open ``state.db`` read-only without ever creating a file next to it.

    The path is resolved once (``realpath``): SQLite looks for ``-wal`` and ``-shm`` in the real
    file's directory, so the sidecar checks and the connect use that same resolved path.

    With a non-empty ``-wal`` the committed rows may live only there, so the database is opened
    ``mode=ro`` by path; that needs the ``-shm`` too, because without it SQLite would create one.
    A non-empty ``-wal`` without ``-shm`` cannot be read without writing, so it raises
    ``_CannotReadSafely`` and the caller reads nothing (no orphan, and no judgement from content).
    Without a non-empty ``-wal`` nothing can be missing from the main file and it is opened
    ``immutable=1`` (no locking, no sidecar, works in a read-only directory); on Linux through the
    already checked descriptor. The returned descriptor (or ``None``) is closed by the caller
    after the connection.

    Residual window: ``/proc/self/fd/N`` does not pin the descriptor (SQLite resolves the link to
    a path and opens that), and the ``mode=ro`` branch opens the path itself, so in every branch an
    attacker who owns the state directory has a few-microsecond window between the checks and the
    open. It is narrowed by comparing the descriptor with the path (device and inode, regular)
    right before connecting. The state directory is private (mode 0700), so this needs the user's
    own account.
    """
    try:
        real = Path(os.path.realpath(path))
    except (OSError, ValueError):
        return None
    fd = _open_regular(real)
    if fd is None:
        return None
    try:
        wal = _wal_has_content(real)
        if wal and not real.with_name(real.name + "-shm").exists():
            raise _CannotReadSafely
        held, now = os.fstat(fd), os.stat(real)
        if not (
            stat.S_ISREG(now.st_mode) and (held.st_dev, held.st_ino) == (now.st_dev, now.st_ino)
        ):
            os.close(fd)
            return None
        if wal:
            uri = f"file:{quote(str(real))}?mode=ro"
            return sqlite3.connect(uri, uri=True, timeout=0), fd
        proc = f"/proc/self/fd/{fd}"
        target = proc if os.path.exists(proc) else str(real)
        return sqlite3.connect(f"file:{quote(target)}?immutable=1", uri=True, timeout=0), fd
    except _CannotReadSafely:
        os.close(fd)
        raise
    except (OSError, sqlite3.Error, ValueError):
        os.close(fd)
        return None


def _db_policies(path: Path) -> set[str] | None:
    """Policy names stored in ``state.db`` (read-only), or ``None`` when it is not usable.

    The ``meta(key TEXT PRIMARY KEY, value TEXT)`` columns, ``policy_state.policy`` and
    ``decisions.policy`` are those of the state store; issue #12's schema must match these names.
    Usable means a database with a ``meta.schema_version`` row, the same test ``check`` applies
    (interface.md, Exit codes). Only names that follow the policy-name grammar are returned;
    anything else in a tampered database is ignored and never printed. The read is bounded in
    rows and in work.
    """
    try:
        opened = _connect(path)
    except _CannotReadSafely:
        return set()  # a live WAL without its -shm: nothing is learned, nothing is judged
    if opened is None:
        return None
    db, fd = opened
    names: set[str] = set()
    steps = 0

    def busy() -> int:
        nonlocal steps
        steps += 1
        return 1 if steps * 1000 > _DB_VM_STEPS else 0

    try:
        db.set_progress_handler(busy, 1000)
        db.execute("PRAGMA trusted_schema=OFF")
        try:
            has_schema = db.execute("SELECT 1 FROM meta WHERE key = 'schema_version'").fetchone()
        except sqlite3.Error:
            return None
        if has_schema is None:
            return None
        for table in ("policy_state", "decisions"):
            try:
                rows = db.execute(f"SELECT DISTINCT policy FROM {table} LIMIT 5000").fetchall()  # noqa: S608
            except sqlite3.Error:
                continue  # no such table (or an unreadable one): nothing to learn from it
            for (value,) in rows:
                if isinstance(value, str) and ids.is_policy_name(value):
                    names.add(value)
    except sqlite3.Error:
        return None
    finally:
        db.close()
        if fd is not None:
            os.close(fd)
    return names


def _check_state(loaded: LoadedConfig, state: Path, out: _Out) -> None:
    stored = _db_policies(state / "state.db")
    if stored is None:
        # A fresh install has no state.db until the first check: not a problem. With an audit
        # history next to it, a database that is missing, empty or without a schema is the
        # unknown state every other command refuses (design.md, Error handling).
        if _non_empty_file(state / "audit.jsonl"):
            out.problem(
                "state_db_missing",
                "state.db",
                "state.db is missing, empty or has no schema_version but audit.jsonl has records",
            )
        return
    for name in sorted(stored - set(loaded.policies)):
        out.warning(
            "orphan_state", ("policies", name), "policy is in state.db but not in the config"
        )


# --- the checks ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Unit:
    """A list of checks of a policy or of a repo override, with the path of that list."""

    prefix: Path_
    checks: Sequence[Any]


def _units(loaded: LoadedConfig) -> Iterator[_Unit]:
    for name, entry in loaded.policies.items():
        if entry.policy is not None:
            yield _Unit(("policies", name), entry.policy.checks)
    for (repo, name), scoped in loaded.overrides.items():
        if scoped.override is not None and scoped.override.checks is not None:
            yield _Unit(("repos", repo, "policies", name), scoped.override.checks)


def _check_script(check: ScriptCheck, at: Path_, out: _Out) -> None:
    if not _executable_file(check.argv[0]):
        out.problem(
            "unresolved_argv0",
            (*at, "argv", 0),
            "argv[0] is not an executable regular file",
        )
    for j, arg in enumerate(check.argv[1:], 1):
        if "/" in arg and not arg.startswith("/"):
            out.warning(
                "relative_argv",
                (*at, "argv", j),
                "a relative path-like argument is never resolved and never hashed",
            )


def _check_agent(
    check: AgentCheck,
    at: Path_,
    loaded: LoadedConfig,
    plugins: dict[str, _Plugin],
    used: dict[str, _Plugin],
    out: _Out,
) -> None:
    block = loaded.shared.agent
    if check.instruction_file is not None and not _regular_file(
        check.instruction_file, INSTRUCTION_CAP
    ):
        out.problem(
            "instruction_file_unreadable",
            (*at, "instruction_file"),
            "instruction_file is not a readable regular file of at most 64 KiB",
        )
    skill_at: Path_ = (*at, "skill") if check.skill is not None else ("agent", "skill")
    skill = check.skill if check.skill is not None else block.skill
    plugin_name, _, skill_name = skill.partition(":")
    plugin = plugins.get(plugin_name)
    if plugin is None:
        out.problem("plugin_not_found", skill_at, "no plugin directory has the skill's plugin name")
    else:
        used[plugin.directory] = plugin
        if not _regular_file(f"{plugin.directory}/skills/{skill_name}/SKILL.md", None):
            out.problem("skill_not_found", skill_at, "the plugin has no skills/<skill>/SKILL.md")

    if check.setting_sources is not None:
        sources, sources_at = check.setting_sources, (*at, "setting_sources")
    else:
        sources, sources_at = block.setting_sources, ("agent", "setting_sources")
    if sources:
        out.problem(
            "unsafe_setting_sources",
            sources_at,
            "setting_sources must be empty: claude-session refuses gate-check with any source",
        )
    if check.sandbox is not None:
        sandbox, sandbox_at = check.sandbox, (*at, "sandbox")
    else:
        sandbox, sandbox_at = block.sandbox, ("agent", "sandbox")
    if sandbox != "required":
        out.warning(
            "sandbox_lowered", sandbox_at, f"sandbox is {sandbox}: the session is less isolated"
        )


def _check_deadlines(loaded: LoadedConfig, out: _Out) -> None:
    defaults = loaded.shared.defaults
    for name, entry in loaded.policies.items():
        if entry.policy is None:
            continue
        policy = entry.policy
        if any(isinstance(c, AgentCheck) for c in policy.checks):
            at: Path_ = ("policies", name, "timeout") if policy.timeout else ("defaults", "timeout")
            _deadline(policy.timeout or defaults.timeout, at, name, loaded, out)
        for (repo, o_name), scoped in loaded.overrides.items():
            if o_name != name or scoped.override is None:
                continue
            ov = scoped.override
            if ov.timeout is None and ov.checks is None:
                continue
            effective = loaded.resolve_policy(name, repo)
            if not any(isinstance(c, AgentCheck) for c in effective.checks):
                continue
            prefix: Path_ = ("repos", repo, "policies", name)
            at = (*prefix, "timeout") if ov.timeout is not None else (*prefix, "checks")
            _deadline(effective.timeout or defaults.timeout, at, name, loaded, out)


def _deadline(deadline: timedelta, at: Path_, name: str, loaded: LoadedConfig, out: _Out) -> None:
    reserve = loaded.shared.defaults.record_reserve
    budget = loaded.shared.agent.min_start_budget
    if deadline - reserve - LAUNCH_OVERHEAD < budget:
        out.problem(
            "deadline_too_short",
            at,
            f"policy {name}: the deadline minus record_reserve minus 5 s is below "
            "agent.min_start_budget, so no agent check can start",
        )


def validate_config(
    loaded: LoadedConfig,
    *,
    environ: Mapping[str, str],
    bundled_plugin: str | None = None,
    state_dir: Path | None = None,
) -> Report:
    """Every problem and warning of a loaded config. Reads files; never runs a process."""
    out = _Out()
    for problem in loaded.shared_problems:
        out.add_problem(problem)
    for problem in loaded.policy_problems():
        out.add_problem(problem)

    bundled = bundled_plugin if bundled_plugin is not None else bundled_plugin_dir()
    plugins = _index_plugins(loaded.shared.agent.plugin_dirs, bundled, out)
    used: dict[str, _Plugin] = {}
    has_agent = False
    for unit in _units(loaded):
        if unit.checks and all(isinstance(c, AgentCheck) for c in unit.checks):
            out.warning("agent_only_policy", unit.prefix, "policy has no script or rule check")
        for i, check in enumerate(unit.checks):
            at: Path_ = (*unit.prefix, "checks", i)
            if isinstance(check, ScriptCheck):
                _check_script(check, at, out)
            elif isinstance(check, AgentCheck):
                has_agent = True
                _check_agent(check, at, loaded, plugins, used, out)
    # The session always gets the bundled plugin; the plugin of the check's skill comes too.
    if has_agent:
        bundled_entry = next((p for p in plugins.values() if p.directory == bundled), None)
        used.setdefault(bundled, bundled_entry or _Plugin(bundled, ("agent",)))
    for plugin in used.values():
        missing = _missing_placeholders(plugin.directory)
        if missing:
            out.problem(
                "plugin_placeholders_missing",
                plugin.origin,
                "the plugin directory lacks the placeholder " + ", ".join(missing),
            )
    _check_deadlines(loaded, out)

    # Taken from the raw config, so a policy that failed to parse still counts: the kind of this
    # finding must not flip to a warning because of an unrelated mistake in the same policy.
    any_agent = has_agent or any(
        e.has_agent_check for e in (*loaded.policies.values(), *loaded.overrides.values())
    )
    resolved = resolve_session_cmd(loaded.shared.session_cmd, environ=environ)
    if resolved is None:
        message = (
            "session_cmd[0] was not found (an absolute path, or a name in the fixed directories)"
        )
        if any_agent:
            out.problem("session_cmd_unresolved", "session_cmd", message)
        else:
            out.warning("session_cmd_unresolved", "session_cmd", message)
    else:
        out.report.session_cmd = resolved[0]

    _check_state(loaded, state_dir if state_dir is not None else audit.state_dir(), out)
    return out.report


# --- the command ---------------------------------------------------------------------------------


def _text(report: Report) -> str:
    lines = [f"problem {p.code} {p.path}: {p.message}" for p in report.problems]
    lines += [f"warning {w.code} {w.path}: {w.message}" for w in report.warnings]
    if report.session_cmd_known:
        shown = sanitize(report.session_cmd, 256) if report.session_cmd else "not found"
        lines.append(f"session_cmd: {shown}")
    lines.append("invalid" if report.problems else "valid")
    return "\n".join(lines)


def handle(ctx: Context) -> Result:
    try:
        loaded = load_config(ctx.config)
    except ConfigInvalidError as exc:
        # The text cannot be parsed: nothing else can be judged, but validate lists it.
        report = Report(
            problems=[ConfigProblem("invalid_value", "config", exc.message)],
            session_cmd_known=False,
        )
    else:
        report = validate_config(loaded, environ=os.environ)
    if getattr(ctx.args, "probe", False) and not report.problems:
        # TODO(#26): run the probe and fill the ``probe`` member; exit 12 when it fails.
        raise InternalError("validate --probe is not implemented yet")
    payload = {
        "valid": not report.problems,
        "problems": [p.as_dict() for p in report.problems],
        "warnings": [w.as_dict() for w in report.warnings],
        "probe": None,
    }
    return Result(payload=payload, text=_text(report), exit_code=2 if report.problems else 0)
