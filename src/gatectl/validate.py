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

from gatectl import audit, engine, ids, probe, store
from gatectl.config import (
    ConfigProblem,
    LoadedConfig,
    load_config,
    problem_path,
    resolve_session_cmd,
)
from gatectl.config_models import AgentCheck, ScriptCheck
from gatectl.context import Context, Result
from gatectl.errors import ConfigInvalidError
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


_SQLITE_MAGIC = b"SQLite format 3\x00"
_SKIP: Any = object()  # a sentinel version: the database is not judged (see _read_db)


def _wal_has_content(path: Path) -> bool:
    # a WAL of 32 bytes or fewer is only its header: no frames, so nothing the main file lacks
    try:
        return os.lstat(path.with_name(path.name + "-wal")).st_size > 32
    except OSError:
        return False


def _open_regular(path: Path) -> int | None:
    """A descriptor for ``path`` when it is a regular file (a link is refused), else ``None``.

    The open never blocks (``O_NONBLOCK``) and never follows a link, so a FIFO or link swapped in
    for the file cannot hang or redirect it; the type is read from the descriptor.
    """
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except (OSError, ValueError):
        return None
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            return fd
    except OSError:
        pass
    os.close(fd)
    return None


@dataclass(frozen=True)
class _StoredDb:
    """What a read-only look at ``state.db`` found: the schema version in the store's terms
    (``None``: an empty file or one with no tables; ``False``: not SQLite's, or tables but no
    ``meta.schema_version`` row; ``_SKIP``: not judged; else the number) and the policy names."""

    version: int | None | bool
    names: frozenset[str] = frozenset()


def _read_db(path: Path) -> _StoredDb:
    """Look at a ``state.db`` that is a regular file (read-only, never blocking, never writing).

    The file is read only as far as its first 16 bytes unless it is a SQLite file with an empty or
    absent WAL. A non-empty file whose header is not SQLite's is junk (``False``) whatever its WAL
    holds. With frames in the WAL the committed rows may live only there and reading them needs
    the ``-shm``, which SQLite writes to even for a read; ``validate`` never writes next to the
    database, so it judges nothing (``_SKIP``). Anything the store refuses without a reason (an
    unreadable or damaged file, a busy one, a ``schema_version`` that is not a usable number,
    a ``meta`` table with other columns) is also ``_SKIP``.

    The ``meta(key TEXT PRIMARY KEY, value TEXT)`` columns, ``policy_state.policy`` and
    ``decisions.policy`` are those of the state store. The version is read as the store reads it
    (``store.parse_schema_version``), and the verdict on it is the store's (``store.db_verdict``).
    Only names that follow the policy-name grammar are returned; anything else in a tampered
    database is ignored and never printed. The read is bounded in rows and in work. It opens the
    already checked descriptor ``immutable`` (no locking, no sidecar, works in a read-only
    directory); the state directory is private (0700), so the few-microsecond window between the
    checks and the open needs the user's own account.
    """
    fd = _open_regular(path)
    if fd is None:
        return _StoredDb(_SKIP)
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            return _StoredDb(_SKIP if _wal_has_content(path) else None)
        if os.pread(fd, len(_SQLITE_MAGIC), 0) != _SQLITE_MAGIC:
            return _StoredDb(False)
        if _wal_has_content(path):
            return _StoredDb(_SKIP)
        return _query_db(path, fd)
    except OSError:
        return _StoredDb(_SKIP)
    finally:
        os.close(fd)


def _query_db(path: Path, fd: int) -> _StoredDb:
    proc = f"/proc/self/fd/{fd}"
    target = proc if os.path.exists(proc) else str(path)
    try:
        db = sqlite3.connect(f"file:{quote(target)}?immutable=1", uri=True, timeout=0)
    except (sqlite3.Error, ValueError):
        return _StoredDb(_SKIP)
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
            if db.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone() is None:
                return _StoredDb(None)  # a SQLite file with no tables
            row = db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        except sqlite3.Error as exc:
            if store.is_not_a_database(exc) or "no such table: meta" in str(exc):
                return _StoredDb(False)  # junk, or tables of another program
            return _StoredDb(_SKIP)  # damaged, busy or another meta: the store refuses plainly
        if row is None:
            return _StoredDb(False)
        version = store.parse_schema_version(row[0])
        if version is None:
            return _StoredDb(_SKIP)  # an unusable value: the store refuses it plainly
        for table in ("policy_state", "decisions"):
            try:
                rows = db.execute(f"SELECT DISTINCT policy FROM {table} LIMIT 5000").fetchall()  # noqa: S608
            except sqlite3.Error:
                continue  # no such table (or an unreadable one): nothing to learn from it
            for (value,) in rows:
                if isinstance(value, str) and ids.is_policy_name(value):
                    names.add(value)
    except sqlite3.Error:
        return _StoredDb(_SKIP)
    finally:
        db.close()
    return _StoredDb(version, frozenset(names))


def _state_dir_is_real(state: Path) -> bool:
    """Whether ``state`` is a real directory (not a link, not another file type) owned by this
    user, the store's own test of its directory (``store._vet_dir``). Where the store refuses the
    directory without a reason, ``validate`` is silent. A missing directory is also ``False``: a
    fresh install is valid."""
    try:
        info = os.lstat(state)
    except OSError:  # missing, a parent that is a file, or not searchable
        return False
    return stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()


def _sidecars_are_vetted(db: Path) -> bool:
    """Whether the ``-wal`` and ``-shm`` files are absent or regular files owned by this user
    (the store's ``_vet_sidecars``: it refuses anything else without a reason)."""
    for suffix in ("-wal", "-shm"):
        try:
            info = os.lstat(db.with_name(db.name + suffix))
        except FileNotFoundError:
            continue
        except OSError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            return False
    return True


def _check_state(loaded: LoadedConfig, state: Path, out: _Out) -> None:
    # `state_db_missing` only where the store refuses with that reason (design.md, state store),
    # plus a foreign or junk database with no history. Where the store refuses without a reason
    # (a bad state directory, a non-regular or linked state.db, a damaged or unreadable file, a
    # permission problem) `validate` is silent: it cannot repair a mode, and `check` explains.
    if not _state_dir_is_real(state):
        return
    path = state / "state.db"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        found = _StoredDb(None)
    except OSError:  # not searchable, or other: the store would repair or refuse plainly
        return
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            return
        if not _sidecars_are_vetted(path):
            return
        found = _read_db(path)
    if found.version is _SKIP:
        return
    verdict = store.db_verdict(store.has_history(state), found.version)
    if verdict == "state_db_missing":
        out.problem(
            "state_db_missing",
            "state.db",
            "state.db is missing, empty or has no schema_version but audit.jsonl has records",
        )
        return
    if verdict == "not_gatectl":
        out.problem(
            "state_db_missing",
            "state.db",
            "state.db is not a gatectl database (it has no schema_version)",
        )
        return
    for name in sorted(found.names - set(loaded.policies)):
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


PROBE_GAP = (
    "probe note: the probe covers the agent: block only; per-check overrides of sandbox, skill, "
    "permission_profile, setting_sources, env_allowlist and model are not covered "
    "(validate still checks them)"
)


def _probe_lines(result: probe.ProbeResult) -> list[str]:
    facts = (
        f"exit_code {_shown(result.exit_code)} end_reason {_shown(result.end_reason)} "
        f"sandbox_active {_shown(result.sandbox_active)}"
    )
    head = "probe: ok" if result.ok else f"probe: failed {sanitize(result.failed or '', 2048)}"
    return [f"{head} ({facts})", PROBE_GAP]


def _shown(value: object) -> str:
    if value is None:
        return "unknown"
    return str(value).lower() if isinstance(value, bool) else sanitize(str(value), 64)


def _text(report: Report, ran: probe.ProbeResult | None = None) -> str:
    lines = [f"problem {p.code} {p.path}: {p.message}" for p in report.problems]
    lines += [f"warning {w.code} {w.path}: {w.message}" for w in report.warnings]
    if report.session_cmd_known:
        shown = sanitize(report.session_cmd, 256) if report.session_cmd else "not found"
        lines.append(f"session_cmd: {shown}")
    if ran is not None:
        lines += _probe_lines(ran)
    lines.append("invalid" if report.problems else "valid")
    return "\n".join(lines)


def handle(ctx: Context) -> Result:
    loaded: LoadedConfig | None = None
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
    ran = None
    if getattr(ctx.args, "probe", False) and loaded is not None and not report.problems:
        ran = probe.run_probe(loaded, engine.default_env())
    payload = {
        "valid": not report.problems,
        "problems": [p.as_dict() for p in report.problems],
        "warnings": [w.as_dict() for w in report.warnings],
        "probe": ran.as_dict() if ran is not None else None,
    }
    exit_code = 2 if report.problems else (12 if ran is not None and not ran.ok else 0)
    return Result(payload=payload, text=_text(report, ran), exit_code=exit_code)
