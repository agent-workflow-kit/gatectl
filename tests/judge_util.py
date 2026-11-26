"""Builders for the judge tests: a real frozen artifact file and the ``exec`` outcome and
``status`` objects that describe it, in the shapes of the pinned claude-session schemas."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from gatectl import agentjudge

NONCE = "0123456789abcdef0123456789abcdef"
SESSION = "cs-abcdefgh"


def verdict_doc(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema_version": 1,
        "nonce": NONCE,
        "decision": "allow",
        "confidence": 0.95,
        "reasons": ["looks fine"],
    }
    doc.update(over)
    return doc


def verdict_bytes(**over: Any) -> bytes:
    return json.dumps(verdict_doc(**over)).encode("utf-8")


def artifact_entry(path: Path, data: bytes, **over: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": "verdict.json",
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }
    entry.update(over)
    return entry


def report(entry: dict[str, Any] | None, **over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "status": "done",
        "implicit": False,
        "summary": "untrusted summary",
        "reason": None,
        "artifact": entry,
        "reported_at": "2026-01-01T00:00:00Z",
    }
    body.update(over)
    return body


def outcome_doc(entry: dict[str, Any] | None, **over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "csession_id": SESSION,
        "run": 1,
        "phase": "session",
        "outcome": "done",
        "end_reason": "normal",
        "exit_code": 0,
        "state": "exited",
        "report": report(entry),
    }
    doc.update(over)
    return doc


def status_doc(entry: dict[str, Any] | None, **over: Any) -> dict[str, Any]:
    run: dict[str, Any] = {
        "run": 1,
        "implicit_done": False,
        "outcome": "done",
        "end_reason": "normal",
        "exit_code": 0,
        "report": report(entry),
    }
    run.update(over)
    return {"csession_id": SESSION, "state": "exited", "run": run}


def write_artifact(directory: Path, data: bytes, name: str = "verdict.json") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(data)
    path.chmod(0o444)
    return path


def good_run(
    directory: Path,
    data: bytes | None = None,
    *,
    nonce: str = NONCE,
    mutate: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
) -> agentjudge.RawRun:
    """A run whose artifact file exists, is described correctly by ``status`` and by ``exec``.

    ``mutate(outcome, status)`` edits the two objects (deep copies) before the run is built.
    """
    data = verdict_bytes() if data is None else data
    path = write_artifact(directory, data)
    entry = artifact_entry(path, data)
    outcome = outcome_doc(copy.deepcopy(entry))
    status = status_doc(copy.deepcopy(entry))
    if mutate is not None:
        mutate(outcome, status)
    return agentjudge.RawRun(0, outcome, status, nonce, 1)


END_REASONS = (
    "normal", "auto_exit", "user_exit", "forwarded_term", "forwarded_hup", "forwarded_int",
    "stopped", "timeout", "max_turns", "api_error", "no_result", "no_report", "result_rejected",
    "no_session_start", "wrapper_lost", "lost", "internal_error", "hook_veto", "hook_escalate",
    "hook_timeout", "canceled", "never_adopted", "launch_interrupted", "config_invalid",
    "claude_not_found", "sandbox_unavailable", "socket_path_too_long",
    "invalid_permission_profile", "unsafe_cwd", "unsafe_path", "unsafe_plugin_dir",
    "unsafe_read_dir", "plugin_dir_missing", "git_dir_changed", "no_git_cwd",
    "fork_cwd_unsupported", "no_tty", "tmpdir_unsafe", "session_dir_unsafe",
    "unsafe_claude_args", "unsafe_setting_sources", "claude_too_old", "exit_3", "signal_kill",
)  # fmt: skip
