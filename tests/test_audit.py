"""Append-only audit and log writers (interface.md, Audit and log)."""

from __future__ import annotations

import contextlib
import copy
import errno
import json
import multiprocessing
import os
import signal
import stat
from pathlib import Path
from typing import Any

import pytest

from gatectl import audit, clock
from gatectl.sanitize import MARKER
from tests.schema_util import assert_valid

DID = "gd-aaaaaaaaaaaa"
CAP = 64 * 1024


@pytest.fixture
def sdir(tmp_path: Path) -> Path:
    return tmp_path / "state" / "gatectl"


def decision_record(**over: Any) -> dict[str, Any]:
    record = audit.audit_record(
        action="decision",
        target="pol@github.com/o/r",
        decision_id=DID,
        actor="auto:unknown",
        stdin_tty=False,
        actor_source="default",
        inputs={
            "policy": "pol",
            "scope": "github.com/o/r",
            "input_sha256": "0" * 64,
            "fingerprint": "sha256:" + "1" * 64,
        },
        result={
            "decision": "allow",
            "reason": "all_passed",
            "state": "shadow",
            "shadow": True,
            "enforced": False,
        },
    )
    record.update(over)
    return record


@contextlib.contextmanager
def hang_guard(seconds: int = 10):
    """Fail the test instead of hanging if the body blocks (FIFO opens)."""

    def _fire(signum, frame):  # pragma: no cover - only on a regression
        raise AssertionError("blocked")

    old = signal.signal(signal.SIGALRM, _fire)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def read_lines(path: Path) -> list[str]:
    data = path.read_bytes()
    return [] if not data else data.decode("utf-8").split("\n")[:-1]


class TestStateDir:
    def test_xdg_state_home(self, isolated_home: Path) -> None:
        assert audit.state_dir() == isolated_home / ".local" / "state" / "gatectl"

    def test_falls_back_to_home(self, isolated_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("XDG_STATE_HOME")
        assert audit.state_dir() == isolated_home / ".local" / "state" / "gatectl"

    def test_empty_xdg_is_ignored(self, isolated_home: Path, monkeypatch) -> None:
        monkeypatch.setenv("XDG_STATE_HOME", "")
        assert audit.state_dir() == isolated_home / ".local" / "state" / "gatectl"

    def test_relative_xdg_is_ignored(self, isolated_home: Path, monkeypatch) -> None:
        monkeypatch.setenv("XDG_STATE_HOME", "relative/dir")
        assert audit.state_dir() == isolated_home / ".local" / "state" / "gatectl"


class TestAppend:
    def test_creates_dir_0700_and_files_0600(self, sdir: Path) -> None:
        audit.append_audit(decision_record(), state_dir=sdir)
        audit.append_log(audit.log_record(level="info", event="cron"), state_dir=sdir)
        assert stat.S_IMODE(sdir.stat().st_mode) == 0o700
        for name in ("audit.jsonl", "log.jsonl"):
            assert stat.S_IMODE((sdir / name).stat().st_mode) == 0o600

    def test_mode_is_explicit_not_umask(self, sdir: Path) -> None:
        old = os.umask(0o000)
        try:
            audit.append_audit(decision_record(), state_dir=sdir)
        finally:
            os.umask(old)
        assert stat.S_IMODE((sdir / "audit.jsonl").stat().st_mode) == 0o600
        assert stat.S_IMODE(sdir.stat().st_mode) == 0o700

    def test_restrictive_umask_does_not_break(self, sdir: Path) -> None:
        old = os.umask(0o277 & 0o077)
        try:
            audit.append_log(audit.log_record(level="info", event="cron"), state_dir=sdir)
        finally:
            os.umask(old)
        assert stat.S_IMODE((sdir / "log.jsonl").stat().st_mode) == 0o600

    def test_existing_dir_mode_is_tightened(self, sdir: Path) -> None:
        sdir.mkdir(parents=True, mode=0o755)
        os.chmod(sdir, 0o755)
        audit.append_audit(decision_record(), state_dir=sdir)
        assert stat.S_IMODE(sdir.stat().st_mode) == 0o700

    def test_existing_file_mode_is_tightened(self, sdir: Path) -> None:
        sdir.mkdir(parents=True)
        path = sdir / "audit.jsonl"
        path.write_bytes(b"")
        os.chmod(path, 0o644)
        audit.append_audit(decision_record(), state_dir=sdir)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert len(read_lines(path)) == 1

    def test_file_owned_by_someone_else_is_refused(
        self, sdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sdir.mkdir(parents=True, mode=0o700)
        path = sdir / "audit.jsonl"
        path.write_bytes(b"")
        monkeypatch.setattr(audit, "_geteuid", lambda: os.geteuid() + 1)
        with pytest.raises(OSError, match="not owned"):
            audit._open_append(path)
        assert path.read_bytes() == b""

    def test_dir_owned_by_someone_else_is_refused(
        self, sdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sdir.mkdir(parents=True, mode=0o700)
        monkeypatch.setattr(audit, "_geteuid", lambda: os.geteuid() + 1)
        with pytest.raises(OSError, match="not owned"):
            audit.append_audit(decision_record(), state_dir=sdir)
        assert not (sdir / "audit.jsonl").exists()

    def test_symlinked_state_dir_is_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(OSError):
            audit.append_audit(decision_record(), state_dir=link)
        assert not (real / "audit.jsonl").exists()

    def test_directory_target_is_refused(self, sdir: Path) -> None:
        (sdir / "audit.jsonl").mkdir(parents=True)
        with pytest.raises(OSError):
            audit.append_audit(decision_record(), state_dir=sdir)

    def test_device_target_is_refused(self, sdir: Path) -> None:
        sdir.mkdir(parents=True)
        (sdir / "log.jsonl").symlink_to("/dev/null")  # O_NOFOLLOW refuses it as well
        with pytest.raises(OSError):
            audit.append_log(audit.log_record(level="info", event="cron"), state_dir=sdir)

    def test_fifo_target_is_refused_without_blocking(self, sdir: Path) -> None:
        sdir.mkdir(parents=True)
        os.mkfifo(sdir / "audit.jsonl", 0o600)
        with hang_guard(), pytest.raises(OSError):
            audit.append_audit(decision_record(), state_dir=sdir)

    def test_fifo_with_a_reader_is_still_refused(self, sdir: Path) -> None:
        sdir.mkdir(parents=True)
        fifo = sdir / "audit.jsonl"
        os.mkfifo(fifo, 0o600)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        try:
            with hang_guard(), pytest.raises(OSError, match="not a regular file"):
                audit.append_audit(decision_record(), state_dir=sdir)
        finally:
            os.close(reader)

    def test_descriptor_is_blocking_after_open(self, sdir: Path) -> None:
        sdir.mkdir(parents=True)
        fd = audit._open_append(sdir / "log.jsonl")
        try:
            assert os.get_blocking(fd)
        finally:
            os.close(fd)

    def test_one_json_line_per_record_appended(self, sdir: Path) -> None:
        for i in range(3):
            audit.append_audit(decision_record(target=f"p{i}@*"), state_dir=sdir)
        lines = read_lines(sdir / "audit.jsonl")
        assert [json.loads(line)["target"] for line in lines] == ["p0@*", "p1@*", "p2@*"]

    def test_existing_content_is_preserved(self, sdir: Path) -> None:
        sdir.mkdir(parents=True)
        (sdir / "log.jsonl").write_bytes(b"not json\n")
        audit.append_log(audit.log_record(level="info", event="cron"), state_dir=sdir)
        lines = read_lines(sdir / "log.jsonl")
        assert lines[0] == "not json"
        assert json.loads(lines[1])["event"] == "cron"

    def test_line_is_ascii_json_without_raw_separators(self, sdir: Path) -> None:
        rec = audit.log_record(level="info", event="warning", message="café 日本")
        audit.append_log(rec, state_dir=sdir)
        raw = (sdir / "log.jsonl").read_bytes()
        assert raw.isascii()
        assert raw.count(b"\n") == 1
        assert json.loads(raw)["message"] == "café 日本"

    def test_single_write_call_on_append_descriptor(
        self, sdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[int, int]] = []
        flags: list[int] = []
        real_write, real_open = os.write, os.open

        def spy_write(fd: int, data: Any) -> int:
            calls.append((fd, len(data)))
            return real_write(fd, data)

        def spy_open(path: Any, fl: int, *a: Any, **k: Any) -> int:
            flags.append(fl)
            return real_open(path, fl, *a, **k)

        monkeypatch.setattr(audit, "_write", spy_write)
        monkeypatch.setattr(audit, "_open", spy_open)
        audit.append_audit(decision_record(), state_dir=sdir)
        assert len(calls) == 1
        assert any(f & os.O_APPEND for f in flags)
        assert all(f & os.O_APPEND for f in flags if f & os.O_WRONLY)

    def test_descriptor_is_closed(self, sdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        opened: list[int] = []
        real_open = os.open

        def spy_open(path: Any, fl: int, *a: Any, **k: Any) -> int:
            fd = real_open(path, fl, *a, **k)
            opened.append(fd)
            return fd

        monkeypatch.setattr(audit, "_open", spy_open)
        audit.append_audit(decision_record(), state_dir=sdir)
        for fd in opened:
            with pytest.raises(OSError):
                os.fstat(fd)

    def test_symlinked_file_is_refused(self, sdir: Path, tmp_path: Path) -> None:
        sdir.mkdir(parents=True)
        target = tmp_path / "elsewhere"
        target.write_bytes(b"")
        (sdir / "audit.jsonl").symlink_to(target)
        with pytest.raises(OSError):
            audit.append_audit(decision_record(), state_dir=sdir)
        assert target.read_bytes() == b""


class TestFailures:
    def test_short_write_is_never_truncated_back(
        self, sdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        audit.append_audit(decision_record(target="first@*"), state_dir=sdir)
        path = sdir / "audit.jsonl"
        before = path.read_bytes()
        real_write = os.write

        def short(fd: int, data: Any) -> int:
            return real_write(fd, bytes(data)[:10])

        monkeypatch.setattr(audit, "_write", short)
        with pytest.raises(audit.ShortWriteError):
            audit.append_audit(decision_record(target="second@*"), state_dir=sdir)
        after = path.read_bytes()
        assert len(after) == len(before) + 10
        assert after.startswith(before)

    def test_short_write_to_log_is_not_truncated_either(
        self, sdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_write = os.write
        monkeypatch.setattr(audit, "_write", lambda fd, data: real_write(fd, bytes(data)[:5]))
        with pytest.raises(audit.ShortWriteError):
            audit.append_log(audit.log_record(level="info", event="cron"), state_dir=sdir)
        assert (sdir / "log.jsonl").stat().st_size == 5

    def test_write_error_propagates_and_file_untouched(
        self, sdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        audit.append_audit(decision_record(), state_dir=sdir)
        before = (sdir / "audit.jsonl").read_bytes()

        def boom(fd: int, data: Any) -> int:
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(audit, "_write", boom)
        with pytest.raises(OSError) as exc:
            audit.append_audit(decision_record(), state_dir=sdir)
        assert exc.value.errno == errno.ENOSPC
        assert (sdir / "audit.jsonl").read_bytes() == before

    def test_zero_byte_write_is_a_short_write(
        self, sdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(audit, "_write", lambda fd, data: 0)
        with pytest.raises(audit.ShortWriteError):
            audit.append_audit(decision_record(), state_dir=sdir)

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permissions")
    def test_read_only_parent_directory(self, sdir: Path) -> None:
        sdir.parent.mkdir(parents=True)
        os.chmod(sdir.parent, 0o500)
        try:
            with pytest.raises(PermissionError):
                audit.append_audit(decision_record(), state_dir=sdir)
        finally:
            os.chmod(sdir.parent, 0o700)
        assert not sdir.exists()

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permissions")
    def test_read_only_file(self, sdir: Path) -> None:
        sdir.mkdir(parents=True)
        path = sdir / "audit.jsonl"
        path.write_bytes(b"x\n")
        os.chmod(path, 0o400)
        with pytest.raises(PermissionError):
            audit.append_audit(decision_record(), state_dir=sdir)
        assert path.read_bytes() == b"x\n"

    def test_state_dir_path_is_a_file(self, tmp_path: Path) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_bytes(b"")
        with pytest.raises(OSError):
            audit.append_audit(decision_record(), state_dir=blocker / "gatectl")

    def test_unserializable_record_writes_nothing(self, sdir: Path) -> None:
        bad = audit.log_record(level="info", event="warning", data={"x": {1, 2}})
        with pytest.raises(TypeError):
            audit.append_log(bad, state_dir=sdir)
        assert not (sdir / "log.jsonl").exists() or (sdir / "log.jsonl").read_bytes() == b""

    def test_nan_writes_nothing(self, sdir: Path) -> None:
        bad = audit.log_record(level="info", event="warning", data={"x": float("nan")})
        with pytest.raises(ValueError):
            audit.append_log(bad, state_dir=sdir)
        assert not (sdir / "log.jsonl").exists() or (sdir / "log.jsonl").read_bytes() == b""


class TestCap:
    def test_small_line_untouched(self, sdir: Path) -> None:
        rec = audit.log_record(level="info", event="warning", message="hello")
        audit.append_log(rec, state_dir=sdir)
        assert json.loads(read_lines(sdir / "log.jsonl")[0])["message"] == "hello"

    def test_oversized_log_line_is_capped(self, sdir: Path) -> None:
        rec = audit.log_record(
            level="warn",
            event="warning",
            message="m" * 2048,
            data={f"k{i}": "v" * 256 for i in range(600)},
        )
        audit.append_log(rec, state_dir=sdir)
        raw = (sdir / "log.jsonl").read_bytes()
        assert len(raw) <= CAP
        assert raw.endswith(b"\n") and raw.count(b"\n") == 1
        parsed = json.loads(raw)
        assert_valid("log", parsed)
        assert parsed["event"] == "warning"

    def test_cap_includes_the_newline(self) -> None:
        def rec(pad: int) -> dict[str, Any]:
            return {
                "ts": "2026-01-01T00:00:00.000000Z",
                "level": "info",
                "event": "warning",
                "data": {"x": "a" * pad},
            }

        pad = CAP - len(audit.encode_line(rec(0), sanitize_text=False))
        exact = audit.encode_line(rec(pad), sanitize_text=False)
        assert len(exact) == CAP
        assert json.loads(exact)["data"]["x"] == "a" * pad
        over = audit.encode_line(rec(pad + 1), sanitize_text=False)
        assert len(over) == CAP
        assert json.loads(over)["data"]["x"] == "a" * pad  # shortened by exactly the excess

    def test_longest_free_text_is_shortened_first_and_others_survive(self) -> None:
        rec = {
            "ts": "2026-01-01T00:00:00.000000Z",
            "level": "info",
            "event": "warning",
            "message": "short message",
            "data": {"big": "y" * 200_000, "keep": "kept"},
        }
        parsed = json.loads(audit.encode_line(rec, sanitize_text=False))
        assert parsed["message"] == "short message"
        assert parsed["data"]["keep"] == "kept"
        assert 0 < len(parsed["data"]["big"]) < 200_000

    def test_astral_text_counted_in_bytes(self) -> None:
        rec = {
            "ts": "2026-01-01T00:00:00.000000Z",
            "level": "info",
            "event": "warning",
            "data": {"a": "\U0001f600" * 30_000},
        }
        line = audit.encode_line(rec, sanitize_text=False)
        assert len(line) <= CAP
        json.loads(line)

    def test_many_free_text_values_all_emptied_if_needed(self) -> None:
        rec = {
            "ts": "2026-01-01T00:00:00.000000Z",
            "level": "info",
            "event": "warning",
            "data": {f"key{i:05d}": "z" * 10 for i in range(20_000)},
        }
        line = audit.encode_line(rec, sanitize_text=False)
        assert len(line) <= CAP
        assert json.loads(line)["data"] is None

    def test_hopeless_record_raises_and_writes_nothing(self, sdir: Path) -> None:
        # A non-free-text field the writer must not alter is itself over the cap.
        rec = {"ts": "2026-01-01T00:00:00.000000Z", "level": "info", "event": "e" * 70_000}
        with pytest.raises(audit.RecordTooLargeError):
            audit.append_log(rec, state_dir=sdir)
        assert not (sdir / "log.jsonl").exists() or (sdir / "log.jsonl").read_bytes() == b""

    def test_oversized_state_change_reason_is_capped_and_valid(self, sdir: Path) -> None:
        rec = audit.audit_record(
            action="state_change",
            target="pol@*",
            decision_id=[],
            actor="human:alice",
            stdin_tty=True,
            actor_source="flag",
            inputs={"policy": "pol", "scope": "*", "state": "enforced"},
            result={
                "previous_state": "shadow",
                "state": "enforced",
                "cause": "set",
                "reason": "r" * 500_000,
                "triggered_by": None,
            },
        )
        audit.append_audit(rec, state_dir=sdir)
        parsed = json.loads(read_lines(sdir / "audit.jsonl")[0])
        assert_valid("audit", parsed)
        assert len(parsed["result"]["reason"]) == 1024

    def test_encode_does_not_mutate_input(self) -> None:
        rec = audit.log_record(level="info", event="warning", data={"a": "x\n"})
        snapshot = json.dumps(rec, sort_keys=True)
        audit.encode_line(rec)
        assert json.dumps(rec, sort_keys=True) == snapshot

    def test_encode_does_not_mutate_input_when_shortening(self) -> None:
        rec = audit.log_record(
            level="info",
            event="warning",
            message="m" * 2000,
            data={"a": ["x" * 40_000, {"b": "y" * 40_000}], "c": "z" * 40_000},
        )
        before = copy.deepcopy(rec)
        assert len(audit.encode_line(rec)) <= CAP
        assert rec == before
        audit_rec = decision_record()
        audit_rec["result"] = {"state": "x", "reason": "r" * 500_000}
        audit_rec["data"] = {"k": "d" * 500_000}
        before = copy.deepcopy(audit_rec)
        assert len(audit.encode_line(audit_rec)) <= CAP
        assert audit_rec == before


class TestSanitizing:
    def test_message_is_sanitized_and_capped_at_2048(self, sdir: Path) -> None:
        rec = audit.log_record(level="warn", event="warning", message="a\nb\x1b[31m" + "c" * 5000)
        audit.append_log(rec, state_dir=sdir)
        parsed = json.loads(read_lines(sdir / "log.jsonl")[0])
        assert parsed["message"].startswith(f"a{MARKER}b{MARKER}[31m")
        assert len(parsed["message"]) == 2048
        assert_valid("log", parsed)

    def test_raw_record_text_is_sanitized_by_the_writer_too(self, sdir: Path) -> None:
        rec = {
            "ts": "2026-01-01T00:00:00.000000Z",
            "level": "info",
            "event": "warning",
            "message": "x y\ud800z",
            "data": {"k\n": ["v\x00", {"n": "‮"}], "n": 1, "t": True, "z": None},
        }
        audit.append_log(rec, state_dir=sdir)
        parsed = json.loads(read_lines(sdir / "log.jsonl")[0])
        assert parsed["message"] == f"x{MARKER}y{MARKER}z"
        assert parsed["data"] == {
            f"k{MARKER}": [f"v{MARKER}", {"n": MARKER}],
            "n": 1,
            "t": True,
            "z": None,
        }

    def test_data_strings_capped_at_256(self, sdir: Path) -> None:
        rec = audit.log_record(level="info", event="warning", data={"a": "q" * 1000})
        audit.append_log(rec, state_dir=sdir)
        assert len(json.loads(read_lines(sdir / "log.jsonl")[0])["data"]["a"]) == 256

    def test_deep_data_is_collapsed_not_a_crash(self, sdir: Path) -> None:
        deep: Any = "leaf"
        for _ in range(5000):
            deep = {"d": deep}
        rec = audit.log_record(level="info", event="warning", data=deep)
        audit.append_log(rec, state_dir=sdir)
        parsed = json.loads(read_lines(sdir / "log.jsonl")[0])
        assert_valid("log", parsed)

    def test_reason_with_newline_cannot_forge_a_line(self, sdir: Path) -> None:
        forged = '"}\n{"action":"decision"}'
        rec = audit.audit_record(
            action="state_change",
            target="pol@*",
            decision_id=[],
            actor="human:alice",
            stdin_tty=True,
            actor_source="flag",
            inputs={"policy": "pol", "scope": "*", "state": "off"},
            result={
                "previous_state": "shadow",
                "state": "off",
                "cause": "set",
                "reason": forged,
                "triggered_by": None,
            },
        )
        audit.append_audit(rec, state_dir=sdir)
        assert len(read_lines(sdir / "audit.jsonl")) == 1


class TestRecordsValidateAgainstSchemas:
    def test_decision(self, sdir: Path) -> None:
        audit.append_audit(decision_record(), state_dir=sdir)
        parsed = json.loads(read_lines(sdir / "audit.jsonl")[0])
        assert_valid("audit", parsed)
        assert parsed["inputs"]["decision_ids"] == []
        assert parsed["inputs"]["actor_source"] == "default"
        assert parsed["stdin_tty"] is False

    def test_decision_with_caller_ids(self) -> None:
        rec = decision_record()
        rec2 = audit.audit_record(
            action="decision",
            target=rec["target"],
            decision_id=DID,
            actor="auto:unknown",
            stdin_tty=False,
            actor_source="flag",
            caller_decision_ids=("a.b:c", "x"),
            inputs=rec["inputs"],
            result=rec["result"],
        )
        assert rec2["inputs"]["decision_ids"] == ["a.b:c", "x"]
        assert_valid("audit", json.loads(audit.encode_line(rec2)))

    def test_outcome(self) -> None:
        rec = audit.audit_record(
            action="outcome",
            target=DID,
            decision_id=DID,
            actor="human:alice",
            stdin_tty=True,
            actor_source="flag",
            inputs={"signal": "human", "outcome": "disagree"},
            result={
                "outcome": "disagree",
                "signal": "human",
                "effective_outcome": "disagree",
                "miss": "unsafe",
            },
        )
        assert_valid("audit", json.loads(audit.encode_line(rec)))

    def test_state_change_miss(self) -> None:
        rec = audit.audit_record(
            action="state_change",
            target="pol@github.com/o/r",
            decision_id=["caller-1"],
            caller_decision_ids=("caller-1",),
            actor="auto:gatectl",
            stdin_tty=False,
            actor_source="default",
            inputs={"policy": "pol", "scope": "github.com/o/r", "state": "shadow"},
            result={
                "previous_state": "enforced",
                "state": "shadow",
                "cause": "miss",
                "reason": None,
                "triggered_by": DID,
            },
        )
        assert_valid("audit", json.loads(audit.encode_line(rec)))

    def test_prune(self) -> None:
        rec = audit.audit_record(
            action="prune",
            target="state.db",
            decision_id=[],
            actor="auto:unknown",
            stdin_tty=False,
            actor_source="default",
            inputs={"older_than": "90d"},
            result={"counts": {"decisions": 1, "outcomes": 2, "cache": 3}, "older_than": "90d"},
        )
        assert_valid("audit", json.loads(audit.encode_line(rec)))

    def test_audit_timestamp_is_fixed_width(self) -> None:
        assert len(decision_record()["ts"]) == 27

    def test_every_log_event_and_level(self) -> None:
        events = [
            "check_off",
            "shadow_failure",
            "hook_skipped",
            "hook_failed",
            "reconcile",
            "drop_skipped",
            "terminated",
            "cron",
            "warning",
        ]
        for event in events:
            for level in ("debug", "info", "warn", "error"):
                rec = audit.log_record(level=level, event=event)
                assert_valid("log", json.loads(audit.encode_line(rec)))

    def test_log_with_all_fields(self) -> None:
        rec = audit.log_record(
            level="warn",
            event="hook_failed",
            message="boom",
            policy="pol",
            scope="*",
            decision_id=DID,
            hook="post-decision",
            data={"exit": 3},
        )
        assert_valid("log", json.loads(audit.encode_line(rec)))

    def test_log_record_rejects_unknown_event_and_level(self) -> None:
        with pytest.raises(ValueError, match="event"):
            audit.log_record(level="info", event="nope")
        with pytest.raises(ValueError, match="level"):
            audit.log_record(level="loud", event="cron")

    def test_audit_record_rejects_unknown_action(self) -> None:
        with pytest.raises(ValueError, match="action"):
            audit.audit_record(
                action="delete",
                target="x",
                decision_id=[],
                actor="auto:x",
                stdin_tty=False,
                actor_source="default",
                inputs={},
                result={},
            )

    def test_audit_record_rejects_too_many_caller_ids(self) -> None:
        with pytest.raises(ValueError, match="decision_ids"):
            audit.audit_record(
                action="prune",
                target="state.db",
                decision_id=[],
                actor="auto:x",
                stdin_tty=False,
                actor_source="default",
                caller_decision_ids=tuple(f"i{n}" for n in range(17)),
                inputs={"older_than": None},
                result={"counts": {"decisions": 0, "outcomes": 0, "cache": 0}, "older_than": None},
            )

    def test_injected_clock(self) -> None:
        rec = audit.log_record(
            level="info", event="cron", now=lambda: clock.parse_ts("2030-05-06T07:08:09.000010Z")
        )
        assert rec["ts"] == "2030-05-06T07:08:09.000010Z"


def _hammer(path: str, worker: int, count: int, size: int) -> None:
    sd = Path(path)
    for i in range(count):
        pad = "p" * (size if i % 7 == 0 else 20)
        audit.append_log(
            {
                "ts": "2026-01-01T00:00:00.000000Z",
                "level": "info",
                "event": "warning",
                "message": f"w{worker}-{i}",
                "data": {"pad": pad, "worker": worker, "i": i},
            },
            state_dir=sd,
            sanitize_text=False,
        )


class TestConcurrency:
    def test_concurrent_processes_never_interleave(self, sdir: Path) -> None:
        ctx = multiprocessing.get_context("fork")
        workers, count = 6, 60
        procs = [
            ctx.Process(target=_hammer, args=(str(sdir), w, count, 30_000)) for w in range(workers)
        ]
        for p in procs:
            p.start()
        try:
            for p in procs:
                p.join(timeout=120)
        finally:
            for p in procs:
                if p.is_alive():
                    p.kill()  # this exact child, started above
                    p.join(timeout=10)
        assert all(p.exitcode == 0 for p in procs)
        raw = (sdir / "log.jsonl").read_bytes()
        lines = raw.split(b"\n")
        assert lines.pop() == b""
        assert len(lines) == workers * count
        seen: set[tuple[int, int]] = set()
        for line in lines:
            rec = json.loads(line)
            seen.add((rec["data"]["worker"], rec["data"]["i"]))
            assert rec["message"] == f"w{rec['data']['worker']}-{rec['data']['i']}"
            assert set(rec["data"]["pad"]) == {"p"}
        assert len(seen) == workers * count

    def test_concurrent_first_creation_is_safe(self, sdir: Path) -> None:
        ctx = multiprocessing.get_context("fork")
        procs = [ctx.Process(target=_hammer, args=(str(sdir), w, 5, 100)) for w in range(8)]
        for p in procs:
            p.start()
        try:
            for p in procs:
                p.join(timeout=60)
        finally:
            for p in procs:
                if p.is_alive():
                    p.kill()
                    p.join(timeout=10)
        assert all(p.exitcode == 0 for p in procs)
        assert len(read_lines(sdir / "log.jsonl")) == 40
        assert stat.S_IMODE((sdir / "log.jsonl").stat().st_mode) == 0o600


class TestKeyCollisions:
    def _data(self, data: dict[str, Any]) -> dict[str, Any]:
        rec = audit.log_record(level="info", event="warning", data=data)
        return json.loads(audit.encode_line(rec))["data"]

    def test_sanitized_keys_stay_distinct(self) -> None:
        out = self._data({"a\x00": 1, "a\x01": 2, "a\ufffd": 3})
        assert len(out) == 3
        assert sorted(out.values()) == [1, 2, 3]
        assert out == {f"a{MARKER}": 1, f"a{MARKER}#2": 2, f"a{MARKER}#3": 3}

    def test_capped_keys_stay_distinct_within_the_cap(self) -> None:
        out = self._data({"k" * 300 + "1": 1, "k" * 300 + "2": 2, "k" * 300 + "3": 3})
        assert sorted(out.values()) == [1, 2, 3]
        assert all(len(key) <= 256 for key in out)
        assert len(out) == 3

    def test_many_colliding_keys_are_unique_in_linear_time(self) -> None:
        import time

        data = {"a" * 256 + str(i): i for i in range(8000)}
        start = time.monotonic()
        out = audit._clean(data, True)
        elapsed = time.monotonic() - start
        assert len(out) == 8000
        assert all(len(key) <= 256 for key in out)
        assert sorted(out.values()) == list(range(8000))
        assert elapsed < 2

    def test_natural_suffixed_key_is_not_overwritten(self) -> None:
        natural = f"a{MARKER}#2"
        out = self._data({natural: 0, "a\x00": 1, "a\x01": 2})
        assert out == {natural: 0, f"a{MARKER}": 1, f"a{MARKER}#3": 2}
        out = self._data({"a\x00": 1, "a\x01": 2, natural: 0})
        assert sorted(out.values()) == [0, 1, 2]
        assert len(out) == 3

    def test_unsanitized_keys_are_untouched(self) -> None:
        rec = audit.log_record(level="info", event="warning", data={"a\x00": 1, "a\x01": 2})
        data = json.loads(audit.encode_line(rec, sanitize_text=False))["data"]
        assert data == {"a\x00": 1, "a\x01": 2}


class TestCapsWithoutSanitizing:
    def test_message_and_reason_are_cut_when_the_flag_is_off(self) -> None:
        rec = audit.log_record(level="info", event="warning", message="m\n" * 3000)
        out = json.loads(audit.encode_line(rec, sanitize_text=False))
        assert out["message"] == ("m\n" * 3000)[:2048]
        audit_rec = decision_record(result={"state": "x", "reason": "r\n" * 3000})
        out = json.loads(audit.encode_line(audit_rec, sanitize_text=False))
        assert out["result"]["reason"] == ("r\n" * 3000)[:1024]


class TestDecisionIdList:
    def _build(self, ids: list[str]) -> dict[str, Any]:
        return audit.audit_record(
            action="prune",
            target="p@*",
            decision_id=ids,
            actor="auto:unknown",
            stdin_tty=False,
            actor_source="default",
            inputs={},
            result={},
        )

    def test_seventeen_ids_are_refused(self) -> None:
        with pytest.raises(ValueError):
            self._build([f"id{i}" for i in range(17)])

    def test_sixteen_ids_are_accepted(self) -> None:
        rec = self._build([f"id{i}" for i in range(16)])
        assert len(rec["decision_id"]) == 16

    @pytest.mark.parametrize("bad", ["", "a b", "x" * 129, "a\n"])
    def test_ids_outside_the_grammar_are_refused(self, bad: str) -> None:
        with pytest.raises(ValueError):
            self._build(["ok", bad])
