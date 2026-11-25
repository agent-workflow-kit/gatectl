"""``gatectl export``: JSON lines of audit.jsonl or log.jsonl, ``--since``, skipped lines."""

from __future__ import annotations

import io
import json
import os
import tracemalloc
from pathlib import Path
from typing import Any

import pytest

from gatectl import audit
from gatectl.cli import main
from tests.command_util import CANARY, isolate
from tests.history_util import ts

OLD = "2020-01-01T00:00:00.000000Z"


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = isolate(monkeypatch, tmp_path)
    path.mkdir(parents=True)
    return path


def rec(when: str, **extra: Any) -> dict[str, Any]:
    return {"ts": when, "n": extra.pop("n", 0), **extra}


def write_lines(path: Path, *lines: str | dict[str, Any] | bytes) -> None:
    out = b""
    for line in lines:
        if isinstance(line, dict):
            out += json.dumps(line, separators=(",", ":")).encode() + b"\n"
        elif isinstance(line, str):
            out += line.encode() + b"\n"
        else:
            out += line
    path.write_bytes(out)


def export(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, list[str], str]:
    code = main(["export", *argv])
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err


def test_default_prints_audit_records_in_file_order(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    write_lines(state_dir / "audit.jsonl", rec(ts(2), n=1), rec(ts(1), n=2))
    write_lines(state_dir / "log.jsonl", rec(ts(3), n=9))
    code, lines, err = export(capsys)
    assert (code, err) == (0, "")
    assert [json.loads(line)["n"] for line in lines] == [1, 2]


def test_log_prints_log_records(capsys: pytest.CaptureFixture[str], state_dir: Path) -> None:
    write_lines(state_dir / "audit.jsonl", rec(ts(2), n=1))
    write_lines(state_dir / "log.jsonl", rec(ts(3), n=9))
    code, lines, _ = export(capsys, "--log")
    assert code == 0 and [json.loads(line)["n"] for line in lines] == [9]


def test_real_audit_records_round_trip_unchanged(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    record = audit.audit_record(
        action="state_change",
        target="p@*",
        decision_id=(),
        actor="human:ann",
        stdin_tty=True,
        actor_source="flag",
        caller_decision_ids=(),
        inputs={"policy": "p", "scope": "*", "state": "shadow"},
        result={
            "previous_state": "off",
            "state": "shadow",
            "cause": "set",
            "reason": "é ok",
            "triggered_by": None,
        },
    )
    audit.append_audit(record, state_dir=state_dir)
    raw = (state_dir / "audit.jsonl").read_text(encoding="ascii")
    code, lines, _ = export(capsys)
    assert code == 0 and "\n".join(lines) + "\n" == raw


def test_since_filters_by_the_records_ts_inclusively(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    write_lines(
        state_dir / "audit.jsonl",
        rec(OLD, n=1),
        rec("2026-11-24T12:00:00.000000Z", n=2),
        rec("2026-11-24T12:00:00.000001Z", n=3),
        rec("2026-11-24T11:59:59.999999Z", n=4),
    )
    _, lines, _ = export(capsys, "--since", "2026-11-24T12:00:00Z")
    assert [json.loads(line)["n"] for line in lines] == [2, 3]
    _, lines, _ = export(capsys, "--since", "2026-11-24T13:00:00+01:00")
    assert [json.loads(line)["n"] for line in lines] == [2, 3]
    _, lines, _ = export(capsys, "--since", "1h")
    assert lines == []


@pytest.mark.parametrize("bad", ["", "soon", "2026-11-24", "1w", "-1h", "%"])
def test_a_bad_since_exits_2(capsys: pytest.CaptureFixture[str], state_dir: Path, bad: str) -> None:
    code, lines, err = export(capsys, "--since", bad)
    assert code == 2 and lines == []
    assert bad not in err or bad == ""


def test_lines_that_do_not_parse_are_skipped_and_reported(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    write_lines(
        state_dir / "audit.jsonl",
        rec(ts(1), n=1),
        "not json",
        "[1,2]",
        '{"no_ts": 1}',
        '{"ts": "yesterday"}',
        f'{{"ts": "{ts(2)}", "n": NaN}}',
        '{"ts": "' + ts(2) + '", "n": 1e999}',
        "",
        rec(ts(3), n=2),
    )
    code, lines, err = export(capsys)
    assert code == 0
    assert [json.loads(line)["n"] for line in lines] == [1, 2]
    assert err == "gatectl: warning export: 7 lines skipped (not valid records)\n"


def test_one_skipped_line_is_singular_and_a_clean_file_is_silent(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    write_lines(state_dir / "audit.jsonl", rec(ts(1)), "oops")
    _, _, err = export(capsys)
    assert err == "gatectl: warning export: 1 line skipped (not valid records)\n"
    write_lines(state_dir / "audit.jsonl", rec(ts(1)))
    assert export(capsys)[2] == ""


def test_the_skip_report_is_not_silenced_by_quiet(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    write_lines(state_dir / "audit.jsonl", "oops")
    code = main(["export", "--quiet"])
    assert code == 0 and "1 line skipped" in capsys.readouterr().err


def test_an_oversized_line_is_skipped_without_reading_it_whole(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    big = b'{"ts":"' + ts(1).encode() + b'","x":"' + b"A" * 3_000_000 + b'"}\n'
    write_lines(state_dir / "audit.jsonl", rec(ts(1), n=1), big, rec(ts(2), n=2))
    tracemalloc.start()
    try:
        code, lines, err = export(capsys)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert code == 0 and [json.loads(line)["n"] for line in lines] == [1, 2]
    assert "1 line skipped" in err
    assert peak < 1_000_000


def test_a_line_just_over_the_cap_is_skipped_and_one_at_the_cap_is_kept(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    head = b'{"ts":"' + ts(1).encode() + b'","x":"'
    tail = b'"}'
    fit = head + b"A" * (audit.LINE_CAP - len(head) - len(tail)) + tail
    assert len(fit) == audit.LINE_CAP
    over = fit.replace(b"A", b"B", 1) + b"C"
    write_lines(state_dir / "audit.jsonl", fit + b"\n", over + b"\n", rec(ts(5), n=5))
    _, lines, err = export(capsys)
    assert len(lines) == 2 and json.loads(lines[1])["n"] == 5
    assert "1 line skipped" in err


def test_hostile_text_in_a_record_is_sanitized(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    evil = f"{CANARY}\x1b[31m\x00‮x"
    write_lines(
        state_dir / "audit.jsonl",
        {"ts": ts(1), "target": evil, "result": {evil: [evil, {"k": evil}]}},
    )
    code, lines, err = export(capsys)
    assert code == 0 and err == ""
    (line,) = lines
    assert line.isascii() and "\\u001b" not in line and "\\u202e" not in line
    assert "\\u0000" not in line and CANARY in line
    assert json.loads(line)["target"] == CANARY + "�[31m��x"


def test_raw_control_bytes_in_the_file_never_reach_stdout(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    write_lines(
        state_dir / "audit.jsonl",
        b'{"ts":"' + ts(1).encode() + b'","x":"\x1b[2J\xe2\x80\xae"}\n',
        rec(ts(2), n=2),
    )
    code, lines, err = export(capsys)
    out = "\n".join(lines)
    assert code == 0 and "\x1b" not in out and "‮" not in out
    assert [json.loads(line)["n"] for line in lines] == [2] and "1 line skipped" in err


def test_deep_nesting_is_cut_not_crashing(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    deep = "[" * 20 + "1" + "]" * 20
    too_deep = "[" * 30000 + "]" * 30000
    write_lines(
        state_dir / "audit.jsonl",
        f'{{"ts":"{ts(1)}","d":{deep}}}',
        f'{{"ts":"{ts(2)}","d":{too_deep}}}',
        rec(ts(3), n=3),
    )
    code, lines, err = export(capsys)
    assert code == 0 and len(lines) in (2, 3)
    assert json.loads(lines[-1])["n"] == 3


def test_no_file_prints_nothing_and_creates_nothing(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    code, lines, err = export(capsys)
    assert (code, lines, err) == (0, [], "")
    assert list(state_dir.iterdir()) == []


def test_an_empty_file_prints_nothing(capsys: pytest.CaptureFixture[str], state_dir: Path) -> None:
    (state_dir / "audit.jsonl").write_bytes(b"")
    assert export(capsys) == (0, [], "")


def test_a_symlink_is_refused_with_fixed_text(
    capsys: pytest.CaptureFixture[str], state_dir: Path, tmp_path: Path
) -> None:
    target = tmp_path / "elsewhere.jsonl"
    write_lines(target, rec(ts(1)))
    os.symlink(target, state_dir / "audit.jsonl")
    code, lines, err = export(capsys)
    assert code == 1 and lines == []
    assert "elsewhere" not in err and err.startswith("gatectl: internal:")


def test_a_fifo_is_refused_and_never_blocks(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    os.mkfifo(state_dir / "audit.jsonl")
    code, lines, err = export(capsys)
    assert code == 1 and lines == [] and err.startswith("gatectl: internal:")


def test_a_directory_is_refused(capsys: pytest.CaptureFixture[str], state_dir: Path) -> None:
    (state_dir / "log.jsonl").mkdir()
    code, lines, _ = export(capsys, "--log")
    assert code == 1 and lines == []


def test_export_writes_nothing_but_stdout(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    write_lines(state_dir / "audit.jsonl", rec(ts(1)), "bad")
    write_lines(state_dir / "log.jsonl", rec(ts(1)))
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in state_dir.iterdir()}
    export(capsys)
    export(capsys, "--log", "--since", "1d")
    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in state_dir.iterdir()}
    assert before == after


def test_a_closed_pipe_stops_quietly_after_the_first_write(
    monkeypatch: pytest.MonkeyPatch, state_dir: Path
) -> None:
    write_lines(state_dir / "audit.jsonl", *[rec(ts(1), n=n) for n in range(50)])
    calls: list[str] = []

    class Closed(io.StringIO):
        def write(self, text: str) -> int:
            calls.append(text)
            raise BrokenPipeError

    monkeypatch.setattr("sys.stdout", Closed())
    assert main(["export"]) == 0
    assert len(calls) == 1


def test_only_the_bytes_present_at_the_start_are_read(
    capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    """A file that keeps growing cannot make export run forever: it stops at the size it had."""
    write_lines(state_dir / "audit.jsonl", rec(ts(1), n=1))
    path = state_dir / "audit.jsonl"
    original = os.fstat

    grown = False

    def growing(fd: int) -> os.stat_result:
        nonlocal grown
        info = original(fd)
        if not grown:
            grown = True
            with open(path, "ab") as handle:  # a writer appends right after the size was read
                handle.write(json.dumps(rec(ts(2), n=2)).encode() + b"\n")
        return info

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(os, "fstat", growing)
        code, lines, _ = export(capsys)
    assert code == 0 and [json.loads(line)["n"] for line in lines] == [1]


def test_an_error_while_streaming_keeps_what_was_written_and_prints_the_envelope(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from collections.abc import Iterator

    from gatectl import commands
    from gatectl.commands import Context, Result
    from gatectl.errors import InternalError

    def chunks() -> Iterator[str]:
        yield "first\n"
        raise InternalError("boom")

    def handler(ctx: Context) -> Result:
        return Result(stream=chunks())

    monkeypatch.setattr(commands, "HANDLERS", {"export": handler})
    code = main(["export", "--json"])
    out = capsys.readouterr().out
    assert code == 1
    assert out.startswith("first\n") and '"code":"internal"' in out
