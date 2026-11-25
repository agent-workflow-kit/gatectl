"""The real gateway, exercised with real (tiny Python) children.

Every child that is started is stopped through its own handle (the pid captured at launch), in a
``finally``; nothing is ever killed by pattern.
"""

from __future__ import annotations

import copy
import io
import json
import os
import pickle
import signal
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import fields
from pathlib import Path

import pytest

from gatectl.gateway import (
    Child,
    ChildSpec,
    Gateway,
    Stdio,
    SubprocessGateway,
    read_capped,
)

PY = sys.executable


def py(code: str, *args: str) -> tuple[str, ...]:
    return (PY, "-c", code, *args)


@contextmanager
def started(gw: Gateway, spec: ChildSpec) -> Iterator[Child]:
    """Start a child; always kill its group (if own) and reap it by its recorded pid."""
    child = gw.start(spec)
    try:
        yield child
    finally:
        if child.own_group:
            child.signal_group(signal.SIGKILL)
        else:
            if child.poll() is None:
                os.kill(child.pid, signal.SIGKILL)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()
        child.wait(timeout=10)


def spec(argv: tuple[str, ...], **kw: object) -> ChildSpec:
    fields: dict[str, object] = {
        "stdin": Stdio.DEVNULL,
        "stdout": Stdio.PIPE,
        "stderr": Stdio.DEVNULL,
    }
    fields.update(kw)
    return ChildSpec(argv, **fields)  # type: ignore[arg-type]


def output(child: Child) -> bytes:
    assert child.stdout is not None
    return read_capped(child.stdout, 1 << 20).data


# --- the spec: nothing is implicit ---------------------------------------------------------


def test_spec_requires_all_three_streams_explicitly() -> None:
    with pytest.raises(TypeError):
        ChildSpec(("x",))  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        ChildSpec(("x",), stdin=Stdio.DEVNULL, stdout=Stdio.PIPE)  # type: ignore[call-arg]


@pytest.mark.parametrize("bad", [None, 0, 1, 2, -1, "pipe", True, object()])
@pytest.mark.parametrize("which", ["stdin", "stdout", "stderr"])
def test_spec_rejects_anything_but_devnull_or_pipe(which: str, bad: object) -> None:
    fields: dict[str, object] = {"stdin": Stdio.DEVNULL, "stdout": Stdio.DEVNULL}
    fields["stderr"] = Stdio.DEVNULL
    fields[which] = bad
    with pytest.raises(ValueError, match=which):
        ChildSpec(("x",), **fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "argv",
    [(), [], "ls -l", b"ls", ("",), ("ls", 3), ("ls", "a\x00b"), ("a\x00",), None],
)
def test_spec_rejects_bad_argv(argv: object) -> None:
    with pytest.raises(ValueError, match="argv"):
        ChildSpec(
            argv,  # type: ignore[arg-type]
            stdin=Stdio.DEVNULL,
            stdout=Stdio.DEVNULL,
            stderr=Stdio.DEVNULL,
        )


def test_spec_accepts_a_list_and_freezes_it() -> None:
    s = ChildSpec(
        ["a", "b"],  # type: ignore[arg-type]
        stdin=Stdio.DEVNULL,
        stdout=Stdio.DEVNULL,
        stderr=Stdio.DEVNULL,
    )
    assert s.argv == ("a", "b")


def test_spec_rejects_non_string_env() -> None:
    with pytest.raises(ValueError, match="env"):
        spec(("x",), env={"A": 1})
    with pytest.raises(ValueError, match="env"):
        spec(("x",), env={"A=B": "1"})
    with pytest.raises(ValueError, match="env"):
        spec(("x",), env={"A": "a\x00"})


def test_spec_env_is_read_only_and_hashable() -> None:
    env = {"A": "1"}
    s = spec(("x",), env=env)
    env["B"] = "2"  # the caller's dict is not shared with the spec
    assert dict(s.env or {}) == {"A": "1"}
    with pytest.raises(TypeError):
        s.env["C"] = "3"  # type: ignore[index]
    assert hash(s) == hash(spec(("x",), env={"A": "1"}))
    assert s == spec(("x",), env={"A": "1"})
    assert s != spec(("x",), env={"A": "2"})
    assert isinstance(hash(spec(("x",))), int)


def test_spec_repr_does_not_leak_env_values() -> None:
    assert "hunter2" not in repr(spec(("x",), env={"TOKEN": "hunter2"}))


@pytest.mark.parametrize("bad", [None, 0, 1, "yes"])
def test_spec_rejects_non_bool_own_group(bad: object) -> None:
    with pytest.raises(ValueError, match="own_group"):
        spec(("x",), own_group=bad)


@pytest.mark.parametrize("bad", [3, b"/tmp", Path("/tmp"), "a\x00b"])
def test_spec_rejects_bad_cwd(bad: object) -> None:
    with pytest.raises(ValueError, match="cwd"):
        spec(("x",), cwd=bad)


@pytest.mark.parametrize("bad", ["A=1", ["A"], 3, ("A", "1")])
def test_spec_rejects_non_mapping_env(bad: object) -> None:
    with pytest.raises(ValueError, match="env"):
        spec(("x",), env=bad)


def test_spec_fields_match_init_parameters() -> None:
    import inspect

    params = set(inspect.signature(ChildSpec.__init__).parameters) - {"self"}
    assert {f.name for f in fields(ChildSpec)} == params


# --- the real gateway -----------------------------------------------------------------------


def test_stdout_is_captured_and_stdin_devnull_reads_eof() -> None:
    code = "import sys; sys.stdout.write('[' + sys.stdin.read() + ']')"
    with started(SubprocessGateway(), spec(py(code))) as child:
        assert output(child) == b"[]"
        assert child.wait(timeout=10) == 0


def test_stdin_pipe_is_written_and_closed_by_the_caller() -> None:
    code = "import sys; sys.stdout.write(sys.stdin.read().upper())"
    with started(SubprocessGateway(), spec(py(code), stdin=Stdio.PIPE)) as child:
        assert child.stdin is not None
        child.stdin.write(b"abc")
        child.stdin.close()
        assert output(child) == b"ABC"


def test_unrequested_streams_are_not_exposed() -> None:
    with started(SubprocessGateway(), spec(py("pass"))) as child:
        assert child.stdin is None
        assert child.stderr is None
        assert child.stdout is not None


def test_stderr_pipe_is_separate_from_stdout() -> None:
    code = "import sys; sys.stdout.write('o'); sys.stderr.write('e')"
    with started(SubprocessGateway(), spec(py(code), stderr=Stdio.PIPE)) as child:
        assert child.stderr is not None
        assert read_capped(child.stderr, 100).data == b"e"
        assert output(child) == b"o"


def test_close_fds_a_parent_descriptor_is_not_inherited() -> None:
    r, w = os.pipe()
    os.set_inheritable(r, True)
    os.set_inheritable(w, True)
    try:
        code = (
            "import os, sys\n"
            "fd = int(sys.argv[1])\n"
            "try:\n"
            "    os.fstat(fd)\n"
            "    print('open')\n"
            "except OSError:\n"
            "    print('closed')\n"
        )
        with started(SubprocessGateway(), spec(py(code, str(r)))) as child:
            assert output(child).strip() == b"closed"
    finally:
        os.close(r)
        os.close(w)


def test_child_holds_no_descriptor_above_2_that_the_caller_had_open(tmp_path: Path) -> None:
    held = tmp_path / "held-by-caller"
    code = (
        "import os, json\n"
        "targets = []\n"
        "for n in os.listdir('/proc/self/fd'):\n"
        "    if int(n) > 2:\n"
        "        try:\n"
        "            targets.append(os.readlink('/proc/self/fd/' + n))\n"
        "        except OSError:\n"
        "            pass\n"
        "print(json.dumps(targets))\n"
    )
    r, w = os.pipe()
    with held.open("wb") as f:
        os.set_inheritable(f.fileno(), True)
        os.set_inheritable(r, True)
        try:
            with started(SubprocessGateway(), spec(py(code))) as child:
                targets = json.loads(output(child))
        finally:
            os.close(r)
            os.close(w)
    assert not [t for t in targets if t == str(held) or t.startswith("pipe:")]


def test_argv_is_never_run_through_a_shell(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    hostile = f"$(touch {marker}); `touch {marker}`; touch {marker}"
    code = "import sys; sys.stdout.write(sys.argv[1])"
    with started(SubprocessGateway(), spec(py(code, hostile))) as child:
        assert output(child).decode() == hostile
    assert not marker.exists()


def test_env_is_exactly_the_one_given_and_cwd_is_applied(tmp_path: Path) -> None:
    code = "import os, json; print(json.dumps([dict(os.environ), os.getcwd()]))"
    env = {"ONLY": "1"}
    with started(SubprocessGateway(), spec(py(code), env=env, cwd=str(tmp_path))) as child:
        seen, cwd = json.loads(output(child))
    assert seen["ONLY"] == "1"
    # Nothing of the caller's environment leaks in (the interpreter may add LC_CTYPE itself).
    assert not {"HOME", "PATH", "XDG_CONFIG_HOME"} & set(seen)
    assert cwd == str(tmp_path.resolve())


def test_empty_env_gives_the_child_no_home() -> None:
    code = "import os; print(os.environ.get('HOME'))"
    with started(SubprocessGateway(), spec(py(code), env={})) as child:
        assert output(child).strip() == b"None"


def test_env_none_inherits_the_callers_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GATECTL_TEST_MARK", "yes")
    code = "import os; print(os.environ.get('GATECTL_TEST_MARK'))"
    with started(SubprocessGateway(), spec(py(code))) as child:
        assert output(child).strip() == b"yes"


def test_missing_binary_raises_file_not_found(tmp_path: Path) -> None:
    gw = SubprocessGateway()
    with pytest.raises(FileNotFoundError):
        gw.start(spec((str(tmp_path / "nope"),)))


def test_own_group_makes_the_child_a_group_leader() -> None:
    code = "import os; print(os.getpgid(0), os.getpid())"
    with started(SubprocessGateway(), spec(py(code), own_group=True)) as child:
        assert child.own_group
        pgid, pid = map(int, output(child).split())
        assert pgid == pid == child.pid
        assert pgid != os.getpgid(0)


def test_without_own_group_the_child_shares_ours() -> None:
    code = "import os; print(os.getpgid(0))"
    with started(SubprocessGateway(), spec(py(code))) as child:
        assert not child.own_group
        assert int(output(child)) == os.getpgid(0)


def test_signal_group_refuses_when_the_child_is_not_a_group_leader() -> None:
    with started(SubprocessGateway(), spec(py("import time; time.sleep(30)"))) as child:
        with pytest.raises(ValueError, match="own process group"):
            child.signal_group(signal.SIGTERM)
        assert child.poll() is None  # and nothing was signaled


def _zombie_or_missing(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True
    return stat.rsplit(")", 1)[1].split()[0] == "Z"


def _gone(pgid: int, grandchild: int, deadline: float = 5.0) -> bool:
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        # killpg(.., 0) also succeeds for an unreaped zombie; that counts as gone.
        if _zombie_or_missing(grandchild):
            return True
        time.sleep(0.02)
    return False


def test_signal_group_kills_a_grandchild_that_ignores_sigterm() -> None:
    code = (
        "import subprocess, sys, signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "g = subprocess.Popen([sys.executable, '-c',\n"
        "    'import signal, time;"
        " signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'],\n"
        "    stdin=subprocess.DEVNULL)\n"
        "print(g.pid, flush=True)\n"
        "time.sleep(30)\n"
    )
    with started(SubprocessGateway(), spec(py(code), own_group=True)) as child:
        assert child.stdout is not None
        grandchild = int(child.stdout.readline())
        assert os.getpgid(grandchild) == child.pid
        child.signal_group(signal.SIGTERM)
        time.sleep(0.2)
        assert child.poll() is None  # the leader ignores SIGTERM
        os.kill(grandchild, 0)  # and so does the grandchild: still alive
        child.signal_group(signal.SIGKILL)
        assert child.wait(timeout=10) == -signal.SIGKILL
        assert _gone(child.pid, grandchild), "the grandchild survived SIGKILL of the group"


def test_wait_exited_then_signal_group_sweeps_stragglers_before_reaping() -> None:
    code = (
        "import subprocess, sys\n"
        "g = subprocess.Popen([sys.executable, '-c',\n"
        "    'import signal, time;"
        " signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'],\n"
        "    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)\n"
        "print(g.pid, flush=True)\n"
    )
    with started(SubprocessGateway(), spec(py(code), own_group=True)) as child:
        assert child.stdout is not None
        grandchild = int(child.stdout.readline())
        assert child.wait_exited(timeout=10) is True
        # Exited but not reaped: still a zombie the kernel can report on.
        assert os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
        os.kill(grandchild, 0)  # the straggler is alive
        child.signal_group(signal.SIGKILL)  # works: the leader was not reaped
        assert child.wait(timeout=10) == 0
        assert _gone(child.pid, grandchild), "the straggler survived"


def test_wait_exited_is_true_after_reaping_and_false_while_running() -> None:
    with started(SubprocessGateway(), spec(py("import time; time.sleep(30)"))) as child:
        assert child.wait_exited(timeout=0.05) is False
        assert child.poll() is None
    with started(SubprocessGateway(), spec(py("pass"))) as child:
        assert child.wait(timeout=10) == 0
        assert child.wait_exited(timeout=0) is True


def test_wait_exited_without_timeout_blocks_until_exit() -> None:
    with started(SubprocessGateway(), spec(py("import time; time.sleep(0.2)"))) as child:
        assert child.wait_exited() is True
        assert child.wait(timeout=10) == 0


def test_signal_group_after_the_leader_was_reaped_is_a_no_op() -> None:
    with started(SubprocessGateway(), spec(py("pass"), own_group=True)) as child:
        assert child.wait(timeout=10) == 0
        child.signal_group(signal.SIGKILL)  # the group id may be reused: nothing is signaled


def test_wait_timeout_raises_and_poll_reports_running() -> None:
    with started(SubprocessGateway(), spec(py("import time; time.sleep(30)"))) as child:
        assert child.poll() is None
        with pytest.raises(TimeoutError):
            child.wait(timeout=0.05)


def test_gateway_satisfies_the_protocol() -> None:
    gw: Gateway = SubprocessGateway()
    assert gw is not None


# --- read_capped ----------------------------------------------------------------------------


def _stream(data: bytes) -> io.BytesIO:
    return io.BytesIO(data)


def test_read_capped_under_the_cap() -> None:
    r = read_capped(_stream(b"abc"), 10)
    assert (r.data, r.truncated) == (b"abc", False)


def test_read_capped_exactly_at_the_cap_is_not_truncated() -> None:
    r = read_capped(_stream(b"abcde"), 5)
    assert (r.data, r.truncated) == (b"abcde", False)


def test_read_capped_over_the_cap_keeps_the_prefix_and_flags_truncation() -> None:
    r = read_capped(_stream(b"abcdef"), 5)
    assert (r.data, r.truncated) == (b"abcde", True)


def test_read_capped_empty_stream() -> None:
    r = read_capped(_stream(b""), 5)
    assert (r.data, r.truncated) == (b"", False)


def test_read_capped_zero_cap_discards_everything() -> None:
    assert read_capped(_stream(b"x"), 0).truncated
    assert read_capped(_stream(b""), 0).truncated is False


def test_read_capped_negative_cap_is_an_error() -> None:
    with pytest.raises(ValueError, match="cap"):
        read_capped(_stream(b""), -1)


def test_read_capped_drains_a_huge_output_so_the_child_never_blocks() -> None:
    code = "import sys; sys.stdout.buffer.write(b'x' * 5_000_000)"
    with started(SubprocessGateway(), spec(py(code))) as child:
        assert child.stdout is not None
        r = read_capped(child.stdout, 1000)
        assert len(r.data) == 1000 and r.truncated
        assert child.wait(timeout=10) == 0


def test_read_capped_keeps_binary_data_intact() -> None:
    data = bytes(range(256)) + "é ".encode()
    r = read_capped(_stream(data), 10_000)
    assert r.data == data


def test_wait_exited_after_out_of_band_reap_makes_signal_group_a_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with started(SubprocessGateway(), spec(py("pass"), own_group=True)) as child:
        os.waitpid(child.pid, 0)  # someone else reaps the leader
        assert child.wait_exited(timeout=10) is True

        def boom(*_a: object) -> None:
            raise AssertionError("killpg on a possibly reused pid")

        monkeypatch.setattr("gatectl.gateway.os.killpg", boom)
        child.signal_group(signal.SIGKILL)


def test_child_spec_survives_deepcopy_and_pickle() -> None:
    original = spec(py("pass"), own_group=True, cwd="/tmp", env={"A": "1"})
    for clone in (copy.deepcopy(original), pickle.loads(pickle.dumps(original))):
        assert clone == original
        assert clone.env == {"A": "1"}
        with pytest.raises(TypeError):
            clone.env["B"] = "2"  # type: ignore[index]
    bare = spec(py("pass"))
    assert copy.deepcopy(bare) == bare
