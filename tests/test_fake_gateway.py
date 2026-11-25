from __future__ import annotations

import signal

import pytest

from gatectl.gateway import ChildSpec, Gateway, Stdio, read_capped
from tests.fake_gateway import FakeGateway, FakeResult


def count_words(gw: Gateway, text: str) -> int:
    """A stand-in consumer: code under test receives its gateway by injection."""
    child = gw.start(
        ChildSpec(("wc", "-w"), stdin=Stdio.PIPE, stdout=Stdio.PIPE, stderr=Stdio.DEVNULL)
    )
    assert child.stdin is not None and child.stdout is not None
    child.stdin.write(text.encode())
    child.stdin.close()
    return int(read_capped(child.stdout, 64).data)


def test_consumer_uses_the_injected_fake_and_the_calls_are_recorded() -> None:
    gw = FakeGateway(script=lambda spec: FakeResult(stdout=b"3\n"))
    assert count_words(gw, "a b c") == 3
    assert [c.argv for c in gw.calls] == [("wc", "-w")]
    call = gw.calls[0]
    assert (call.stdin, call.stdout, call.stderr) == (Stdio.PIPE, Stdio.PIPE, Stdio.DEVNULL)
    assert gw.children[0].stdin is not None and gw.children[0].stdin.closed


def test_script_sees_each_spec_and_calls_keep_order() -> None:
    seen: list[str] = []

    def script(spec: ChildSpec) -> FakeResult:
        seen.append(spec.argv[0])
        return FakeResult(stdout=spec.argv[0].encode())

    gw = FakeGateway(script=script)
    for name in ("a", "b", "c"):
        child = gw.start(
            ChildSpec((name,), stdin=Stdio.DEVNULL, stdout=Stdio.PIPE, stderr=Stdio.DEVNULL)
        )
        assert child.stdout is not None
        assert read_capped(child.stdout, 8).data == name.encode()
    assert seen == ["a", "b", "c"] == [c.argv[0] for c in gw.calls]
    assert len({c.pid for c in gw.children}) == 3


def test_fake_child_group_signals_are_recorded_and_kill_ends_it() -> None:
    gw = FakeGateway(script=lambda spec: FakeResult(running=True))
    child = gw.start(
        ChildSpec(
            ("x",), stdin=Stdio.DEVNULL, stdout=Stdio.DEVNULL, stderr=Stdio.DEVNULL, own_group=True
        )
    )
    assert child.poll() is None
    child.signal_group(signal.SIGTERM)
    assert gw.children[0].signals == [signal.SIGTERM]
    assert child.poll() is None
    child.signal_group(signal.SIGKILL)
    assert child.wait() == -signal.SIGKILL


def test_fake_child_refuses_group_signal_without_own_group() -> None:
    gw = FakeGateway()
    child = gw.start(
        ChildSpec(("x",), stdin=Stdio.DEVNULL, stdout=Stdio.DEVNULL, stderr=Stdio.DEVNULL)
    )
    with pytest.raises(ValueError, match="own process group"):
        child.signal_group(signal.SIGTERM)


def _own_group() -> ChildSpec:
    return ChildSpec(
        ("x",), stdin=Stdio.DEVNULL, stdout=Stdio.DEVNULL, stderr=Stdio.DEVNULL, own_group=True
    )


def test_fake_wait_exited_does_not_reap_and_still_accepts_signals() -> None:
    gw = FakeGateway(script=lambda spec: FakeResult(returncode=0))
    child = gw.start(_own_group())
    assert child.wait_exited(timeout=1) is True
    assert not gw.children[0].reaped
    child.signal_group(signal.SIGKILL)
    assert gw.children[0].signals == [signal.SIGKILL]
    assert child.wait() == 0


def test_fake_signal_group_after_reaping_is_a_no_op() -> None:
    gw = FakeGateway()
    child = gw.start(_own_group())
    assert child.poll() == 0
    child.signal_group(signal.SIGKILL)
    assert gw.children[0].signals == []


def test_fake_wait_exited_is_false_while_running() -> None:
    gw = FakeGateway(script=lambda spec: FakeResult(running=True))
    assert gw.start(_own_group()).wait_exited(timeout=0.01) is False
