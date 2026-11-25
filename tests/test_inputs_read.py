"""Bounded, non-blocking reading of a check's input (interface.md, Check order step 2)."""

from __future__ import annotations

import os
import pty
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from gatectl import inputs
from gatectl.errors import UsageError

CAP = 1024


@pytest.fixture
def pipe() -> Iterator[tuple[int, int]]:
    r, w = os.pipe()
    yield r, w
    for fd in (r, w):
        try:
            os.close(fd)
        except OSError:
            pass


def _file(tmp_path: Path, data: bytes, name: str = "in.json") -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def read(source: str | None, *, fd: int = 0, cap: int = CAP, **kw: object) -> inputs.RawInput:
    return inputs.read_input(source, max_bytes=cap, stdin_fd=fd, **kw)  # type: ignore[arg-type]


# ---- --input file -----------------------------------------------------------------------------


def test_file_complete(tmp_path: Path) -> None:
    raw = read(_file(tmp_path, b'{"a":1}'))
    assert (raw.data, raw.status) == (b'{"a":1}', "complete")


def test_file_exactly_at_cap_is_complete(tmp_path: Path) -> None:
    raw = read(_file(tmp_path, b"x" * CAP))
    assert (len(raw.data), raw.status) == (CAP, "complete")


def test_file_one_over_cap_is_too_large_and_keeps_cap_plus_one(tmp_path: Path) -> None:
    raw = read(_file(tmp_path, b"x" * (CAP + 1)))
    assert (len(raw.data), raw.status) == (CAP + 1, "too_large")


def test_huge_sparse_file_is_read_bounded(tmp_path: Path) -> None:
    p = tmp_path / "big"
    with open(p, "wb") as f:
        f.truncate(4 * 1024 * 1024 * 1024)
    raw = read(str(p))
    assert (len(raw.data), raw.status) == (CAP + 1, "too_large")


def test_empty_file_is_complete_and_empty(tmp_path: Path) -> None:
    raw = read(_file(tmp_path, b""))
    assert (raw.data, raw.status) == (b"", "complete")


def test_symlink_to_regular_file_is_followed(tmp_path: Path) -> None:
    target = _file(tmp_path, b"{}")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert read(str(link)).data == b"{}"


def test_missing_file_is_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        read(str(tmp_path / "nope"))


def test_directory_is_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        read(str(tmp_path))


def test_unreadable_file_is_usage_error(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads anything")
    p = _file(tmp_path, b"{}")
    os.chmod(p, 0)
    with pytest.raises(UsageError):
        read(p)


def test_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    start = time.monotonic()
    with pytest.raises(UsageError):
        read(str(fifo))
    assert time.monotonic() - start < 2


@pytest.mark.parametrize("dev", ["/dev/zero", "/dev/null", "/dev/urandom"])
def test_character_devices_are_refused(dev: str) -> None:
    if not os.path.exists(dev):
        pytest.skip("no such device")
    with pytest.raises(UsageError):
        read(dev)


def test_bad_paths_are_usage_errors() -> None:
    for bad in ("", "a\x00b", "x" * 5000):
        with pytest.raises(UsageError):
            read(bad)


def test_usage_error_does_not_echo_the_path(tmp_path: Path) -> None:
    secret = tmp_path / "SECRETMARK-missing"
    with pytest.raises(UsageError) as info:
        read(str(secret))
    assert "SECRETMARK" not in str(info.value)
    assert "SECRETMARK" not in info.value.message
    assert info.value.__cause__ is None


def test_file_read_stops_at_the_deadline(tmp_path: Path) -> None:
    raw = read(_file(tmp_path, b"{}"), deadline=10.0, reserve=0.0, monotonic=lambda: 11.0)
    assert raw.status == "timeout"


# ---- stdin ------------------------------------------------------------------------------------


@pytest.mark.parametrize("source", [None, "-"])
def test_stdin_pipe_complete(pipe: tuple[int, int], source: str | None) -> None:
    r, w = pipe
    os.write(w, b'{"a":1}')
    os.close(w)
    raw = read(source, fd=r)
    assert (raw.data, raw.status) == (b'{"a":1}', "complete")


def test_stdin_dev_null_is_empty_and_complete() -> None:
    fd = os.open("/dev/null", os.O_RDONLY)
    try:
        raw = read(None, fd=fd)
    finally:
        os.close(fd)
    assert (raw.data, raw.status) == (b"", "complete")


def test_stdin_regular_file_is_bounded_and_stops_reading(tmp_path: Path) -> None:
    p = tmp_path / "big"
    with open(p, "wb") as f:
        f.truncate(1024 * 1024 * 1024)
    fd = os.open(p, os.O_RDONLY)
    try:
        raw = read(None, fd=fd)
        assert (len(raw.data), raw.status) == (CAP + 1, "too_large")
        assert os.lseek(fd, 0, os.SEEK_CUR) == CAP + 1
    finally:
        os.close(fd)


def test_stdin_huge_pipe_is_not_drained(pipe: tuple[int, int]) -> None:
    r, w = pipe
    stop = threading.Event()
    written = [0]

    def writer() -> None:
        os.set_blocking(w, False)
        chunk = b"x" * 65536
        while not stop.is_set() and written[0] < 64 * 1024 * 1024:
            try:
                written[0] += os.write(w, chunk)
            except BlockingIOError:
                time.sleep(0.005)
            except OSError:
                return

    t = threading.Thread(target=writer)
    t.start()
    try:
        raw = read(None, fd=r, deadline=time.monotonic() + 30, reserve=0.0)
        assert (len(raw.data), raw.status) == (CAP + 1, "too_large")
    finally:
        stop.set()
        t.join(5)
    assert written[0] < 64 * 1024 * 1024  # the reader did not consume until EOF


def test_stdin_partial_reads_are_assembled(pipe: tuple[int, int]) -> None:
    r, w = pipe
    body = b'{"abc":"defghij"}'

    def writer() -> None:
        for i in range(len(body)):
            os.write(w, body[i : i + 1])
            time.sleep(0.003)
        os.close(w)

    t = threading.Thread(target=writer)
    t.start()
    raw = read(None, fd=r, deadline=time.monotonic() + 30, reserve=0.0)
    t.join(5)
    assert (raw.data, raw.status) == (body, "complete")


def test_slow_writer_stops_at_the_deadline_keeping_the_reserve(pipe: tuple[int, int]) -> None:
    r, w = pipe
    os.write(w, b'{"a":')
    start = time.monotonic()
    raw = read(None, fd=r, deadline=start + 0.6, reserve=0.3)
    elapsed = time.monotonic() - start
    assert raw.status == "timeout"
    assert raw.data == b'{"a":'  # the partial read is kept: its hash is the raw bytes read
    assert 0.2 <= elapsed < 0.55  # stopped at deadline minus reserve, not at the deadline


def test_silent_writer_times_out_with_nothing(pipe: tuple[int, int]) -> None:
    r, _ = pipe
    start = time.monotonic()
    raw = read(None, fd=r, deadline=start + 0.3, reserve=0.0)
    assert (raw.data, raw.status) == (b"", "timeout")
    assert time.monotonic() - start < 2


def test_no_deadline_still_returns_on_eof(pipe: tuple[int, int]) -> None:
    r, w = pipe
    os.close(w)
    assert read(None, fd=r).status == "complete"


def test_writer_that_finishes_just_in_time_is_complete(pipe: tuple[int, int]) -> None:
    r, w = pipe

    def writer() -> None:
        time.sleep(0.1)
        os.write(w, b"{}")
        os.close(w)

    t = threading.Thread(target=writer)
    t.start()
    raw = read(None, fd=r, deadline=time.monotonic() + 10, reserve=0.0)
    t.join(5)
    assert (raw.data, raw.status) == (b"{}", "complete")


def test_stdin_reader_leaves_the_descriptor_blocking(pipe: tuple[int, int]) -> None:
    r, w = pipe
    os.write(w, b"{}")
    os.close(w)
    read(None, fd=r)
    assert os.get_blocking(r) is True  # the open file description is shared with the parent


def test_stdin_tty_without_input_is_usage_error() -> None:
    master, slave = pty.openpty()
    try:
        for source in (None, "-"):
            with pytest.raises(UsageError):
                read(source, fd=slave)
    finally:
        os.close(master)
        os.close(slave)


def test_tty_is_fine_when_a_file_is_given(tmp_path: Path) -> None:
    master, slave = pty.openpty()
    try:
        assert read(_file(tmp_path, b"{}"), fd=slave).data == b"{}"
    finally:
        os.close(master)
        os.close(slave)


def test_closed_stdin_is_usage_error() -> None:
    r, w = os.pipe()
    os.close(r)
    os.close(w)
    with pytest.raises(UsageError):
        read(None, fd=r)


def test_directory_as_stdin_is_usage_error(tmp_path: Path) -> None:
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        with pytest.raises(UsageError):
            read(None, fd=fd)
    finally:
        os.close(fd)


def test_write_only_stdin_is_usage_error(tmp_path: Path) -> None:
    fd = os.open(tmp_path / "w", os.O_WRONLY | os.O_CREAT)
    try:
        with pytest.raises(UsageError):
            read(None, fd=fd)
    finally:
        os.close(fd)


def test_stdin_peer_reset_is_usage_error_or_complete() -> None:
    import socket

    a, b = socket.socketpair()
    b.sendall(b"{}")
    b.close()
    try:
        raw = read(None, fd=a.fileno())
        assert raw.data == b"{}"
    finally:
        a.close()


def test_invalid_arguments() -> None:
    with pytest.raises(ValueError):
        inputs.read_input(None, max_bytes=0)
    with pytest.raises(ValueError):
        inputs.read_input(None, max_bytes=-1)
