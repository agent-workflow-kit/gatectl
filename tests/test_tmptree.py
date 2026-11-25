"""The ``tmp/<decision_id>/`` tree: private creation, the owner file and safe removal."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from gatectl import procinfo
from gatectl.tmptree import (
    UnsafeTree,
    create_decision_dir,
    make_script_dir,
    remove_tree,
)

ID = "gd-abcdefghijkl"


def mode(p: Path) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


def test_decision_dir_is_private_with_the_owner_file_written(tmp_path: Path) -> None:
    d = create_decision_dir(tmp_path / "state", ID)
    assert d == tmp_path / "state" / "tmp" / ID
    assert mode(tmp_path / "state" / "tmp") == 0o700 and mode(d) == 0o700
    owner = json.loads((d / "owner").read_text())
    assert owner["pid"] == os.getpid()
    assert owner["start"] == procinfo.start_time(os.getpid())
    assert owner["boot_id"] == procinfo.boot_id()
    assert mode(d / "owner") == 0o600


def test_a_second_call_reuses_the_directory_and_keeps_the_owner(tmp_path: Path) -> None:
    d = create_decision_dir(tmp_path, ID)
    before = (d / "owner").read_bytes()
    assert create_decision_dir(tmp_path, ID) == d
    assert (d / "owner").read_bytes() == before


@pytest.mark.parametrize(
    "bad", ["", "..", "../x", "gd-ABC", "gd-abcdefghijk", "x/y", "gd-abcdefghijkl/"]
)
def test_a_decision_id_that_is_not_one_is_refused(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ValueError, match="decision id"):
        create_decision_dir(tmp_path, bad)
    assert not (tmp_path / "tmp").exists() or list((tmp_path / "tmp").iterdir()) == []


def test_a_symlink_in_place_of_the_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "tmp").mkdir(mode=0o700)
    target = tmp_path / "elsewhere"
    target.mkdir()
    os.symlink(target, tmp_path / "tmp" / ID)
    with pytest.raises(UnsafeTree):
        create_decision_dir(tmp_path, ID)
    assert list(target.iterdir()) == []


def test_a_regular_file_in_place_of_the_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "tmp").mkdir(mode=0o700)
    (tmp_path / "tmp" / ID).write_text("x")
    with pytest.raises(UnsafeTree):
        create_decision_dir(tmp_path, ID)


def test_script_dir_is_empty_and_private(tmp_path: Path) -> None:
    d = create_decision_dir(tmp_path, ID)
    s = make_script_dir(d, 1)
    assert s == d / "s-1" and mode(s) == 0o700 and list(s.iterdir()) == []
    with pytest.raises(FileExistsError):
        make_script_dir(d, 1)
    with pytest.raises(ValueError, match="script"):
        make_script_dir(d, 0)


def test_remove_tree_deletes_nested_content_and_unwritable_directories(tmp_path: Path) -> None:
    root = tmp_path / "t"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "f").write_text("x")
    (root / "a" / "g").write_text("y")
    (root / "a" / "b").chmod(0o500)
    (root / "a").chmod(0o000)
    remove_tree(root)
    assert not root.exists()


def test_remove_tree_unlinks_links_without_following_them(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("precious")
    root = tmp_path / "t"
    root.mkdir()
    os.symlink(outside, root / "dirlink")
    os.symlink(outside / "keep", root / "filelink")
    os.symlink("/nonexistent", root / "dangling")
    remove_tree(root)
    assert not root.exists()
    assert (outside / "keep").read_text() == "precious"


def test_remove_tree_refuses_a_link_as_the_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("precious")
    os.symlink(outside, tmp_path / "t")
    with pytest.raises(UnsafeTree):
        remove_tree(tmp_path / "t")
    assert (outside / "keep").exists()


def test_remove_tree_refuses_a_file_type_it_did_not_create_and_keeps_owner(
    tmp_path: Path,
) -> None:
    root = create_decision_dir(tmp_path, ID)
    (root / "ok").write_text("x")
    os.mkfifo(root / "pipe")
    with pytest.raises(UnsafeTree, match="pipe"):
        remove_tree(root)
    # ``owner`` goes last, so a half-removed tree still names its owner for ``reconcile``.
    assert (root / "owner").exists()


def test_remove_tree_deletes_owner_last(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = create_decision_dir(tmp_path, ID)
    (root / "z").write_text("x")
    (root / "a").write_text("x")
    order: list[str] = []
    real = os.unlink

    def spy(path: str, *, dir_fd: int | None = None) -> None:
        order.append(str(path))
        real(path, dir_fd=dir_fd)

    monkeypatch.setattr("gatectl.tmptree.os.unlink", spy)
    remove_tree(root)
    assert order[-1] == "owner" and set(order) == {"owner", "z", "a"}


def test_remove_tree_refuses_absurd_depth_and_leaves_it(tmp_path: Path) -> None:
    root = tmp_path / "t"
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        os.mkdir("t", dir_fd=fd)
        d2 = os.open("t", os.O_RDONLY, dir_fd=fd)
        os.close(fd)
        fd = d2
        for _ in range(400):
            os.mkdir("d", dir_fd=fd)
            nxt = os.open("d", os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = nxt
    finally:
        os.close(fd)
    with pytest.raises(UnsafeTree, match="deep"):
        remove_tree(root)
    assert root.exists()


def test_remove_tree_of_a_missing_path_is_a_no_op(tmp_path: Path) -> None:
    remove_tree(tmp_path / "never")


# --- review round: parent handling, special files, state directory, creation races ---------


def test_remove_tree_with_a_symlinked_parent_is_refused_not_a_silent_no_op(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    os.symlink(real, link)
    # The label is missing behind the link, but the link itself is not what gatectl made.
    with pytest.raises(UnsafeTree):
        remove_tree(link / "s-1")


def test_remove_tree_with_an_unreadable_parent_is_unsafe_not_an_oserror(tmp_path: Path) -> None:
    parent = tmp_path / "p"
    (parent / "s-1").mkdir(parents=True)
    parent.chmod(0)
    try:
        with pytest.raises(UnsafeTree):
            remove_tree(parent / "s-1")
    finally:
        parent.chmod(0o700)


def test_remove_tree_with_a_missing_parent_is_a_no_op(tmp_path: Path) -> None:
    remove_tree(tmp_path / "gone" / "s-1")


def test_remove_tree_refuses_a_socket_and_keeps_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket

    root = tmp_path / "t"
    root.mkdir()
    monkeypatch.chdir(root)  # a relative name keeps the path under the AF_UNIX length limit
    sock = socket.socket(socket.AF_UNIX)
    try:
        sock.bind("s")
    finally:
        sock.close()
    with pytest.raises(UnsafeTree, match="unexpected file type"):
        remove_tree(root)
    assert root.exists()


def test_the_depth_cap_message_does_not_embed_the_whole_path(tmp_path: Path) -> None:
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        os.mkdir("t", dir_fd=fd)
        d2 = os.open("t", os.O_RDONLY, dir_fd=fd)
        os.close(fd)
        fd = d2
        for _ in range(400):
            os.mkdir("dddddddddd", dir_fd=fd)
            nxt = os.open("dddddddddd", os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = nxt
    finally:
        os.close(fd)
    with pytest.raises(UnsafeTree) as info:
        remove_tree(tmp_path / "t")
    assert len(str(info.value)) < 400


def test_a_fresh_state_directory_is_0700_whatever_the_umask(tmp_path: Path) -> None:
    old = os.umask(0o022)
    try:
        create_decision_dir(tmp_path / "a" / "state", ID)
    finally:
        os.umask(old)
    assert mode(tmp_path / "a" / "state") == 0o700
    assert mode(tmp_path / "a" / "state" / "tmp") == 0o700


def test_an_existing_loose_state_directory_is_tightened(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    state.chmod(0o755)
    create_decision_dir(state, ID)
    assert mode(state) == 0o700


def test_a_symlinked_state_directory_is_refused_with_a_clear_message(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    os.symlink(real, tmp_path / "state")
    with pytest.raises(UnsafeTree, match="state directory is not a real directory"):
        create_decision_dir(tmp_path / "state", ID)
    assert list(real.iterdir()) == []


def test_a_state_directory_that_is_a_file_is_refused_with_a_clear_message(tmp_path: Path) -> None:
    (tmp_path / "state").write_text("x")
    with pytest.raises(UnsafeTree, match="state directory is not a real directory"):
        create_decision_dir(tmp_path / "state", ID)


def test_a_failed_owner_write_leaves_no_directory_and_the_real_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import errno

    def boom(fd: int, data: bytes) -> int:
        raise OSError(errno.ENOSPC, "no space")

    monkeypatch.setattr("gatectl.tmptree.os.write", boom)
    with pytest.raises(OSError) as info:
        create_decision_dir(tmp_path, ID)
    assert info.value.errno == errno.ENOSPC  # not ENOTEMPTY from the rmdir
    assert not (tmp_path / "tmp" / ID).exists()


def test_a_short_owner_write_is_completed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = os.write

    def one_byte(fd: int, data: bytes) -> int:
        return real(fd, bytes(data)[:1])

    monkeypatch.setattr("gatectl.tmptree.os.write", one_byte)
    d = create_decision_dir(tmp_path, ID)
    assert json.loads((d / "owner").read_text())["pid"] == os.getpid()


def test_the_script_dir_is_made_relative_to_the_held_decision_dir(tmp_path: Path) -> None:
    d = create_decision_dir(tmp_path, ID)
    moved = tmp_path / "tmp" / "moved"
    os.symlink(moved, tmp_path / "tmp" / "swap")
    # A decision dir that is a link is refused (nothing is created through it).
    with pytest.raises(UnsafeTree):
        make_script_dir(tmp_path / "tmp" / "swap", 1)
    assert make_script_dir(d, 2) == d / "s-2"
