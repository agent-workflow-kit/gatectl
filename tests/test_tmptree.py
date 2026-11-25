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


@pytest.mark.parametrize("bad", ["", "..", "../x", "gd-ABC", "gd-abcdefghijk", "x/y", "gd-abcdefghijkl/"])
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
