"""The ``tmp/<decision_id>/`` tree: private creation and safe removal (interface.md, Files).

A ``check`` process keeps one directory per decision under the state directory's ``tmp/``,
mode 0700, with an ``owner`` file written first (the creating process's pid, start time and
boot id, so ``reconcile`` can tell a dead owner from a live one) and an ``s-<n>/`` working
directory per script check. Everything is created exclusively and without following links.

Removal walks with directory file descriptors, never follows a link (a link is unlinked, not
entered), never crosses a mount point, makes each directory writable before emptying it,
deletes ``owner`` last, and refuses on anything unexpected (a directory or file not owned by
this user, a file type nobody here creates, a changed device or identity, absurd depth) by
raising ``UnsafeTree``; the caller reports it and leaves the rest to ``reconcile``.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from gatectl import ids, procinfo

OWNER = "owner"
# A check's working directory is shallow; deeper than this is hostile or broken, so it is left.
MAX_DEPTH = 100
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class UnsafeTree(Exception):
    """A tree (or its name) is not what gatectl would have created; nothing further was done."""


def _unsafe(path: str, why: str) -> UnsafeTree:
    return UnsafeTree(f"{path}: {why}")


def _mine(info: os.stat_result) -> bool:
    return info.st_uid == os.geteuid()


def _open_dir(name: str, dir_fd: int | None, label: str) -> int:
    """Open a directory without following a link; make it readable first if it is not."""
    try:
        before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise _unsafe(label, "not a directory (links are not followed)")
        if not _mine(before):
            raise _unsafe(label, "not owned by this user")
        try:
            fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
        except PermissionError:
            os.chmod(name, 0o700, dir_fd=dir_fd)
            fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError as e:
        raise _unsafe(label, e.strerror or "cannot open") from e
    after = os.fstat(fd)
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or not _mine(after):
        os.close(fd)
        raise _unsafe(label, "changed while opening")
    return fd


def _state_tmp(state_dir: Path) -> int:
    """Open ``<state_dir>/tmp`` (created 0700 if missing) and return its descriptor."""
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(state_dir / "tmp", 0o700)
    except FileExistsError:
        pass
    state_fd = os.open(state_dir, _DIR_FLAGS)
    try:
        fd = _open_dir("tmp", state_fd, str(state_dir / "tmp"))
    finally:
        os.close(state_fd)
    os.fchmod(fd, 0o700)
    return fd


def create_decision_dir(state_dir: Path, decision_id: str) -> Path:
    """Create (or reuse) ``tmp/<decision_id>/``, mode 0700, with its ``owner`` file first.

    An existing directory is reused only if it is a real directory owned by this user; its
    ``owner`` is left as it is. A link or a file in its place is refused.
    """
    if not ids.is_decision_id(decision_id):
        raise ValueError(f"not a decision id: {decision_id!r}")
    tmp_fd = _state_tmp(state_dir)
    path = state_dir / "tmp" / decision_id
    try:
        try:
            os.mkdir(decision_id, 0o700, dir_fd=tmp_fd)
        except FileExistsError:
            os.close(_open_dir(decision_id, tmp_fd, str(path)))
            return path
        fd = _open_dir(decision_id, tmp_fd, str(path))
        try:
            _write_owner(fd, str(path))
        except BaseException:
            os.close(fd)
            os.rmdir(decision_id, dir_fd=tmp_fd)
            raise
        os.close(fd)
        return path
    finally:
        os.close(tmp_fd)


def _write_owner(dir_fd: int, label: str) -> None:
    record = {
        "pid": os.getpid(),
        "start": procinfo.start_time(os.getpid()),
        "boot_id": procinfo.boot_id(),
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(OWNER, flags, 0o600, dir_fd=dir_fd)
    try:
        os.write(fd, json.dumps(record).encode("ascii"))
    finally:
        os.close(fd)


def make_script_dir(decision_dir: Path, n: int) -> Path:
    """Create the private, empty ``s-<n>/`` working directory of the n-th script check."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError(f"script check number must be 1 or more, got {n!r}")
    path = decision_dir / f"s-{n}"
    os.mkdir(path, 0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or not _mine(info):
        raise _unsafe(str(path), "not the directory just created")
    return path


def remove_tree(path: Path | str) -> None:
    """Remove a directory tree under the rules in the module docstring; no-op if missing."""
    label = os.fspath(path)
    try:
        os.lstat(label)
    except FileNotFoundError:
        return
    parent_fd = os.open(os.path.dirname(label) or ".", _DIR_FLAGS)
    try:
        name = os.path.basename(label)
        fd = _open_dir(name, parent_fd, label)
        try:
            _empty(fd, os.fstat(fd).st_dev, 0, True, label)
        finally:
            os.close(fd)
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError as e:
            raise _unsafe(label, e.strerror or "cannot remove") from e
    finally:
        os.close(parent_fd)


def _empty(fd: int, dev: int, depth: int, top: bool, label: str) -> None:
    if depth > MAX_DEPTH:
        raise _unsafe(label, "tree too deep")
    try:
        os.fchmod(fd, 0o700)
        with os.scandir(fd) as entries:
            names = sorted(e.name for e in entries)
        for name in names:
            if top and name == OWNER:
                continue
            _remove_entry(fd, name, dev, depth, f"{label}/{name}")
        if top and OWNER in names:
            _remove_entry(fd, OWNER, dev, depth, f"{label}/{OWNER}")
    except OSError as e:
        raise _unsafe(label, e.strerror or "cannot remove") from e


def _remove_entry(fd: int, name: str, dev: int, depth: int, label: str) -> None:
    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    kind = info.st_mode
    if stat.S_ISLNK(kind):
        os.unlink(name, dir_fd=fd)
    elif stat.S_ISREG(kind):
        if not _mine(info):
            raise _unsafe(label, "not owned by this user")
        os.unlink(name, dir_fd=fd)
    elif stat.S_ISDIR(kind):
        if info.st_dev != dev:
            raise _unsafe(label, "on another device")
        child = _open_dir(name, fd, label)
        try:
            _empty(child, dev, depth + 1, False, label)
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=fd)
    else:
        raise _unsafe(label, "unexpected file type")
