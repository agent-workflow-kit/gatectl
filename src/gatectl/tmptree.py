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
import secrets
import stat
import sys
from pathlib import Path

from gatectl import ids, procinfo

OWNER = "owner"
# A check's working directory is shallow; deeper than this is hostile or broken, so it is left.
MAX_DEPTH = 100
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class UnsafeTree(Exception):
    """A tree (or its name) is not what gatectl would have created; nothing further was done."""


_LABEL_MAX = 160


def _unsafe(path: str, why: str) -> UnsafeTree:
    if len(path) > _LABEL_MAX:  # a deep tree must not put its whole path in a message
        path = f"{path[: _LABEL_MAX // 2]}...{path[-(_LABEL_MAX // 2 - 3) :]}"
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
            _make_accessible(name, dir_fd, before, label)
            fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError as e:
        raise _unsafe(label, e.strerror or "cannot open") from e
    after = os.fstat(fd)
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or not _mine(after):
        os.close(fd)
        raise _unsafe(label, "changed while opening")
    return fd


def _make_accessible(name: str, dir_fd: int | None, before: os.stat_result, label: str) -> None:
    """chmod 0700 a directory that cannot be opened, through a handle that is not a path.

    The entry is opened with ``O_PATH`` and ``O_NOFOLLOW`` (no permission needed, a link is
    not followed), its identity is compared with what was judged, and only then is it changed,
    through ``/proc/self/fd``, so a swap after the judgment cannot redirect the chmod. Where
    there is no ``O_PATH`` the directory is refused (macOS: todo(#37)).
    """
    if not sys.platform.startswith("linux"):
        raise _unsafe(label, "not readable and cannot be made readable safely")
    pfd = os.open(name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        now = os.fstat(pfd)
        if (now.st_dev, now.st_ino) != (before.st_dev, before.st_ino) or not _mine(now):
            raise _unsafe(label, "changed while opening")
        os.chmod(f"/proc/self/fd/{pfd}", 0o700)
    finally:
        os.close(pfd)


def _state_tmp(state_dir: Path) -> int:
    """Open ``<state_dir>/tmp`` (created 0700 if missing) and return its descriptor.

    The state directory is judged like ``store.py`` judges it: a real directory owned by this
    user (a link or a file is refused with a clear message), created 0700 whatever the umask,
    an existing one tightened to 0700.
    """
    state_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(state_dir, 0o700)
    except FileExistsError:
        pass
    try:
        state_fd = os.open(state_dir, _DIR_FLAGS)
    except OSError as e:
        raise _unsafe(str(state_dir), f"the state directory is not a real directory ({e})") from e
    try:
        info = os.fstat(state_fd)
        if not _mine(info):
            raise _unsafe(str(state_dir), "the state directory is not owned by the current user")
        if stat.S_IMODE(info.st_mode) != 0o700:
            os.fchmod(state_fd, 0o700)
        try:
            os.mkdir("tmp", 0o700, dir_fd=state_fd)
        except FileExistsError:
            pass
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
            # Unlink a partly written owner first, or the rmdir fails with ENOTEMPTY and hides
            # the real error.
            try:
                os.unlink(OWNER, dir_fd=fd)
            except OSError:
                pass
            os.close(fd)
            try:
                os.rmdir(decision_id, dir_fd=tmp_fd)
            except OSError:
                pass
            raise
        os.close(fd)
        return path
    finally:
        os.close(tmp_fd)


HOOK_PREFIX = "hook-"
PAYLOAD = "payload.json"


def create_hook_dir(state_dir: Path, payload: bytes) -> Path:
    """Create ``tmp/hook-<random>/`` (mode 0700) with its ``owner`` file (the calling process:
    the hook supervisor) and ``payload.json`` (mode 0600) holding ``payload``.

    The name is 64 random bits, created exclusively (a clash retries). A failure leaves nothing.
    """
    tmp_fd = _state_tmp(state_dir)
    try:
        for _ in range(8):
            name = HOOK_PREFIX + secrets.token_hex(8)
            try:
                os.mkdir(name, 0o700, dir_fd=tmp_fd)
            except FileExistsError:
                continue
            break
        else:
            raise OSError("no unused hook directory name")
        path = state_dir / "tmp" / name
        try:
            fd = _open_dir(name, tmp_fd, str(path))
        except BaseException:
            try:
                os.rmdir(name, dir_fd=tmp_fd)
            except OSError:
                pass
            raise
        try:
            _write_owner(fd, str(path))
            _write_payload(fd, payload)
        except BaseException:
            for leftover in (PAYLOAD, OWNER):
                try:
                    os.unlink(leftover, dir_fd=fd)
                except OSError:
                    pass
            os.close(fd)
            fd = -1
            try:
                os.rmdir(name, dir_fd=tmp_fd)
            except OSError:
                pass
            raise
        finally:
            if fd >= 0:
                os.close(fd)
        return path
    finally:
        os.close(tmp_fd)


def _write_payload(dir_fd: int, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(PAYLOAD, flags, 0o600, dir_fd=dir_fd)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)


def _write_owner(dir_fd: int, label: str) -> None:
    record = {
        "pid": os.getpid(),
        "start": procinfo.start_time(os.getpid()),
        "boot_id": procinfo.boot_id(),
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(OWNER, flags, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(json.dumps(record).encode("ascii"))
        while view:
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)


def make_script_dir(decision_dir: Path, n: int) -> Path:
    """Create the private, empty ``s-<n>/`` working directory of the n-th script check.

    The decision directory is opened once without following a link and ``s-<n>`` is made
    relative to that descriptor, so a swap of the directory's name cannot redirect it.
    """
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError(f"script check number must be 1 or more, got {n!r}")
    path = decision_dir / f"s-{n}"
    try:
        parent_fd = os.open(decision_dir, _DIR_FLAGS)
    except OSError as e:
        raise _unsafe(str(decision_dir), e.strerror or "cannot open") from e
    try:
        if not _mine(os.fstat(parent_fd)):
            raise _unsafe(str(decision_dir), "not owned by this user")
        os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        fd = os.open(path.name, _DIR_FLAGS, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or not _mine(info):
                raise _unsafe(str(path), "not the directory just created")
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    return path


def remove_tree(path: Path | str) -> None:
    """Remove a directory tree under the rules in the module docstring; no-op if missing.

    The parent is opened first, without following a link, and judged; only then is a missing
    ``path`` a no-op. Every failure on the way is ``UnsafeTree``, never a bare ``OSError``.
    """
    label = os.fspath(path)
    parent_label = os.path.dirname(label) or "."
    name = os.path.basename(label)
    try:
        parent_fd = os.open(parent_label, _DIR_FLAGS)
    except FileNotFoundError:
        return  # nothing above it: nothing to remove
    except OSError as e:
        raise _unsafe(parent_label, e.strerror or "cannot open the parent") from e
    try:
        if not _mine(os.fstat(parent_fd)):
            raise _unsafe(parent_label, "not owned by this user")
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as e:
            raise _unsafe(label, e.strerror or "cannot look at it") from e
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
