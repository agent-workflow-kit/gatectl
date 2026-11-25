"""gatectl: policy decisions (allow / deny / escalate) with first-class shadow mode."""

import os


def _ensure_stdin_fd() -> None:
    """Make descriptor 0 valid before anything else is imported or opened. A launcher that closed
    it leaves slot 0 free for the first file anything opens (an import can take it), and
    ``--reason-file -`` would then read that unrelated file. Point it at /dev/null (never a
    terminal, so the caller stays non-human)."""
    try:
        os.fstat(0)
        return
    except OSError:
        pass
    try:
        fd = os.open(os.devnull, os.O_RDONLY)
        if fd != 0:
            os.dup2(fd, 0)
            os.close(fd)
    except OSError:
        pass


_ensure_stdin_fd()

from importlib.metadata import PackageNotFoundError, version  # noqa: E402 (after the fd fix)

try:
    __version__ = version("gatectl")
except PackageNotFoundError:  # run from a source tree that was never installed
    __version__ = "0.0.0+unknown"
