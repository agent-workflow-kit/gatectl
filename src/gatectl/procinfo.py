"""Process identity: the boot id and a process's start time (interface.md, Files).

A pid alone is not an identity (pids are reused); a pid plus its start time within one boot is.
Linux reads ``/proc``. Other platforms have no portable method here yet, so both functions
return a value that never matches anything real (``None`` and ``""``).
"""

from __future__ import annotations

_BOOT_ID = "/proc/sys/kernel/random/boot_id"


def boot_id() -> str:
    """The kernel's boot id, or an empty string where it cannot be read."""
    try:
        with open(_BOOT_ID, encoding="ascii") as f:
            return f.read().strip()
    except (OSError, UnicodeDecodeError):
        return ""


def start_time(pid: int) -> str | None:
    """The process's start time in clock ticks since boot, as text, or ``None`` if unknown.

    ``/proc/<pid>/stat`` is read after its last ``)``, because the command name before it may
    itself contain spaces and parentheses; the start time is the 22nd field overall.
    """
    try:
        with open(f"/proc/{int(pid)}/stat", "rb") as f:
            data = f.read()
        fields = data[data.rindex(b")") + 2 :].split()
        return fields[19].decode("ascii")
    except (OSError, ValueError, IndexError):
        return None


# TODO(#37): the macOS method for a process start time (and its boot id).
