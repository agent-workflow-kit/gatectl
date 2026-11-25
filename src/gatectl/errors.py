"""Errors that carry an exit code (interface.md, Exit codes).

Messages are fixed text naming the kind of problem. They never include the offending value:
every error ``message`` is untrusted-text-safe by construction (interface.md, Untrusted text).
"""

from __future__ import annotations


class GatectlError(Exception):
    """Base class: a failure with a documented exit code."""

    exit_code = 1


class UsageError(GatectlError):
    """Bad flags or values (exit 2)."""

    exit_code = 2


class NotFoundError(GatectlError):
    """A decision id that does not exist (exit 10)."""

    exit_code = 10


class AmbiguousError(GatectlError):
    """A decision-id prefix that matches more than one decision (exit 21)."""

    exit_code = 21
