"""The judging seam of an agent check (issue #25 owns the body of ``judge``).

The run sequence (``agent.py``, issue #24) ends with raw facts about a run: the exit code of
``exec``, the outcome object it printed, the ``status`` object and the run's nonce. Turning
those into a verdict (the outcome table, reading and validating the artifact, the confidence
threshold) is judging, and it is the only place that can produce an ``allow`` for a run.

What is here, and what is not:

* ``Judgement`` is the closed result. An ``allow`` can only be built from a ``Verdict`` (the
  strictly validated artifact type of ``agentcache``), so nothing unvalidated can allow.
* ``from_verdict`` is the threshold rule and the ``detail`` rule, used for a fresh verdict and
  for a cache hit alike.
* ``judge`` and ``start_failed`` are STUBS. TODO(#25): implement the outcome table, read the
  artifact from the frozen path ``status`` reports (at most 16 KiB, no links, name, size and
  SHA-256 against ``status``), validate it strictly against ``raw.nonce`` and return
  ``from_verdict`` of the validated fields; until then every completed run escalates
  ``check_error``, so an agent check can never allow.

Nothing in a ``RawRun`` is trusted: it is what claude-session printed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from gatectl import agentcache
from gatectl.sanitize import sanitize

DETAIL_CAP = 1024
NOT_VALIDATED = "agent verdict not validated"

Verdict = Literal["allow", "deny", "escalate"]


@dataclass(frozen=True)
class RawRun:
    """The facts of one finished run, as claude-session reported them (untrusted).

    ``outcome`` is the parsed object ``exec`` printed (``None`` when it printed nothing usable);
    ``status`` is the parsed ``status --json`` object (``None`` when ``status`` was not asked or
    gave nothing usable: it is only asked after an ``exec`` that exited 0). ``nonce`` is the
    run's secret: it never leaves this object (not in ``repr``).
    """

    exec_code: int
    outcome: Mapping[str, Any] | None
    status: Mapping[str, Any] | None
    nonce: str = field(repr=False)


@dataclass(frozen=True)
class Judgement:
    """A check's verdict. ``validated`` is the artifact an ``allow`` rests on; an ``allow``
    without one cannot be built."""

    verdict: Verdict
    reason: str | None
    detail: str | None
    confidence: float | None = None
    validated: agentcache.Verdict | None = None
    # True only for a valid artifact of a ``done`` run: the one thing the cache may store.
    cacheable: bool = False

    def __post_init__(self) -> None:
        if self.verdict == "allow" and (self.validated is None or self.reason is not None):
            raise ValueError("an allow needs a validated artifact and no reason")
        if self.verdict not in ("allow", "deny", "escalate"):
            raise ValueError("unknown verdict")
        if self.cacheable and self.validated is None:
            raise ValueError("only a validated artifact is cacheable")


def escalate(reason: str, detail: str | None) -> Judgement:
    return Judgement("escalate", reason, detail)


def from_verdict(
    verdict: agentcache.Verdict, threshold: float, *, cacheable: bool = False
) -> Judgement:
    """The check's verdict for a validated artifact (interface.md, Using the artifact).

    The artifact's ``decision`` stands, except that an ``allow`` below ``threshold`` becomes an
    ``escalate`` (``low_confidence``); a ``deny`` or ``escalate`` is never loosened. ``detail``
    is the reasons joined with ``; ``, sanitized and cut to 1024 characters. ``cacheable`` is
    for the caller that holds a valid artifact of a ``done`` run (a cache hit passes False).
    """
    detail = sanitize("; ".join(verdict.reasons), DETAIL_CAP) or None
    decision = verdict.decision
    if decision == "allow":
        if verdict.confidence < threshold:
            return Judgement(
                "escalate", "low_confidence", detail, verdict.confidence, verdict, cacheable
            )
        return Judgement("allow", None, detail, verdict.confidence, verdict, cacheable)
    reason = "check_denied" if decision == "deny" else "check_escalated"
    shown: Verdict = "deny" if decision == "deny" else "escalate"
    return Judgement(shown, reason, detail, verdict.confidence, verdict, cacheable)


def judge(raw: RawRun, *, threshold: float) -> Judgement:
    """STUB (TODO(#25)): every completed run is an escalation, never an allow."""
    del raw, threshold
    return escalate("check_error", NOT_VALIDATED)


def start_failed(exit_code: int | None, end_reason: str | None) -> Judgement:
    """STUB (TODO(#25)): a ``start`` that failed. ``end_reason`` is the closed token of the error
    envelope when it had one. Until the table lands: ``check_error``."""
    del exit_code, end_reason
    return escalate("check_error", "start failed")
