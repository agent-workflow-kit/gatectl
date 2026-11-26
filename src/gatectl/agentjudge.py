"""Judging an agent run (interface.md, Agent checks: Artifact, Using the artifact, Outcome
handling). This is the only place that can turn a model's output into an ``allow``.

The run sequence (``agent.py``, issue #24) ends with raw facts about a run: the exit code of
``exec``, the outcome object it printed, the ``status`` object and the run's nonce. Turning
those into a verdict (the outcome table, reading and validating the artifact, the confidence
threshold) is judging, and it is the only place that can produce an ``allow`` for a run.

What is here:

* ``Judgement`` is the closed result. An ``allow`` can only be built from a ``Verdict`` (the
  strictly validated artifact type of ``agentcache``), so nothing unvalidated can allow.
* ``judge`` applies the outcome table by ``exec``'s exit code (the authority: the printed outcome
  never overrides it). Exit 0 is usable only with outcome ``done``, an explicit report (not
  ``implicit``), a ``status`` that agrees, and an artifact that is read and validated here:
  ``read_artifact`` (the frozen path ``status`` reports, no link followed at any component, a
  regular file, at most 16 KiB, opened once and checked with ``fstat`` before and after the read,
  size and SHA-256 equal to ``status``) and ``parse_artifact`` (strict JSON, exactly the five
  keys, the run's nonce compared in constant time). Anything else escalates and never allows.
* ``from_verdict`` is the threshold rule and the ``detail`` rule, used for a fresh verdict and
  for a cache hit alike. An ``allow`` below the threshold becomes ``low_confidence``; a ``deny``
  or ``escalate`` is never loosened.
* ``start_failed`` maps a failed ``start`` (and the adoption failures of ``exec``, exit 12).

Only a valid artifact of a ``done`` run is ``cacheable``; no failure is. The cache write itself
is the engine's, after the decision is recorded. Detail text of every non-artifact row is fixed
text: nothing the session printed is echoed except the sanitized, capped ``reasons`` of a valid
artifact.

Nothing in a ``RawRun`` is trusted: it is what claude-session printed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from gatectl import agentcache
from gatectl.sanitize import MARKER, sanitize

DETAIL_CAP = 1024
ARTIFACT_NAME = "verdict.json"
ARTIFACT_MAX = 16 * 1024
_PATH_MAX = 4096
_SHA = re.compile(r"[0-9a-f]{64}", re.ASCII)
_REFUSAL_TOKENS = frozenset({"unsafe_setting_sources", "sandbox_unavailable", "claude_not_found"})
_KEYS = frozenset({"schema_version", "nonce", "decision", "confidence", "reasons"})

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
    # The run number ``start`` returned: the run both ``exec`` and ``status`` must describe.
    run: int = 0


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
        if self.verdict == "allow":
            validated = self.validated
            confidence = self.confidence
            if (
                not isinstance(validated, agentcache.Verdict)
                or validated.decision != "allow"
                or self.reason is not None
                or confidence is None
                or type(confidence) not in (int, float)
                or not math.isfinite(confidence)
                or confidence != validated.confidence
            ):
                raise ValueError("an allow needs its own validated allow artifact and no reason")
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
    if (
        type(threshold) not in (int, float)
        or not math.isfinite(threshold)
        or not 0 <= threshold <= 1
    ):
        raise ValueError("threshold must be a number in [0, 1]")
    detail = sanitize("; ".join(verdict.reasons), DETAIL_CAP) or None
    decision = verdict.decision
    if decision == "allow":
        if not verdict.confidence >= threshold:
            return Judgement(
                "escalate", "low_confidence", detail, verdict.confidence, verdict, cacheable
            )
        return Judgement("allow", None, detail, verdict.confidence, verdict, cacheable)
    reason = "check_denied" if decision == "deny" else "check_escalated"
    shown: Verdict = "deny" if decision == "deny" else "escalate"
    return Judgement(shown, reason, detail, verdict.confidence, verdict, cacheable)


class ArtifactError(Exception):
    """The artifact is unusable. ``detail`` is fixed text (never artifact content)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _invalid(detail: str) -> ArtifactError:
    return ArtifactError(detail)


# -- reading ----------------------------------------------------------------------------------


def _open_leaf(path: str) -> int:
    """Open ``path`` read-only, following no link at any component (``OSError`` or
    ``ArtifactError`` otherwise). The leaf is opened non-blocking, so a FIFO cannot hang us."""
    if not path.startswith("/") or "\0" in path or len(path) > _PATH_MAX:
        raise _invalid("artifact path unusable")
    parts = path.split("/")[1:]
    if not parts or any(p in ("", ".", "..") for p in parts):
        raise _invalid("artifact path unusable")
    base = os.O_RDONLY | os.O_CLOEXEC
    fd = os.open("/", base | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, base | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return os.open(parts[-1], base | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY, dir_fd=fd)
    finally:
        os.close(fd)


def _same(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (
        b.st_dev,
        b.st_ino,
        b.st_size,
        b.st_mtime_ns,
        b.st_ctime_ns,
    )


def read_artifact(entry: Mapping[str, Any]) -> bytes:
    """The bytes of the frozen artifact ``status`` describes, or ``ArtifactError``.

    ``entry`` is ``status``'s ``artifact`` object (untrusted): the name must be ``verdict.json``,
    the size an int within the 16 KiB cap and the SHA-256 64 lowercase hex characters. The file
    is opened once; what is read is bounded by the stated size plus one byte, must be exactly
    that size, must hash to the stated SHA-256, and the file must not have changed (device,
    inode, size, mtime and ctime) between the ``fstat`` before the read and the one after.
    """
    name, path, sha, size = (entry.get(k) for k in ("name", "path", "sha256", "size"))
    if not isinstance(name, str) or name != ARTIFACT_NAME:
        raise _invalid("artifact name is not verdict.json")
    if not isinstance(path, str):
        raise _invalid("artifact path unusable")
    if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
        raise _invalid("artifact sha256 unusable")
    if type(size) is not int or not 0 <= size <= ARTIFACT_MAX:
        raise _invalid("artifact size unusable or over 16 KiB")
    try:
        fd = _open_leaf(path)
    except (OSError, ValueError):  # ValueError: UnicodeEncodeError, an embedded NUL
        raise _invalid("artifact not readable") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise _invalid("artifact is not a regular file")
        if before.st_size != size:
            raise _invalid("artifact size differs from status")
        chunks: list[bytes] = []
        total = 0
        while total <= size:
            chunk = os.read(fd, min(8192, size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(fd)
    except OSError:
        raise _invalid("artifact not readable") from None
    finally:
        os.close(fd)
    if total != size or not _same(before, after):
        raise _invalid("artifact changed while it was read")
    data = b"".join(chunks)
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest().encode(), sha.encode()):
        raise _invalid("artifact sha256 differs from status")
    return data


# -- validating -------------------------------------------------------------------------------


def _no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constant(_: str) -> Any:
    raise ValueError("not JSON")


def parse_artifact(data: bytes, nonce: str) -> agentcache.Verdict:
    """The validated artifact fields, or ``ArtifactError``.

    Strict JSON (UTF-8, no BOM, no duplicate key, no NaN or Infinity, at most 16 KiB), a JSON
    object with exactly ``schema_version`` (the int 1), ``nonce`` (equal to ``nonce``, compared
    in constant time), ``decision`` (allow, deny or escalate), ``confidence`` (an int or float in
    [0, 1], not a bool) and ``reasons`` (a list of at most 10 strings of at most 500 characters).
    ``reasons`` are sanitized (the one-for-one replacement of ``sanitize``) before they are kept,
    and a model-echoed ``nonce`` in one is replaced by the marker.
    """
    if type(data) is not bytes:
        raise _invalid("artifact is not bytes")
    if not isinstance(nonce, str) or not nonce or not nonce.isascii():
        raise _invalid("no usable nonce")
    if len(data) > ARTIFACT_MAX:
        raise _invalid("artifact over 16 KiB")
    try:
        doc = json.loads(
            data.decode("utf-8"), object_pairs_hook=_no_dups, parse_constant=_no_constant
        )
    except (ValueError, RecursionError):  # includes UnicodeDecodeError and JSONDecodeError
        raise _invalid("artifact is not strict JSON") from None
    if not isinstance(doc, dict) or set(doc) != _KEYS:
        raise _invalid("artifact keys are not exactly the schema's")
    version = doc["schema_version"]
    if type(version) is not int or version != 1:
        raise _invalid("artifact schema_version is not 1")
    seen = doc["nonce"]
    if (
        not isinstance(seen, str)
        or not seen.isascii()
        or not hmac.compare_digest(seen.encode("ascii"), nonce.encode("ascii"))
    ):
        raise _invalid("artifact nonce does not match")
    reasons = doc["reasons"]
    if not (
        isinstance(reasons, list)
        and len(reasons) <= agentcache.MAX_REASONS
        and all(isinstance(r, str) and len(r) <= agentcache.MAX_REASON_CHARS for r in reasons)
    ):  # measured before sanitize, which would cut an over-long reason to fit
        raise _invalid("artifact reasons are not at most 10 strings of 500 characters")
    try:
        confidence = doc["confidence"]
        return agentcache.Verdict(
            doc["decision"],
            float(confidence) if type(confidence) in (int, float) else confidence,
            tuple(sanitize(r.replace(nonce, MARKER), agentcache.MAX_REASON_CHARS) for r in reasons),
        )
    except (ValueError, TypeError, OverflowError):
        raise _invalid("artifact decision, confidence or reasons invalid") from None


# -- the outcome table ------------------------------------------------------------------------

_DETAIL_BY_EXIT = {
    13: "the agent reported blocked or needs input",
    14: "the agent ended without reporting",
    16: "the agent run timed out",
}


def _int(value: object) -> bool:
    return type(value) is int


def _usable_run(outcome: object, status: object, launched: object) -> Mapping[str, Any]:
    """Check an exit-0 run's ``exec`` outcome and ``status`` agree that it is an explicit,
    done report with an artifact; return ``status``'s artifact object, or raise."""
    if not isinstance(outcome, Mapping):
        raise _invalid("no usable outcome")
    if outcome.get("outcome") != "done" or not (
        _int(outcome.get("exit_code")) and outcome["exit_code"] == 0
    ):
        raise _invalid("the run did not end done")
    out_report = outcome.get("report")
    if not isinstance(out_report, Mapping) or out_report.get("status") != "done":
        raise _invalid("the run has no done report")
    if out_report.get("implicit") is not False:
        raise _invalid("the done report is implicit")
    out_art = out_report.get("artifact")
    if not isinstance(out_art, Mapping):
        raise _invalid("the done report has no artifact")
    if not isinstance(status, Mapping):
        raise _NoStatus
    run = status.get("run")
    if not isinstance(run, Mapping):
        raise _invalid("status has no run")
    if run.get("outcome") != "done" or not (_int(run.get("exit_code")) and run["exit_code"] == 0):
        raise _invalid("status does not report a done run")
    if not (
        _int(run.get("run"))
        and _int(outcome.get("run"))
        and _int(launched)
        and run["run"] == outcome["run"] == launched
    ):
        raise _invalid("status describes another run")
    rep = run.get("report")
    if (
        not isinstance(rep, Mapping)
        or rep.get("status") != "done"
        or rep.get("implicit") is not False
    ):
        raise _invalid("status has no explicit done report")
    art = rep.get("artifact")
    if not isinstance(art, Mapping):
        raise _invalid("status reports no artifact")
    for key in ("name", "sha256", "size"):
        if out_art.get(key) != art.get(key) or type(out_art.get(key)) is not type(art.get(key)):
            raise _invalid("outcome and status disagree on the artifact")
    return art


class _NoStatus(Exception):
    pass


def _exec_failed(code: int, outcome: Mapping[str, Any] | None) -> Judgement:
    if code in _DETAIL_BY_EXIT:
        reason = {13: "check_escalated", 14: "agent_unreported", 16: "timeout"}[code]
        return escalate(reason, _DETAIL_BY_EXIT[code])
    end = outcome.get("end_reason") if isinstance(outcome, Mapping) else None
    if code == 12:
        return start_failed(12, end if isinstance(end, str) else None)
    return escalate(
        "check_error", f"agent run failed (exit {code})" if 0 <= code < 1000 else "agent run failed"
    )


def judge(raw: RawRun, *, threshold: float) -> Judgement:
    """The check's verdict for one finished run (see the module text). Never raises for what the
    session printed: an artifact problem is ``artifact_invalid``; the engine still wraps an
    unexpected exception into ``check_error``."""
    code = raw.exec_code
    if not _int(code):
        return escalate("check_error", "agent run failed")
    if code != 0:
        return _exec_failed(code, raw.outcome)
    try:
        art = _usable_run(raw.outcome, raw.status, raw.run)
        verdict = parse_artifact(read_artifact(art), raw.nonce)
    except _NoStatus:
        return escalate("check_error", "status unusable")
    except ArtifactError as error:
        return escalate("artifact_invalid", error.detail)
    return from_verdict(verdict, threshold, cacheable=True)


def start_failed(exit_code: int | None, end_reason: str | None) -> Judgement:
    """A ``start`` (or an adopting ``exec``) that exited 12 is mapped by its end reason:
    ``sandbox_unavailable``, ``claude_not_found`` (``tool_missing``); every other end reason,
    ``unsafe_setting_sources`` included, and every other exit is ``check_error``."""
    if _int(exit_code) and exit_code == 12:
        if end_reason == "sandbox_unavailable":
            return escalate("sandbox_unavailable", "the sandbox is unavailable")
        if end_reason == "claude_not_found":
            return escalate("tool_missing", "claude not found")
        if isinstance(end_reason, str) and end_reason in _REFUSAL_TOKENS:
            return escalate("check_error", f"launch refused: {end_reason}")
        return escalate("check_error", "launch refused")
    return escalate("check_error", "start failed")
