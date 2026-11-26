"""``validate --probe``: one real agent run on a built-in input (interface.md, Agent checks: Probe).

The probe is the one place where ``validate`` runs a process, and only when asked: it costs one
run. It goes through the same code as a ``check`` (``agent.find_plugin_dirs``, the slot, the
private ``tmp/<id>/``, ``agent.run_session`` and the strict judge), so it proves the real
configuration end to end: the sandbox, the skill, the plugin and a validated artifact.

It records no decision, no audit line and no cache row. Its only write is the pair of ``meta``
markers ``probe_ok_at`` and ``probe_agent_hash`` after a pass; a failed probe removes any earlier
pair, so the ``set ... enforced`` hint comes back (fail closed). The hash is
``agenthash.agent_config_hash`` of the configuration the probe actually ran with.

The probe covers the ``agent:`` block's settings only; a check that sets its own ``sandbox``,
``skill``, ``permission_profile``, ``setting_sources``, ``env_allowlist`` or ``model`` is an
accepted gap (``validate`` still checks those values).

Every text in a ``ProbeResult`` is fixed: nothing claude-session printed, no model text (not even
the artifact's ``reasons``) and no config value is echoed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from gatectl import (
    agent,
    agentfiles,
    agenthash,
    audit,
    clock,
    fingerprint,
    ids,
    slots,
    tmptree,
)
from gatectl import store as store_mod
from gatectl.config import LoadedConfig
from gatectl.config_models import AgentCheck
from gatectl.engine import Env
from gatectl.sanitize import sanitize

POLICY_LABEL = "probe"
CHECK_NAME = "probe"
INPUT: dict[str, Any] = {"probe": "gatectl validate --probe", "expected_decision": "allow"}
INSTRUCTION = (
    "This is a self-test of the gatectl agent path, not a real policy decision. "
    "The input is a fixed object that asks for the decision allow. "
    "Decide allow with confidence 1 and the single reason \"probe\"."
)
FAILED_CAP = 2048
_ALLOWED_LOOK = {
    "check_denied": "the agent denied the probe input",
    "check_escalated": "the agent escalated the probe input",
    "low_confidence": "the agent's allow was below the threshold",
}


@dataclass(frozen=True)
class ProbeResult:
    exit_code: int | None
    end_reason: str | None
    sandbox_active: bool | None
    ok: bool
    failed: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "end_reason": self.end_reason,
            "sandbox_active": self.sandbox_active,
            "ok": self.ok,
            "failed": self.failed,
        }


def _fail(
    reason: str,
    detail: str,
    *,
    exit_code: int | None = None,
    end_reason: str | None = None,
    sandbox_active: bool | None = None,
) -> ProbeResult:
    text = sanitize(f"{reason}: {detail}", FAILED_CAP)
    return ProbeResult(exit_code, end_reason, sandbox_active, False, text)


def _store_marker(store: store_mod.Store, config_hash: str) -> None:
    stamp = clock.now_ts()

    def body() -> None:
        for key, value in (("probe_ok_at", stamp), ("probe_agent_hash", config_hash)):
            store.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    store.transact(body)


def _clear_marker(store: store_mod.Store) -> None:
    try:
        store.transact(
            lambda: store.execute(
                "DELETE FROM meta WHERE key IN ('probe_ok_at', 'probe_agent_hash')"
            )
        )
    except Exception:  # noqa: S110 - a marker that cannot be cleared never hides the failure
        pass


def run_probe(loaded: LoadedConfig, env: Env) -> ProbeResult:
    """Run the probe for a valid config. Never raises for a failure of the run (the store's own
    refusals, such as a newer schema, are the ``InternalError`` every command has)."""
    shared = loaded.shared
    bundled = fingerprint.bundled_plugin_dir()
    check = AgentCheck(name=CHECK_NAME, type="agent", instruction=INSTRUCTION)
    cfg = agent.resolve_settings(check, shared, None, bundled)
    try:
        plugin_dirs = agent.find_plugin_dirs(cfg.skill, shared.agent.plugin_dirs, bundled)
    except agent.ToolMissing:
        return _fail("tool_missing", "the plugin or skill was not found")
    session_cmd = loaded.session_cmd_resolved()
    if session_cmd is None:
        return _fail("tool_missing", "session_cmd was not found")
    digest = hashlib.sha256(INSTRUCTION.encode("utf-8")).hexdigest()
    try:
        prepared = agentfiles.prepare(
            INPUT,
            agentfiles.Instruction(INSTRUCTION, digest),
            input_max_bytes=cfg.input_max_bytes,
        )
    except agentfiles.AgentFilesError as error:
        return _fail(error.reason, error.detail)
    config_hash = agenthash.agent_config_hash(shared, session_cmd)

    deadline = env.monotonic() + cfg.timeout + agent.LAUNCH_OVERHEAD

    def window() -> float:
        return deadline - env.monotonic() - agent.LAUNCH_OVERHEAD

    store = store_mod.open_store(create=True)
    assert store is not None
    with store:
        result = _run(loaded, env, store, cfg, prepared, plugin_dirs, session_cmd, window)
        if not result.ok:
            _clear_marker(store)
            return result
        try:
            _store_marker(store, config_hash)
        except Exception:  # fixed text; the cause is never echoed
            _clear_marker(store)
            return _fail(
                "marker_unwritable",
                "the probe passed but its marker could not be stored",
                exit_code=result.exit_code,
                end_reason=result.end_reason,
                sandbox_active=result.sandbox_active,
            )
    return result


def _run(
    loaded: LoadedConfig,
    env: Env,
    store: store_mod.Store,
    cfg: agent.Settings,
    prepared: agentfiles.PreparedFiles,
    plugin_dirs: tuple[str, ...],
    session_cmd: list[str],
    window: Any,
) -> ProbeResult:
    decision_id = ids.new_decision_id()
    if window() < cfg.min_start_budget:
        return _fail("budget_exhausted", "not enough time to start the probe")
    try:
        slot = slots.wait_for_slot(
            store,
            decision_id=decision_id,
            max_parallel=cfg.max_parallel,
            expires_at=datetime.now(UTC) + timedelta(seconds=cfg.timeout + 65.0),
            launch_window=window,
            min_start_budget=cfg.min_start_budget,
            monotonic=env.monotonic,
        )
    except Exception:
        return _fail("check_error", "agent slot unavailable")
    if slot is None:
        return _fail("busy", "no agent slot became free")
    state = audit.state_dir()
    with slots.held(store, slot):
        if window() < cfg.min_start_budget:
            return _fail("budget_exhausted", "not enough time to start the probe")
        try:
            return _launch(
                loaded, env, store, slot, cfg, prepared, plugin_dirs, session_cmd, window,
                decision_id,
            )  # fmt: skip
        finally:
            try:
                tmptree.remove_tree(state / "tmp" / decision_id)
            except Exception:  # noqa: S110 - what stays is reconcile's
                pass


def _launch(
    loaded: LoadedConfig,
    env: Env,
    store: store_mod.Store,
    slot: slots.Slot,
    cfg: agent.Settings,
    prepared: agentfiles.PreparedFiles,
    plugin_dirs: tuple[str, ...],
    session_cmd: list[str],
    window: Any,
    decision_id: str,
) -> ProbeResult:
    state = audit.state_dir()
    try:
        decision_dir = tmptree.create_decision_dir(state, decision_id)
        files = prepared.write(decision_dir)
    except (tmptree.UnsafeTree, OSError, ValueError):
        return _fail("check_error", "agent files could not be written")
    try:
        launch = agent.Launch(
            session_cmd=tuple(session_cmd),
            skill=cfg.skill,
            prompt_file=str(files.prompt_path),
            input_file=str(files.input_path),
            outcome_file=str(decision_dir / agent.OUTCOME_NAME),
            plugin_dirs=plugin_dirs,
            timeout_s=agent.launch_seconds(cfg.timeout, window()),
            policy=POLICY_LABEL,
            decision_id=decision_id,
            state_tag=agent.state_tag(state),
            permission_profile=cfg.permission_profile,
            sandbox=cfg.sandbox,
            setting_sources=cfg.setting_sources,
            env_allowlist=cfg.env_allowlist,
            model=cfg.model,
        )
        # TODO(#35): pass a ``cancel`` that turns true on SIGTERM, SIGINT and SIGHUP.
        try:
            session = agent.run_session(
                env.gateway,
                launch,
                nonce=files.nonce,
                threshold=cfg.threshold,
                environ=env.environ,
                limits=env.limits,
                store=store,
                slot=slot,
                monotonic=env.monotonic,
            )
        except Exception:  # a bug is a failed probe, never a pass
            return _fail("check_error", "agent run failed")
    finally:
        for cleanup in (
            files.delete,
            lambda: tmptree.remove_private_files(files.directory, [agent.OUTCOME_NAME]),
        ):
            try:
                cleanup()
            except Exception:  # noqa: S110 - the whole directory is removed next
                pass
    return _judge(session, cfg)


def _judge(session: agent.SessionResult, cfg: agent.Settings) -> ProbeResult:
    facts: dict[str, Any] = {
        "exit_code": session.exit_code,
        "end_reason": session.end_reason,
        "sandbox_active": session.sandbox_active,
    }
    j = session.judgement
    if j.verdict != "allow":
        reason = j.reason or "check_error"
        # A validated artifact's detail is the model's text: never shown, a fixed line instead.
        detail = _ALLOWED_LOOK.get(reason) if j.validated is not None else j.detail
        return _fail(reason, detail or "the probe did not pass", **facts)
    if cfg.sandbox == "required" and session.sandbox_active is not True:
        return _fail("sandbox_inactive", "the sandbox was required but is not active", **facts)
    return ProbeResult(session.exit_code, session.end_reason, session.sandbox_active, True, None)
