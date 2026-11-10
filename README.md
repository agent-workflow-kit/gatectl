# gatectl

Policy decisions (allow / deny / escalate) with first-class shadow mode.

## Status

Designed: the interface is specified in [docs/interface.md](docs/interface.md) (0.1.0-design) and the decisions are in [docs/design.md](docs/design.md).

## Layer

L1 (primitive). Works fully standalone: a policy of script and rule checks needs nothing else. Agent checks need claude-session.

## What it does

A caller sends a JSON object describing a step (typically a hook payload) and names a policy. gatectl runs the policy's checks, returns `allow`, `deny` or `escalate` with a reason, and records the decision. A policy is a named, ordered list of checks of three kinds: **script** checks (a command that reads the input on stdin and answers with an exit code), **rule** checks (a small declarative test of input fields) and **agent** checks (a Claude session that applies written instructions and returns a decision with a confidence). Script and rule checks always run first, and an agent check can only tighten a decision.

Each policy is `off`, `shadow` or `enforced`, per repo or for all repos. New policies start in `shadow`: everything runs and is recorded, but `check` never blocks, and exit 0 means "do not block", never "authorize". Callers that use a gate to enable an automatic action must require `"enforced": true` and `"decision": "allow"` in the result. A `not_applicable` answer carries `"enforced": false` and never satisfies that rule. People or tools then record whether each decision was right (`outcome agree|disagree`), which builds per-policy, per-repo track records that recommend when enforcing is safe. A wrong `allow` on an enforced policy returns that repo to `shadow` automatically. Every decision is audited.

## Quick start

```text
gatectl validate
echo '{"repo": "github.com/org/repo", "head_sha": "0123abcd"}' | gatectl check auto-merge
gatectl outcome <decision-id> agree
gatectl stats
gatectl set auto-merge enforced --repo github.com/org/repo
```

## Commands

```text
gatectl check <policy> [--input <file> | --input -] [--timeout <seconds>] [--repo <id>] [--no-cache] [--dry-run] [--actor A]
gatectl outcome <decision-id> agree|disagree [--signal S] [--reason-file F|-]
gatectl decisions [--since T] [--policy P] [--repo R] [--object-id X] [--outcome pending|agree|disagree] [--decision allow|deny|escalate] [--declared key=value] [--limit N]
gatectl show <decision-id>
gatectl stats [--policy P] [--repo R] [--since T]
gatectl set <policy> off|shadow|enforced [--repo ID] [--all] [--reason-file F]
gatectl policies [--repo ID]
gatectl validate [--probe]
gatectl export [--log] [--since T]
gatectl reconcile [--dry-run]
gatectl prune [--older-than D] [--dry-run]
gatectl cron install|uninstall [--dry-run]
```

`check` prints one JSON object on stdout. Exit codes: 0 allow (or any result in `shadow` or `off`), 11 deny, 13 escalate, 12 operation failed (`validate --probe`), 20 refused, 21 ambiguous id, 1 internal error, 2 usage error. Setting `enforced` is a human action; `gatectl set <policy> off --all` is the kill switch, and `shadow` and `off` disable veto gates, so watch `post-state-change`. The full rules are in [docs/interface.md](docs/interface.md#commands).

## Using it as a hook

A policy is wired as a `pre-` hook of another tool. Give the hook a timeout at least 30 s above `gatectl check`'s `--timeout`, so a slow check escalates instead of being killed and counted as a veto:

```yaml
hooks:
  pre-merge:
    - cmd: "gatectl check auto-merge --timeout 540"
      timeout: 600
```

A claude-session `pre-launch` hook that calls gatectl must set `exclude_kinds: [gate-check]`, or gatectl's own agent checks recurse until the hook times out; a `post-state-change` entry that notifies should exclude `gate-check` too.

### Wiring checklist

1. The caller's hook `timeout` must be at least 30 s above gatectl's `--timeout`: a check can end up to 30 s after its deadline when an agent run hangs (see Deadline, Bounds in the interface). The default hook timeout is 30 s and the default deadline is 60 s, so a hook wired without both is killed and counted as a veto even in shadow.
2. Set `exclude_kinds: [gate-check]` as above. A policy can also exclude the case itself: `applies_when: [{path: launch_kind, op: ne, value: gate-check}]` on a claude-session `pre-launch` policy. There is no negated glob; to exclude by label use a script check.
3. A jobsctl `pre-start` gate holds the job's slot while it runs.
4. The hook lists of forgectl, pr-comment, wtctl and termctl have no selectors, so a policy wired there sees every action of that hook point. Give the policy an `applies_when` that selects the actions it guards, so other actions answer `allow` with reason `not_applicable` and nothing is run or recorded. forgectl and pr-comment report an approving review as `action: review` with `event: approve`, and the separate `approve` command as `action: approve`, so a policy that gates approvals uses `applies_when: [{path: action, op: in, value: [review, approve]}]` and still sees every review. `event` is null for every action except a review, so a condition on it must start with `{path: event, op: ne, value: null}`; without that guard it errors and counts as applicable. `applies_when` is a scoping filter, never a detector: test only fields the caller derives from a trusted source, never text an attacker writes (a `glob` on a command line is skipped by a payload that does not match), and a `not_applicable` answer never authorizes an automatic action.
5. jobsctl and termctl payloads carry no repo, so their decisions are scoped `*` and `input: {require: [repo]}` would escalate every call.
6. A gate wired as a hook files no outcomes. A human files `agree` (a tool that relays a human's own action passes `--actor human:<name>`); automation can file `disagree` (`--signal revert`, `--signal incident`), and its `agree` is recorded but never counts. A gate that only automation operates (auto-merge) therefore builds a record only when a human files outcomes, for example from `gatectl decisions --outcome pending --json` at a TTY.
7. `shadow` and `off` remove a veto: wire `post-state-change` to a notification. Before removing a policy from the config run `gatectl set <policy> shadow --all`: its rows outlive it, and re-adding the name resumes them (with a `definition_changed` warning if the definition differs). `validate` reports `orphan_state` for such a policy.
8. Trying a policy: every real `check` is recorded, so iterate with a scratch policy name that stays `off` or `shadow` and ignore its pending decisions (they never count); `check --dry-run` validates without running.
9. A syntax error in the shared part of the config or an invalid definition of the wired policy makes `check` exit 2, a veto for a hook caller even in shadow. Run `gatectl validate` before saving; `set <policy> off --all`, `outcome` and the read-only commands keep working while the file parses.
10. A policy called by a harness rule should put `object_type` and `object_id` in its input (and list volatile fields in `input.ignore`), so polling one object counts as one case.

### Binding an action to a decision

A decision id only references a recorded decision. A caller that must prove which revision a gate evaluated compares the declared field in `gatectl show <id> --json` with the revision it acts on; pr-comment's `--decision-id` guard is a presence check. List the revision key in the policy's `input.require` so it is a declared field. `input_sha256` is reproducible: see Input hash in the interface for the serializer and test vectors.

## Configuration

`~/.config/gatectl/config.yaml` plus `config.d/*.yaml`; see [config.example.yaml](config.example.yaml) for every key with its default. Policies are defined inline under `policies:`, with per-repo overrides under `repos.<id>.policies.<name>`. The runtime state of a policy lives in gatectl's state directory, not in the config.

## Dependencies

| Tool | Binding | Needed for | Install |
|---|---|---|---|
| claude-session | B (configurable command, `session_cmd`) | agent checks only | `uv tool install git+https://github.com/agent-workflow-kit/claude-session` |

Agent checks also need Claude Code and, because they run in claude-session's required sandbox, `bubblewrap` and `socat` on Linux and WSL2 (Seatbelt on macOS). Install claude-session with `UV_LINK_MODE=copy`. gatectl finds `claude-session` in `~/.local/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/usr/bin` and `/bin`; a tool installed elsewhere needs an absolute `session_cmd`. `reconcile` is safe on an install without claude-session: it skips the session sweep. If an agent check cannot find `claude-session`, the decision is `escalate` with an install hint, never `allow`.

## Environment variables

These config keys can be set as `GATECTL_<KEY>`, nested keys joined with `__` (`GATECTL_DEFAULTS__TIMEOUT`): `defaults.timeout`, `defaults.script_timeout`, `defaults.record_reserve`, `agent.timeout`, `agent.cache_ttl`, `agent.max_parallel`, `agent.min_start_budget`, `retention.older_than`. Safety keys (`agent.sandbox`, `agent.permission_profile`, `agent.setting_sources`, `agent.env_allowlist`, `agent.threshold`, `agent.model`, `agent.input_max_bytes`, `defaults.input_max_bytes`), lists and structured config cannot be set from the environment. gatectl reads no credentials.

## Install

```text
uv tool install git+https://github.com/agent-workflow-kit/gatectl
```

## Documentation

- [Interface](docs/interface.md) and [design](docs/design.md)
- [awkit architecture](../awkit-docs/architecture.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/architecture.md))
- [awkit design guide](../awkit-docs/design-guide.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/design-guide.md))

## License

MIT, see LICENSE.
