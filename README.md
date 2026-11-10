# gatectl

Policy decisions (allow / deny / escalate) with first-class shadow mode.

## Status

Designed: the interface is specified in [docs/interface.md](docs/interface.md) (0.1.0-design) and the decisions are in [docs/design.md](docs/design.md). Implementation follows [docs/plan.md](docs/plan.md).

## Layer

L1 (primitive). Works fully standalone: a policy of script and rule checks needs nothing else. Agent checks need claude-session.

## What it does

A caller sends a JSON object describing a step (typically a hook payload) and names a policy. gatectl runs the policy's checks, returns `allow`, `deny` or `escalate` with a reason, and records the decision. A policy is a named, ordered list of checks of three kinds: **script** checks (a command that reads the input on stdin and answers with an exit code), **rule** checks (a small declarative test of input fields) and **agent** checks (a Claude session that applies written instructions and returns a decision with a confidence). Script and rule checks always run first, and an agent check can only tighten a decision.

Each policy is `off`, `shadow` or `enforced`, per repo or for all repos. New policies start in `shadow`: everything runs and is recorded, but `check` never blocks, and exit 0 means "do not block", never "authorize". Callers that use a gate to enable an automatic action must require `"enforced": true` and `"decision": "allow"` in the result. People or tools then record whether each decision was right (`outcome agree|disagree`), which builds per-policy, per-repo track records that recommend when enforcing is safe. A wrong `allow` on an enforced policy returns that repo to `shadow` automatically. Every decision is audited.

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
gatectl check <policy> [--input <file> | --input -] [--timeout <seconds>] [--repo <id>] [--no-cache] [--dry-run]
gatectl outcome <decision-id> agree|disagree [--signal <name>] [--reason-file <file>]
gatectl decisions [--since <time>] [--policy <p>] [--repo <id>] [--object-id <x>] [--outcome pending|agree|disagree]
gatectl show <decision-id>
gatectl stats [--policy <p>] [--repo <id>] [--since <time>]
gatectl set <policy> off|shadow|enforced [--repo <id>]
gatectl policies [--repo <id>]
gatectl validate [--probe]
gatectl export [--log] [--since <time>]
gatectl reconcile
gatectl prune [--older-than <duration>]
gatectl cron install|uninstall
```

`check` prints one JSON object on stdout. Exit codes: 0 allow (or any result in `shadow` or `off`), 11 deny, 13 escalate, 1 internal error, 2 usage error. Setting `enforced` is a human action. The full rules are in [docs/interface.md](docs/interface.md).

## Using it as a hook

A policy is wired as a `pre-` hook of another tool. Give the hook a long timeout and `gatectl check` a shorter `--timeout`, so a slow check escalates instead of being killed and counted as a veto:

```yaml
hooks:
  pre-merge:
    - cmd: "gatectl check auto-merge --timeout 540"
      timeout: 600
```

A hook that launches claude-session sessions must set `exclude_kinds: [gate-check]`, or gatectl's own agent checks recurse.

## Configuration

`~/.config/gatectl/config.yaml` plus `config.d/*.yaml`; see [config.example.yaml](config.example.yaml) for every key with its default. Policies are defined inline under `policies:`, with per-repo overrides under `repos.<id>.policies.<name>`. The runtime state of a policy lives in gatectl's state directory, not in the config.

## Dependencies

| Tool | Binding | Needed for | Install |
|---|---|---|---|
| claude-session | B (configurable command, `session_cmd`) | agent checks only | `uv tool install git+https://github.com/agent-workflow-kit/claude-session` |

Agent checks also need Claude Code and, because they run in claude-session's required sandbox, `bubblewrap` and `socat` on Linux and WSL2 (Seatbelt on macOS). Install claude-session with `UV_LINK_MODE=copy`. If an agent check cannot find `claude-session`, the decision is `escalate` with an install hint, never `allow`.

## Environment variables

Top-level scalar config keys can be set as `GATECTL_<KEY>` (`GATECTL_DEFAULTS__TIMEOUT`). gatectl reads no credentials.

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
