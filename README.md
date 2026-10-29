# gatectl

Policy decisions (allow / deny / escalate) with first-class shadow mode.

## Status

Pre-design: interface not yet specified; see [docs/design.md](docs/design.md).

## Layer

L1 (primitive). Works fully standalone.

## What it does

A policy is a named, ordered list of checks: deterministic scripts (JSON on stdin → exit code/JSON) and agent checks (a Claude skill returning decision + confidence, with a threshold). `check` reads input JSON from a file or stdin, exits 0 allow, 11 deny, 13 escalate, and prints JSON with `decision_id`, `decision`, `state`, `shadow` and `enforced`. Policies are `off`, `shadow` or `enforced`; new policies start in shadow, where exit 0 means "do not block", never "authorize". Outcome feedback builds per-policy, per-repo track records that recommend enforcing; a miss returns an enforced policy to shadow. Every decision is audited.

## Indicative commands

Indicative, finalized in [docs/interface.md](docs/interface.md):

```text
gatectl check <policy> [--input <file> | --input -] [--timeout <seconds>]
gatectl outcome <decision-id> agree|disagree
gatectl decisions --json [--since <time>]
gatectl stats
gatectl set <policy> off|shadow|enforced
gatectl policies
```

## Dependencies

- claude-session (agent checks, headless, kind `gate-check`): binding: TBD (A/B/C), decided in this tool's design session

## Install

```text
uv tool install git+https://github.com/agent-workflow-kit/gatectl
```

## Documentation

- [awkit architecture](../awkit-docs/architecture.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/architecture.md))
- [awkit design guide](../awkit-docs/design-guide.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/design-guide.md))

## License

MIT — see LICENSE.
