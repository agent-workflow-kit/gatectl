# gatectl: design

Status: Seeded from awkit architecture v1.4; not yet designed.

## Role and layer

Policy decisions (allow / deny / escalate) with first-class shadow mode. Layer: L1 (primitive). Works fully standalone.

## Responsibilities

From architecture §5.1 (verbatim):

Policy decisions with first-class shadow mode.

- Commands: `check <policy> [--input <file> | --input -] [--timeout <seconds>]`, `outcome <decision-id> agree|disagree`, `decisions --json [--since <time>]`, `stats`, `set <policy> off|shadow|enforced`, `policies`.
- Uses: claude-session (agent checks, headless, kind `gate-check`); ships `plugin/` with its default agent-check skills.
- Notes: `check` reads the input JSON from the file given, or from stdin when `--input` is `-` or absent (exit 2 if absent and stdin is a TTY). It exits 0 allow, 11 deny, 13 escalate, and prints JSON on stdout including `decision_id`, `decision`, `state`, `shadow` and `enforced`. Policy states and shadow mode are described in section 12.3. A policy is a named, ordered list of checks: deterministic scripts (JSON on stdin → exit code/JSON) and agent checks (a Claude skill returning decision + confidence, with a threshold). Combination and miss handling are in section 12.3. Policies declare their expected input; they are global with per-repo overrides keyed off the input's `repo`. Every decision is audited.

## Uses

- claude-session (agent checks, headless, kind `gate-check`): binding TBD (A/B/C), decided in this design session

## Relevant architecture sections

Read these sections of `../awkit-docs/architecture.md` before designing:

- §3.4: cross-cutting principles (hooks, escalation, untrusted text in files)
- §5.5: capability slots (`gate-check`, headless-only, configured in config)
- §6: conventions summary
- §8: Claude session model (how agent checks run via `claude-session exec`)
- §12: autonomy and gates (12.1 defaults, 12.2 escalation, 12.3 gates, 12.4 confirmations)
- §13: security (13.1 review profile for `gate-check`, 13.2 fencing and transport)
- §14: audit (gatectl records every decision, including shadow decisions and outcomes)
- §20: this tool's constraints and open topics
- design guide §11, §12: skill-wrapper pattern (exempt from `--mode`); gate safety rules

## Constraints (decided)

From architecture §20:

- Policy states are `off | shadow | enforced`.
- New policies start in `shadow`.
- Auto-disable returns an enforced policy to `shadow`.
- Agent checks run with kind `gate-check`.

Packaging: The bundled plugin is shipped inside the package and located via `importlib.resources.files('gatectl') / 'plugin'`.

## Open topics

From architecture §20:

- policy file format
- agent check contract
- outcome workflow and recommendation thresholds
- sources of after-the-fact failure signals (e.g. a later revert of an allowed change)

## Decisions

| Decision | Rationale | Date |
|---|---|---|

## Questions for the design session

1. What is the policy file format (checks, order, thresholds, declared input, per-repo overrides keyed off the input's `repo`), and where do policy files live?
2. What is the agent check contract: inputs given to the `gate-check` skill (fenced input JSON), the artifact returned (decision + confidence), and validation?
3. How does the outcome workflow work, and what thresholds make a track record recommend enforcing?
4. Which after-the-fact failure signals (e.g. a later revert of an allowed change) count as misses, where do they come from, and how are they recorded?
