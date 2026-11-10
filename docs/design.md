# gatectl: design

Status: designed, 2026-11-09 (interface 0.1.0-design). [interface.md](interface.md) holds the normative rules; this document records the decisions, the reasoning and the internal structure, and links to the interface headings instead of restating them.

## Role and layer

Policy decisions (allow, deny, escalate) with first-class shadow mode. Layer 1 (primitive). It works fully standalone: a policy made of script and rule checks needs nothing but gatectl. Agent checks need claude-session. It is shareable and runs on Linux, WSL and macOS (architecture C4).

## Uses

| Tool | Binding | What for |
|---|---|---|
| claude-session | B (configurable command, `session_cmd`, default `claude-session`) | agent checks: `exec --kind gate-check --mode headless`, `status`, `stop`, `forget`, and `--dry-run` for the probe |

No other tool of ours is used. gatectl never reads a git host, a ticket system or another tool's `state.db`. Consumers wire it as a `pre-` hook, call it directly, or file late signals with `outcome`; gatectl does not know which (architecture 3.4).

## Decisions

| # | Decision | Where |
|---|---|---|
| D-1 | Policies are defined inline in the config (`policies:` in `config.yaml` or drop-ins); state lives in `state.db`, never in the config | [Policies](interface.md#policies) |
| D-2 | A declared input is a small field list (`require`, `types`); a mismatch escalates with `input_invalid`; a missing `repo` falls back to the global policy | [Input declaration](interface.md#input-declaration) |
| D-3 | Script checks: argv list, allowlisted environment, private cwd, own process group; the exit code decides and anything unexpected escalates | [Script checks](interface.md#script-checks) |
| D-4 | A closed `rule` check type for deterministic field tests; a comparison on a missing or mistyped path escalates instead of being false | [Rule checks](interface.md#rule-checks) |
| D-5 | Agent checks use one bundled skill `gatectl:gate-check`, a nonce-fenced `input.json`, a nonce-echoing `verdict.json` artifact, strict validation and a one-way confidence threshold | [Agent checks](interface.md#agent-checks) |
| D-6 | Agent results are reused for an identical input within a TTL; script and rule checks always run | [Agent checks](interface.md#agent-checks) |
| D-7 | At most three agent runs are live at once across processes, through leases in `state.db` | [Agent checks](interface.md#agent-checks) |
| D-8 | One deadline per `check`, checks capped by their own timeouts, a minimum budget to start an agent check, escalate on exhaustion | [Deadline](interface.md#deadline) |
| D-9 | Deterministic checks run first; agent checks run only while the result is `allow`; deny > escalate > allow | [Check order](interface.md#check-order) |
| D-10 | Only an unsafe miss (a disagree on an enforced `allow`) drops a scope to shadow; over-strict misses are counted, not acted on | [Outcomes](interface.md#outcomes) |
| D-11 | State is per policy and scope (a repo id or `*`); a miss writes a shadow row for that repo only | [Decisions, states and scopes](interface.md#decisions-states-and-scopes) |
| D-12 | The recommendation is the Clopper-Pearson upper bound of the unsafe-miss rate, per policy, repo and fingerprint; advisory only | [Track records and recommendation](interface.md#track-records-and-recommendation) |
| D-13 | `set ... enforced` is a human action; tightening is open to any actor | [State changes](interface.md#state-changes) |
| D-14 | Late failure signals come in through `outcome --signal`, never through a gatectl-side detector | [Outcomes](interface.md#outcomes) |
| D-15 | An `agree` counts only from a human actor; a `disagree` from anyone; only a human can supersede one | [Outcomes](interface.md#outcomes) |
| D-16 | `off` records nothing; `shadow` fails open once its state is known; `enforced` and an unknown state fail closed (exit 1) | [Exit codes](interface.md#exit-codes) |
| D-17 | A decision records identity, hash and declared fields, not the input; `record_input` adds a capped copy to `state.db` only | [Input declaration](interface.md#input-declaration) |
| D-18 | A per-repo override replaces whole keys; its definition has its own fingerprint and record | [Per-repo overrides](interface.md#per-repo-overrides) |
| D-19 | A policy edit starts a new track record (fingerprint) | [Fingerprint](interface.md#fingerprint) |
| D-20 | `check` prints only the result JSON with a closed reason list | [Check result](interface.md#check-result), [Reasons](interface.md#reasons) |
| D-21 | The audit line is appended inside the decision's transaction before the commit | [Audit and log](interface.md#audit-and-log) |
| D-22 | `validate --probe` is the opt-in self-test of the agent path | [Agent checks](interface.md#agent-checks) |
| D-23 | Custom skills ship as plugins listed in `agent.plugin_dirs`, because agent sessions load no setting sources | [Agent checks](interface.md#agent-checks) |

## Resolved open topics

The four open topics from the architecture (section 20) are settled as follows.

- **Policy file format:** inline config, no policy files (D-1, D-2, D-18). Checks are `script`, `rule` or `agent`.
- **Agent check contract:** the fenced input, the prompt file, the artifact, validation and the threshold are in [Agent checks](interface.md#agent-checks) (D-5).
- **Outcome workflow and thresholds:** [Outcomes](interface.md#outcomes) and [Track records and recommendation](interface.md#track-records-and-recommendation) (D-10, D-12, D-15).
- **After-the-fact failure signals:** gatectl records them but does not detect them: a caller or a human files `outcome disagree --signal <name>` (D-14).

## Live verification

Spikes ran against Claude Code with claude-session from this repository set, on Linux. Records are private; the facts relied on are below, and each is a `live` or process regression test in [plan.md](plan.md).

| Behavior | Verdict | Used by |
|---|---|---|
| A headless `gate-check` round trip with a skill, a fenced input file and an artifact works; a haiku run took 20 to 48 s and about $0.005 | verified, unsandboxed and sandboxed | D-5, D-8 |
| claude-session exits 0 with outcome `done` for a missing skill and passes an unusable artifact through unvalidated | verified | D-5 (own validation, preflight) |
| Confidence is not calibrated: a clear allow scored 0.95 to 0.97, an ambiguous input 0.60 to 0.65 whichever way the model decided | verified | D-5 (one-way gate) |
| Under `dontAsk` the first denied Bash call can make the agent stop reporting; a skill that reads with Read and uses Bash only for the report call reported in every later run | verified | D-5 (skill text) |
| A sandboxed run needs placeholder files in a read-only plugin directory; Glob is unavailable in the session; the sandbox needs copied, not hard-linked, code and an interpreter outside link farms | verified | D-5, packaging, platform notes |
| `claude-session --dry-run` reports the sandbox available for broken setups | verified | D-22 |
| A run with no report ends exit 14, needs-input or blocked exit 13, a timeout without a report exit 16; every one maps to `escalate` | verified | D-5, D-8 |
| Three to six parallel runs, sandboxed or not, did not interfere | verified (launches were 1 to 3 s apart) | D-7 |
| A sandboxed injection attempt: the agent escalated and never tried the reads, so containment is shown by configuration only | not shown by attack | live test, Residual risks |
| `forget` hides the session at once; its directories stay for the retention period; Claude Code's transcripts stay | verified | cleanup, Residual risks |
| `subprocess.run(timeout=)` leaves a grandchild running; a selector loop with its own process group, a group kill after the leader exits and output caps survives 13 hostile cases | verified | D-3 |
| Allowlisted environments keep token variables out of checks; inherited ones leaked every one | verified | D-3 |
| `BEGIN IMMEDIATE` with a re-read of the state gave 0 stale decisions in 1000; recording an earlier snapshot gave 6; eight writers lost or tore no audit lines up to 64 KB | verified | D-21 |
| After a SIGKILL of gatectl the whole check group leaks; `PR_SET_PDEATHSIG` kills only the leader; a lifeline-pipe watchdog killed the group | verified (the watchdog's completion handshake still needs its own test) | D-3 |
| Zero-miss upper bound at 95% is `1 - 0.05^(1/n)`: 59 clean outcomes for 5%, 149 for 2% | computed and checked | D-12 |
| Fixed-width UTC timestamps sort correctly as strings; mixed offsets and fractions do not | verified | state model |

Still to verify: a live sandbox containment attack, the lifeline watchdog handshake, true same-second parallel launches, and a macOS run of everything above.

## Modules

| Module | Responsibility |
|---|---|
| `cli.py` | argparse, exit codes, human and JSON output |
| `config.py` | Pydantic models, drop-in merge, policy resolution with overrides, the fingerprint |
| `engine.py` | one `check`: input validation, scope and state, ordering, deadline, combination |
| `runner.py` | the script runner: selector loop, process group, output caps, lifeline watchdog |
| `rules.py` | the closed rule evaluator |
| `agent.py` | the fenced input and prompt files, the claude-session calls, artifact validation, cache use, slots, forget, the probe |
| `store.py` | SQLite in WAL mode, additive-only migrations, decisions, outcomes, state rows, cache, leases |
| `stats.py` | counts, the effective-outcome rule, the Clopper-Pearson bound by bisection |
| `audit.py` | appends to `audit.jsonl` and `log.jsonl` |
| `hooks.py` | the three post hooks |
| `gateway.py` | every subprocess call, so tests substitute fakes |
| `plugin/` (package data) | the bundled plugin: `.claude-plugin/plugin.json`, `skills/gate-check/SKILL.md`, the placeholder files, the permission profile resource |

Dependencies: `pyyaml` (the stdlib cannot read YAML) and `pydantic` (config validation, as in every awkit tool). The Clopper-Pearson bound is a bisection on the binomial distribution in the stdlib, so no numeric library is needed; JSON handling is the stdlib's.

## Data model

`state.db` (SQLite, WAL, private; migrations additive only):

| Table | Holds |
|---|---|
| `meta` | schema version |
| `policy_state` | `(policy, scope)` primary key, `state`, `set_by`, `set_at`, `cause` (`set` or `miss`) |
| `decisions` | id, time, policy, scope, fingerprint, effective state, decision, reason, `tool`, `hook`, `object_type`, `object_id`, `repo`, `input_sha256`, declared fields (JSON), per-check results (JSON), actor, optional full input |
| `outcomes` | append-only: decision id, time, outcome, signal, actor, actor kind, capped reason |
| `agent_cache` | key, time, validated artifact fields, the decision id that produced them |
| `agent_slots` | slot number, holder PID and start time, expiry, `csession_id`, run start |

The effective outcome of a decision is computed from its outcomes (Outcomes); it is not stored. Timestamps are fixed-width UTC strings. A `check` takes `BEGIN IMMEDIATE`, re-reads the policy state, inserts the decision, appends the audit line and commits; an outcome that triggers the automatic drop writes its row, the `policy_state` row and the audit lines in one transaction.

## Concurrency

Commands that cron or a caller run concurrently are safe: decisions and outcomes are independent rows, state changes are single transactions, and agent slots are leases (holder PID plus start time plus expiry; a dead holder's lease is taken over, as in the design guide). `reconcile` is idempotent. Script checks of different `check` processes do not coordinate; only agent runs are capped.

## Error handling

- A failure fails fast with the key or id named. Before the policy's state is known, any failure exits 1 (a hook caller treats it as a veto). After it is known, `shadow` and `off` never block and `enforced` fails closed (exit 1).
- Every check failure maps to `escalate` with a reason from the closed list, never to `allow`. Output from checks is untrusted text, sanitized and capped before it is stored or shown.
- A crashed `check` can leave an agent run: its slot row names the session, and `reconcile` stops and forgets it.

## Test strategy

All subprocess calls go through `gateway.py`; tests substitute fakes.

- **Fake claude-session** in `tests/fakebin/`: scenarios for a valid artifact, a nonce mismatch, a wrong schema, no artifact, unreported (exit 14), timeout (exit 16), needs-input (exit 13), `sandbox_unavailable` (exit 12), a missing skill and a hang. Sibling `outcome` and `status` schemas are copied into `tests/` pinned to claude-session's version.
- **Process tests** with real child processes: the hostile-script cases from the spike (a grandchild that ignores SIGTERM, 100 MB of output, closed stdout, a check that never reads a 5 MB stdin, an early exit, bad UTF-8, duplicate keys, deep nesting, control characters), the group kill, the lifeline watchdog and the output caps.
- **Store tests:** eight concurrent writers, audit-before-commit ordering, the state re-read, migration refusal for a newer schema.
- **Golden files** for every `--json` output and hook payload, validated against `schemas/`.
- **Property tests** for the effective-outcome rule, the rule evaluator (missing, mistyped and null paths) and the combination rule (deny > escalate > allow; an agent never loosens).
- **`live` tests** (deselected by default, never in CI): the sandboxed round trip, the injection input, parallel runs, `validate --probe`, and every spike behavior in the table above.

## Architecture changes

Architecture v1.15 (recorded in the architecture, [roadmap](https://github.com/agent-workflow-kit/awkit-docs/blob/main/roadmap.md) unchanged): section 12.3 defines a miss as an unsafe miss only and makes state per policy and scope; the section 5.1 gatectl entry lists the added commands (`show`, `validate`, `export`, `reconcile`, `prune`, `cron`), the `rule` check type, `--repo`, `--signal` and the outcome semantics; section 20's gatectl entry records the four open topics as resolved. The interface registry row moves to 0.1.0-design.
