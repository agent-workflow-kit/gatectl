# gatectl: design

Status: designed, 2026-11-10 (interface 0.1.0-design). [interface.md](interface.md) holds the normative rules; this document records the decisions, the reasoning and the internal structure, and links to the interface headings instead of restating them.

## Role and layer

Policy decisions (allow, deny, escalate) with first-class shadow mode. Layer 1 (primitive). It works fully standalone: a policy made of script and rule checks needs nothing but gatectl. Agent checks need claude-session. It is shareable and runs on Linux, WSL and macOS (architecture C4). A gate wired as a hook files no outcomes itself, and a hook caller needs its own timeouts, selectors and `exclude_kinds`; the wiring checklist in the [README](../README.md) covers both.

## Uses

| Tool | Binding | What for |
|---|---|---|
| claude-session | B (configurable command, `session_cmd`, default `claude-session`, resolved in a fixed directory list and never through the caller's `PATH`) | agent checks: `start` and `exec --session-id` with `--kind gate-check --mode headless`, `status`, `list`, `stop`, `forget` |

No other tool of ours is used. gatectl never reads a git host, a ticket system or another tool's `state.db`. Consumers wire it as a `pre-` hook, call it directly, or file late signals with `outcome`; gatectl does not know which (architecture 3.4).

## Decisions

| # | Decision | Where |
|---|---|---|
| D-1 | Policies are defined inline in the config (`policies:` in `config.yaml` or drop-ins); state lives in `state.db`, never in the config; the config's `state` is `off` or `shadow` | [Policies](interface.md#policies) |
| D-2 | A declared input is a small field list (`require`, `types`); a mismatch escalates with `input_invalid`; a missing or null `repo` falls back to the global scope; with no `--repo`, an unusable payload or an unusable `repo` makes the scope indeterminate and escalates under the strictest state; `--repo` is trusted and wins | [Input declaration](interface.md#input-declaration) |
| D-3 | Script checks: argv list, allowlisted environment, private cwd, own process group; the exit code decides and anything unexpected escalates; `argv[0]` is absolute and resolution failures at run time escalate `tool_missing` | [Script checks](interface.md#script-checks) |
| D-4 | A closed `rule` check type for deterministic field tests; conditions are an ordered AND with short-circuit; a comparison on a missing, null or mistyped path escalates (`check_error`) rather than being false (a recorded change from the first approved wording); glob is matched without backtracking under size caps | [Rule checks](interface.md#rule-checks) |
| D-5 | Agent checks use one bundled skill `gatectl:gate-check`, a nonce-fenced `input.json`, a nonce-echoing `verdict.json` artifact, strict validation and a one-way confidence threshold; the agent input is capped at 64 KiB and written pretty-printed with an end marker, so the agent can read all of it | [Agent checks](interface.md#agent-checks) |
| D-6 | Agent results are reused for an identical input within a TTL; the cache key is the policy's fingerprint for the scope, the check name, the scope and the input hash without the `input.ignore` keys (which list volatile fields), and rows carry their own `expires_at`; script and rule checks always run | [Agent checks](interface.md#agent-checks) |
| D-7 | At most three agent runs are live at once across processes, through leases in `state.db`; liveness by PID, start time and boot id, and a slot only counts against the cap | [Agent checks](interface.md#agent-checks) |
| D-8 | One deadline per `check`, checks capped by their own timeouts, a minimum budget to start an agent check, escalate on exhaustion; the deadline starts at process start, agent checks follow the five steps in Deadline, and `validate` rejects policies that cannot start an agent check; agent checks launch in a window `L = R - 5 s`, every claude-session call has a 5 s timeout, `exec` is guarded at `n + 10 s`, and a check ends at most 30 s after its deadline | [Deadline](interface.md#deadline) |
| D-9 | Deterministic checks run first; agent checks run only while the result is `allow`; deny > escalate > allow | [Check order](interface.md#check-order) |
| D-10 | Only an unsafe miss (a disagree on an enforced `allow`) drops a scope to shadow, and only while the state row that gave the decision its state is still the effective row (compared by revision, not by time); over-strict misses are counted, not acted on | [Outcomes](interface.md#outcomes) |
| D-11 | State is per policy and scope (a repo id or `*`); a miss writes a shadow row for that repo only; an override cannot set `state`, and `set --all` is the kill switch; `set` of an unchanged row is a no-op, a row creation is a change | [Decisions, states and scopes](interface.md#decisions-states-and-scopes) |
| D-12 | The recommendation is the Clopper-Pearson upper bound of the unsafe-miss rate, per policy, repo and fingerprint; `n` counts cases, so repeated checks of one object count once (a case is keyed by a hash taken at record time); advisory only | [Track records and recommendation](interface.md#track-records-and-recommendation) |
| D-13 | `set ... enforced` is a human action; `shadow` and `off` are open to any actor so automation can fail safe (for a veto gate they remove the veto, see [Residual risks](interface.md#residual-risks)) | [State changes](interface.md#state-changes) |
| D-14 | Late failure signals come in through `outcome --signal`, never through a gatectl-side detector | [Outcomes](interface.md#outcomes) |
| D-15 | An `agree` counts only from a human actor; a `disagree` from anyone; only a human can supersede one | [Outcomes](interface.md#outcomes) |
| D-16 | `off` records nothing; `shadow` fails open once its state is known; `enforced` and an unknown state fail closed (exit 1); a config error is local to the policy it is in; a shared-key error stops `check`, `reconcile`, `prune`, `cron` and `set enforced`, while the kill switch, `outcome` and the read-only commands carry on with defaults | [Exit codes](interface.md#exit-codes) |
| D-17 | A decision records identity, hash and declared fields, not the input; `record_input` adds a capped copy to `state.db` only; declared fields are validated before recording; `prune` keeps current-fingerprint records | [Input declaration](interface.md#input-declaration) |
| D-18 | A per-repo override replaces whole keys; its definition has its own fingerprint and record; an override cannot set `state` | [Per-repo overrides](interface.md#per-repo-overrides) |
| D-19 | A policy edit starts a new track record (fingerprint); the fingerprint covers skill, plugin, profile, instruction and script file hashes; the fingerprint is computed over a normalized definition (defaults filled in); a state row remembers the fingerprint it was set for, `check` warns when the definition changed under an enforced scope, and a human `set enforced` on a row with a stale fingerprint re-enforces it | [Fingerprint](interface.md#fingerprint) |
| D-20 | `check` prints only the result JSON with a closed reason list; `checks` lists every check in execution order | [Check result](interface.md#check-result), [Reasons](interface.md#reasons) |
| D-21 | The audit line is appended inside the decision's transaction before the commit | [Audit and log](interface.md#audit-and-log) |
| D-22 | `validate --probe` is the opt-in self-test of the agent path; the `set ... enforced` hint compares a hash of the agent configuration | [Agent checks](interface.md#agent-checks) |
| D-23 | Custom skills ship as plugins listed in `agent.plugin_dirs`, because agent sessions load no setting sources; a plugin is passed to a session only for the checks that use it | [Agent checks](interface.md#agent-checks) |
| D-24 | Post hooks never hold the caller's descriptors: a result is printed before hooks start, hooks of `check` are always detached, hook output is discarded | [Hooks](interface.md#hooks) |
| D-25 | A policy may declare `applies_when`; when false the gate allows with `not_applicable`, runs nothing and records nothing; the answer carries `shadow: false` and `enforced: false`, so it never authorizes an automatic action; `off` is checked before `applies_when` | [Policy keys](interface.md#policy-keys), [Check order](interface.md#check-order) |
| D-26 | Every `tmp/` entry is a directory with an `owner` file; liveness is the owner's PID, start time and boot id; `reconcile` sweeps by that, never by slot rows | [Files](interface.md#files) |
| D-27 | State rows carry a store-wide revision; each decision records the revision of the row that gave it its state; the automatic drop compares revisions | [State changes](interface.md#state-changes), [Outcomes](interface.md#outcomes) |

## Review decisions

Review pass 1 put eleven questions to the user and pass 2 one. The user chose the recommended option each time, except R-5, which was the design session's own call. R-n answers question N-n of the review.

- **R-1:** veto gates stay advisory against a same-account adversary. `set shadow|off` and `outcome disagree` stay open to any actor so automation can always fail safe; the veto case is a documented residual risk and operators wire `post-state-change` to a notification ([Residual risks](interface.md#residual-risks), D-13).
- **R-2:** a present but unusable payload `repo` escalates `input_invalid` under the strictest state of the policy; absent or null uses scope `*`. Read in pass 2 as: with `--repo` given an invalid payload `repo` only warns, and with no `--repo` any input from which no repo can be extracted is resolved like an invalid `repo` ([Identifiers](interface.md#identifiers), D-2).
- **R-3:** a rule check on a missing, null or mistyped path escalates `check_error` instead of being false ([Rule checks](interface.md#rule-checks), D-4).
- **R-4:** `applies_when` and the reason `not_applicable` ([Policy keys](interface.md#policy-keys), D-25).
- **R-5:** the check result echoes `input_sha256`, a decision id is a reference and not an authorization, and there is no `verify` command ([Check result](interface.md#check-result)).
- **R-6:** track records count cases, `pending` is the void, with no `void` outcome and no bulk command ([Track records and recommendation](interface.md#track-records-and-recommendation), D-12).
- **R-7:** `definition_changed` warns when a definition differs from the fingerprint its state row was set for; the config `state` is `off` or `shadow` ([State changes](interface.md#state-changes), D-19).
- **R-8:** the shared config structure is validated at load and each policy separately; the 60 s default deadline stays and `validate` reports `deadline_too_short` ([Config](interface.md#config), [Deadline](interface.md#deadline), D-8, D-16).
- **R-9:** `prune` never deletes decisions of a current fingerprint ([Commands](interface.md#commands), D-17).
- **R-10:** `argv[0]` must be absolute, and the check's `PATH` loses empty and relative entries ([Script checks](interface.md#script-checks), D-3).
- **R-11:** a result with no recorded decision omits `decision_id` rather than printing null ([Check result](interface.md#check-result), D-20).
- **R-12:** a human files `agree` (at a terminal, or through a tool that relays the human's own action, such as review-watch's accept); automation files only `disagree` (reverts, incidents); an automatic `agree` is recorded and never counts, so S-18 stays and the README and Outcomes no longer say that automation can build a track record ([Outcomes](interface.md#outcomes), D-15).

## Resolved open topics

The four open topics from the architecture (section 20) are settled as follows.

- **Policy file format:** inline config, no policy files (D-1, D-2, D-18). Checks are `script`, `rule` or `agent`.
- **Agent check contract:** the fenced input, the prompt file, the artifact, validation and the threshold are in [Agent checks](interface.md#agent-checks) (D-5).
- **Outcome workflow and thresholds:** [Outcomes](interface.md#outcomes) and [Track records and recommendation](interface.md#track-records-and-recommendation) (D-10, D-12, D-15).
- **After-the-fact failure signals:** gatectl records them but does not detect them: a caller or a human files `outcome disagree --signal <name>` (D-14).

## Live verification

Spikes ran against Claude Code with claude-session from this repository set, on Linux. Records are private; the facts relied on are below, and each is a `live` or process regression test in the implementation plan.

| Behavior | Verdict | Used by |
|---|---|---|
| A headless `gate-check` round trip with a skill, a fenced input file and an artifact works; a haiku run took 20 to 48 s and about $0.005 | verified, unsandboxed and sandboxed | D-5, D-8 |
| claude-session exits 0 with outcome `done` for a missing skill and passes an unusable artifact through unvalidated | verified | D-5 (own validation, preflight) |
| Confidence is not calibrated: a clear allow scored 0.95 to 0.97, an ambiguous input 0.60 to 0.65 whichever way the model decided | verified | D-5 (one-way gate) |
| Under `dontAsk` the first denied Bash call can make the agent stop reporting; a skill that reads with Read and uses Bash only for the report call reported in every later run | verified | D-5 (skill text) |
| A sandboxed run needs placeholder files in a read-only plugin directory; Glob is unavailable in the session; the sandbox needs copied, not hard-linked, code and an interpreter outside link farms | verified | D-5, packaging, platform notes |
| `claude-session --dry-run` reports the sandbox available for broken setups | verified | D-22 (the probe is therefore a real run; the design does not use `--dry-run`) |
| A run with no report ends exit 14, needs-input or blocked exit 13, a timeout without a report exit 16; every one maps to `escalate` | verified | D-5, D-8 |
| Three to six parallel runs, sandboxed or not, did not interfere | verified (launches were 1 to 3 s apart) | D-7 |
| A sandboxed injection attempt: the agent escalated and never tried the reads, so containment is shown by configuration only | not shown by attack | live test, Residual risks |
| `forget` hides the session at once; its directories stay for the retention period; Claude Code's transcripts stay | verified | cleanup, Residual risks |
| `subprocess.run(timeout=)` leaves a grandchild running; a selector loop with its own process group, a group kill after the leader exits and output caps survives 13 hostile cases | verified | D-3 |
| Allowlisted environments keep token variables out of checks; inherited ones leaked every one | verified | D-3 |
| `BEGIN IMMEDIATE` with a re-read of the state gave 0 stale decisions in 1000; recording an earlier snapshot gave 6; eight writers lost or tore no audit lines up to 64 KB | verified | D-21 |
| After a SIGKILL of gatectl the whole check group leaks; `PR_SET_PDEATHSIG` kills only the leader; a lifeline-pipe watchdog killed the group | verified (the watchdog's completion handshake, including the `waitid` order before the reap, still needs its own test) | D-3 |
| Zero-miss upper bound at 95% is `1 - 0.05^(1/n)`: 59 clean outcomes for 5%, 149 for 2% | computed and checked | D-12 |
| A glob translated to a regular expression (`[^/]*a[^/]*a[^/]*a[^/]*b` on 1,500 `a`) did not finish in 40 s; `1e999` parses to `inf` and `"\ud800"` parses but fails to encode as UTF-8 | reproduced in review | D-4, D-17 |
| claude-session `start --json` prints `csession_id`, the run and the `exec --session-id --run` argv; `forget` refuses a live or pending session; `--timeout 0` is a usage error; a non-empty `--setting-sources` for a third-party-reading run fails with `unsafe_setting_sources` | checked against claude-session's interface, not run live | D-7, D-8, D-23, plan's live tests |
| Fixed-width UTC timestamps sort correctly as strings; mixed offsets and fractions do not | verified | state model |
| A single Read of a large one-line file is cut at a token cap and the rest is not shown | verified | D-5 (pretty-printed input, 64 KiB cap, end marker) |
| Python's `sys.stdout.close()` leaves descriptor 1 open (standard streams do not own descriptors 0 to 2) | standard behavior, not re-run | D-24 (descriptors pointed at `/dev/null` with `dup2`) |

Still to verify: a live sandbox containment attack, the lifeline watchdog handshake, true same-second parallel launches, `start` plus `exec --session-id` and `stop` of a pending run from a headless caller, whether a changed `SKILL.md` changes the fingerprint, how many turns a run takes (to decide whether `agent.max_turns` earns a key), the macOS method for process start time (slot liveness), whether `os.waitid` with `WNOWAIT` exists on macOS (otherwise `kqueue`), slot liveness across a reboot (boot id), and a macOS run of everything above.

## Modules

| Module | Responsibility |
|---|---|
| `cli.py` | argparse, exit codes, human and JSON output |
| `config.py` | Pydantic models, drop-in merge, policy resolution with overrides, the fingerprint |
| `engine.py` | one `check`: input validation, scope and state, ordering, deadline, combination |
| `runner.py` | the script runner: selector loop, process group, output caps, lifeline watchdog |
| `rules.py` | the closed rule evaluator, including the non-backtracking glob matcher and its size caps |
| `agent.py` | the fenced input and prompt files, the claude-session calls (`start`, `exec --session-id`, `status`, `list`, `stop`, `forget`), artifact validation, the 64 KiB input cap, cache use, slots, cleanup, the probe |
| `store.py` | SQLite in WAL mode, additive-only migrations, decisions, outcomes, state rows with revisions, case keys, cache, slot leases and the maintenance leases of `reconcile` and `prune` |
| `stats.py` | counts, the effective-outcome rule, the Clopper-Pearson bound by bisection |
| `audit.py` | appends to `audit.jsonl` and `log.jsonl` |
| `hooks.py` | the three post hooks, started detached by a supervisor process |
| `gateway.py` | every subprocess call, so tests substitute fakes |
| `plugin/` (package data) | the bundled plugin: `.claude-plugin/plugin.json`, `skills/gate-check/SKILL.md`, the placeholder files, the permission profile file (a copy of claude-session's built-in `review` profile, added in the plan's agent stage, with a test that fails when it drifts from a pinned copy of the built-in) |

Dependencies: `pyyaml` (the stdlib cannot read YAML) and `pydantic` (config validation, as in every awkit tool). The Clopper-Pearson bound is a bisection on the binomial distribution in the stdlib, so no numeric library is needed; JSON handling is the stdlib's.

## Data model

`state.db` (SQLite, WAL, private; migrations additive only):

| Table | Holds |
|---|---|
| `meta` | `schema_version`, `probe_ok_at`, `probe_agent_hash`, the `state_rev` counter, the `lease:reconcile` and `lease:prune` rows (holder PID, start time, boot id) |
| `policy_state` | `(policy, scope)` primary key, `state`, `set_by`, `set_at`, `cause` (`set` or `miss`), `fingerprint` (of the scope's own definition when the row was written), `rev` (from the store-wide counter) |
| `decisions` | id, time, policy, scope, fingerprint, effective state, decision, reason, `tool`, `hook`, `object_type`, `object_id`, `repo`, `input_sha256`, `case_key` (a hash taken at record time), `state_rev` (the `rev` of the row that gave the decision its state, null for the config's initial state or an indeterminate scope), declared fields (JSON), per-check results (JSON), actor, optional full input |
| `outcomes` | append-only, with an autoincrement `seq` that orders them: decision id, time, outcome, signal, actor, actor kind, capped reason |
| `agent_cache` | key, time, `expires_at`, validated artifact fields, the decision id that produced them |
| `agent_slots` | holder PID, holder start time, boot id, decision id, `csession_id`, run start, `expires_at` (no slot number) |

`tmp/<decision_id>/` directories and `tmp/hook-*` directories carry an `owner` file; `reconcile` removes the ones whose owner is dead. Row revisions replace timestamps wherever two events must be ordered (outcomes by `seq`, state rows by `rev`).

The effective outcome of a decision is computed from its outcomes (Outcomes); it is not stored. Timestamps are fixed-width UTC strings. A `check` takes `BEGIN IMMEDIATE`, re-reads the policy state, inserts the decision, appends the audit line and commits, and the re-read state decides the printed result and the exit code; an outcome that triggers the automatic drop writes its row, the `policy_state` row and the audit lines in one transaction.

## Concurrency

Commands that cron or a caller run concurrently are safe: decisions and outcomes are independent rows, state changes are single transactions, and agent slots are leases (holder PID plus start time decide liveness; expiry is informational, so a clock step never frees a live slot). A write waits at most `defaults.record_reserve` for the lock and a reader never waits. `reconcile` and `prune` take a lease row each; a second caller exits 0 with `already_running`. Script checks of different `check` processes do not coordinate; only agent runs are capped.

## Error handling

- A failure fails fast with the key or id named. Before the policy's state is known, any failure exits 1 (a hook caller treats it as a veto). After it is known, `shadow` and `off` never block and `enforced` fails closed (exit 1).
- Every check failure maps to `escalate` with a reason from the closed list, never to `allow`. Output from checks is untrusted text, sanitized and capped before it is stored or shown.
- A crashed `check` can leave an agent run: `reconcile` finds its session by the `owner=gatectl` and `state=<tag>` labels, stops and forgets it when no live `tmp/<id>/` owner exists, and removes the directory.
- A missing `state.db` next to a non-empty audit log is an unknown state (exit 1); gatectl never starts a fresh database over an existing history. A `state.db` with no schema next to a non-empty audit log is an unknown state too (exit 1).
- A hook cannot delay or change a `check` result.
- The residual risks (a same-account process lowering a veto gate, privacy of forgotten sessions, a trusted agent rewriting the config) are listed in [Residual risks](interface.md#residual-risks).

## Test strategy

All subprocess calls go through `gateway.py`; tests substitute fakes.

- **Fake claude-session** in `tests/fakebin/`: scenarios for a valid artifact, a nonce mismatch, a wrong schema, no artifact, unreported (exit 14, also `no_result`), timeout (exit 16), a `done` run whose end reason is `timeout`, needs-input (exit 13), `sandbox_unavailable` (exit 12), `claude_not_found` (exit 12), a status whose SHA-256 differs, a missing skill and a hang, each for `start`, `exec --session-id`, `list`, `stop` and `forget`; also exit 13 (`check_escalated`), exit 0 with an outcome other than `done`, and exit 0 with `report.implicit` true. Sibling `outcome` and `status` schemas are copied into `tests/` pinned to claude-session's version.
- **Process tests** with real child processes: the hostile-script cases from the spike (a grandchild that ignores SIGTERM, 100 MB of output, closed stdout, a check that never reads a 5 MB stdin, an early exit, bad UTF-8, duplicate keys, deep nesting, control characters), the group kill, the lifeline watchdog and the output caps. Added for the review results: a caller that reads `check` stdout to EOF while an async and a sync post hook sleep 20 s sees EOF and the exit within one second, and a hook cannot write to the caller's stdout or stderr; the caller kills `check` with SIGTERM during a script check and during an agent run and no process or session is left; SIGKILL of gatectl during an agent run, after which `reconcile` stops and forgets the session and removes `tmp/<id>`; `reconcile` run in a loop while a 20 s script check, an agent run and a hook are live removes nothing of theirs, and after a SIGKILL of each owner the next `reconcile` removes the directory and stops and forgets the session; a fake claude-session whose `exec` ignores SIGTERM and whose `stop` hangs: `check` exits within deadline + 30 s with `escalate`/`timeout` and no leaked process, and SIGTERM during `start` leaves no session after `reconcile`; the EOF test extended to the lifeline watchdog and to a `check` killed with SIGKILL while an `exec` runs (the caller reading to EOF is released at once; a container without an init is listed in the README); a truncated payload, an oversized payload and a stalled writer with an enforced repo row and a shadow `*` row each escalate and exit 13, and the same with `--repo` of the enforced repo; a zombie holder frees its slot; killing gatectl between the group sweep and the `done` message and between `done` and the reap, with no recycled group signaled; strict JSON cases (`1e999`, a lone surrogate escape, a 100k-deep array, a 5,000-digit integer, a 1 MiB repo string, a FIFO or `/dev/zero` as `--input`, a numeric `object_id` recorded as null), each `input_invalid` or exit 2 with nothing failing during recording.
- **Store tests:** eight concurrent writers, audit-before-commit ordering, the state re-read, migration refusal for a newer schema, a `set` that commits during a long `check` in each of the six state pairs (recorded state, printed flags and exit code agree), and 16 concurrent callers with no `database is locked` escaping; an invalid `hooks:` key makes `check` exit 2 while `set P off --all`, `outcome` and `decisions` work; `prune` while 16 `check` callers record (no caller waits longer than `record_reserve`); a short audit write leaves a parseable file; an empty `state.db` next to a non-empty audit log exits 1.
- **Golden files** for every `--json` output and hook payload, validated against `schemas/`; a `not_applicable` answer in an enforced scope prints `enforced: false`; the three input-hash vectors of the interface.
- **Property tests** for the effective-outcome rule, the rule evaluator (missing, mistyped and null paths) and the combination rule (deny > escalate > allow; an agent never loosens), short-circuit order and guard idioms of rule checks, the glob matcher against a reference regex on short random strings (the adversarial pattern `**a**a**a**a**b` against a 4 KiB `a` string finishes in under 100 ms and against a larger string is a `check_error`), the outcome sequence `human:a agree`, `auto:b disagree`, `human:a agree` ending `agree`, and a Clopper-Pearson golden table (n=59, k=0 recommends enforcing; n=58 does not). Also: two configs that differ only in an explicit default have equal fingerprints, and a changed `agent.model` changes the fingerprint of a check that has no `model` of its own; drop ordering (a decision under row rev 5, a re-enforcement at rev 9, a late `disagree`: no drop, also with a clock stepped back) and `set enforced` on a stale row clears `definition_changed`; cases (the same object polled 20 times with a changing `ci` object declared and ignored is one case, and a null `object_id` groups by `input_sha256`); `in` with null.
- **`live` tests** (deselected by default, never in CI): the sandboxed round trip, the injection input, parallel runs, `validate --probe`, and every spike behavior in the table above, a 60 KiB input with the hostile text at the end (the agent reads to the closing fence or escalates) and a 500 KB input (`input_invalid` without a session).

## Architecture changes

Architecture v1.15 (recorded in the architecture, [roadmap](https://github.com/agent-workflow-kit/awkit-docs/blob/main/roadmap.md) unchanged): section 12.3 defines a miss as an unsafe miss only and makes state per policy and scope; the section 5.1 gatectl entry lists the added commands (`show`, `validate`, `export`, `reconcile`, `prune`, `cron`), the `rule` check type, `--repo`, `--signal` and the outcome semantics; section 20's gatectl entry records the four open topics as resolved. The interface registry row moves to 0.1.0-design. Review pass 2 changed sentences within the same version: a `not_applicable` answer carries `enforced: false` and never authorizes, automatic `agree` never counts (R-12), the timeouts bullet's 30 s margin, and the track record bullet's note on who files outcomes. Review pass 1 added to the same version: `applies_when` and the reason `not_applicable`, track records counted by case, `set --all` for `off` and `shadow`, `--actor` and `--decision-id` on every command, `reconcile --dry-run`, a `decision_id` that is omitted when no decision was recorded, post hooks detached from the caller, and the gatectl glossary entry naming rule checks (the section 12.3 timeouts bullet and a gate-as-hook note changed too).
