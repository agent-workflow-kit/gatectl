# gatectl: interface

Status: designed, 2026-11-09 (interface 0.1.0-design). This document is the single normative source for gatectl's rules. `design.md` records the decisions and the internal structure and links to the headings here instead of restating them; the README, the architecture and the schemas follow it. Machine-readable shapes are in `schemas/`.

## Concepts

gatectl answers one question for a caller: may this step go ahead? A caller sends a JSON object describing the step (typically a hook payload) and names a **policy**. gatectl runs the policy's checks and returns a **decision** (`allow`, `deny` or `escalate`) with a reason, and records it. Callers that act on the answer are separate tools; gatectl never performs the step.

### Identifiers

- **Policy name:** `^[a-z0-9][a-z0-9_-]{0,63}$`. An unknown policy name is a usage error (exit 2) in every command.
- **Decision id:** `gd-` followed by 12 lowercase base32 characters (`a-z`, `2-7`), generated from random bytes. Commands accept the full id or a unique prefix of at least 6 characters after `gd-` (the `gd-` itself is optional in input); a shorter prefix exits 2, an ambiguous one exits 21, an unknown one exits 10. The id satisfies the hook decision-id grammar callers validate (`^[A-Za-z0-9._:@/-]{1,128}$`).
- **Repo id:** `host/<full project path>` as in the design guide: a lowercase host with an optional `:port`, then `/` and path segments of `[A-Za-z0-9._-]`. gatectl never derives a repo from the working directory (hooks run in untrusted directories); the repo is `--repo`, else the input object's top-level `repo` string. A value that does not match the grammar counts as absent and adds the warning `repo_invalid` to the result.
- **Scope:** a repo id, or `*` (all repos). A decision's scope is its repo id, or `*` when it has no usable repo.
- **Check name:** `^[a-z0-9][a-z0-9_-]{0,63}$`, unique within a policy.
- **Signal:** `^[a-z][a-z0-9_-]{0,31}$`, a free label naming where an outcome came from (`human`, `auto`, `revert`, `incident`, anything else).
- **Duration:** `0`, or an integer and a unit: `ms`, `s`, `m`, `h`, `d` (for example `500ms`, `20s`, `10m`). `--timeout` takes a number of seconds (decimals allowed).
- **Time:** every stored and printed timestamp is UTC in the fixed form `YYYY-MM-DDTHH:MM:SS.ffffffZ`. `--since` takes an RFC 3339 time (`Z` or an offset, never naive) or a duration meaning "now minus".

### Decisions, states and scopes

- **Decision:** `allow`, `deny` or `escalate`. Severity order is `deny` > `escalate` > `allow`.
- **State:** `off`, `shadow` or `enforced`. New policies start in `shadow`; the config's `state` key sets only the initial state.
- **Effective state** of a policy for a scope: the stored row for the decision's repo, else the stored row for `*`, else the policy's initial state. State changes happen only through `set` and the automatic drop in Outcomes.
- **Shadow** means: run everything, record the would-be decision, never block (exit 0). Exit 0 in shadow means "do not block", never "authorize": a caller that uses a gate to enable an automatic action must require `"enforced": true` and `"decision": "allow"` in the result, and otherwise fall back to the manual default.

### Actors and human actions

`--actor` is `human:<name>` or `auto:<name>`. The default is `human:<me.name>` when stdin and stderr are TTYs, otherwise `auto:unknown`. An actor is a claim: a same-user process can lie about it, so every human-only rule below is advisory against such a process (Residual risks). A **human action** is one run from a TTY or with an `--actor human:<name>` argument; the audit record carries `stdin_tty`.

### Untrusted text

Everything that comes from the input, from a check, from an agent or from an `outcome` reason is untrusted: payload values, script output, artifact `reasons`, check `detail`, outcome reasons. The schemas mark these fields `x-untrusted`. gatectl replaces control characters with visible markers before storing or printing them, caps every length, never puts such text in argv or in the environment of any process, and never prints input text outside the declared fields.

## Policies

A policy is a named, ordered list of checks plus a declared input. Policies live in the config (`policies:`), in `config.yaml` or any drop-in; there are no policy files. A policy's mutable state lives in `state.db`, never in the config.

```yaml
policies:
  auto-merge:
    state: shadow
    timeout: 60s
    input: {require: [repo, head_sha], types: {repo: string, head_sha: string}}
    checks:
      - {name: ci-green, type: rule, when: [{path: ci.state, op: ne, value: passing}], then: deny}
      - {name: scope, type: script, argv: [/usr/local/bin/check-scope], timeout: 20s}
      - {name: reviewer, type: agent, instruction: "Escalate if the change touches security-sensitive code.", threshold: 0.8}
```

### Policy keys

| Key | Meaning | Default |
|---|---|---|
| `state` | initial state for scopes with no stored row | `shadow` |
| `timeout` | total deadline for one `check` | `defaults.timeout` |
| `input` | declared input (below) | none |
| `checks` | ordered list, at least one | required |
| `cache_ttl` | agent-check reuse window (Agent checks) | `agent.cache_ttl` |
| `record_input` | also store the capped full input in `state.db` (never in the audit log) | `false` |
| `recommend` | `{confidence, max_miss_rate}` for Track records | `defaults.recommend` |

Unknown keys, an empty `checks` list, duplicate check names and a check of an unknown `type` are config errors (exit 2, naming the key).

### Input declaration

`input` declares the top-level keys the policy needs: `require` is a list of keys that must be present and not `null` unless typed nullable, and `types` maps a key to `string`, `integer`, `number`, `boolean`, `object` or `array`, with a trailing `?` for a nullable key (`string?`). The input must be a JSON object of at most `input_max_bytes` (1 MiB) in strict JSON: UTF-8, no `NaN` or `Infinity`, no duplicate keys, nesting at most 64 deep. A violation escalates the decision with reason `input_invalid` (never allows, never a usage error); an input that is not a JSON object or does not parse is also `input_invalid` for a known policy. Script checks still receive the whole input. The values of the keys named in `require` and `types` are the policy's **declared fields**: they are recorded with each decision (strings capped at 256 characters, other values at 1 KiB of canonical JSON), and no other input text is stored unless `record_input` is on.

The input's top-level `tool`, `hook`, `object_type` and `object_id` strings are recorded with the decision when present (capped), so a caller can find its decisions later.

### Per-repo overrides

`repos.<repo-id>.policies.<name>` may set any policy key. A key it sets replaces the global key entirely, lists included; nothing merges inside a key. The decision's scope picks the override, and the override's effective definition has its own fingerprint, state rows and track record. The repo comes from the caller's payload: it selects a configuration and is not a security boundary. `validate` reports an override that names an unknown policy or key.

### Fingerprint

The fingerprint is `sha256:` plus the hex SHA-256 of the canonical JSON (sorted keys, no whitespace) of the policy's effective definition for a scope: the policy name, `input`, and every check with all of its keys, where an agent check also carries its resolved `skill`, `model`, `threshold`, permission profile, sandbox, setting sources and env allowlist, and its instruction text (for `instruction_file`, the file's SHA-256), and a script check carries the SHA-256 of every argv element that names an existing regular file of at most 1 MiB. It excludes `state`, `timeout`s, `cache_ttl`, `record_input` and `recommend`. Editing anything it covers starts a fresh track record.

## Checks

Checks of the three types below run in a fixed order (Check order). Every check yields a **verdict** (`allow`, `deny`, `escalate`, or `skipped` for an agent check that did not run) and a **reason code** from the closed list in Reasons.

### Script checks

```yaml
- {name: scope, type: script, argv: [/usr/local/bin/check-scope], timeout: 20s, env_allow: [SCOPE_DIR]}
```

- `argv` is a list, never a shell string. `argv[0]` is resolved to an absolute path when the policy is loaded: an absolute path as given, a bare name by searching the `PATH` gatectl was started with (empty and relative `PATH` entries are ignored). A name that does not resolve is a config error.
- The input JSON is written to the check's stdin. The check runs in a private empty directory, in its own process group that gatectl creates and records, with a timeout (`timeout`, default `defaults.script_timeout`, capped by the remaining budget). stdout and stderr are each read up to 64 KiB; more than that is discarded and noted.
- The environment is built from scratch from `defaults.script_env_allow` (default `PATH`, `HOME`, `LANG`, `LC_*`) plus the check's `env_allow`; a variable that is not in the allowlist never reaches the check, so token variables stay out unless a check names one. `PATH` has empty and relative entries removed.
- **The exit code decides:** 0 is `allow`, 11 is `deny`, 13 is `escalate`, anything else (a crash, a signal, `126`, `127`, `2`, a timeout) is `escalate` with reason `check_error` (`timeout` for a timeout). stdout may be one strict JSON object with an optional `reason` string (at most 1024 characters, kept as the check's `detail`) and an optional `decision`; a `decision` that disagrees with the exit code escalates (`check_error`). A parse failure of the output drops only the `detail`, never the verdict. An exit code of 256 wraps to 0 and cannot be told from a clean 0 (Residual risks).
- On a timeout or when the decision ends early, gatectl signals the check's process group (SIGTERM, then SIGKILL after a 2 s grace), and kills the group again after the leader exits. A lifeline pipe makes a watchdog kill the group if gatectl itself dies. A process that calls `setsid` leaves the group and is not killed (Residual risks).

### Rule checks

```yaml
- name: ci-green
  type: rule
  when:
    - {path: ci.state, op: ne, value: passing}
  then: deny
  else: allow
```

A rule is a pure function of the input: no process, no environment, no timeout. If every condition in `when` (at least one) holds the verdict is `then`, else it is `else` (default `allow`). A condition is `{path, op, value}`:

- `path` is dotted keys with numeric array indexes (`a.b.0.c`); key characters are `[A-Za-z0-9_-]`.
- Operators: `eq`, `ne` (JSON equality; arrays and objects compare whole; booleans never equal numbers), `in`, `not_in` (`value` is a list of scalars), `lt`, `le`, `gt`, `ge` (both sides numbers, not booleans), `glob` (the path value is a string, or a list of strings of which any may match; `*` matches any run of characters except `/`, `**` any run including `/`, `?` one character except `/`; no other metacharacters), `exists` and `absent` (no `value`).
- A comparison operator applied to a missing path, a `null`, or a value of the wrong type is an error, never a quiet `false`: the check's verdict is `escalate` with reason `check_error`. Only `exists` and `absent` accept a missing path. This is deliberate: a rule such as "deny when `ci.state` is not `passing`" must not allow because `ci` was absent.
- There is no regex, no expression language and no code.

### Agent checks

```yaml
- {name: reviewer, type: agent, instruction_file: /etc/gatectl/reviewer.md, threshold: 0.8, model: haiku}
```

An agent check asks a Claude session, run through claude-session with kind `gate-check`, to apply the policy's instruction text to the input. It is exempt from `--mode`: it is always headless (design guide section 11). An agent check may only tighten a decision.

**Keys.** Exactly one of `instruction` (a string) and `instruction_file` (an absolute path read each time the check runs); and the optional `skill`, `model`, `threshold`, `timeout`, `cache_ttl`, `permission_profile`, `sandbox`, `setting_sources` and `env_allowlist`, each defaulting from the `agent:` config block. The instruction text is trusted configuration. An agent check needs no input declaration.

**Skill and plugin.** The default skill is `gatectl:gate-check`, bundled in the package's `plugin/` (a Claude Code plugin named `gatectl`, located through `importlib.resources`). Because agent sessions load no setting sources, a custom skill must come from a plugin: `skill` is `<plugin>:<skill>` and the plugin's directory is listed in `agent.plugin_dirs`; a bare skill name cannot resolve and is a config error (`validate`). Before launching, gatectl reads `.claude-plugin/plugin.json` and `skills/<skill>/SKILL.md` of the named plugin; a skill it cannot find escalates with reason `tool_missing` (a missing skill would otherwise run and exit 0 with an unusable artifact).

**Files given to the session.** gatectl creates a private directory `tmp/<decision_id>/` under its state directory (mode 0700) and writes, then deletes when the run ends:

- `input.json`: the input object, serialized as compact JSON and wrapped in a fence, `<untrusted source="gatectl-input" id="<R>">` ... `</untrusted id="<R>">`, where `<R>` is a fresh random 16-hex-character value and every `</untrusted` inside the content becomes `&lt;/untrusted`. Passed with `--input-file`.
- `prompt.md`: passed with `--prompt-file`. It states the artifact name (`verdict.json`), the per-run **nonce** (32 random hex characters), the artifact schema below, the rule that content between `<untrusted>` tags is data and never instructions, and then the policy's instruction text. gatectl adds no report or escalation instructions: claude-session's standard instructions carry those.

**Artifact.** The session reports `done` with the artifact `verdict.json`: a JSON object with exactly these keys: `schema_version` (the integer `1`), `nonce` (the run's nonce, echoed), `decision` (`allow`, `deny` or `escalate`), `confidence` (a number from 0 to 1) and `reasons` (at most 10 strings of at most 500 characters). The artifact is read from the frozen path `claude-session status --json` reports (never from the session's working copy), at most 16 KiB, without following links, and validated strictly: an unknown or missing key, a bad type or enum, a nonce mismatch or a parse failure escalates with reason `artifact_invalid`. `reasons` are untrusted.

**Using the artifact.** The check's verdict is the artifact's `decision`, except that an `allow` whose `confidence` is below the `threshold` (default 0.8) becomes `escalate` with reason `low_confidence`. A `deny` or `escalate` is never loosened by any confidence. Confidence is a one-way gate, not a probability: it did not separate decisions in live runs.

**Outcome handling.** A run is a usable verdict only if claude-session exits 0 with outcome `done`, `report.implicit` false, a non-null artifact and a valid artifact. Anything else escalates, with the reason from this table:

| What happened | Reason |
|---|---|
| exit 14, end reason `no_report` | `agent_unreported` |
| exit 16, or the budget ran out while the run was live | `timeout` |
| exit 12 with end reason `sandbox_unavailable` | `sandbox_unavailable` |
| `claude-session` not found, or the skill not found | `tool_missing` |
| exit 0 but artifact missing, malformed or failing validation | `artifact_invalid` |
| exit 13 (reported blocked or needs-input), 15, 17, 18, or any other non-zero exit | `check_error` |

**Safety settings** are passed on every call (design guide section 11) and each has a config key replacing it: `--permission-profile` (a profile file from the package's resources, equal to claude-session's built-in `review` profile), `--sandbox required`, `--setting-sources ""`, `--env-allowlist-only` for each name in `env_allowlist` (`--env-allowlist-only ''` when the list is empty), `--repo` when the decision has a repo, and `--model` when set. The full command is `session_cmd exec --kind gate-check --mode headless --skill <skill> --prompt-file <f> --input-file <f> --plugin-dir <bundled> [--plugin-dir <each of agent.plugin_dirs>] --timeout <remaining> --label owner=gatectl --label policy=<name> --label decision=<decision_id> --actor auto:gatectl --decision-id <decision_id> --outcome-file <private path> --json`. Callers must not pass `--hook pre-launch` selectors that match `gate-check`: a `pre-launch` hook that calls gatectl must set `exclude_kinds: [gate-check]` or it recurses until its timeout (claude-session residual risk).

**Reuse.** The result of an agent check is reused for an identical input: the cache key is the agent check's fingerprint (skill, instruction text, model, threshold, safety settings) plus the SHA-256 of the input JSON, valid for `cache_ttl` (default 10 minutes, `0` turns it off). Only a valid artifact from a `done` run is cached; a failure never is. Script and rule checks always run again. A reused result is marked `reused: true`, still produces its own decision with a new `decision_id` and audit line, and `--no-cache` forces a fresh run.

**Slots.** At most `agent.max_parallel` (default 3) agent runs are live across all gatectl processes. A slot is a lease in `state.db` (holder PID, process start time, expiry; a dead holder's lease is taken over). The check waits for a slot within its remaining budget and then escalates with reason `busy`.

**Cleanup.** After reading the artifact, gatectl copies its validated fields into `state.db`, calls `session_cmd forget <csession_id>`, and deletes the private directory. Claude Code's own transcript under its projects directory is not removed by `forget` (Residual risks). A run that is still live when the budget ends is stopped with `session_cmd stop`, then forgotten.

**Probe.** `validate --probe` runs one agent check on a built-in input whose instruction asks for `allow`, with the configured safety settings, and reports exit code, end reason, `sandbox_active` and what failed. It costs one run and happens only when asked.

## Check order

One `check` runs these steps in order:

1. **Resolve.** Parse flags and load the config (a config error exits 2; an unreadable config or state exits 1). An unknown policy exits 2.
2. **Read the input** from `--input <file>`, or stdin when `--input` is `-` or absent (exit 2 if absent and stdin is a TTY). Over `input_max_bytes` or not a strict JSON object is `input_invalid`.
3. **Scope and state.** The scope is `--repo`, else the input's `repo` when it matches the repo grammar, else `*`. Apply the repo override, compute the fingerprint and the effective state.
4. **`off`:** log a line, print the `off` result and exit 0. No checks run and no decision is recorded.
5. **Input declaration.** A mismatch skips every check: the decision is `escalate`, reason `input_invalid`, and it is recorded.
6. **Deterministic checks.** Script and rule checks run in their listed order. The first `deny` ends the run (later checks are `skipped`). An `escalate` does not stop later script and rule checks, which can still tighten it to `deny`.
7. **Agent checks.** They run, in listed order, only if the result so far is `allow`; once the result is `deny` or `escalate` the remaining agent checks are `skipped`. An agent check that would start with less than `agent.min_start_budget` (default 30 s) of the budget left does not start: `escalate`, reason `budget_exhausted`. Deterministic checks always run before agent checks, whatever order the YAML lists them in.
8. **Combine and record.** The decision is the most severe verdict. The reason is the reason of the first `deny`, else of the first `escalate` in check order, else `all_passed`. Then, in one `BEGIN IMMEDIATE` transaction, gatectl re-reads the effective state, inserts the decision with that state, appends its audit line and commits; only then does it fire `post-decision`, print the result and exit.

A decision's recorded `state` is the state read inside the transaction. In `shadow` and `off` a failure after the state is known never blocks (Exit codes); in `enforced` it exits 1.

### Deadline

One monotonic deadline covers the whole `check`: `--timeout` (seconds) if given, else the policy's `timeout`, else `defaults.timeout` (60 s). Each check gets the remaining budget minus `defaults.record_reserve` (default 2 s, kept for recording and output), capped by its own `timeout` (script default 20 s, agent default 300 s). When the budget ends, the check in progress is stopped and the result is `escalate`, reason `timeout`, naming the check; in `shadow` the exit stays 0. Callers set `--timeout` below the hook's own timeout (for example 540 under a 600 s hook) so a slow check escalates instead of being killed and counted as a veto.

## Reasons

`reason` is a closed list. The policy's `reason` and each check's `reason` come from it; free text goes only in a check's `detail`.

| Reason | Meaning |
|---|---|
| `all_passed` | every check allowed |
| `check_denied` | a check denied |
| `check_escalated` | a check escalated by its own verdict |
| `input_invalid` | the input is missing a declared key, has the wrong type, is too large or is not a strict JSON object |
| `timeout` | a check ran out of its time |
| `budget_exhausted` | too little of the deadline was left to start an agent check |
| `busy` | no agent slot became free within the budget |
| `tool_missing` | `claude-session`, the skill or the plugin could not be found |
| `agent_unreported` | the agent run ended without a report |
| `artifact_invalid` | the agent's artifact is missing or fails validation |
| `low_confidence` | the agent allowed below the threshold |
| `sandbox_unavailable` | the required sandbox could not start |
| `check_error` | a check crashed, was killed, printed contradictory output, or hit a rule type error |

## Outcomes

After the fact, someone says whether a decision was right: `gatectl outcome <decision-id> agree|disagree [--signal S] [--reason-file F]`.

| Decision | `agree` means | `disagree` means | Counts as |
|---|---|---|---|
| `allow` | it was right to allow | it should not have been allowed | unsafe miss |
| `deny` | blocking was right | it should have been allowed | over-strict miss |
| `escalate` | a human was needed | it could have been decided automatically | over-strict miss |

- Outcomes are append-only: each is a record with its actor, signal and optional untrusted reason. A decision made while the policy was `off` does not exist, so it has none. A repeat of the latest outcome from the same actor and signal is a no-op (exit 0, `changed: false`).
- **Effective outcome** of a decision: read its outcomes in time order. A `disagree` from any actor sets it to `disagree`. An `agree` from a `human:*` actor sets it to `agree`. An `agree` from any other actor is recorded and shown but never changes it. No outcome yet is `pending`. So an automatic `agree` can neither inflate a record nor cancel a `disagree`; only a later human outcome supersedes one.
- `--signal` defaults to `human` for a human actor and `auto` otherwise. A late failure source (a revert, an incident) files `outcome <id> disagree --signal revert`; gatectl knows no sources of its own. Callers find the decision by the id they stored, or with `decisions --policy P --object-id X`.
- **Automatic drop to shadow.** When a decision whose effective outcome becomes `disagree` was an `allow` made while its scope was `enforced`, and the scope's effective state is still `enforced`, gatectl writes a `shadow` row for that decision's scope (the repo, or `*`), appends a `state_change` audit record with cause `miss` and the decision id, and fires `post-state-change`, all in the transaction that recorded the outcome. Other repos keep their state. An over-strict miss, or a miss on a `shadow` decision, only counts in the record.

### Track records and recommendation

`stats` builds one record per policy, repo (or none) and fingerprint: decisions by verdict, outcomes by effective outcome, unsafe and over-strict misses, counts by signal and by actor kind (human, automatic, unattributed), and per-reason counts with the time each was last seen. Shadow and enforced decisions both count. Records are not pooled across repos.

The recommendation uses unsafe misses only. With `n` resolved `allow` decisions (effective outcome `agree` or `disagree`) under the current fingerprint and `k` unsafe misses, `upper_bound` is the one-sided Clopper-Pearson upper bound at `recommend.confidence` (default 0.95), computed by bisection. `recommend` is `enforce` when the scope is not `enforced` and `upper_bound <= recommend.max_miss_rate` (default 0.05; with `k = 0` that takes 59 agreeing outcomes), `not_yet` otherwise, `keep` when `enforced` and the bound holds, and `reconsider` when `enforced` and it does not. It is advisory: gatectl never enforces by itself. With `--since`, the counts cover only that window and `recommend` is `null`.

## State changes

`gatectl set <policy> off|shadow|enforced [--repo ID] [--reason-file F]` writes the state row for the scope (`*` without `--repo`). Setting `shadow` or `off` is allowed to any actor, because it only tightens. Setting `enforced` is a human action; any other attempt exits 20 with reason `human_required`. A human may enforce without a recommendation. Setting a state that already holds is a no-op (`changed: false`). `set` is audited with its actor and reason; the effective state of every other scope is untouched. When the policy has an agent check and no `validate --probe` has succeeded since the last config change, `set ... enforced` prints a hint to run it; the hint never blocks.

## Commands

All commands take `--json`, `--config PATH`, `--verbose` and `--quiet`. `--version` prints `gatectl <version>`. `outcome`, `set` and `prune` take `--actor` and a repeatable `--decision-id`.

### `check`

`gatectl check <policy> [--input <file> | --input -] [--timeout <seconds>] [--repo <id>] [--no-cache] [--dry-run] [--actor A]`. Evaluates the policy (Check order) and prints the check result on stdout as JSON, always, whatever `--json` says; human-readable text goes to stderr on a TTY. `--dry-run` loads and validates the policy, the declaration and the input, prints the resolved plan (policy, scope, effective state, fingerprint, each check with its resolved argv or skill, and what would be skipped) and runs nothing and records nothing. `--actor` is recorded with the decision.

### `outcome`

`gatectl outcome <decision-id> agree|disagree [--signal S] [--reason-file F|-]`. Records an outcome (Outcomes). The reason is untrusted, at most 1 KiB.

### `decisions`

`gatectl decisions [--since T] [--policy P] [--repo R] [--object-id X] [--outcome pending|agree|disagree] [--limit N]`. Lists decisions, newest first (default limit 100), with their effective outcome.

### `show`

`gatectl show <decision-id>`. One decision in full: every check's result and detail, the declared fields, the cache source, the outcome history, the effective outcome and the recorded input hash.

### `stats`

`gatectl stats [--policy P] [--repo R] [--since T]`. Track records and recommendations (Track records and recommendation).

### `set`

`gatectl set <policy> off|shadow|enforced [--repo ID] [--reason-file F]` (State changes).

### `policies`

`gatectl policies [--repo ID]`. Every policy with its initial state, its stored scope rows (state, who set it, when, cause), the effective state for the given repo (or `*`), its fingerprint, a summary of each check and the recommendation of each record. With `--repo` it shows that repo's effective definition.

### `validate`

`gatectl validate [--probe]`. Lints the config without running a check: schema, unknown keys, unresolved `argv[0]`, missing skill or plugin, `instruction_file` not readable, overrides naming unknown policies or keys, bare skill names, relative paths, and an agent check whose `session_cmd` does not resolve. Exit 0 when valid, 2 when not, printing each problem as `{code, path, message}`. `--probe` also runs the probe (Agent checks) and exits 12 when it fails.

### `export`

`gatectl export [--log] [--since T]`. Prints `audit.jsonl` (default) or `log.jsonl` records as JSON lines.

### `reconcile`

`gatectl reconcile`. Takes over stale leases and, for agent slots whose holder is dead, stops and forgets the `gate-check` session recorded on the slot, then removes its private directory. It reports what it changed. Safe to run at any time and under cron.

### `prune`

`gatectl prune [--older-than D] [--dry-run]`. Deletes decisions, outcomes and cache rows older than `D` from `state.db`; `audit.jsonl` and `log.jsonl` are never pruned. Without `--older-than` it uses `retention.older_than` and does nothing when that is `null` (the default). Audited.

### `cron`

`gatectl cron install|uninstall`. Writes or removes the tagged block `# gatectl managed` in the user's crontab, with an explicit `PATH` including `~/.local/bin`: `gatectl reconcile --quiet` every 15 minutes, and `gatectl prune --quiet` daily when `retention.older_than` is set. `awkit cron install` writes the same block.

## Global flags

| Flag | Meaning |
|---|---|
| `--json` | machine-readable output (always on for `check`) |
| `--config PATH` | config file, replacing `~/.config/gatectl/config.yaml` (drop-ins still apply from its directory) |
| `--verbose`, `--quiet` | more or less stderr |
| `--actor A` | `human:<name>` or `auto:<name>` |
| `--decision-id ID` | repeatable; recorded in the audit record of the command |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `check`: allow, or any result in `shadow` or `off`; other commands: success |
| 1 | internal error; `check` also uses it when the policy's state is unknown (config or database unreadable) and for any internal failure while the state is `enforced` |
| 2 | usage error: bad flags, an unknown policy, a config error, no `--input` with a TTY stdin |
| 10 | not found: a decision id |
| 11 | `check` in `enforced`: deny |
| 12 | the requested operation failed for an expected reason (`validate --probe` failed) |
| 13 | `check` in `enforced`: escalate |
| 20 | refused: `set ... enforced` without a human (`human_required`) |
| 21 | ambiguous decision-id prefix |

There are no tool-specific codes above 22. In `shadow` and `off`, gatectl never exits with anything but 0 for a decision it could evaluate: when the state is known to be `shadow` or `off` and a later step fails (for example the decision cannot be written), `check` exits 0 with `decision_id` null, an `error` object in the result and a warning on stderr, because nothing may rely on a shadow result.

## Output by exit code

- **`check`** exits 0, 11 and 13 print the check result. Exits 1 and 2 print the error envelope. A `--dry-run` prints the plan.
- **Other commands** print their result object on exit 0 and the error envelope otherwise. `validate` exit 2 and `--probe` exit 12 print the problem list or probe report.

### Check result

```json
{
  "schema_version": 1,
  "decision_id": "gd-4k2m9q7x3a1b",
  "policy": "auto-merge",
  "scope": "github.com/org/repo",
  "state": "shadow",
  "shadow": true,
  "enforced": false,
  "decision": "allow",
  "reason": "all_passed",
  "fingerprint": "sha256:...",
  "checks": [
    {"name": "ci-green", "type": "rule", "verdict": "allow", "reason": null, "detail": null, "duration_ms": 1},
    {"name": "reviewer", "type": "agent", "verdict": "allow", "reason": null, "detail": null, "confidence": 0.95, "reused": false, "duration_ms": 31000}
  ],
  "warnings": [],
  "error": null
}
```

`decision` is the would-be decision and is `null`, with `decision_id` null, when the state is `off` or the result is a shadow failure. `enforced` is true only in the `enforced` state. `state` is the effective state read when the decision was recorded. A check's `reason` is `null` when it allowed; `confidence` and `reused` appear on agent checks only. `warnings` holds codes such as `repo_invalid`. No input text is printed, only the declared fields' values in the recorded decision (shown by `show`), never in this result. stdout carries only this object, so a hook caller that reads a hook's stdout finds `decision_id`.

### Other results

`outcome`: `{decision_id, outcome, signal, actor, changed, effective_outcome, miss: null|"unsafe"|"over_strict", state_change: null|{policy, scope, state, cause}}`. `set`: `{policy, scope, state, previous_state, changed, hint}`. `decisions`: `{decisions: [...], truncated}`. `show`, `stats`, `policies`, `validate`, `export` (JSON lines), `reconcile`, `prune`: their documented shapes in `schemas/cli/`.

### Error envelope

`{"error": {"code": "...", "message": "...", "reason": "...", "details": {...}}}`. `code` is one of `usage` (2), `config_invalid` (2), `not_found` (10), `ambiguous` (21), `refused` (20, with `reason`), `failed` (12) and `internal` (1). Messages name the offending key or id.

## Hooks

gatectl is the gate, so it has no `pre-` hooks. It fires three post hooks, configured under `hooks:` with `cmd`, `timeout` (default 30 s) and `async`. A hook receives the JSON payload on stdin and runs through `sh -c` in its own process group, with no `{...}` substitution and the environment of gatectl; its failure is logged and warned, never fatal. Payloads carry no input text and no `labels` key (gatectl stores no labelled objects). Common keys: `tool` (`gatectl`), `hook`, `object_type`, `object_id`, `repo` (nullable).

| Hook | Fires | `object_type` / `object_id` | Other keys |
|---|---|---|---|
| `post-decision` | after a decision is recorded and committed | `decision` / the decision id | `policy`, `scope`, `state`, `shadow`, `enforced`, `decision`, `reason`, `fingerprint`, `actor`, `input_tool`, `input_hook`, `input_object_id`, `checks` (name, type, verdict, reason, duration) |
| `post-outcome` | after an outcome is recorded | `outcome` / the decision id | `policy`, `scope`, `outcome`, `signal`, `actor`, `effective_outcome`, `previous_effective_outcome`, `miss` |
| `post-state-change` | after `set` changed a state, or the automatic drop wrote one | `policy` / the policy name | `scope`, `state`, `previous_state`, `cause` (`set` or `miss`), `actor`, `decision_id` (for `miss`) |

Hook environment: `GATECTL_HOOK`, `GATECTL_ID` (the object id) and `GATECTL_OBJECT_TYPE`. These names are reserved and never read as config. Wire `post-state-change` to a notification: an automatic drop to shadow is the event a human should hear about.

### Using gatectl as a hook

A caller wires a gate as a `pre-` hook, for example `cmd: "gatectl check start-work --timeout 540"` with `timeout: 600`. The caller's `pre-` hook rules apply to the exit code (0 continues, 13 escalates, anything else vetoes) and the printed `decision_id` is recorded in the caller's audit entry. A hook that launches claude-session sessions must exclude the `gate-check` kind.

## Config

`~/.config/gatectl/config.yaml` (XDG-aware) plus `config.d/*.yaml` merged in lexical order (maps merge, hook lists append). `config.example.yaml` documents every key with its default.

| Key | Default |
|---|---|
| `me.name` | the OS username (used only for the default actor) |
| `session_cmd` | `[claude-session]` (binding B) |
| `defaults.timeout` | `60s` |
| `defaults.script_timeout` | `20s` |
| `defaults.record_reserve` | `2s` |
| `defaults.input_max_bytes` | `1048576` |
| `defaults.script_env_allow` | `[PATH, HOME, LANG, "LC_*"]` |
| `defaults.recommend` | `{confidence: 0.95, max_miss_rate: 0.05}` |
| `agent.skill` | `gatectl:gate-check` |
| `agent.plugin_dirs` | `[]` |
| `agent.model` | `null` (Claude Code's default) |
| `agent.permission_profile` | `null` (the bundled profile file) |
| `agent.sandbox` | `required` |
| `agent.setting_sources` | `[]` |
| `agent.env_allowlist` | `[]` |
| `agent.threshold` | `0.8` |
| `agent.timeout` | `300s` |
| `agent.cache_ttl` | `10m` |
| `agent.max_parallel` | `3` |
| `agent.min_start_budget` | `30s` |
| `retention.older_than` | `null` |
| `policies` | `{}` |
| `repos.<id>.policies.<name>` | none |
| `hooks` | `{}` |

Invalid config fails fast with a message naming the key. Precedence is flags > per-repo overrides > environment variables > global config (including drop-ins) > built-in defaults. A policy's `state` in the config is only its initial state. The bundled permission profile, sandbox level, setting sources and env allowlist can each be replaced by the keys above, so a more permissive or stricter setup never depends on another tool's config.

## Environment variables

Top-level scalar config keys may be set as `GATECTL_<KEY>`, nested keys joined with `__` (`GATECTL_DEFAULTS__TIMEOUT`, `GATECTL_AGENT__MAX_PARALLEL`). Lists and structured config (`policies`, `repos`, `hooks`, `session_cmd`, `agent.plugin_dirs`, the env allowlists) cannot be set from the environment. `GATECTL_HOOK`, `GATECTL_ID` and `GATECTL_OBJECT_TYPE` are reserved for hooks. gatectl holds no credentials and reads no token variables; claude-session handles Claude's own login.

## Audit and log

`~/.local/state/gatectl/audit.jsonl` is appended for every decision, outcome, state change and prune; `log.jsonl` holds structured events (an `off` check, a shadow failure, a skipped hook, a reconcile). Both are public, append-only contracts (`schemas/audit.json`, `schemas/log.json`).

| Audit `action` | Fires | `target` | `result` |
|---|---|---|---|
| `decision` | a decision was recorded | `<policy>@<scope>` | decision, reason, state, shadow, enforced |
| `outcome` | an outcome was recorded | the decision id | outcome, signal, effective outcome, miss kind |
| `state_change` | `set`, or the automatic drop | `<policy>@<scope>` | previous and new state, cause, reason |
| `prune` | rows were deleted | `state.db` | counts, the age |

A decision's record carries `actor`, `decision_id` (the decision's own id), the `input_sha256`, the fingerprint and the policy, never the input. The record is appended inside the transaction that inserts the decision, before the commit, so a returned decision always has an audit line (a crash can leave a line for a decision that did not commit, never the reverse). A `check` while the policy is `off` writes a log event only. Retention is forever.

## Files

| Path | Contents |
|---|---|
| `~/.config/gatectl/config.yaml`, `config.d/*.yaml` | config |
| `~/.local/state/gatectl/state.db` | SQLite, WAL, private: state rows, decisions, outcomes, cache, leases, schema version |
| `~/.local/state/gatectl/audit.jsonl`, `log.jsonl` | public contracts |
| `~/.local/state/gatectl/tmp/<decision_id>/` | the agent run's input and prompt files, mode 0700, deleted when the run ends |

Policy files, `instruction_file`s and script paths must be outside every path an isolated Claude session can write, like every other tool's config.

## Labels

gatectl stores no labelled objects and has no label commands. Its claude-session sessions carry `owner=gatectl`, `policy=<name>` and `decision=<decision_id>`.

## TUI

None in v1. A `browse` view of decisions and track records is a 1.x candidate.

## Upgrades

`state.db` migrations are additive only; a database from a newer gatectl is refused (exit 1, `schema_newer`) without touching it. Policy fingerprints change only when the rules in Fingerprint change, which starts fresh records.

## Residual risks

- A same-user process, including a prompt-injected trusted agent, can pass any `--actor`, so the human-only rules (`set ... enforced`, counting an `agree`) are advisory against it. They stop automation that does not lie.
- A script check that calls `setsid` leaves its process group and is not killed on a timeout.
- An exit code of 256 wraps to 0 and reads as `allow`.
- Fencing and the nonce do not stop a model from being steered; an agent check can only tighten a decision, and a deterministic check must back every automatic action. Agent confidence is not calibrated.
- Claude Code's transcripts of gate-check sessions stay under its projects directory after `forget`.
- The sandbox's containment of a gate-check session was shown by configuration only; a live injection attempt that tries to read outside the session has not been observed to succeed or to be refused.
- `claude-session --dry-run` can report the sandbox as available for a setup that fails at run time; `validate --probe` is the check.
- If gatectl is killed with SIGKILL, running script checks are killed by the lifeline watchdog, but a live agent run ends only through claude-session's own parent-death handling and `reconcile`.
- A policy edited between a decision and its outcome keeps the old fingerprint: the outcome counts toward the old record.

## Platform notes

Linux, WSL and macOS are supported. Agent checks need claude-session and its required sandbox: `bubblewrap` and `socat` on Linux and WSL2, Seatbelt on macOS; WSL1 has no sandbox. The lifeline watchdog uses a pipe, not `PR_SET_PDEATHSIG`, so it works on every platform. Install claude-session with copied, not hard-linked, files (`UV_LINK_MODE=copy`) and an interpreter that does not go through a link outside the sandbox's readable directories. gatectl's bundled plugin directory ships the placeholder files `.claude/`, `.mcp.json`, `CLAUDE.md` and `CLAUDE.local.md`, because a sandboxed session refuses a read-only plugin directory without them. File watching is not used.
