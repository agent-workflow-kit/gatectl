# gatectl: interface

Status: designed, 2026-11-10 (interface 0.1.0-design). This document is the single normative source for gatectl's rules. `design.md` records the decisions and the internal structure and links to the headings here instead of restating them; the README, the architecture and the schemas follow it. Machine-readable shapes are in `schemas/`.

## Concepts

gatectl answers one question for a caller: may this step go ahead? A caller sends a JSON object describing the step (typically a hook payload) and names a **policy**. gatectl runs the policy's checks and returns a **decision** (`allow`, `deny` or `escalate`) with a reason, and records it. Callers that act on the answer are separate tools; gatectl never performs the step. Terms defined later are used earlier in places: Track records and recommendation, Check order, Residual risks, declared fields (Input declaration) and effective definition (Fingerprint).

### Identifiers

- **Policy name:** `^[a-z0-9][a-z0-9_-]{0,63}$`. A policy name that is neither in the config nor in `state.db` is a usage error (exit 2) in every command (error envelope `code: usage`, `details.kind: unknown_policy`). A name that is only in `state.db` (a removed or renamed policy) is accepted read-only by `decisions`, `stats` and `show` (rows are marked `configured: false`) and by `set <name> off|shadow`, which is how its rows are lowered before the name is reused; `check` and `set ... enforced` exit 2 for it, and `policies` lists only configured policies.
- **Decision id:** `gd-` followed by 12 lowercase base32 characters (`a-z`, `2-7`), generated from random bytes. Commands accept the full id or a unique prefix of at least 6 characters after `gd-`; the `gd-` is stripped once when present, and the rest must be base32 (`a-z`, `2-7`) before any lookup (a `%` or `_` is a usage error, exit 2). A shorter prefix exits 2, an ambiguous one exits 21, an unknown one exits 10. The id satisfies the hook decision-id grammar callers validate (`^[A-Za-z0-9._:@/-]{1,128}$`). A decision id is a reference to a recorded decision, not an authorization. The id is generated once per `check`: when the first script or agent check needs `tmp/<decision_id>/`, else when a decision is recorded at step 8. The same id names the directory, the session label and the recorded decision. A probe generates a `gd-` id the same way and records no decision.
- **Repo id:** `host/<full project path>` as in the design guide: a lowercase host with an optional `:port`, then `/` and path segments of `[A-Za-z0-9._-]`. The grammar is matched against the whole string, is at most 255 characters, and a path segment of `.` or `..` is invalid. A repo is compared exactly as written (no case folding; callers pass one spelling). gatectl never derives a repo from the working directory (hooks run in untrusted directories). The repo is `--repo`, else the input object's top-level `repo`. A `--repo` flag value that fails the grammar exits 2 in every command that takes it (`check` never accepts `*`; Scope lists the commands that do). `--repo` is the trusted source: when it is given, the payload `repo` never selects the scope or the state, a valid payload `repo` that differs adds the warning `repo_mismatch`, an invalid one adds `repo_invalid`, and nothing else changes. Without `--repo`, a payload `repo` that is absent or JSON `null` selects scope `*`. The scope is **indeterminate** when there is no `--repo` and either the payload `repo` is present and is not a valid repo id (a non-string, or a string failing the grammar; warning `repo_invalid`) or the input is unusable (over `input_max_bytes`, not a strict JSON object, or not fully read by the deadline), because no repo can be trusted. For an indeterminate scope the decision is `escalate` (Check order, steps 2 and 5), its scope is `*`, and its state is the strictest state (`enforced` over `shadow` over `off`) among the policy's stored rows when it has any, and the config's initial state only when it has none (so `set <policy> off --all` turns an indeterminate input `off` too, a policy with no rows uses its initial state, and a stored `enforced` row anywhere still wins); the state is resolved at step 3 and again at step 8, so a malformed repo, a truncated payload or a stalled writer cannot move an enforced policy to shadow.
- **Scope:** a repo id, or `*` (all repos). A decision's scope is its repo id, or `*` when it has no repo. `--repo '*'` names scope `*` in `decisions`, `stats`, `policies` and `set`; every other use of `*` as a repo exits 2.
- **Check name:** `^[a-z0-9][a-z0-9_-]{0,63}$`, unique within a policy.
- **Signal:** `^[a-z][a-z0-9_-]{0,31}$`, a free label naming where an outcome came from (`human`, `auto`, `revert`, `incident`, anything else).
- **Duration:** `0`, or an integer and a unit: `ms`, `s`, `m`, `h`, `d` (for example `500ms`, `20s`, `10m`). `--timeout` takes a number of seconds (decimals allowed).
- **Time:** every stored and printed timestamp is UTC in the fixed form `YYYY-MM-DDTHH:MM:SS.ffffffZ`. `--since` takes an RFC 3339 time (`Z` or an offset, never naive) or a duration meaning "now minus". Cache reuse and `since` use the wall clock; a cache row dated in the future is ignored.
- **Input hash:** `input_sha256` is the SHA-256 of the canonical serialization of the whole parsed input: the UTF-8 bytes of the value with object keys sorted by Unicode code point, no whitespace (separators `,` and `:`), characters kept as written except those JSON requires to be escaped, integers as written, and other numbers in their shortest round-trip decimal form (Python's `json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`). When no object was parsed (an input over the cap, not UTF-8, not strict JSON, or not fully read) it is the SHA-256 of the raw bytes read (at most `input_max_bytes` + 1). It is the value in the check result, the audit log and `show`, and the base of the cache key. Test vectors: `{"b":1,"a":"é","c":[1.5,true,null]}` serializes to `{"a":"é","b":1,"c":[1.5,true,null]}` with hash `2332fe002293e35042867b9afd7a8a2a470df3cc466fe44903a5b44f99d16b92`; `{"repo":"github.com/org/repo","head_sha":"0123abcd"}` has hash `82ad1dd601d033fddc136731fab553afa585dd3ad0f9f3745b42708aea02a855`; the raw bytes `not json` have hash `7ccfa1fbf3940e6f0c0375d87c0f9235a50514e14cb427bdfaf5077987b26ccf`.

### Decisions, states and scopes

- **Decision:** `allow`, `deny` or `escalate`. Severity order is `deny` > `escalate` > `allow`.
- **State:** `off`, `shadow` or `enforced`. New policies start in `shadow`; the config's `state` key sets only the initial state and is `off` or `shadow`.
- **Effective state** of a policy for a scope: the stored row for the decision's repo, else the stored row for `*`, else the policy's initial state. State changes happen only through `set` and the automatic drop in Outcomes; a row is never created by `check`.
- **Shadow** means: run everything, record the would-be decision, never block (exit 0). Exit 0 in shadow means "do not block", never "authorize": a caller that uses a gate to enable an automatic action must require `"enforced": true` and `"decision": "allow"` in the result, and otherwise fall back to the manual default. A `not_applicable` answer (Check order, step 4a) evaluated nothing: it prints `shadow: false` and `enforced: false` whatever the scope's state, so it never satisfies that rule and never authorizes an automatic action.

### Actors and human actions

`--actor` is `human:<name>` or `auto:<name>` (`<name>` matches `[A-Za-z0-9._@-]{1,64}`). Without `--actor` the default is `human:<me.name>` when stdin is a TTY, otherwise `auto:unknown`; a `me.name` or OS user name outside the charset has each disallowed character replaced by `_` and is cut to 64 characters (an empty one becomes `user`). A **human action** is one whose effective actor is `human:<name>`: an explicit `--actor` must be `human:<name>` with a non-blank name (any other explicit actor is not human, even with a TTY), and without `--actor` stdin must be a TTY. An actor is a claim: a same-user process can lie about it, so every human-only rule is advisory against such a process (Residual risks). The audit record carries `stdin_tty` and `actor_source`.

### Untrusted text

Everything that comes from the input, from a check, from an agent or from an `outcome` reason is untrusted: payload values, script output, artifact `reasons`, check `detail`, outcome reasons. The schemas mark these fields `x-untrusted`. gatectl replaces every code point whose Unicode category is `Cc`, `Cf`, `Zl`, `Zp`, `Cs`, `Co` or `Cn`, and any other non-printable character except the space, with the marker `�` before storing or printing it (the stored and printed text only: hashes, the cache key, case keys and `--declared` matching use the original value), caps every length (256 characters unless a field says otherwise), never puts such text in argv or in the environment of any process, and never prints input text outside the declared fields. `--verbose` output and every error `message` go through the same sanitizer and never include input text or a raw flag value.

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
| `state` | initial state for scopes with no stored row: `off` or `shadow`; `enforced` is a config error whose message says to use `gatectl set` | `shadow` |
| `timeout` | total deadline for one `check` | `defaults.timeout` |
| `applies_when` | a non-empty list of rule conditions, evaluated exactly like a rule check's `when` (ordered, stopping at the first false or error); when one is false the policy does not apply (Check order, step 4a) | none (always applies) |
| `input` | declared input (below) | none |
| `checks` | ordered list, at least one | required |
| `cache_ttl` | agent-check reuse window; precedence check > policy > `agent.cache_ttl` | `agent.cache_ttl` |
| `record_input` | also store the capped full input in `state.db` (never in the audit log) | `false` |
| `recommend` | `{confidence, max_miss_rate}` for Track records and recommendation | `defaults.recommend` |

`applies_when` is a scoping filter, not a detector: write it over fields the caller sets from a trusted source. A condition that fails to match skips the gate. A null on a nullable path makes `eq` with a non-null value an error, which counts as applicable (Rule checks); put `{path: P, op: ne, value: null}` first when a field is null for some actions.

Unknown keys, an empty `checks` list, duplicate check names and a check of an unknown `type` are config errors (exit 2, naming the key; see Config for how far a config error reaches).

### Input declaration

`input` declares the top-level keys the policy needs: `require` is a list of keys that must be present and not `null` unless typed nullable, `types` maps a key to `string`, `integer`, `number`, `boolean`, `object` or `array`, with a trailing `?` for a nullable key (`string?`), and `ignore` lists top-level keys (volatile fields such as a timestamp or an event id) that are left out of the cache key; they are still given to the check, still part of `input_sha256` and still part of the fingerprint. `ignore` may not name `repo` (a config error `invalid_value`: the scope is part of the key, and a payload repo decides it); it also leaves the key out of case identity (Track records and recommendation). `string`, `boolean`, `object` and `array` are the JSON types; `integer` is a JSON number written without a fraction or exponent (`1.0` is not an integer); `number` is any JSON number; booleans are never numbers. A key in `types` but not in `require` may be absent; when present it must match (`null` only with `?`).

The input must be a JSON object of at most `input_max_bytes` (1 MiB) in strict JSON: UTF-8; no `NaN` or `Infinity` token; every number finite after parsing (`1e999` is invalid); no string with an unpaired surrogate (`"\ud800"` is invalid); no duplicate keys at any depth; nesting at most 64, checked without recursion (a pre-scan) before decoding; any error raised while parsing (including number or recursion limits) is `input_invalid`. Declared fields and the identity strings are validated as finite and encodable as UTF-8 before step 5 of Check order, so recording cannot fail on input content. A violation escalates the decision with reason `input_invalid` (never allows, never a usage error); an input that is not a JSON object or does not parse is also `input_invalid` for a known policy. Script checks still receive the whole input.

The values of the keys named in `require` and `types` are the policy's **declared fields**. A declared string is stored capped at 256 characters; any other declared value whose canonical JSON exceeds 1 KiB is stored as the string `[truncated: <n> bytes]`. gatectl stores no input text outside the declared fields, the identity strings, a script's or agent's `detail` and cached agent `reasons` (which can quote input), unless `record_input` is on. When the input is not parseable or fails the declaration, the declared fields and `tool`, `hook`, `object_type`, `object_id` are null. A policy that gates an action bound to a revision (a head sha, a base ref) should list that key in `require`, so the revision is a declared field of every decision.

The input's top-level `tool`, `hook`, `object_type` and `object_id` are recorded with the decision when present, capped at 256 characters; a present value that is not a string is recorded as null.

### Per-repo overrides

`repos.<repo-id>.policies.<name>` may set any policy key except `state` (a repo's state is its stored row; `state` in an override is a config error naming the key). A key it sets replaces the global key entirely, lists included; nothing merges inside a key, with two exceptions: a key `recommend` set by an override is a whole map in which a missing sub-key takes the value of `defaults.recommend`, and `input` is replaced whole. The decision's scope picks the override, and the override's effective definition has its own fingerprint, state rows and track record. The repo comes from the caller's payload: it selects a configuration and is not a security boundary. `validate` reports an override that names an unknown policy or key.

### Fingerprint

The fingerprint is `sha256:` plus the SHA-256 of the canonical JSON (sorted keys, compact, UTF-8) of the policy's **effective definition** for a scope: the policy name, `input`, `applies_when` (if any) and every check with all of its keys except `timeout` and `cache_ttl`, in a normalized form with every default filled in, so that spelling a default explicitly does not change the fingerprint (a rule's `else: allow` is present, an agent check's `skill`, `model`, `threshold`, `sandbox`, `setting_sources`, `env_allowlist` and `permission_profile` are replaced by their resolved values and the hash below, a script check's `env_allow` is replaced by the effective environment allowlist). An agent check also carries the SHA-256 of its permission-profile file, of its instruction text (the bytes of `instruction_file` or the `instruction` string) and of the `SKILL.md` and `plugin.json` of its skill's plugin. A script check also carries its effective environment allowlist (`defaults.script_env_allow` plus `env_allow`) and the SHA-256 of every `argv` element that is an absolute path to an existing regular file (a file over 1 MiB, in practice an interpreter or a binary, contributes its size and modification time instead; the deadline is checked between files). It excludes `state`, the policy and check `timeout`s, `cache_ttl`, `record_input`, `recommend`, `session_cmd` and the working directory. A file that cannot be read contributes the fixed marker `unreadable`; computing the fingerprint never fails and never depends on the caller's working directory. Editing anything it covers starts a fresh track record.

## Checks

Checks of the three types below run in a fixed order (Check order). Every check yields a **verdict** (`allow`, `deny`, `escalate`, or `skipped` for a check that did not run: a script or agent check after the deadline, any script or agent check after a `deny`, or an agent check after an `escalate`; a rule check is never skipped for the deadline) and a **reason code** from the closed list in Reasons. `checks` in the result and in the record lists every check of the effective policy in execution order: rule and script checks in listed order, then agent checks in listed order (the YAML order of mixed types is not kept). A `skipped` check has `reason: null`, `detail: null`, `duration_ms: 0`, and for an agent check `confidence: null`, `reused: false`. When the declaration fails (`input_invalid`), `checks` is empty. "Check order" means this execution order everywhere (the reason of the first `escalate` is the first in it).

### Script checks

```yaml
- {name: scope, type: script, argv: [/usr/local/bin/check-scope], timeout: 20s, env_allow: [SCOPE_DIR]}
```

- `argv` is a list, never a shell string. `argv[0]` must be an absolute path (a config error otherwise). Whether it exists and is executable is checked when the check starts, never at load; a missing or non-executable file escalates with reason `tool_missing`. Other elements are passed as given: a relative path-like element (it contains `/` and is not absolute) is never resolved and never hashed, and `validate` warns `relative_argv`.
- The input JSON is written to the check's stdin without blocking and bounded by the check's timeout; a closed pipe is ignored. The check runs in a private empty directory `tmp/<decision_id>/s-<n>/` (mode 0700, `<n>` counting the script checks of this process from 1), removed after the check (Files, Removal of `tmp/` trees), in its own process group that gatectl creates and records, with a timeout (`timeout`, default `defaults.script_timeout`, capped by the remaining budget). stdout and stderr are each read up to 64 KiB; more than that is discarded and noted with the warning `output_truncated`. stderr is read (so the pipe cannot fill) up to 64 KiB and then discarded; it is never stored or printed. The `detail` of a check that did not allow comes from the stdout `reason` when there is one, else is `exit <n>`, `signal <n>`, `timeout` or `not started`.
- The environment is built from scratch from `defaults.script_env_allow` (default `PATH`, `HOME`, `LANG`, `LC_*`) plus the check's `env_allow`; a variable that is not in the allowlist never reaches the check, so token variables stay out unless a check names one. `env_allow` entries are exact names matching `^[A-Za-z_][A-Za-z0-9_]*$`; only `defaults.script_env_allow` accepts a trailing `*`. The `PATH` a check receives has empty and relative entries removed.
- **The exit code decides:** 0 is `allow`, 11 is `deny`, 13 is `escalate`, anything else (a crash, a signal, `126`, `127`, `2`, a timeout) is `escalate` with reason `check_error` (`timeout` for a timeout). stdout may be one strict JSON object with an optional `reason` string (at most 1024 characters, kept as the check's `detail`; a longer one is truncated, not dropped) and an optional `decision`; an unknown key in the object is ignored; a `decision` that disagrees with the exit code escalates (`check_error`). A parse failure of the output drops only the `detail`, never the verdict. An exit code of 256 wraps to 0 and cannot be told from a clean 0 (Residual risks).
- On a timeout or when the decision ends early, gatectl signals the check's process group (SIGTERM, then SIGKILL after a 2 s grace). Completion is detected without reaping the leader (`waitid` with `WNOHANG | WNOWAIT`), so the group id cannot be reused before the sweep; gatectl kills the remaining group, tells the lifeline watchdog `done`, and only then reaps the leader. A lifeline pipe makes a watchdog kill the group if gatectl itself dies. A process that calls `setsid` leaves the group and is not killed (Residual risks).

### Rule checks

```yaml
- name: ci-green
  type: rule
  when:
    - {path: ci.state, op: ne, value: passing}
  then: deny
  else: allow
```

A rule is a pure function of the input: no process, no environment and no clock; its cost is bounded by the limits in `glob`. `when` is a list of at least one condition, evaluated in listed order as an AND that stops at the first result: the first condition that is false ends the check with the `else` verdict; the first condition that errors ends it with `escalate`, reason `check_error`; if all hold the verdict is `then`. `then` is required and `else` defaults to `allow`; both are `allow`, `deny` or `escalate`. The check's `detail` is null unless it errored. A condition is `{path, op, value}`:

- `value` is required for `eq`, `ne`, `in`, `not_in`, `lt`, `le`, `gt`, `ge` and `glob`, and forbidden for `exists` and `absent` (a config error naming the key).
- `path` is dotted keys with numeric array indexes (`a.b.0.c`); key characters are `[A-Za-z0-9_-]`; a numeric segment is an index when the value is an array and a key when it is an object.
- Operators: `eq`, `ne` (JSON equality; arrays and objects compare whole; booleans never equal numbers; `value` may be JSON null to test for a present null), `in`, `not_in` (`value` is a list of scalars, null allowed; the path value must be a scalar), `lt`, `le`, `gt`, `ge` (both sides numbers, not booleans), `glob` (below), `exists` (the key is present, also when its value is null) and `absent` (the key is missing).
- A comparison operator applied to a missing path, to a null (except `eq` and `ne` with a null `value`, and `in` and `not_in` whose list contains null: a null path value then compares as a value) or to a value of the wrong type is an error, never a quiet `false`: the check's verdict is `escalate` with reason `check_error` and its `detail` names the path and the problem (`missing`, `null`, `type`). Only `exists` and `absent` accept a missing path. This is deliberate: a rule such as "deny when `ci.state` is not `passing`" must not allow because `ci` was absent. To make an optional field safe, put an `exists` condition first: `when: [{path: labels, op: exists}, {path: labels, op: glob, value: 'hold*'}]` is false, not an error, when `labels` is absent.
- `glob`: the path value is a string, or a list of strings of which any may match. `*` matches any run of characters except `/`, `**` any run including `/`, `?` one character except `/`; no other metacharacters; the match is anchored to the whole string and case sensitive. A pattern is tokenized once when the config is loaded and may be at most 128 characters after tokenizing (longer is a config error). The matcher must not translate the pattern into a regular expression or backtrack: it advances the set of live pattern positions one subject character at a time (a bit set is the intended form), so its cost is at most pattern length times subject length. Limits per condition: a subject string at most 4 KiB, a list at most 256 elements, all strings together at most 16 KiB; a larger subject is an error (`escalate`, `check_error`, detail `too large`). The deadline is checked between conditions. A `glob` against `labels` entries such as `pr=github.com/org/repo#3` needs `**` (`pr=**`), because `*` stops at `/`.
- There is no regex, no expression language and no code. There is no cross-field comparison, list quantifier or length; a policy that needs them uses a script check.

`validate` also reports a `then` or `else` outside the three verdicts, a missing or forbidden `value` and a glob pattern over 128 characters.

### Agent checks

```yaml
- {name: reviewer, type: agent, instruction_file: /etc/gatectl/reviewer.md, threshold: 0.8, model: haiku}
```

An agent check asks a Claude session, run through claude-session with kind `gate-check`, to apply the policy's instruction text to the input. It is exempt from `--mode`: it is always headless (design guide section 11). An agent check may only tighten a decision.

**Keys.** Exactly one of `instruction` (a string) and `instruction_file` (an absolute path read when the check runs); and the optional `skill`, `model`, `threshold`, `timeout`, `cache_ttl`, `permission_profile`, `sandbox`, `setting_sources` and `env_allowlist`, each defaulting from the `agent:` config block. The instruction text is trusted configuration. An `instruction_file` is opened without blocking, must be a regular file of at most 64 KiB, and is read once when the fingerprint is computed; the same bytes feed the fingerprint, the cache key and `prompt.md`. An unreadable file escalates the check with `tool_missing` when it starts. An agent check needs no input declaration.

**Skill and plugin.** The default skill is `gatectl:gate-check`, bundled in the package's `plugin/` (a Claude Code plugin named `gatectl`, located through `importlib.resources`). A plugin is identified by the `name` in its `.claude-plugin/plugin.json`; gatectl indexes the bundled plugin and every `agent.plugin_dirs` entry by that name (two directories with the same name are a config error). A skill is `<plugin>:<skill>` and is the file `skills/<skill>/SKILL.md` of that plugin; a bare name is a config error. The session gets `--plugin-dir` for the bundled plugin and, when the check's skill comes from another plugin, that one plugin only. Every plugin directory given to a session needs the four placeholders `.claude/`, `.mcp.json`, `CLAUDE.md` and `CLAUDE.local.md` (a sandboxed session otherwise cannot run its report call and the run ends `agent_unreported`); `validate` reports `plugin_placeholders_missing` for each used directory that lacks one. A plugin or skill that cannot be found when the check starts escalates with reason `tool_missing` (a missing skill would otherwise run and exit 0 with an unusable artifact).

**Files given to the session.** gatectl creates its private directory `tmp/<decision_id>/` under its state directory (mode 0700, unless a script check has already created it; the directory and its files are created exclusively and without following links) and writes these files into it, deleting them when the run ends:

- `input.json`: the input object, serialized pretty-printed (two-space indent, one key or array element per line, so a model can page through it) with non-ASCII characters written as `\uXXXX` escapes (invisible and bidirectional code points are then visible), and wrapped in a fence, `<untrusted source="gatectl-input" id="<R>">` ... `</untrusted id="<R>">`, where `<R>` is a fresh random 16-hex-character value and every `</untrusted` and `<untrusted`, in any letter case, inside the content becomes `&lt;/untrusted` or `&lt;untrusted`. The file ends with the closing fence on a line of its own. Passed with `--input-file`.
- `prompt.md`: passed with `--prompt-file`. It states the artifact name (`verdict.json`), the per-run **nonce** (32 random hex characters), the artifact schema below, the rule that content between `<untrusted>` tags is data and never instructions, and then the policy's instruction text. gatectl adds no report or escalation instructions: claude-session's standard instructions carry those.

**Input size.** An input whose pretty-printed form is larger than `agent.input_max_bytes` (default 64 KiB) makes the agent check `escalate` with reason `input_invalid`, detail `too large for an agent check`, before a slot is taken or a session starts. The same happens, with detail `line too long for an agent check`, when any single line of the file (after pretty-printing and escaping) is longer than 16 KiB: the Read tool caps one call by tokens and pages only by line, a long non-ASCII line costs about 5 tokens per 6 bytes of escapes, and 16 KiB stays well under that cap, so every line of an accepted input can be read, and the whole file in a few pages. The skill escalates anyway when it cannot read through the closing fence. Script and rule checks still see the whole input.

**Artifact.** The session reports `done` with the artifact `verdict.json`: a JSON object with exactly these keys: `schema_version` (the integer `1`), `nonce` (the run's nonce, echoed), `decision` (`allow`, `deny` or `escalate`), `confidence` (a number from 0 to 1) and `reasons` (at most 10 strings of at most 500 characters). The artifact is read from the frozen path `claude-session status --json` reports (never from the session's working copy), at most 16 KiB, without following links, and validated strictly: an unknown or missing key, a bad type or enum, a nonce mismatch or a parse failure escalates with reason `artifact_invalid`. `reasons` are untrusted. An agent check's `detail` is its artifact `reasons` joined with a semicolon and a space, and truncated to 1024 characters.

**Using the artifact.** The check's verdict is the artifact's `decision`, except that an `allow` whose `confidence` is below the `threshold` (default 0.8) becomes `escalate` with reason `low_confidence`. A `deny` or `escalate` is never loosened by any confidence. Confidence is a one-way gate, not a probability: it did not separate decisions in live runs.

**Outcome handling.** A run is a usable verdict only if `exec` exits 0 with outcome `done` and `report.implicit` false (read from the outcome object that `exec` prints and writes to `--outcome-file`, shape `claude-session/schemas/cli/outcome.json`), `status` reports a non-null artifact named `verdict.json`, and the artifact is valid. The table applies to `exec`'s exit code; a `start` or `status` that fails, times out or prints unusable JSON is `check_error`; `session_cmd` not found is `tool_missing`; a failing `forget` never changes the verdict. Anything else escalates, with the reason from this table:

| What happened | Reason |
|---|---|
| exit 14 (any end reason) | `agent_unreported` |
| exit 16 | `timeout` |
| exit 12 with end reason `sandbox_unavailable` | `sandbox_unavailable` |
| exit 12 with end reason `claude_not_found`; `session_cmd` not found; the skill or plugin not found | `tool_missing` |
| exit 0 but outcome not `done`, or `report.implicit` true, or the artifact missing, malformed or invalid, or its name, size or SHA-256 differing from what `status` reports | `artifact_invalid` |
| exit 13 (the agent reported blocked or needs-input) | `check_escalated` |
| exit 15, 17, 18, any other exit 12 end reason (including `unsafe_setting_sources`), any other non-zero exit | `check_error` |

The verdict is judged by claude-session's outcome, not by gatectl's budget: a run with exit 0, outcome `done` and a valid artifact is used even if its end reason is `timeout`.

**Safety settings** are passed on every call (design guide section 11) and each has a config key replacing it:

| Setting | Passed as |
|---|---|
| `permission_profile` | `--permission-profile <file>` (the bundled file, a copy of claude-session's built-in `review` profile, or the configured absolute path) |
| `sandbox` (`required`, `preferred` or `off`) | `--sandbox <value>` verbatim |
| `setting_sources` | `--setting-sources "<comma list>"` (`""` when empty; for `gate-check` a non-empty list makes claude-session refuse the launch, `unsafe_setting_sources`, exit 12, which becomes `check_error`) |
| `env_allowlist` | `--env-allowlist-only <NAME>` per name, or `--env-allowlist-only ''` |
| `model` | `--model=<m>` when set |
| the decision's repo | `--repo=<id>` when the decision has a repo |

`validate` reports `sandbox_lowered` (a warning) for `preferred` and `off`, and `unsafe_setting_sources` (an error) for a non-empty `setting_sources`. A `model` of `null` follows Claude Code's default, so a Claude Code update can change the judge: pin `model` for a policy that matters. Callers must not pass `--hook pre-launch` selectors that match `gate-check`: a `pre-launch` hook that calls gatectl must set `exclude_kinds: [gate-check]` or it recurses until its timeout (claude-session residual risk).

**Run sequence.** One agent run is these steps, in order:

1. `session_cmd start --kind gate-check --mode headless --skill <skill> --prompt-file <f> --input-file <f> --plugin-dir <bundled> [--plugin-dir <the plugin holding the check's skill>] --timeout <n>s --label owner=gatectl --label policy=<name> --label decision=<decision_id> --label state=<tag> --actor auto:gatectl --decision-id <decision_id> --permission-profile <file> --sandbox <level> --setting-sources "" --env-allowlist-only <NAME>... [--repo=<id>] [--model=<m>] --json`. It prints `csession_id` and the run number.
2. gatectl stores `csession_id` in its slot row.
3. `session_cmd exec --session-id <id> --run <n> --outcome-file <private path> --json`. gatectl waits for it for at most the `--timeout` given in step 1 plus 10 s. If it has not returned by then: `session_cmd stop <id> --grace 2s --actor auto:gatectl`, then SIGTERM to the `exec` child (exact PID), then SIGKILL after 2 s.
4. `session_cmd status <id> --json` for the frozen artifact path, `sha256`, `size` and `sandbox_active`.
5. `session_cmd forget <id> --actor auto:gatectl --decision-id <decision_id>`, delete `input.json` and `prompt.md`, release the slot.

After a failure of any step (including a `start` that exits 12 and allocated a session) gatectl runs `session_cmd list --label decision=<decision_id> --json`, runs `stop --grace 2s --actor auto:gatectl` on every session whose run is not final (live or pending; a pending run is cancelled by `stop`, and `forget` refuses it) and then `forget`, and removes the directory and releases the slot. A failed `forget` or `stop` is left to `reconcile`. `forget` runs on every path that allocated a session.

**Reuse.** The result of an agent check is reused for an identical input: the cache key is the SHA-256 of the policy's fingerprint for the scope (it covers the policy name, `input.ignore` and every check), the agent check's name, the scope, and the hash of the input with the policy's `input.ignore` keys removed; a row is valid for the effective `cache_ttl` (default 10 minutes) and carries its own `expires_at` (its time plus that ttl); a row whose time is later than now, or whose `expires_at` has passed, is ignored. With an effective `cache_ttl` of `0` the cache is neither read nor written. Only a valid artifact from a `done` run is cached; a failure never is. Script and rule checks always run again. A reused result is marked `reused: true`, its `duration_ms` is the time spent reading the cache, it still produces its own decision with a new `decision_id` and audit line, and `--no-cache` skips the lookup but still writes the fresh result.

**Slots.** At most `agent.max_parallel` (default 3) agent runs are live across all gatectl processes. A slot is a row in `state.db` (holder PID, holder process start time, boot id, decision id, `csession_id`, run start, `expires_at` = the check's deadline plus 60 s). A slot only counts against `agent.max_parallel`; it is not the liveness signal of a session or a directory (see `reconcile`). A slot is free when its holder is dead: the PID is gone or is a zombie, or its process start time or the boot id differs from the row's. The holder's start time is read after the last `)` of `/proc/<pid>/stat` on Linux (a process can name itself anything). `expires_at` is informational (`reconcile` reports an overdue live holder) and never frees a live holder. Acquiring a slot is one `BEGIN IMMEDIATE` transaction that deletes dead holders' rows and inserts the new row; it succeeds while fewer than the acquiring process's `agent.max_parallel` rows are live (there is no slot number). A slot is acquired before the agent run's files are written. Waiting follows Deadline, step 3.

**Cleanup.** After reading the artifact, gatectl copies its validated fields into `state.db`, runs `forget` (Run sequence, step 5) and deletes the run's files; the directory itself is removed when the check ends. Claude Code's own transcript under its projects directory is not removed by `forget` (Residual risks). A run that is still live when claude-session's own `--timeout` ends is finished by claude-session (exit 16); gatectl calls `stop` only on the overdue and signal paths in the run sequence.

**Probe.** `validate --probe` runs one agent check on a built-in input whose instruction asks for `allow`, with the configured safety settings, and reports exit code, end reason, `sandbox_active` and what failed. It costs one run and happens only when asked. A probe acquires a slot, generates a `gd-` id, creates `tmp/<id>/` and labels its session `decision=<id>` like any run, so a concurrent `reconcile` leaves it alone; it records no decision and no audit line. A successful probe stores `probe_ok_at` and `probe_agent_hash` in `state.db`. The probe runs with the `agent:` block's settings; a check that sets its own `sandbox`, `skill`, `permission_profile`, `setting_sources`, `env_allowlist` or `model` is not covered by it (an accepted gap). `validate` applies `sandbox_lowered` and `unsafe_setting_sources` to every agent check's resolved values, per-check overrides included.

## Check order

One `check` runs these steps in order:

1. **Resolve.** Parse flags and load the config (see Config for what a config error is; an unreadable config or state exits 1). An unknown policy exits 2.
2. **Read the input** from `--input <file>`, or stdin when `--input` is `-` or absent (exit 2 if absent and stdin is a TTY; a `--input` file that is missing, unreadable or not a regular file exits 2). A `--reason-file` and `--input` are regular files (stdin excepted) read at most the size cap plus one byte, opened without blocking. Reading stops at `input_max_bytes` + 1 bytes and when `R` reaches 0 (the reserve is kept for recording). An input over `input_max_bytes`, not a strict JSON object, or not fully read by then is **unusable**: the decision is `escalate` with reason `input_invalid` (`timeout` when the read stopped at the deadline), no check runs, and it is recorded like any decision at step 8 using the reserve. Its scope and state come from step 3.
3. **Scope and state.** The scope is `--repo` when given; otherwise the input's `repo` when it is a valid repo id; otherwise `*` when `repo` is absent or null; otherwise the scope is indeterminate (Identifiers). Apply the repo override, compute the fingerprint and the effective state (for an indeterminate scope: the strictest state over the policy's stored rows, else its initial state).
4. **`off`:** log a `check_off` event, print the `off` result and exit 0. Nothing else is evaluated: not `applies_when`, not the declaration; no check runs and no decision is recorded.
4a. **Applicability.** If `applies_when` is present, the scope is determinate and the input parsed as a JSON object, evaluate it exactly as a rule check's `when` (ordered, stopping at the first condition that is false or errors). A false condition ends the check with `allow`, reason `not_applicable`: no check runs, no decision is recorded and nothing is logged, there is no `decision_id` and no `input_sha256`, `checks` is empty, `state` is the effective state, `shadow` and `enforced` are `false`, and the exit is 0 in every state. A condition that errors, an input that is not a JSON object and an indeterminate scope all count as applicable (fail closed): the check goes on to step 5.
5. **Input declaration.** An unusable input, an indeterminate scope or a declaration mismatch skips every check: the decision is `escalate`, reason `input_invalid` (`timeout` for a read that hit the deadline), `checks` is empty, and it is recorded. When the input did not parse, the declared fields and the identity strings are null.
6. **Deterministic checks.** Script and rule checks run in their listed order. The first `deny` ends the run (later checks are `skipped`). An `escalate` does not stop later script and rule checks, which can still tighten it to `deny`.
7. **Agent checks.** They run, in listed order, only if the result so far is `allow`; once the result is `deny` or `escalate` the remaining agent checks are `skipped`. Deterministic checks always run before agent checks, whatever order the YAML lists them in. Each agent check follows the steps in Deadline.
8. **Combine and record.** The decision is the most severe verdict. The reason is the reason of the first `deny`, else of the first `escalate` in check order, else `all_passed`. Then, in one `BEGIN IMMEDIATE` transaction, gatectl re-reads the effective state, inserts the decision with that state (and the `rev` of the row that supplied it, `state_rev`), appends its audit line and commits. After the commit it prints the result, flushes it, points descriptors 0, 1 and 2 at `/dev/null` (`dup2`: a stream is never merely closed, because closing a Python stream does not close the descriptor), starts the hook supervisor and exits without waiting for it.

The state read inside the step 8 transaction decides everything that follows: the recorded `state`, the printed `state`, `shadow` and `enforced` fields and the exit code. If a `set` committed while the checks ran, the decision is recorded and answered under the new state (`shadow` to `enforced`: exit follows the decision; `enforced` to `shadow`: exit 0). If the new state is `off`, nothing is recorded (a `check_off` log event only) and the `off` result is printed with an empty `checks`. For an indeterminate scope the re-read applies the same strictest-state rule. In `shadow` and `off` a failure after the state is known never blocks (Exit codes); in `enforced` it exits 1.

**Signals.** On SIGTERM, SIGINT or SIGHUP gatectl stops what it started: it signals the process group of each running script check, kills the process group of a hook it is waiting for, sends SIGTERM to its own `exec` child by exact PID, and runs the failure clean-up of the Run sequence (the `list` by label, `stop`, `forget`, remove the directory, release the slot) with the call timeouts above and within 10 s in total; what is left is `reconcile`'s. It writes a `terminated` log event, records no decision and exits 128 plus the signal number. A caller that timed out has already counted a veto; this only prevents leaked work.

### Deadline

One monotonic deadline starts when the process starts and covers reading the input. Its length is `--timeout` (a finite number of seconds greater than 0 and at most 86400; anything else exits 2) if given, else the policy's `timeout`, else `defaults.timeout` (60 s). The repo is known only after the input is read: when a per-repo override replaces `timeout`, the deadline becomes the start plus the override's `timeout` from that moment (never earlier than now). The usable budget `R` at any moment is the deadline minus now minus `defaults.record_reserve` (default 2 s, kept for recording and output). The **launch window** of an agent run is `L = R - 5 s`; the 5 s covers `start`, `status` and `forget`.

Rule checks always run (they take no time) and are never skipped for the deadline; a rule's `deny` after a timeout still outranks it. A script check starts only when `R` is greater than 0; its timeout is the smaller of its own `timeout` and `R`. If `R` is 0 or less when a script check would start, that check is not started: its verdict is `escalate`, reason `timeout`, detail `not started`, and every later script and agent check is `skipped`.

An agent check runs these steps in order. 1. Cache lookup: a hit needs no budget and no slot. 2. If `L` is below `agent.min_start_budget` (default 30 s), the check does not start: `escalate`, reason `budget_exhausted`. 3. Wait for a slot (poll every 250 ms); the wait ends with `escalate`, reason `busy`, when `L` falls below `agent.min_start_budget`. 4. After the slot is held, repeat step 2 and release the slot if it fails. 5. Launch with `--timeout <n>s` where `n` is the smaller of the check's timeout (agent default 300 s) and `L`, rounded up to a whole second (claude-session rejects 0).

When the budget ends while a check runs, the check in progress is stopped and the result is `escalate`, reason `timeout`, naming the check; in `shadow` the exit stays 0. Callers set the hook timeout at least 30 s above `--timeout` (for example `--timeout 540` under a 600 s hook; 20 s plus `record_reserve` is the worst case, see Bounds), so a slow check escalates instead of being killed and counted as a veto; the default hook timeout is 30 s and the default deadline is 60 s, so a hook wired without both is killed. `validate` reports `deadline_too_short` for a policy with an agent check whose effective deadline minus `record_reserve` minus 5 s is below `agent.min_start_budget` (also for `repos` overrides).

**Bounds.** Every claude-session call other than `exec` has a 5 s timeout; one that expires is abandoned (its process is signaled by exact PID) and counts as a failed step. `exec` is waited for at most `n + 10 s` (claude-session's own `kill_grace` after its timeout). A check normally answers before its deadline. When an agent run overruns, `start` may have taken its full 5 s before `exec` begins, so the `exec` guard (`n + 10 s`, with `n <= L`) expires at most `10 s - record_reserve` after the deadline (8 s by default). The failure clean-up that follows (the `list` by label, `stop <id> --grace 2s`, SIGTERM to the `exec` child and SIGKILL after 2 s, a second `stop`, `forget`) shares one budget of 10 s, as on the signal path; each call gets the smaller of 5 s and what is left of it. Recording follows (the lock wait is at most `record_reserve`, retried once, so at most 2 x `record_reserve`). The worst case with every call at its limit is therefore the deadline plus 20 s plus `record_reserve` (22 s by default). A step that could not finish is left to `reconcile`. Callers must set the hook's own timeout at least 30 s above `--timeout`, which holds for a `record_reserve` up to 10 s; with a larger `defaults.record_reserve` the margin is 20 s plus that value.

## Reasons

`reason` is a closed list. The policy's `reason` and each check's `reason` come from it; free text goes only in a check's `detail`.

| Reason | Meaning |
|---|---|
| `all_passed` | every check allowed |
| `check_denied` | a check denied |
| `check_escalated` | a check escalated by its own verdict |
| `input_invalid` | the input is missing a declared key, has the wrong type, is too large, is not a strict JSON object or has an unusable `repo`, or is too large for an agent check |
| `timeout` | a check ran out of its time, or the input read did |
| `budget_exhausted` | too little of the deadline was left to start an agent check |
| `busy` | no agent slot became free within the budget |
| `tool_missing` | `claude-session`, the skill, the plugin, an `instruction_file` or a script executable could not be found or read (its `detail` names the missing command and, for `claude-session`, the install command `uv tool install git+https://github.com/agent-workflow-kit/claude-session`) |
| `agent_unreported` | the agent run ended without a report |
| `artifact_invalid` | the agent's artifact is missing or fails validation |
| `low_confidence` | the agent allowed below the threshold |
| `sandbox_unavailable` | the required sandbox could not start |
| `check_error` | a check crashed, was killed, printed contradictory output, or hit a rule type error |
| `not_applicable` | the policy's `applies_when` is false; nothing ran (never an authorization) |

## Outcomes

After the fact, someone says whether a decision was right: `gatectl outcome <decision-id> agree|disagree [--signal S] [--reason-file F]`.

| Decision | `agree` means | `disagree` means | Counts as |
|---|---|---|---|
| `allow` | it was right to allow | it should not have been allowed | unsafe miss |
| `deny` | blocking was right | it should have been allowed | over-strict miss |
| `escalate` | a human was needed | it could have been decided automatically | over-strict miss |

- Outcomes are append-only: each is a record with its actor, signal and optional untrusted reason. A decision made while the policy was `off` does not exist, so it has none, and neither does a `not_applicable` answer. Outcomes are ordered by their insertion sequence number, not by their clock (equal or stepped-back timestamps cannot reorder them). Every `outcome` call appends one record; `changed` is true when the decision's effective outcome changed. A reason is read to at most 1 KiB (`--reason-file -` waits at most 10 s for stdin) and a longer one is truncated with a final `…`. An id that is unknown or was pruned exits 10 (`not_found`, message "unknown or pruned id; see audit.jsonl"). An outcome on a decision of a policy that is no longer configured is recorded and counted but never changes a state (a `drop_skipped` log event).
- **Effective outcome** of a decision: read its outcome records in sequence order. A `disagree` from any actor sets it to `disagree`. An `agree` from a `human:*` actor sets it to `agree`. An `agree` from any other actor is recorded and shown but never changes it. No outcome yet is `pending`. So an automatic `agree` can neither inflate a record nor cancel a `disagree`; only a later human outcome supersedes one.
- `--signal` defaults to `human` for a human actor and `auto` otherwise. A late failure source (a revert, an incident) files `outcome <id> disagree --signal revert`; gatectl knows no sources of its own. Callers find the decision by the id they stored, or with `decisions --policy P --object-id X`. Gates wired as hooks file no outcomes themselves. Whoever operates the gate files them, within the rules above: a human files `agree` (at a TTY, or a tool relaying the human's own action with `--actor human:<name>`, as review-watch does when you accept or reject a draft), and automation (a cron job, a harness rule) files `disagree` for a revert or an incident. An automatic `agree` is recorded and never counts, so a gate that only automation operates builds no record until a human files its outcomes, for example in a batch from `decisions --outcome pending --json`; see the README wiring checklist.
- **Automatic drop to shadow.** When an outcome makes a decision's effective outcome `disagree` (from `agree` or `pending`) and that decision was an `allow` recorded in state `enforced`, and the row that gave the decision its state (its `state_rev`, recorded on the decision) is still the effective state row of the decision's scope (the repo row, else the `*` row), gatectl writes a `shadow` row for the decision's scope (the repo, or `*`: a decision with no repo drops the `*` row, which drops every repo that inherits it), appends a `state_change` audit record with cause `miss` whose `result.triggered_by` is the decision's id, all in the transaction that recorded the outcome, then fires `post-state-change` after the commit. A different effective row (a re-enforcement, a repo row written since, a drop already done) means the miss belongs to an earlier enforcement: it is counted and nothing else happens (a `drop_skipped` log event). Other repos keep their state. An over-strict miss, or a miss on a `shadow` decision, only counts in the record. The outcome result's `miss` is non-null only when this outcome record changed the effective outcome to `disagree` (so a second `disagree` on an already `disagree` decision has `miss: null`).

### Track records and recommendation

`stats` builds one record per policy, repo (or none) and fingerprint: decisions by verdict, outcomes by effective outcome, unsafe and over-strict misses, counts by signal and by actor kind, and per-reason counts with the time each was last seen. Shadow and enforced decisions both count. Records are keyed by the decision's scope and are not pooled across repos. `actor_kinds`: `human` is a `human:*` actor, `automatic` an `auto:*` actor, `unattributed` the actor `auto:unknown`. `signals` and `actor_kinds` count outcome records (not effective outcomes). `reason_counts` count check entries by their reason (a decision with two failing checks counts twice) with the last time each was seen. `--since` selects decisions by decision time, with all their outcomes.

The recommendation uses unsafe misses only. A **case** is the set of decisions of one record that share a `case_key`, a SHA-256 computed when the decision is recorded: of the canonical JSON of the list `[object_type, object_id, declared values]`, with the keys listed in `input.ignore` left out of the declared values, taken from the validated input before capping, or, when `object_id` is null, the SHA-256 of the canonical serialization of the input with the policy's `input.ignore` keys removed (the same hash the cache key uses; so a retry of the same input is one case, and different inputs are different cases). A harness that polls an object should send `object_type` and `object_id`. `n` is the number of cases that have at least one resolved `allow` decision (effective outcome `agree` or `disagree`), and `k` is the number of those cases in which any resolved `allow` has effective outcome `disagree`; so retries and polling of one object count once. `unsafe_misses` and `over_strict_misses` count decisions (an `allow` with effective outcome `disagree`; a `deny` or `escalate` with `disagree`); `unsafe_miss_cases` is `k`, the number of cases with at least one unsafe miss; `resolved_decisions` is the raw count of resolved `allow` decisions and `resolved_allows` is `n`. `upper_bound` is the one-sided Clopper-Pearson upper bound `U` at `recommend.confidence` (default 0.95): `U` solves `P(X <= k | n, U) = 1 - confidence`, `U = 1` when `k = n`, `U = 1` when `n = 0`; computed by bisection to a tolerance of 1e-9. `recommend` is `enforce` when the scope is not `enforced` and `U <= recommend.max_miss_rate` (default 0.05; with `k = 0` that takes 59 cases, 58 give 0.0503), `not_yet` otherwise, `keep` when `enforced` and `U` holds, `reconsider` when `enforced` and it does not. It is advisory: gatectl never enforces by itself. With `--since`, or for a record whose fingerprint is not the current one for its scope, `recommend` is `null`; the record carries `current: true|false`.

## State changes

`gatectl set <policy> off|shadow|enforced [--repo ID] [--all] [--reason-file F]` writes the state row of exactly one scope (`*` without `--repo`; `--repo '*'` names it too; `--all` together with `--repo` exits 2). `previous_state` is the scope's effective state before the call. A stored row is **equal** to the request when its state matches and, for `enforced`, its fingerprint is the current fingerprint of the row's own scope. An equal row is a no-op (exit 0, `changed: false`, no audit record). Every other call writes the row and has `changed: true`: a row that was absent counts (an explicit row pins the scope even when the effective state does not change), and so does a human `set ... enforced` on an enforced row with a stale fingerprint, which **re-enforces** it: new fingerprint, `set_by`, `set_at` and `rev`, an audit `state_change` whose `previous_state` equals `state`, and no `post-state-change` hook (the state did not change). This is how an operator accepts an edit; a gatectl upgrade that changes the bundled plugin is accepted the same way. Setting `enforced` is a human action (Actors and human actions); any other attempt exits 20 with reason `human_required` and writes a `warning` log event (no audit record: nothing changed). A human may enforce without a recommendation. `shadow` and `off` are open to any actor so that automation can always fail safe: they remove an automatic action's authority. For a gate wired as a veto they also remove the veto, which is a loosening (Residual risks). A global `set` never rewrites a repo row. `--all` is accepted only with `off` or `shadow` (otherwise exit 2): it writes the `*` row and every stored row of the policy in one transaction and audits one `state_change` per scope that changed; the result's `scope` is `*`, `previous_state` and `state` are those of scope `*`, `changed` is true when any scope changed and `scopes_changed` lists the scopes that changed. A policy with no rows at all gets the `*` row. There is no command that deletes a row: after an automatic drop to `shadow`, `set <policy> enforced --repo X` re-enforces X, and a repo row set to `shadow` stays until set again. `set` is audited with its actor and reason; the effective state of every other scope is untouched.

Every state row stores the fingerprint of its own scope's effective definition at the time the row was written (the `*` row with the policy's global definition, a repo row with that repo's effective definition; for an automatic drop, the decision's fingerprint) and a **revision** `rev`, taken from a store-wide counter that increases with every row write. When the scope's effective state is `enforced` and the row that supplies it has a fingerprint different from the current fingerprint of that row's own scope, `check` adds the warning `definition_changed` to its result and `policies` shows `definition_changed: true` for that row; the state does not change. A repo that has its own override and inherits an enforced `*` row is not compared with its own definition (the `*` row is compared with the global one): the override inherits the enforcement and has an empty track record; `set <policy> shadow --repo X` holds it until the record matures. A decision records the `rev` of the row that supplied its state as `state_rev` (null when the state came from the config's initial state or from an indeterminate scope).

`set ... enforced` prints a hint, never blocks: (1) when the policy has an agent check and no `validate --probe` has succeeded for the current agent configuration (`state.db` `meta` keys `probe_ok_at` and `probe_agent_hash`, the SHA-256 of the canonical `agent:` block, the resolved `session_cmd` and the gatectl version), a hint to run it; (2) when the policy has no script or rule check, a hint that no deterministic check backs an automatic action; (3) when `--repo` names a repo for which this policy has no recorded decision, a hint that the repo spelling matches nothing seen yet (a typo such as `Org/Repo` would enforce a scope no caller uses). The `set` result's `hint` is the hints joined by a space, or null.

## Commands

All commands take `--json`, `--config PATH`, `--verbose`, `--quiet`, `--actor` and a repeatable `--decision-id` (Global flags). `--version` prints `gatectl <version>`. `--repo` accepts `*` for scope `*` in `decisions`, `stats`, `policies` and `set`.

### `check`

`gatectl check <policy> [--input <file> | --input -] [--timeout <seconds>] [--repo <id>] [--no-cache] [--dry-run] [--actor A]`. Evaluates the policy (Check order) and prints the check result on stdout as JSON, always, whatever `--json` says; longer human-readable text goes to stderr only on a TTY. Exits 1, 2, 11 and 13 also write exactly one sanitized line to stderr, on a TTY or not, at most 512 characters, built only from closed fields. For exits 11 and 13 it is `gatectl: <decision> <policy>@<scope>: <reason> (<check name>) <decision_id>` (the decision grammar, the policy and scope grammars, a reason code, a configured check name, the decision id); for exits 1 and 2 it is `gatectl: <error code> <policy>` with the policy name when known. A hook caller reports this line as the veto or escalation reason. `--dry-run` loads and validates the policy, the declaration and the input, prints the resolved plan (policy, scope, effective state, fingerprint, each check with its resolved argv or skill, and what would be skipped) and runs nothing and records nothing. A dry run of an input that fails the declaration prints the plan with `input_valid: false` and exits 0. In state `off`, or when `applies_when` is false, the plan shows every check with `would_run: false`. The plan shape is `schemas/cli/check-dry-run.json`. `--actor` is recorded with the decision.

### `outcome`

`gatectl outcome <decision-id> agree|disagree [--signal S] [--reason-file F|-]`. Records an outcome (Outcomes). The reason is untrusted, at most 1 KiB (longer is truncated); `--reason-file -` reads at most 1 KiB + 1 byte and waits at most 10 s.

### `decisions`

`gatectl decisions [--since T] [--policy P] [--repo R] [--object-id X] [--outcome pending|agree|disagree] [--decision allow|deny|escalate] [--declared key=value] [--limit N]`. Lists decisions, newest first (default limit 100), with their effective outcome. Rows carry `declared`, `input_sha256`, `decision`, `state`, `tool`, `hook`, `actor`, `fingerprint`, `state_rev`, `case_key` and the effective outcome. `--outcome` filters by the effective outcome, `--decision` by the verdict, `--declared` by an exact match on a declared string, and `--repo '*'` selects scope `*`.

### `show`

`gatectl show <decision-id>`. One decision in full: every check's result and detail, the declared fields, the cache source, the outcome history, the effective outcome and the recorded input hash.

### `stats`

`gatectl stats [--policy P] [--repo R] [--since T]`. Track records and recommendations (Track records and recommendation).

### `set`

`gatectl set <policy> off|shadow|enforced [--repo ID] [--all] [--reason-file F]` (State changes). `set <policy> off --all` is the kill switch. `--reason-file -` reads at most 1 KiB + 1 byte and waits at most 10 s.

### `policies`

`gatectl policies [--repo ID]`. Every policy with its initial state, its stored scope rows (state, who set it, when, cause, the fingerprint it was set for, its revision `rev`, `definition_changed`), the effective state for the given repo (or `*`), its fingerprint, a summary of each check and the recommendation of each record. With `--repo` it shows that repo's effective definition.

### `validate`

`gatectl validate [--probe]`. Lints the config without running a check: the whole file and each policy and override eagerly, including resolution of binaries, files, skills and plugins. Exit 0 when valid, 2 when not, printing each problem as `{code, path, message}` and each warning in the same shape. Problem codes: `unknown_key`, `invalid_value`, `invalid_rule`, `glob_too_long`, `unresolved_argv0`, `skill_not_found`, `plugin_not_found`, `plugin_placeholders_missing`, `instruction_file_unreadable`, `override_unknown_policy`, `override_unknown_key`, `bare_skill_name`, `unsafe_setting_sources`, `deadline_too_short`, `session_cmd_unresolved` (a problem when some policy or override has an agent check, a warning otherwise) and `state_db_missing`. Warning codes (they never make the config invalid): `relative_argv`, `sandbox_lowered`, `orphan_state` (a policy in `state.db` that is not in the config), `agent_only_policy` (a policy with no script or rule check) and `session_cmd_unresolved` (when no policy or override has an agent check). `--probe` also runs the probe (Agent checks) and exits 12 when it fails.

### `export`

`gatectl export [--log] [--since T]`. Prints `audit.jsonl` (default) or `log.jsonl` records as JSON lines; `--since` filters by the record's `ts`.

### `reconcile`

`gatectl reconcile [--dry-run]`. Takes the `reconcile` lease (below), then: frees slot rows whose holder is dead; removes every `tmp/*` directory whose `owner` file names a process that is not alive (a directory with no readable `owner` file counts as dead 10 minutes after it was created); deletes cache rows past their expiry; and, when `session_cmd` resolves (Config), lists sessions labeled `owner=gatectl` and `state=<tag>` (`session_cmd list --label owner=gatectl --label state=<tag> --json`) and, for each whose `decision=<id>` label matches the decision id grammar (`gd-` and 12 base32 characters; a session with any other value is left alone, neither stopped nor forgotten) and has no `tmp/<id>/` directory with a live owner (the path is derived only from that validated id, and the directory's realpath must lie inside the state directory's `tmp/`), runs `stop --grace 2s` on every run that is not final (live or pending) and then `forget`; as `reconcile` is not bound by a check deadline, its `stop` call has a 15 s timeout (the 2 s grace, the SIGKILL and the wait for the final run), so a stubborn session is killed and not abandoned. A session sweep that cannot run because `session_cmd` does not resolve is skipped with `sessions_checked: false` and exit 0, so a standalone install loses nothing under cron; a `list` that fails ends the sweep, with `sessions_checked: false` and exit 12. Reports counts (`slots_freed`, `sessions_stopped`, `sessions_forgotten`, `tmp_removed`, `cache_expired`), `overdue` (live holders past `expires_at`; never freed) and `overdue_holders` (`{decision_id, pid}` of each, so an operator can `kill -9` that exact PID). Passes `--actor auto:gatectl` to `stop` and `forget`. A label value is compared as a string and never used to build a path; the only path built is `tmp/<id>` from an id that passed the grammar. Safe to run at any time and under cron. `--dry-run` reports what it would do and changes nothing.

### `prune`

`gatectl prune [--older-than D] [--dry-run]`. Deletes decisions, with their outcomes, older than `D` (by decision time) from `state.db`, except current decisions, and deletes cache rows past their `expires_at` whatever `D` is. A decision is **current** when its fingerprint equals the current effective fingerprint of its scope for a configured policy: the repo's override fingerprint when an override for that repo exists, else the global definition's (so the live track record of an ordinary repo is kept); a policy that is no longer configured has no current decisions. A policy whose fingerprint computation hit the `unreadable` marker is skipped entirely and listed in `skipped_policies`, so a transient read failure never makes live records look old. Deletion runs in batches of at most 500 rows per transaction; `prune` never runs `VACUUM` and checkpoints the WAL with `PASSIVE`, so it cannot hold the write lock longer than `record_reserve`. `audit.jsonl` and `log.jsonl` are never pruned. Without `--older-than` it uses `retention.older_than`; when that is `null` it deletes no decisions (expired cache rows are still deleted). The result is `{dry_run, deleted, older_than, kept_current, skipped_policies, already_running}`: `deleted` counts the decisions, outcomes and cache rows and `kept_current` the decisions kept because they are current. `prune` is audited when a non-dry-run call deleted any row; `inputs.older_than` is null when only cache rows were deleted; dry runs are not audited.

**Maintenance lease.** `reconcile` and `prune` each take a lease before doing anything: a `meta` row `lease:<command>` holding the holder's PID, start time and boot id, written in one `BEGIN IMMEDIATE` transaction; a lease whose holder is dead is taken over at once. A second caller that finds a live holder exits 0 with `already_running: true` and does nothing (the counts are 0 and, for `reconcile`, `sessions_checked` is `false`). The lease is released when the command ends.

### `cron`

`gatectl cron install|uninstall [--dry-run]`. Writes or removes one block in the user's crontab, between the lines `# gatectl managed` and `# gatectl managed end`: an explicit `PATH=<home>/.local/bin:/usr/local/bin:/usr/bin:/bin` (`<home>` expanded at install time), a line `XDG_STATE_HOME=<value>` only when that variable was set when the command ran, then `*/15 * * * * gatectl reconcile --quiet` and `17 3 * * * gatectl prune --quiet`, in that order (`prune` still deletes expired cache rows while `retention.older_than` is null). `install` always writes both lines and replaces an existing block, so `awkit cron install` and `gatectl cron install` produce the same block and can run in any order. `--dry-run` reports the lines and changes nothing. `cron` writes a `cron` log event.

## Global flags

| Flag | Meaning |
|---|---|
| `--json` | machine-readable output (always on for `check`) |
| `--config PATH` | config file, replacing `~/.config/gatectl/config.yaml` (drop-ins still apply from its directory) |
| `--verbose`, `--quiet` | more or less stderr |
| `--actor A` | `human:<name>` or `auto:<name>`; accepted by every command (Actors and human actions) |
| `--decision-id ID` | repeatable up to 16 times (exit 2 beyond that), accepted by every command; recorded in the audit record of the command |

`--decision-id` values must match `^[A-Za-z0-9._:@/-]{1,128}$` (exit 2 otherwise); `--actor` must match its grammar. `--decision-id` is the caller's own decision id (from an earlier gate), unrelated to gatectl's `gd-` ids. At most 16 values are accepted. Every audit record carries the caller's ids in `inputs.decision_ids` (an empty array when none); the record's `decision_id` stays gatectl's own id for `decision` and `outcome` records.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `check`: allow, or any result in `shadow` or `off`; other commands: success |
| 1 | internal error; `check` also uses it when the policy's state is unknown (config or database unreadable, or `state.db` missing, or present with no `meta.schema_version` row (an empty or schema-less file), while `audit.jsonl` in the same directory is not empty: `state_db_missing`; gatectl never creates a new database over an existing history; restore the database, or move `audit.jsonl` aside on purpose) and for any internal failure while the state is `enforced` |
| 2 | usage error: bad flags, an unknown policy, a config error, a bad `--timeout`, no `--input` with a TTY stdin |
| 10 | not found: a decision id |
| 11 | `check` in `enforced`: deny |
| 12 | the requested operation failed for an expected reason (`validate --probe` failed) |
| 13 | `check` in `enforced`: escalate |
| 20 | refused: `set ... enforced` without a human (`human_required`) |
| 21 | ambiguous decision-id prefix |

There are no tool-specific codes above 22; a process stopped by a signal exits 128 plus the signal number (Check order, Signals). In `shadow` and `off`, gatectl never exits with anything but 0 for a decision it could evaluate: when the state is known to be `shadow` or `off` and a later step fails (for example the decision cannot be written), `check` exits 0 with no `decision_id` key, the would-be `decision` and `reason` kept, an `error` object and a warning on stderr, because nothing may rely on a shadow result. `BEGIN IMMEDIATE` waits at most `defaults.record_reserve` (default 2 s) for the write lock; a reader never waits (WAL). A lock timeout in step 8 is a failure after the state is known: exit 0 with `error` in `shadow`, exit 1 in `enforced`, and the check retries the transaction once before failing. `state.db-wal` and `state.db-shm` are part of the database: do not remove them by hand.

## Output by exit code

- **`check`** exits 0, 11 and 13 print the check result. Exits 1 and 2 print the error envelope. A `--dry-run` prints the plan.
- **Other commands** print their result object on exit 0 and the error envelope otherwise. `validate` exit 2 and `--probe` exit 12 print the problem list or probe report.

### Check result

```json
{
  "schema_version": 1,
  "decision_id": "gd-4k2m7q5x3a2b",
  "policy": "auto-merge",
  "scope": "github.com/org/repo",
  "state": "shadow",
  "shadow": true,
  "enforced": false,
  "decision": "allow",
  "reason": "all_passed",
  "fingerprint": "sha256:...",
  "input_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "checks": [
    {"name": "ci-green", "type": "rule", "verdict": "allow", "reason": null, "detail": null, "duration_ms": 1},
    {"name": "reviewer", "type": "agent", "verdict": "allow", "reason": null, "detail": null, "confidence": 0.95, "reused": false, "duration_ms": 31000}
  ],
  "warnings": [],
  "error": null
}
```

`decision_id` and `input_sha256` are present exactly when a decision was recorded. In state `off` the result has `decision: null` and no `decision_id` key. In a shadow failure the result keeps the would-be `decision` and `reason` and has no `decision_id` key and a non-null `error`. For `not_applicable` the result has `decision: allow`, reason `not_applicable`, the effective `state`, `shadow: false`, `enforced: false`, no `decision_id` key, no `input_sha256` key and `checks: []`. A caller reads an absent `decision_id` as null. (Callers that read a hook's stdout, such as claude-session and forgectl, accept `decision_id` only as a string or list and warn on anything else, so gatectl never prints a null one.) `shadow` and `enforced` are true only for an evaluated answer in that state (never for `not_applicable`). `state` is the effective state read when the decision was recorded. A check's `reason` is `null` when it allowed; `confidence` and `reused` appear on agent checks only. `input_sha256` identifies exactly what was evaluated; the declared field values are in `show`. `warnings` holds the closed codes `repo_invalid`, `repo_mismatch`, `definition_changed`, `config_problem` (another policy in the config is invalid, or, for a command that runs no check, a shared key is invalid; `validate` lists it) and `output_truncated` (a script's stdout or stderr passed 64 KiB). No input text is printed, only the declared fields' values in the recorded decision (shown by `show`), never in this result. stdout carries only this object, so a hook caller that reads a hook's stdout finds `decision_id`.

### Other results

`outcome`: `{decision_id, outcome, signal, actor, changed, effective_outcome, miss: null|"unsafe"|"over_strict", state_change: null|{policy, scope, state, cause}}`. `set`: `{policy, scope, state, previous_state, changed, scopes_changed, hint}`. `decisions`: `{decisions: [...], truncated}`. `show`, `stats`, `policies`, `validate`, `export` (JSON lines), `reconcile`, `prune`, `cron`: their documented shapes in `schemas/cli/`.

### Error envelope

`{"error": {"code": "...", "message": "...", "reason": "...", "details": {...}}}`. `code` is one of `usage` (2), `config_invalid` (2), `not_found` (10), `ambiguous` (21), `refused` (20, with `reason`), `failed` (12) and `internal` (1). Messages name the offending key or id. `reason` is `human_required` for `refused`, and `schema_newer` or `state_db_missing` for `internal`.

## Hooks

gatectl is the gate, so it has no `pre-` hooks. It fires three post hooks, configured under `hooks:` with `cmd`, `timeout` (default 30 s) and `async`. A hook receives its payload on stdin from `tmp/hook-<random>/payload.json` (mode 0600; the supervisor removes that directory when the hook ends, on SIGTERM after killing the hook's process group, and in a `finally`; a supervisor killed with SIGKILL leaves it for `reconcile`), runs through `sh -c` in its own process group, with no `{...}` substitution and the environment of gatectl. Its stdout and stderr are connected to `/dev/null` and every descriptor above 2 of gatectl is closed in the child: a hook never holds a descriptor of the caller. Every child gatectl starts (the hook supervisor, a hook, the lifeline watchdog, a script check, a `session_cmd` call) gets explicit stdin, stdout and stderr (`/dev/null` or a private pipe gatectl reads) and `close_fds`, so no child ever inherits a descriptor of the caller; a gatectl killed with SIGKILL leaves no process holding the caller's pipes. The supervisor handles SIGTERM by killing the hook's process group and removing its directory. Hook output is discarded; the exit status, the timeout and a skipped hook are written to `log.jsonl` (a non-zero exit or a timeout as `hook_failed`, a skipped hook as `hook_skipped`). A hook's failure is never fatal. Payloads carry no input text and no `labels` key (gatectl stores no labelled objects). Common keys: `tool` (`gatectl`), `hook`, `object_type`, `object_id`, `repo` (nullable).

**Timing.** A result is printed before any hook runs. For `check`, every hook (the only one it fires is `post-decision`) runs detached whatever its `async` value says: a supervisor process in its own session applies the hook's `timeout` and kills the hook's process group, and `check` exits without waiting for it. For `outcome` and `set`, the result is printed first; an `async: false` hook is then awaited within its timeout and an `async: true` hook is detached as above. Hooks of one event run one after the other in config order; for `set --all`, one `post-state-change` fires per scope that changed. Hooks are fired after the commit, never inside a transaction.

| Hook | Fires | `object_type` / `object_id` | Other keys |
|---|---|---|---|
| `post-decision` | after a decision is recorded and committed | `decision` / the decision id | `policy`, `scope`, `state`, `shadow`, `enforced`, `decision`, `reason`, `fingerprint`, `actor`, `checks` (name, type, verdict, reason, duration) |
| `post-outcome` | after an outcome is recorded | `outcome` / the decision id | `policy`, `scope`, `outcome`, `signal`, `actor`, `effective_outcome`, `previous_effective_outcome`, `miss` |
| `post-state-change` | after `set` changed a state or wrote a row (one hook per scope written; not for a re-enforcement of an unchanged state), or the automatic drop wrote one | `policy` / the policy name | `scope`, `state`, `previous_state`, `cause` (`set` or `miss`), `actor`, `decision_id` (for `miss`) |

Hook environment: `GATECTL_HOOK`, `GATECTL_ID` (the object id) and `GATECTL_OBJECT_TYPE`. These names are reserved and never read as config. Wire `post-state-change` to a notification: an automatic drop to shadow is the event a human should hear about.

### Using gatectl as a hook

A caller wires a gate as a `pre-` hook, for example `cmd: "gatectl check start-work --timeout 540"` with `timeout: 600`. The caller's `pre-` hook rules apply to the exit code (0 continues, 13 escalates, anything else vetoes) and the printed `decision_id` is recorded in the caller's audit entry. A hook that launches claude-session sessions must exclude the `gate-check` kind. The README has the wiring checklist.

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
| `agent.input_max_bytes` | `65536` |
| `retention.older_than` | `null` |
| `policies` | `{}` |
| `repos.<id>.policies.<name>` | none |
| `hooks` | `{}` |

`session_cmd[0]` is either an absolute path or a bare file name. A bare name is searched only in `~/.local/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/usr/bin` and `/bin`, in that order, never through the caller's `PATH`; the first regular executable file is used by its absolute path for every call. A name containing `/` that is not absolute is a config error. `validate` prints the resolved path and reports `session_cmd_unresolved` when none is found; the probe hash uses the resolved path.

**Ranges.** A value outside its range is an `invalid_value` config error: `defaults.timeout`, a policy `timeout` and `--timeout`: greater than 0 and at most 86400 s; `defaults.script_timeout`, a check `timeout`, `agent.timeout`, a hook `timeout`: greater than 0; `agent.min_start_budget`: at least 1 s; `defaults.record_reserve`: 100 ms to 60 s; `defaults.input_max_bytes`: 1 to 16777216; `agent.input_max_bytes`: 1024 to 1048576; `agent.max_parallel`: an integer from 1 to 32; `agent.threshold` and a check `threshold`: 0 to 1; `recommend.confidence`: above 0 and below 1; `recommend.max_miss_rate`: above 0 and at most 1; `cache_ttl` (any level): `0` (off) or a duration; `retention.older_than`: null or a duration greater than 0.

The file as a whole (YAML syntax, unknown top-level keys, `me`, `session_cmd`, `defaults`, `agent`, `retention`, `hooks`, the `repos` structure) is validated at load. A failure in the shared part exits 2, naming the key, for `check`, `reconcile`, `prune`, `cron` and `set ... enforced`. The other commands (`set ... off|shadow`, including `--all`, `outcome`, `show`, `decisions`, `stats`, `policies`, `export`) need only a file that parses as YAML: they use the built-in default for an invalid shared key, add the warning `config_problem` to their result (or a line to stderr) and carry on, so the kill switch and the fail-safe commands work whenever the file can be read; `validate` lists the problem. `set <policy> off|shadow` and `outcome` accept any policy name that is in the file or in `state.db`, even one whose own definition is invalid. Each policy and each `repos.<id>.policies.<name>` is validated separately: `check <policy>` fails (exit 2) only when that policy or its override for the scope is invalid; other invalid policies add the warning `config_problem` to its result and are listed by `validate`. A policy that is invalid also fails `set <policy> enforced` (the fingerprint needs its definition). An unreadable config file is an unknown state (exit 1). Resolution of binaries, files, skills and plugins is never done at load; it happens per check (Script checks, Agent checks) and failures escalate with `tool_missing`. `validate` does all of it eagerly.

Precedence for config values is flags > per-repo override > environment variables (only the keys listed in Environment variables) > config (the global file, then drop-ins in lexical order, a later drop-in winning) > built-in defaults. A per-repo override sets policy keys (`timeout`, `cache_ttl`, `checks`, ...), so it beats every `defaults.*` and `agent.*` value, an environment value included; it is not a layer of the `defaults` and `agent` keys (Per-repo overrides). A policy's `state` in the config is only its initial state. The bundled permission profile, sandbox level, setting sources and env allowlist can each be replaced by the keys above, so a more permissive or stricter setup never depends on another tool's config.

Timing and reuse keys, from the strongest to the weakest source:

| Value | Order |
|---|---|
| total deadline | `--timeout`, then the repo override's `timeout`, then the policy's `timeout`, then `defaults.timeout` |
| a check's budget | the check's `timeout`, then `agent.timeout` (agent) or `defaults.script_timeout` (script), capped by the remaining budget |
| reuse window | the check's `cache_ttl`, the policy's `cache_ttl`, `agent.cache_ttl` |

## Environment variables

These config keys may be set as `GATECTL_<KEY>`, nested keys joined with `__`: `defaults.timeout`, `defaults.script_timeout`, `defaults.record_reserve`, `agent.timeout`, `agent.cache_ttl`, `agent.max_parallel`, `agent.min_start_budget`, `retention.older_than` (for example `GATECTL_DEFAULTS__TIMEOUT`, `GATECTL_AGENT__MAX_PARALLEL`). Safety keys (`agent.sandbox`, `agent.permission_profile`, `agent.setting_sources`, `agent.env_allowlist`, `agent.threshold`, `agent.model`, `agent.input_max_bytes`, `defaults.input_max_bytes`), lists and structured config cannot be set from the environment. `GATECTL_HOOK`, `GATECTL_ID` and `GATECTL_OBJECT_TYPE` are reserved for hooks. gatectl holds no credentials and reads no token variables; claude-session handles Claude's own login.

## Audit and log

`~/.local/state/gatectl/audit.jsonl` is appended for every decision, outcome, state change and prune; `log.jsonl` holds structured events. Both are public, append-only contracts (`schemas/audit.json`, `schemas/log.json`; the schemas give the shape and this section the rules).

| Audit `action` | Fires | `target` | `result` |
|---|---|---|---|
| `decision` | a decision was recorded | `<policy>@<scope>` | decision, reason, state, shadow, enforced |
| `outcome` | an outcome was recorded | the decision id | outcome, signal, effective outcome, miss kind |
| `state_change` | `set`, or the automatic drop | `<policy>@<scope>` | previous and new state, cause, reason, `triggered_by` (the decision id for cause `miss`, else null) |
| `prune` | a non-dry-run call deleted rows | `state.db` | counts, the age |

A decision's record carries `actor`, `decision_id` (the decision's own id), the `input_sha256`, the fingerprint and the policy, never the input. Every record carries `stdin_tty` at its top level, and its `inputs` carries `decision_ids` (the caller's `--decision-id` values, an empty array when none) and `actor_source` (`flag` or `default`), so `human:` with `stdin_tty: false` is visible; the per-action `inputs` and `result` shapes are in `schemas/audit.json`. Schema creation and migration commit in their own transaction before any decision is inserted or any audit line is appended, so a `state.db` without a schema (or of zero length) next to a non-empty audit log can only come from outside gatectl (`state_db_missing`). The record is appended inside the transaction that inserts the decision, before the commit, so a returned decision always has an audit line (a crash can leave a line for a decision that did not commit, never the reverse). A `check` while the policy is `off` writes a log event only. A refused `set` (exit 20) is not audited (a `warning` log event). A decision's time is the instant of its step 8 insert (inside the transaction). Every line of both files is written with a single `write` on a descriptor opened with `O_APPEND`, and a line over 64 KiB is capped before writing (its free-text fields are shortened until it fits), so concurrent writers never interleave. A short or failed `audit.jsonl` write (a full disk) is never truncated back, because another writer's line may follow it: the transaction fails, and the partial line stays; `log.jsonl` is never truncated either. A consumer skips a line that does not parse and reports it. Retention is forever.

The log event names are closed: `check_off`, `shadow_failure`, `hook_skipped`, `hook_failed`, `reconcile`, `drop_skipped`, `terminated`, `cron` and `warning`. The warning codes in a check result are the closed list in Check result.

## Files

| Path | Contents |
|---|---|
| `~/.config/gatectl/config.yaml`, `config.d/*.yaml` | config |
| `~/.local/state/gatectl/state.db` | SQLite, WAL, private: state rows, decisions, outcomes, cache, slots, `meta` (schema version, probe markers) |
| `~/.local/state/gatectl/audit.jsonl`, `log.jsonl` | public contracts |
| `~/.local/state/gatectl/tmp/<decision_id>/` | one directory per `check` process, mode 0700, created the first time a check needs one and removed when the check ends: `owner` (the creating process's PID, start time and boot id, written first), `s-<n>/` (the private working directory of the n-th script check, removed when that script ends), and for an agent run `input.json` and `prompt.md` |
| `~/.local/state/gatectl/tmp/hook-<random>/` | one directory per detached hook run: `owner` (the supervisor) and `payload.json` (mode 0600) |

The state directory is `$XDG_STATE_HOME/gatectl`, else `~/.local/state/gatectl`; no other override exists (tests set `XDG_STATE_HOME`). The directory has mode 0700; `state.db`, its `-wal` and `-shm` files, `audit.jsonl` and `log.jsonl` have mode 0600, set explicitly, not through the umask. Every `tmp/` directory and file is created exclusively and without following links.

**Removal of `tmp/` trees** (the end of a check, a script check's `s-<n>/`, and `reconcile`) walks with directory file descriptors, never follows a link (a link is unlinked, not entered), never crosses a mount point, makes each directory writable before deleting its contents, deletes the `owner` file last, and on anything unexpected (a directory that is not owned by the user, a file type it did not create, a changed device) refuses to go further, reports it (a `warning` log event) and leaves the directory to the next `reconcile`.

Policy files, `instruction_file`s and script paths must be outside every path an isolated Claude session can write, like every other tool's config.

## Labels

gatectl stores no labelled objects and has no label commands. Its claude-session sessions carry `owner=gatectl`, `policy=<name>`, `decision=<decision_id>` and `state=<tag>`, where `<tag>` is the first 12 hex characters of the SHA-256 of the realpath of the state directory (symlinks resolved, so every spelling of the path, a cron run's included, gives one tag).

## TUI

None in v1. A `browse` view of decisions and track records is a 1.x candidate.

## Upgrades

`state.db` migrations are additive only; a database from a newer gatectl is refused (exit 1, `schema_newer`) without touching it. Policy fingerprints change only when the rules in Fingerprint change, which starts fresh records.

## Residual risks

- A same-user process, including a prompt-injected trusted agent, can pass any `--actor`, so the human-only rules (`set ... enforced`, counting an `agree`) are advisory against it. They stop automation that does not lie.
- Lowering an enforced scope with `set shadow|off` (any actor) or with an `outcome ... disagree` on an enforced `allow` (any actor; ids are listed by `decisions`) removes a veto gate's veto. A prompt-injected agent in the same account can do either. Wire `post-state-change` to a notification.
- A trusted same-user agent can rewrite the config, instruction files, scripts, the plugin and the bundled permission profile; policy, instruction and script paths must be outside every path an isolated session can write (Files). gatectl warns on a changed definition under an enforced scope (`definition_changed`) and does not prevent it.
- A script check that calls `setsid` leaves its process group and is not killed on a timeout.
- An exit code of 256 wraps to 0 and reads as `allow`.
- Fencing and the nonce do not stop a model from being steered; an agent check can only tighten a decision, and a deterministic check must back every automatic action. Agent confidence is not calibrated. A `model` of `null` follows Claude Code's default, which a Claude Code update can change.
- Claude Code's transcripts of gate-check sessions stay under its projects directory after `forget`. After `forget`, claude-session also keeps the session's staged input, prompt and result for `retention_days` (default 30), deleted only by its `reconcile`. For sensitive inputs, run claude-session's `reconcile` under cron and set a low `retention_days`.
- The sandbox's containment of a gate-check session was shown by configuration only; a live injection attempt that tries to read outside the session has not been observed to succeed or to be refused.
- `claude-session --dry-run` can report the sandbox as available for a setup that fails at run time; `validate --probe` is the check.
- If gatectl is killed with SIGKILL, running script checks are killed by the lifeline watchdog and a live agent run is found by label and stopped by the next `reconcile` (run it under cron).
- A policy edited between a decision and its outcome keeps the old fingerprint: the outcome counts toward the old record.
- Every distinct input can cost one agent run (bounded by `max_parallel` and the cache); a flood can make other checks `busy`.
- `GATECTL_*` timeout and limit variables inherited from a caller change deadlines; safety keys are not environment-settable.
- A caller whose `HOME` or `XDG_STATE_HOME` differs from the operator's reads another state directory (an empty one starts every policy at its initial state).
- The repo comes from the caller's payload: it selects a configuration and is not a security boundary, and its spelling must match exactly.
- The rule language has no cross-field comparison, list quantifiers or lengths; a policy that needs them uses a script check.
- `shadow` and `off` disable veto gates; a decision id references a decision and does not prove which revision it judged (compare the declared fields from `show`).
- A config error in the shared part, or an invalid definition of the wired policy, makes `check` exit 2, which a hook caller counts as a veto even in shadow (the state is unknown); run `validate` before saving, and use `set <policy> off --all` to stop a policy's automatic actions meanwhile.
- Re-adding a removed policy name resumes its stored rows, as editing a policy in place does (with a `definition_changed` warning when the definition differs); lower the rows with `set <policy> shadow --all` before removing a policy.
- State grows without bound: every distinct input is a decision row, current-fingerprint decisions are never pruned, and `audit.jsonl` and `log.jsonl` are never pruned. A flood of distinct inputs can fill the disk, after which every `enforced` check exits 1. Watch the state directory's size; archive the two JSON-lines files with `export --since` and rotate them from outside (gatectl opens each file for every append, so a rename-based rotation is safe).
- `applies_when` is a scoping filter, not a detector: a condition over text an attacker writes can be dodged, and a `not_applicable` answer never authorizes an automatic action (it carries `enforced: false`).
- The probe does not cover per-check safety overrides (`sandbox`, `skill`, `permission_profile`, `setting_sources`, `env_allowlist`, `model`); `validate` still checks them.
- A slot holder that never ends (stopped or in uninterruptible sleep) keeps its slot; `reconcile` names its PID in `overdue_holders`, and `kill -9` of that exact PID frees it.
- The state directory must not be shared across PID namespaces (a container and its host): holder liveness reads `/proc`.

## Platform notes

Linux, WSL and macOS are supported. Agent checks need claude-session and its required sandbox: `bubblewrap` and `socat` on Linux and WSL2, Seatbelt on macOS; WSL1 has no sandbox. The lifeline watchdog uses a pipe, not `PR_SET_PDEATHSIG`, so it works on every platform. Slot liveness uses the holder's PID and process start time, read by a per-platform method (with the boot id). The state directory must not be shared between PID namespaces (a container and its host): holder liveness reads `/proc`, so another namespace's holders would look dead. A container that runs gatectl needs an init process that reaps children (for example `docker run --init`). A holder that never ends (stopped or in uninterruptible sleep) keeps its slot; `reconcile`'s `overdue_holders` names its PID, and `kill -9` of that exact PID frees it. On macOS the group-sweep handshake of Script checks cannot use `waitid` if the interpreter lacks it: completion is detected with a `kqueue` `EVFILT_PROC` / `NOTE_EXIT` watch, which does not reap, and where neither exists the leader is not reaped before the group sweep. Install claude-session with copied, not hard-linked, files (`UV_LINK_MODE=copy`) and an interpreter that does not go through a link outside the sandbox's readable directories. gatectl's bundled plugin directory ships the placeholder files `.claude/`, `.mcp.json`, `CLAUDE.md` and `CLAUDE.local.md`, because a sandboxed session refuses a read-only plugin directory without them. File watching is not used.
