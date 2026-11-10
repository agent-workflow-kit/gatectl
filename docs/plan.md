# gatectl: implementation plan

This plan implements [interface.md](interface.md) and [design.md](design.md). The GitHub issues are the units of work; each is expanded into bite-sized test-first steps when it is picked up. No stage starts before the stage it depends on has merged, and every stage ends with `make verify` green.

## Conventions for every stage

- **Gateway boundary.** Every subprocess call (claude-session, script checks, hooks, `crontab`) goes through `src/gatectl/gateway.py`. Tests substitute fakes; nothing else imports `subprocess`.
- **Fakes and pinned schemas.** A fake `claude-session` lives in `tests/fakebin/` and plays one scenario per case (valid artifact, nonce mismatch, wrong schema, no artifact, unreported, timeout, needs-input, `sandbox_unavailable`, `claude_not_found`, missing skill, hang, a status whose SHA-256 differs). The sibling's `outcome`, `status` and `start` schemas are copied into `tests/` pinned to a claude-session version and never imported.
- **Process tests and live tests.** Behavior that needs real child processes (the script runner, hooks, signals, the lifeline watchdog) is tested with real processes and no network. Anything that needs a real model, the sandbox or a real host is marked `live`, is deselected by default and never runs in CI.
- **Golden files.** Every `--json` output and every hook payload has a golden file validated against `schemas/`; the generator for the schemas stays private, and `check-jsonschema` validates `config.example.yaml` in CI.
- **Spike regressions.** Every behavior a design spike relied on (see the live verification table in design.md) becomes a test in the stage that uses it.
- **Open source and safety.** No private values in code, tests or fixtures; safe public defaults; never destructive git; signal only exact PIDs.
- **`make verify`** (ruff, pyright, pytest, markdown lint) passes before every commit.

## Module map

| Module | Stage | Responsibility |
|---|---|---|
| `gateway.py` | 0 | every subprocess call |
| `config.py` | 1 | Pydantic models, drop-ins, per-part validation, overrides, fingerprint |
| `audit.py` | 0 | `audit.jsonl` and `log.jsonl` writers |
| `store.py` | 2 | SQLite, migrations, state rows, decisions, outcomes, cache, leases |
| `runner.py` | 3 | script runner: selector loop, process group, caps, lifeline watchdog |
| `rules.py` | 3 | the closed rule evaluator and the linear glob matcher |
| `engine.py` | 3 | one `check`: input, scope and state, ordering, deadline, combination |
| `hooks.py` | 3 | detached post hooks |
| `agent.py` | 4 | fenced input and prompt files, run sequence, slots, cache use, artifact validation, probe |
| `stats.py` | 5 | cases, effective outcome, Clopper-Pearson bound |
| `cli.py` | 0 to 6 | argparse and output |
| `plugin/` | 4 | bundled plugin, skill, placeholders, permission-profile file |

## Stage 0: Foundations

**Goal**: A package that parses every command, prints help and `--version`, writes audit and log lines, and has the fakes and golden-file harness.
**Success Criteria**: `gatectl --version` and `--help` work; `gateway.py` is the only module that spawns processes (a test enforces it); the fake `claude-session` runs each scenario; schema validation of sample outputs runs in tests; audit and log records are written with fixed-width UTC timestamps and sanitized text.
**Tests**: gateway substitution; import-boundary test; audit and log schema tests; timestamp and sanitizer unit tests; decision-id generation and prefix parsing.
**Status**: Not Started

## Stage 1: Policies, config and validation (0.1)

**Goal**: Load config and drop-ins, validate shared structure and each policy separately, resolve per-repo overrides, compute fingerprints, and answer `validate`, `policies` (static view) and `check --dry-run`.
**Success Criteria**: an invalid policy fails only its own `check` (the others get `config_problem`); a shared-structure error fails `check`, `reconcile`, `prune`, `cron` and `set ... enforced`, while the kill switch, `outcome` and the read-only commands carry on with defaults and a `config_problem` warning; the fingerprint is stable, ignores timeouts and state, and changes with any covered file or text; every problem code and warning code in the interface is produced by a test.
**Tests**: config schema golden tests; per-part validation matrix; fingerprint property tests (including unreadable files and a changed skill file); `validate` problem-code table; dry-run plan goldens.
**Status**: Not Started

## Stage 2: Store and state (0.2)

**Goal**: The SQLite store with additive migrations, the state rows with their fingerprints and revisions, and the commands that only read and set state: `set`, `policies`, `show`, `decisions`, `export`.
**Success Criteria**: `set enforced` is refused without a human actor; `set --all` writes every scope in one transaction; effective state resolves repo row, then `*` row, then initial state; a missing `state.db` next to a non-empty audit log is refused; a decision's audit line is appended inside its transaction; eight concurrent writers lose and tear nothing.
**Tests**: migration refusal for a newer schema; concurrency tests with real processes; the six state-pair race test (a `set` committing during a `check`); resume of a removed policy's rows; `decisions` filter goldens.
**Status**: Not Started

## Stage 3: Deterministic checks and the `check` engine (0.3)

**Goal**: `check` for policies made of script and rule checks, with input validation, `applies_when`, the three states, the deadline, the combination rule and detached post hooks.
**Success Criteria**: all 13 hostile-script cases from the spike are handled and map to `escalate`; the glob matcher is linear and capped; a rule on a missing, null or mistyped path escalates; an invalid or missing `repo` follows the strictest-state rule (stored rows first, so `set --all off` is honored; a policy without rows uses its initial state); `off` records nothing; a `shadow` failure exits 0 with no `decision_id`; an `enforced` failure exits 1; a false `applies_when` answers `allow` with `not_applicable`, `shadow: false` and `enforced: false` in every state, records nothing and exits 0; a hook cannot hold the caller's stdout.
**Tests**: process tests (grandchild ignoring SIGTERM, 100 MB output, closed stdout, a check that never reads a 5 MB stdin, early exit, bad UTF-8, duplicate keys, deep nesting, control characters, group kill, lifeline watchdog and the done handshake); strict JSON cases (`1e999`, a lone surrogate, deep nesting, a huge integer, a FIFO input); glob property tests against a reference and the adversarial pattern; short-circuit and guard idioms; the combination rule; the exit-code and stderr-line goldens; a caller that reads stdout to EOF while hooks sleep.
**Status**: Not Started

## Stage 4: Agent checks and the bundled skill (0.4)

**Goal**: Agent checks through claude-session: the run sequence, slots, the cache, strict artifact validation, cleanup and the probe, plus the bundled plugin.
**Success Criteria**: every outcome in the agent outcome table maps to its reason against the fake; a usable verdict needs exit 0, outcome `done`, a non-implicit report and a valid, nonce-matching artifact; confidence below the threshold turns an `allow` into `escalate` and never loosens anything else; a cache hit needs no slot; `forget` runs on every path that allocated a session; a hung `exec` and `stop` end the check within its deadline plus 20 s plus `record_reserve` as `escalate`/`timeout`, and every `stop` carries `--grace 2s`; the permission-profile file equals a pinned copy of claude-session's built-in `review` profile (a drift test).
**Tests**: the fake's full scenario list; slot lease tests with dead holders; cache key tests (volatile `input.ignore` fields, scope, fingerprint file hashes); the nonce and fence tests including `</untrusted` neutralizing in any case; a SIGKILL of gatectl during a run followed by `reconcile`; `validate --probe` against the fake. `live`: the sandboxed round trip, the injection input, three parallel runs, a changed `SKILL.md` changing the fingerprint.
**Status**: Not Started

## Stage 5: Outcomes and track records (0.5)

**Goal**: `outcome`, the effective-outcome rule, the automatic drop, `stats` and the recommendation.
**Success Criteria**: only a human `agree` counts and any `disagree` counts; a later human outcome supersedes a `disagree`; a miss on an enforced `allow` writes a `shadow` row for that decision's scope only and only while that enforcement is still current; cases count once per object; the Clopper-Pearson bound matches the golden table (59 clean cases recommend, 58 do not, at 5% and 95%); `post-outcome` and `post-state-change` fire after the commit.
**Tests**: effective-outcome property tests (including `human agree`, `auto disagree`, `human agree` ending `agree`); the automatic drop with re-enforcement races; case-key tests (a null `object_id` hashes the input without its `input.ignore` keys); bound goldens; `--since` and `current` behavior; the `set` hint logic.
**Status**: Not Started

## Stage 6: Operations (0.6)

**Goal**: `reconcile`, `prune`, `cron install|uninstall`, signal handling and the maintenance leases.
**Success Criteria**: `reconcile` frees dead slots, removes `tmp/*` directories whose `owner` file names a dead process (no readable `owner`: after 10 minutes; removal never follows links or crosses mounts and deletes `owner` last) and stops and forgets orphaned `gate-check` sessions found by label without touching a running check; `prune` never deletes current-fingerprint decisions and expires cache rows; the cron block is exactly the one `awkit cron install` writes; SIGTERM, SIGINT and SIGHUP stop what gatectl started and exit 128 plus the signal.
**Tests**: reconcile and prune against fixtures; cron block goldens and idempotent replace; signal tests during a script check and during an agent run; a full-disk and a read-only-filesystem case for the fail-open and fail-closed rules.
**Status**: Not Started

## Stage 7: Live suite, macOS and release readiness (0.7)

**Goal**: The `live` suite complete on Linux and WSL, a macOS run of everything, and the docs ready for 1.0.
**Success Criteria**: every behavior in the live verification table has a `live` or process test; the macOS checklist is done (Seatbelt sandbox, process start time for slot liveness, the watchdog handshake, true same-second parallel launches); the README quick start is verified end to end.
**Tests**: the `live` suite; the macOS checklist; install from a clean machine with claude-session and the sandbox prerequisites.
**Status**: Not Started

## Version roadmap

- **0.x** (stages 0 to 7, one minor per stage): the tool is usable from 0.3 for script and rule policies and from 0.4 with agent checks. No `!` before 1.0.
- **1.0 qualifies when**: the live suite passes on Linux and WSL and the macOS checklist is done; a real policy has run in `shadow`, been enforced by a human and survived a miss-and-recover cycle; the interface and schemas have been stable for a release cycle; the consumers named in the interface registry have wired it without needing a gatectl change.
- **1.x** (additive): a `browse` TUI for decisions and track records; an optional rate limit on agent runs per hour; a `verify` command if consumers adopt a binding check; an `agent.max_turns` key if the live suite shows a need; more bundled example policies.
- **2.0**: nothing planned. A breaking change to the policy format or the result shape would start a 2.0.
