# Runner details

Read this reference only when configuring the runner or inspecting its retained artifacts.

## Plan and execution rules

The runner rejects incomplete plans. It fixes locale, timezone, hash seed, and terminal settings;
executes checks in lexical ID order; records stdout and stderr; and never edits the original
worktree. `timeout_seconds` defaults to 300 and must be an integer from 1 through 3600. A timeout
is a validation gap, not proof of a regression.

Every plan contains a sorted `submodules` array, including `[]` when no submodules changed.
Scaffolding finds changed Gitlinks. The runner initializes their pinned commits only from local Git
module objects; it never follows a `.gitmodules` network URL. Fetch or initialize those objects in
the source repository before validation.

Checks run with `PATH`, `HOME`, temporary/user keys, `LANG` and `LC_ALL=C`, `TZ=UTC`,
`PYTHONHASHSEED=0`, `NO_COLOR`, and `TERM=dumb`. Forward a necessary toolchain setting by name:

```bash
uv run {baseDir}/scripts/post_patch_validation.py run \
  --plan post-patch-validation/plan.json --output post-patch-validation/results \
  --allow-env JAVA_HOME --allow-env CARGO_HOME
```

Forwarded names and values are recorded in `result.json`. An unset requested value is an error.
Credential-like names and execution-changing names such as `LD_PRELOAD`, `BASH_ENV`,
`NODE_OPTIONS`, and `GIT_SSH_COMMAND` are refused. Fixed runner variables and every `PPV_*` name
are reserved.

## Placeholders and isolation

Use `{checkout}`, `{plan_dir}`, `{scratch}`, and, except for exploit and variant checks, `{side}`
in argv and per-check environment values. The corresponding `PPV_*` variables are supplied to the
check. Write only below `{scratch}`. Base and patched runs receive different worktrees, scratch
directories, and private plan copies. Exploit and variant execution order is randomized and their
checkout names do not disclose the side.

Each readable argv element that resolves to a file is recorded in `argv_files` with a SHA-256 digest.
Files below the isolated plan or checkout are archived under `helpers/<sha256>` up to 16 MiB. Files
outside those roots are hashed but not copied, which avoids accidentally retaining credentials.
`verify_evidence.py` verifies the artifact manifest and archived helper hashes. It reports external
or too-large helper files as review items because they cannot be rehashed from the evidence alone.

The evidence isolation is not a host sandbox: helpers execute with the caller's privileges and may
still inspect host state or source differences. Human reviewers must inspect helper intent and real
code invocation. The evidence verifier proves bytes match the record; it cannot prove a helper is a
meaningful test.

Active worktrees are protected by kernel-backed Git locks. If a validator is forcibly killed,
inspect `git worktree list`, then use `git worktree unlock <path>` and `git worktree remove --force
<path>` only for the confirmed stale validator worktree.
