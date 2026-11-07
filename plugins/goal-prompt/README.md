# goal-prompt

Turns a task description into a copy-paste-ready `/goal` command for goal mode in Claude Code or Codex.

## What It Does

A goal prompt has to do two things at once: fit the format (`/goal` is a single line, max 4,000 characters in both harnesses) and actually terminate (goal mode keeps looping until the condition is judged met — a vague condition burns turns forever).

The skill:

- drafts the objective as a termination contract: measurable end state, scope to read first, the command that proves completion, invariants, explicit stop bound
- closes the easy-outs a lazy model would take: deleting code to silence a check, passing on a subset, gaming the gate
- keeps the goal small — every constraint narrows what the model can explore
- never invents missing elements — anything it cannot ground in your request or the repo comes back as a `Missing:` warning
- hardens security-audit goals against reward hacking, following [trailofbits/codex-config](https://github.com/trailofbits/codex-config/blob/main/README.md#goal)
- formats deterministically to one line, warning on a missing stop clause and rejecting output over 4,000 characters instead of truncating

## Example

```
User: turn this into a /goal command:
      Migrate the auth module:
        - replace legacyAuth() with auth.verify()
        - make sure the tests still work

Assistant:
/goal All legacyAuth() call sites use auth.verify(): `rg "legacyAuth\(" -t ts` prints nothing AND `npm test` exits 0 (run both, show the output), without modifying vendor/ or weakening any test. If blocked, stop and report attempted paths and the blocker, or stop after 20 turns.
```

## Components

- `skills/goal-prompt/SKILL.md` — drafting checklist and output contract
- `skills/goal-prompt/scripts/format_goal_prompt.py` — stdlib-only formatter (`--fenced`, `--objective-only`, `--max-chars`)
- `evals/` — with/without-plugin ablation cases (`claude plugin eval goal-prompt --ablation with-without`)

## Calcifier recipe for `goal-prompt`

The [`goal-prompt` Python recipe](skills/goal-prompt/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/goal-prompt/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/goal-prompt/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `brief` | `str` | Required |
| `project_directory` | `str` | `'.'` |
| `conversation` | `str` | `''` |
| `reference_files` | `list[str] \| None` | `None` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
