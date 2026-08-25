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
