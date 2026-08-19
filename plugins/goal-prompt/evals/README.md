# goal-prompt evals

Ablation evals: every case runs the same bare prompt ("Improve this goal: … Give me the final /goal command
to paste.") with and without the plugin, so the score delta measures what the skill actually adds over an
unassisted model.

```sh
claude plugin eval plugins/goal-prompt --ablation with-without --scaffold \
  --allow-tools Bash Write --judge-model sonnet --json result.json
uv run --no-project plugins/goal-prompt/evals/check_contamination.py result.json
```

- `--scaffold` runs each case's `scaffold.sh`, which generates the fixture inside the eval's temp directory.
  Fixtures are deliberately not referenced from this repo via `add_dirs`: that hands every agent an absolute
  path into the repo, one directory walk from SKILL.md and these graders, and baseline agents demonstrably
  find and imitate them — which deflates the delta.
- `check_contamination.py` fails the run if any baseline response contains the plugin's path, its script
  name, or a verbatim SKILL.md phrase — evidence the "no-plugin" arm read the skill off disk and is not a
  real control. It also fails when it has nothing to inspect. Its own tests live next to it.
- `--judge-model sonnet` is required: the default haiku judge cannot follow the graders' scoping instruction
  — judge only the line inside the fenced block — and fails correct answers for content in the accompanying
  `Missing:` list.

| Case | What it measures |
| --- | --- |
| grounded-migration | Single-line copy-ready output; check command grounded in the fixture's package.json; stop clause. |
| ungrounded-vague | With nothing to ground "faster", the goal must not invent metrics, thresholds, or benchmark commands — gaps are flagged back to the user. |
| easy-out-closed | The user's grep-only success check is satisfiable by deleting the callers; the goal must pair it with the fixture's real test suite. |

Graders judge the artifact (the returned `/goal` line and its accompanying warnings), not the agent's
narration. Regex graders enforce the mechanical parts (a stop clause exists); LLM graders judge grounding,
invention, and easy-out closure against the fixture's actual contents.

Measured on 2026-08-14 with scaffold isolation and a clean contamination check (2 runs per arm per case):
the plugin arm passed every grader in every run; the baseline arm passed no case — grounded-migration
without 0.40 (delta +0.60), easy-out-closed without 0.29 (+0.71), ungrounded-vague without 0.25 (+0.75),
mean delta +0.69. Before isolation, baselines that had read the skill off disk scored up to 1.00 —
re-run the contamination check whenever the numbers look too good.
