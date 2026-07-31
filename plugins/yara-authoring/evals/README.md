# Eval suite for `yara-authoring`

Two cases measuring whether the skill makes rules *tighter*, not just whether it produces
a rule: tightening one built from noisy input, and refusing to dress up a loose one as a
detection.

## Running

```bash
claude plugin eval . --ablation with-without --judge-model opus --allow-tools Bash Write
```

The headline number is **Δ** — the with-plugin score minus the no-plugin baseline. A case
that scores 1.0 in both arms measures nothing.

- **`--allow-tools Bash Write`** is the *operator* grant for gated tools. Each
  `prompt.md` also lists `allowed_tools`, but that only declares what the agent may reach
  for within a run; the gated set still has to be granted from outside. Both are required.
- **`--judge-model opus`** because the cases run `model: sonnet`, and a model scoring its
  own output self-prefers. Any judge at sonnet tier or above works, as long as it differs
  from the case's `model:`.

Pilot one run before spending on both cases:

```bash
claude plugin eval . --runs 1 --ablation with-without --case '02-*'
```

Results land in `results/<timestamp>/` (gitignored).

## Cases

| Case | Input | What it is really testing |
|---|---|---|
| `02-string-dump-pe` | Twelve extracted strings, nine of them junk | Picking the three family-unique indicators and saying why the rest were dropped |
| `04-generic-only-trap` | Four generic strings, nothing else | Refusing to hand over a loose rule as a detection; pivoting to structure |

Case 02 is the only one that writes a rule file, so it carries the mechanical checks —
filesize band, PE magic, mutex, PDB path — alongside three `llm` rubrics. Case 04 is
judgement-only: nothing usable is supplied and a rule is asked for anyway, which is where
a baseline model obliges and the skill should not.

The numbers are non-contiguous because the suite was cut down from eight cases; they are
kept as-is so results from earlier runs still line up by name.

## Grader conventions

These are documented, not enforced — the suite has no grader tests, so a new grader that
skips the comment guard below will score a false pass rather than fail loudly.

- **Weights are explicit on every grader** — `2` for `llm` rubrics, `1` for `regex` and
  `file_exists` — so the judgement signal is not diluted by mechanical checks that happen
  to be numerous.
- **Regex graders that target the rule file are anchored to non-comment lines**, with
  `flags: m`:

  ```
  ^(?:[^/\n]|/(?!/))*<pattern>
  ```

  Without the prefix, a model satisfies the grader from a comment — writing
  `// rejected: Global\LarkMtx_7742 is version-specific` while leaving the indicator out
  of the rule. The guard scopes to `//` line comments only; an indicator buried in a
  `/* ... */` block still gets through.
- **`skill-fired.md` carries no `weight:` and no `arm:` on purpose.** A `tool_used`
  grader with `tool: Skill` and no `arm:` is display-only to the harness: dropped from
  the baseline arm, flagged `[with-only, not scored]` in the with-plugin arm, counted in
  neither numerator nor denominator. Adding `arm:` would start scoring a check the
  baseline can never pass and inflate measured uplift. The schema rejects `weight: 0`, so
  omitting `arm:` is the mechanism.
- **`filesize` graders band-check the bound** rather than accepting any number, so a rule
  overfit to the sample does not score the same as one reasoning from the stated size —
  case 02's prompt says ~340KB, and a bound under 400KB fails.
- **Case 04 grades `last_message` only**, and its prompt asks for a reply rather than a
  file. Its rubric accepts either a low-confidence hunting rule or a refusal to write one;
  what fails is a loose rule presented as a normal deployable detection.
