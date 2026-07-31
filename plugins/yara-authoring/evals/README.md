# Eval suite for `yara-authoring`

Three cases. Two measure whether the skill makes rules *tighter* rather than just
producing one; the third is the regression gate — it is the only case that fails when the
skill's own content is removed.

## Running

```bash
CLAUDE_CODE_WALNUT_SPIRE=1 claude plugin eval . --ablation with-without \
  --judge-model opus --allow-tools Bash Write
```

- **`CLAUDE_CODE_WALNUT_SPIRE=1`** is required while `plugin eval` is in early access.
  Without it the command exits with `plugin eval is currently in early access` and runs
  nothing.
- **Install the `yr` CLI first** (`brew install yara-x`). The skill tells the agent to run
  `yr check` and `yr fmt`; on a machine without it the agent falls back to eyeballing the
  syntax, which is a different task and scores differently. Runs from machines that differ
  on this are not comparable, which defeats keeping the case names stable across runs.

The headline number is **Δ** — the with-plugin score minus the no-plugin baseline. A case
that scores 1.0 in both arms measures nothing.

- **`--allow-tools Bash Write`** is the *operator* grant for gated tools. Each
  `prompt.md` also lists `allowed_tools`, but that only declares what the agent may reach
  for within a run; the gated set still has to be granted from outside. Both are required.
- **`--judge-model opus`** because the cases run `model: sonnet`, and a model scoring its
  own output self-prefers. Any judge at sonnet tier or above works, as long as it differs
  from the case's `model:`.

Pilot one run before spending on the whole suite:

```bash
CLAUDE_CODE_WALNUT_SPIRE=1 claude plugin eval . --runs 1 --ablation with-without \
  --case '02-*' --allow-tools Bash Write
```

Results land in `results/<timestamp>/` (gitignored).

## Cases

| Case | Input | What it tests | Δ vs baseline | Detects a gutted skill? |
|---|---|---|---|---|
| `02-string-dump-pe` | Twelve extracted strings, nine of them junk | Picking the three family-unique indicators and saying why the rest were dropped or demoted | +0.52 | **no** |
| `05-legacy-endianness` | A legacy rule with two dead magic-byte branches | Fixing `uint32(0) == 0xCAFEBABE` and explaining why a little-endian read reverses the constant | +0.33 | **no** |
| `06-review-with-linter` | A rule with five concrete defects, for review | Running the plugin's linter and reporting findings by issue code | +0.67 | **yes** |

Case 02 is the only one that writes a rule file, so it carries the mechanical pre-filter
checks alongside three `llm` rubrics.

### Why case 06 is the gate

Cases 02 and 05 both show real uplift over a no-plugin baseline, and neither detects the
skill being broken. That was measured, not assumed:

| Case | intact | guidance deleted |
|---|---|---|
| 02 (−2,988 chars: string-rejection table, `all of`/`any of` table inverted, Grouping by Confidence, Core Principles 2 and 3) | 0.94 | **0.97** |
| 05 (−727 chars: the little-endian callout, the Common Mistakes row, the corrected constants) | 1.00 | **1.00** |
| 06 (−1,045 chars: the Scripts section and the review direction) | 1.00 | **0.60** |

For 02 and 05 the uplift comes from a skill being *loaded*, not from what it says. Sonnet
already knows that `any of` across generic strings is loose and that `uintNN()` reads
little-endian; it just needs to be in a frame where it thinks about YARA carefully. Delete
the guidance and it still answers correctly.

Case 06 works because it tests something only this plugin's files supply: the linter's
issue codes. `reports-linter-codes` passes 3/3 with the skill intact, 0/3 with the Scripts
section removed, and 0/2 with no plugin at all — a regex, so no judge variance. **When
adding a case, prefer this shape**: something only this plugin can supply, checked
mechanically.

Be precise about what it proves, though. It is a *skill-content* gate, not proof the
linter ran. The codes are not secret — `references/style-guide.md` tabulates all nineteen,
and `SKILL.md` names `E002` and `W009` in prose — so an agent could in principle map the
defects to codes by reading the reference and never invoke `yara_lint.py`. The 0/3 result
when the Scripts section is removed is still real: with nothing pointing at the linter,
runs did not go looking for the table either.

The residual risk is a silent pass. If `uv` or the `yara-x` wheel fails in the sandbox,
every script call errors, the agent falls back to the reference table, and
`reports-linter-codes` still passes — worse than the `yr` non-hermeticity above, which
merely scores differently. **This gap is open.** A `linter-output-format` grader matching
the linter's own `SEVERITY [CODE] rule:` layout was tried and removed: it failed 0/3 in
*both* arms, because agents paraphrase findings rather than pasting raw tool output, so it
depressed the with-plugin score without separating anything. `tool_used: Bash` is no better
— Bash gets used for other things in both arms. Until there is a check that distinguishes
execution from lookup, treat a green case 06 on an unfamiliar machine as needing a
confirming look at whether the scripts actually ran.

Case numbers are non-contiguous. The suite was cut from eight cases to two
(`02-string-dump-pe`, `04-generic-only-trap`), then `04-generic-only-trap` was removed
after measuring Δ 0.00 across four runs — both arms scored 50/100/100 and 50/50/100, the
same values in a different order — and `05-legacy-endianness` and `06-review-with-linter`
were added. Names are kept stable so stored results still line up.

## Grader conventions

These are documented, not enforced — the suite has no grader tests, so a new grader that
skips the comment guard below will score a false pass rather than fail loudly.

- **Weights are explicit on every grader** — `2` for `llm` rubrics, `1` for `regex` and
  `file_exists` — so the judgement signal is not diluted by mechanical checks that happen
  to be numerous.
- **Regex graders that target the rule file are anchored to non-comment lines**, with
  `flags: m`:

  ```
  ^(?:[^/\n]|/(?![/*]))*<pattern>
  ```

  Without the prefix, a model satisfies the grader from a comment — writing
  `// rejected: Global\LarkMtx_7742 is version-specific` while leaving the indicator out
  of the rule. The `[/*]` character class blocks both `//` line comments and the opening
  of a `/* ... */` block. It matters most on case 05, whose prompt asks the agent to say
  what was wrong: quoting the original condition as `/* was: uint32(0) == 0xCAFEBABE */`
  is likely behaviour, and with a `//`-only guard that comment both fails
  `no-dead-branch-left` on a correct answer and satisfies `zip-magic-corrected` on a
  broken one. A pattern spanning multiple lines inside a block comment can still slip
  through; strip comments before matching if a future grader needs that.
- **A file-targeted grader fails when its file is missing; it does not pass vacuously.**
  Verified by pointing case 05's `not_contains` grader at a filename no agent writes: the
  harness reports `grader threw: … path "…" does not exist` and scores it 0. So a run that
  writes nothing cannot bank credit from a `not_contains` check, and `no-dead-branch-left`
  needs no companion guard.
- **`skill-fired.md` carries no `weight:` and no `arm:` on purpose.** A `tool_used`
  grader with `tool: Skill` and no `arm:` is display-only to the harness: dropped from
  the baseline arm, flagged `[with-only, not scored]` in the with-plugin arm, counted in
  neither numerator nor denominator. Adding `arm:` would start scoring a check the
  baseline can never pass and inflate measured uplift. The schema rejects `weight: 0`, so
  omitting `arm:` is the mechanism.
- **`filesize` and magic-byte graders check that the pre-filter exists, not that it is
  well chosen.** They accept every notation the skill promotes — `500KB`, `2MB`,
  `400_000`, `0x80000`, a bare byte count of three digits or more — and both spellings of
  the PE magic, `uint16(0) == 0x5A4D` and `uint16be(0) == 0x4D5A` (SKILL.md:63). SKILL.md
  lists numeric underscores as a v1.5.0+ feature rather than recommending them as style,
  but agents emit the form, so the grader accepts it.

  It does reject a bound with fewer than three digits, so `filesize < 0` and `filesize < 2`
  — pre-filters that make the rule match nothing — do not score.

  An earlier version tried to band-check the bound against the prompt's stated ~340KB and
  fail anything under 400KB. That was dropped: it rejected the `_` and hex forms the skill
  itself recommends, and it accepted `900MB`. It also would not have discriminated —
  across seven recorded runs every rule chose 1MB, 2MB or 5MB, so a strict band fails both
  arms equally, which measures as little as passing both. If you reinstate a band check,
  confirm first that real runs land on either side of it.
- **A `regex` grader against the reply takes no `target:` at all.** `focus: last_message`
  is an `llm`-grader key; on a `regex` grader the harness rejects it with
  `Unrecognized key(s) in object: 'focus'`, and `target: {source: last_message}` fails with
  `target: Invalid input`. Omit the key. Only file-targeted regex graders take
  `target: {source: file, path: …}`.
- **`explains-rejections` and `junk-cannot-fire-alone` must agree on what is allowed.**
  They used to conflict: `junk-cannot-fire-alone` accepts generic strings as corroboration
  gated behind a unique indicator, while `explains-rejections` demanded at least two
  strings be left out of the rule entirely. A run that gated everything instead of dropping
  it satisfied the first and failed the second, which is why the same skill scored PASS,
  FAIL, FAIL on three identical runs. `explains-rejections` now accepts either disposition
  — dropped, or present but unable to fire alone — provided the response says which it is
  and why. Case 02 also runs 5 times rather than 3.

  Replacing it with a regex was tried and rejected. Checking the reply for
  rejection-language plus two of the nine junk strings passes all three recorded
  with-plugin replies but also two of three baseline replies, because a baseline model
  names the junk strings, calls them generic, and then uses them anyway in an N-of fallback
  branch. The distinguishing property is the role each string plays in the condition, which
  regex over prose cannot see. Checking the rule file instead does not work either: gated
  corroboration is explicitly allowed, so a `not_contains VirtualAlloc` check would fail a
  correct answer.
- **A grader that no arm can fail is worth deleting, not reweighting.** `finds-the-real-
  defects` in case 06 passes in both arms — base Sonnet finds the defects unaided — and is
  kept only because it would catch a genuine regression into approving a bad rule. An
  earlier `ran-the-linter` grader was dropped outright: it regex-matched the script name in
  the reply, so it failed runs that had demonstrably run the linter but summarised without
  naming the file. `reports-linter-codes` already proves execution, since the codes cannot
  be guessed.
