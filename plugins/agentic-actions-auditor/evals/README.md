# Eval suite

Five cases, weighted by what `../tests` measured: `F` in 16 workflows of 60, `B` in 2,
`H` in 1, and `A`, `D` and `I` in none.

| Case | Vector | Why it is here |
|---|---|---|
| `03-sandbox-and-allowlist` | F, H, I | F is the most common vector in the corpus at 26%, and H rides with it |
| `01-prompt-expression` | B | Uncommon at 3%, but the clearest case where zizmor is silent and the agent is reached |
| `02-env-intermediary` | A | The reference calls it the most commonly missed; absent from the corpus, so coverage |
| `04-neg-safe-agent` | none | Punishes padding |
| `05-neg-no-agent` | none | The boundary: injection zizmor already reports, no agent present |

Three of the five carry a vector, so a run that reports nothing fails at least three.

A dedicated `F` case is the obvious next addition: one case currently carries the most
common vector alongside two others.

## What each negative case is for

`04-neg-safe-agent` is clean by construction: `schedule` and `workflow_dispatch` are not
attacker-controlled, the env block holds only `github.repository`, and the tool list
grants no execution. Its two graders fail on opposite mistakes, one on never stating a
conclusion and one on manufacturing a vector, so neither is satisfied by an empty answer.

`05-neg-no-agent` is the sharper one. The fixture has real shell injection into a `run:`
block and no AI action anywhere. zizmor reports it as `template-injection`; in the corpus
all 12 such findings landed on `run:` steps exactly like this. The skill's own
"When NOT to Use" sends this case to general Actions tooling, so the audit should say the
agentic vectors do not apply while still being useful about the injection. Its two
graders also fail on opposite mistakes.

## Fixtures

Every fixture is written by hand, for the reason `../tests/README.md` gives.

`01-prompt-expression` carries a second workflow, `build.yml`, with no agent in it, so the
precision grader can tell an audit that stays in scope from one that reports everything in
the directory.

## Routing is observed, not gated

Each case carries a `skill-fired` grader with `input_match: agentic-actions-auditor`, so it
records whether this plugin was the thing that loaded rather than whether any skill was.
It has no weight. The sibling case.yaml suites do weight their routing graders, and that
is probably right, but the plugin now ships two entry points and I could not run the
harness to see which one a case actually reaches. Making an untested routing check a
scored gate would risk zeroing every case over a technicality rather than over the
quality of the audit. Weight it once the numbers exist.

## A hand-run pilot, and what it says about these cases

`claude plugin eval` is in early access and I could not run it, so this is not the
ablation. Each fixture went into an isolated directory; one fresh agent got the fixture
and the case prompt, another got the same plus SKILL.md and the references. One run per
arm, and only the no-plugin arm matters below.

**The no-plugin arm passes 01 and 02.** On `triage.yml` it found the issue title and body
reaching the prompt and called it prompt injection rather than shell injection. On
`respond.yml` it traced the comment body through `env:` to the prompt and said the
indirection stops template injection but not prompt injection, which is the exact claim
`no-expression-is-not-safety` exists to gate. With only one arm run, the honest statement
is not that Δ is zero but that there is no headroom: a case the unaided model already
passes cannot be lifted.

A third fixture was then built to discriminate on `F`, pairing
`--allowedTools "Bash(echo:*),Read,Glob"` with a wildcard allowlist so that the plugin's
own rationalization 2 would be the thing under test. The no-plugin arm wrote, unprompted:

> it reads like a harmless print-only permission, but it's still a shell invocation, and
> prefix-style allowlists are permeable to command substitution

and tied it to `ANTHROPIC_API_KEY` and the public reply. That is `F`, stated as well as
the reference states it, without the reference.

Piloting `04-neg-safe-agent` was what turned up the fixture's own bugs, since the unaided
arm reported them: `REPO` never interpolates and a shallow checkout cannot support a
seven-day digest. Its grader now says both are correct to report.

A fourth fixture tested the most plausible remaining hypothesis, that cross-file
resolution would separate the arms: the agent lives only inside a local composite action,
so `.github/workflows` shows a `uses: ./.github/actions/ai-triage` and no agent at all.
The unaided arm followed the reference, found the agent, found the injection, and
volunteered that `anthropic_api_key: ${{ env.ANTHROPIC_API_KEY }}` resolves to nothing
because the `secrets` context is unavailable inside composite actions. That last point is
correct per GitHub's own documentation and is not in `cross-file-resolution.md`, which
covers resolving and input-tracing but not the secrets boundary. Worth adding there,
though not as an eval case, since the unaided model already knows it.

**Four fixtures, four no-plugin passes. The conclusion is about the premise, not the
graders.** On a current frontier model the nine vectors are not scarce knowledge, so an
eval built to ask "does it know vector X" measures the model and will keep measuring the
model however the fixtures are rewritten. Better graders cannot fix that, and neither can
hiding the agent behind another file.

That leaves two places uplift could still live, both untested here:

- **Coverage under scale.** One file with two findings is where a base model does well.
  A directory of fifteen workflows where four carry different vectors is where an
  unaided pass plausibly stops after the obvious two. Recall across a set, not depth on
  one file. This is the hypothesis worth testing next, and it is about stamina rather
  than knowledge, which is why the four failures above do not settle it.
- **Consistent labelling.** Same vector, same letter, same severity across a run, so
  findings can be counted rather than read.

`05-neg-no-agent` is the one case whose behaviour the workflow enforces structurally
rather than asking the model for, so it holds regardless of how strong the model is.

This is worth telling the maintainers rather than quietly reweighting: if the vector
knowledge reproduces without the plugin, the plugin's case has to be made somewhere else,
and #229 deleted a case for exactly this reason.

Ground truth for what each fixture contains is mechanical: `../tests/vectors.py` decides
which vector is present, zizmor decides what the general tooling already reports, and the
audit re-runs both over these fixtures.
