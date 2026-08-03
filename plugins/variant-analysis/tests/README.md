# Variant-analysis eval

One large real codebase — [gradio](https://github.com/gradio-app/gradio) at a pinned
commit — with **two lookalike command-injection vulnerabilities** and **one decoy**
injected by patch.

The hunt is seeded with the first vulnerability only. Finding the second is what the
eval measures; the decoy measures whether precision survives the search that finds it.

| Role | Location | What it is |
|---|---|---|
| **Seed** | `gradio/processing_utils.py:1110` | `extract_video_thumbnail()` interpolates an uploaded video path into an ffmpeg command string, `subprocess.run(..., shell=True)` |
| **Variant** | `gradio/flagging.py:351` | `archive_flagged_media()` interpolates a flagged-sample label into `os.system()` |
| **Decoy** | `gradio/screen_recording_utils.py:14` | `probe_recording_duration()` — same `subprocess.run`, same kind of user-controlled media path, argv list form with no shell |

The variant is deliberately hard to reach from the seed: **different module, different
sink API**. Grepping for the seed's exact sink (`subprocess.run` / `shell=True`) never
finds it. Reaching it requires generalizing to "user data reaches a shell" — which is
the abstraction ladder the skill teaches and the axis fan-out the workflow parallelizes.

The hypothesis under test: the workflow finds the variant and still rules out the decoy;
the skill alone finds only the seed.

## Running

```sh
./setup-gradio.sh              # fetch + patch (~283 MB, one time)
./run_fixtures.sh              # free, offline — verifies the fixture, grader, and workflow syntax
./eval.sh                      # calls Claude: both modes
./eval.sh --mode workflow      # skip the baseline
./eval.sh --runs 3             # variance estimate
./eval.sh --strict-decoy       # also require the decoy in the ruled-out section
./eval.sh --keep               # keep the work dir even on a pass
./setup-gradio.sh --clean      # delete the checkout
```

A passing `eval.sh` deletes its own work dir; a failing one keeps it, because that is when
the transcripts are worth reading. `--keep` keeps it either way, and a dir passed with
`--out` is never deleted. `--mode` accepts only `workflow` and `baseline`: a typo is an
error rather than a silent fallback to the baseline prompt, and a run with no workflow arm
is reported as measuring nothing instead of passing green.

The codebase is **not vendored** — 772 Python files at 283 MB, which is the point. Only
`gradio-vulns.patch` and `ground-truth.json` live in this repo; `work/` is gitignored.

`eval.sh` runs Claude **inside the checkout** rather than a per-run copy, and writes the
report to an absolute path outside it. Copying the tree twice per run would cost more
than the eval. After every run the fixture is re-verified, so an agent that edits the
code it was asked to audit fails the sweep instead of silently changing what later runs
are graded against.

## What "pass" means

The **workflow** mode must:

1. find every unseeded variant (`new_variants_found == new_variants_total`),
2. not report the decoy as real, and
3. score at least as well as the **baseline** (skill only, no workflow).

`--strict-decoy` additionally requires the decoy to appear in the report's ruled-out
section — evidence the sweep was broad enough to surface it and triage sharp enough to
reject it, rather than the search simply never reaching it.

Scoring keys on *new* variants rather than total true positives on purpose. The seed is
handed to the run, and real reports differ on where it goes: some list it under
`## Findings`, others under `## Original Vulnerability` per the template. Both are
correct, so counting the total measured formatting rather than detection.

## Design notes

**The SHA is pinned.** Ground truth records absolute line numbers. Track `main` and the
patch stops applying, the line numbers drift, and the eval grades against the wrong code.
`verify_fixtures.py` fails if the checkout has moved.

**The grader reads the artifact, not the transcript.** A run that describes finding two
variants but writes no report exits `3` (ungradeable), not `0 true positives`. Conflating
those is how an eval starts reporting success for runs that did nothing.

**A finding is a `**Location:**` declaration inside a non-refuted block.** Scraping every
path in the Findings section over-counts badly — it picks up entry points named while
tracing data flow, and rows in triage tables the report itself refuted. Both mistakes
were observed against real reports before this was fixed.

The workflow's report stage is instructed to emit those fields, because the fallback is
what runs when it does not. `score.py` reports which path it used as `extraction_mode`, and
`summarize.py` prints a `loose` column counting the runs that fell back — a score built on
the permissive path is worth less than one built on location fields, and that used to be
invisible.

**Ground truth carries a `span`, not just a line.** A construct is a line *range* — the
function it lives in. Matching on proximity to a single line conflates neighbours: a cold
run reported a helper at lines 4 and 7 of a file whose safe site began at line 10, and a
30-line window scored it as the safe site being reported as real. Spans are exact, and
`verify_fixtures.py` fails if a span stops containing its own anchor line.

**Line-less mentions lean opposite ways for recall and precision.** A report naming the
right file without a line is credited for recall, but is *not* treated as claiming the
decoy. Both directions favour not failing a run that did the work — and the strict half
matters because the decoy's file also holds a genuine upstream finding, so any run that
reported the real one without a line number used to be marked as having flagged the decoy.

**`run_fixtures.sh` is CI-safe; `eval.sh` is not.** `make shell-suites` executes every
`plugins/*/tests/*/run_*.sh` it finds, so the expensive half is deliberately named
outside that pattern. `run_fixtures.sh` also exits 0 with a notice when the codebase has
not been fetched, so CI passes on a machine that never ran setup.

## Caveats

- **This is one test.** Five smaller synthetic codebases were tried first and showed no
  difference between modes — they were small enough that a single context handled them,
  so the fan-out had nothing to buy. That is why the eval moved to one large real
  codebase. One test is thin, but it is testing something the previous five were not.
- **The vulnerabilities are injected, not real.** They are written to sit plausibly
  beside existing code (gradio already shells out to ffmpeg), but a hunt is still looking
  for something planted rather than something that arose naturally.
- **Results vary between runs.** These are LLM runs, not deterministic tests. Use
  `--runs 3` or more before drawing a conclusion, and treat a single run as a smoke test.
- **The baseline still has the skill and its references.** The comparison is workflow
  orchestration versus the same knowledge without it, which is the intended contrast.
