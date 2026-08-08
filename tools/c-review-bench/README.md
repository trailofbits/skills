# c-review benchmark harness — how to run a measurement

Everything needed to run a cell. Past results live in [MEASUREMENTS.md](MEASUREMENTS.md) and
are not repeated here.

A **cell** is one arm on one corpus variant. A **run** is a directory of cells scored
together. The corpora hold deliberately injected bugs and the answers are sealed; the design
assumes a reviewer will try to look them up and makes that useless rather than forbidden.

---

## Run a cell

Cells run in a **hermetic container**. Do not run one on the host: a host session carries
~48 skills into every agent — including c-review's own and other security-review skills — and
an unrelated plugin's `SessionStart` hook will execute inside your measurement
(MEASUREMENTS.md §4). The container is also ~33% cheaper.

```sh
cd tools/c-review-bench

# 1. Plan. Requires every corpus SEALED; it refuses otherwise.
uv run bench.py plan --tier standard --arm c-review --arm fanout --corpus packetloom \
  --out ~/runs/my-run

# 2. Isolate the tree per arm. --exclude is load-bearing: a leftover
#    .c-review-results leaks the previous run into this one.
SRC=~/.cache/c-review-bench/work/packetloom/bench
rsync -a --exclude '.c-review-results' "$SRC/" ~/runs/my-run/iso_creview/packetloom/bench/
diff -r -x '.c-review-results' "$SRC" ~/runs/my-run/iso_creview/packetloom/bench   # silent

# 3. Rewrite the packet for container paths: tree -> /corpus, repo ->
#    /workspace/skills-repo, run dir -> /cell. Then confirm nothing was missed:
grep -o '/Users/[^"` ]*' ~/runs/my-run/creview/packets/*.md | sort -u

# 4. Run it. Never in the foreground — a cell takes 30-100 minutes.
nohup ./devcontainer/run-cell.sh --arm c-review \
  --run ~/runs/my-run/creview --tree ~/runs/my-run/iso_creview/packetloom/bench \
  --corpus packetloom --variant bench --model sonnet > ~/runs/my-run/creview/run.log 2>&1 &
```

`run-cell.sh --arm` takes `c-review`, `fanout`, `bare` or `taxonomy`. **Every arm must use
it**: an arm run on the host and an arm run hermetically are not comparable, and a `fanout`
cell that can see `c-review:c-review` in its own skill list is not measuring undirected
review. The script refuses to start unless exactly one plugin is installed.

**Auth.** The container reads the OAuth token from the macOS Keychain item
`Claude Code-credentials` at launch and passes it as `CLAUDE_CODE_OAUTH_TOKEN`. It is never
written to disk, because it expires; the script warns if under an hour remains. A run that
dies with `Not logged in` needs a refreshed token, not a fix.

**Verify isolation held**, from the cell's own init record:

```sh
jq -r 'select(.subtype=="init")|"plugins:\(.plugins|length) skills:\((.skills//[])|length)"' \
  ~/runs/my-run/creview/logs/*.cli.jsonl | head -1     # expect plugins:1 skills:18
```

---

## Collect and score

Order matters: `plan` needs the corpus **sealed**, `score` needs it **unsealed**.

```sh
# Collect each cell. Get the real token count first — `collect` refuses tokens: 0.
uv run bench.py cost --transcript <cell>/transcripts          # use the tokens_fresh line
uv run bench.py collect --run ~/runs/my-run --arm c-review --corpus packetloom \
  --result <cell>/results/<arm>__<corpus>__bench.result.json \
  --meta   <cell>/results/<arm>__<corpus>__bench.meta.json \
  --transcript <cell>/transcripts

# Anti-cheat per cell as it finishes. Do not wait for `score` to reveal a void cell.
python3 ~/c-review-bench-runs/2026-08-05/ac.py ~/runs/my-run c-review packetloom bench

# Unseal -> score -> RE-SEAL. Never leave a corpus unsealed.
K=$(cat ~/c-review-bench-runs/2026-08-05/KEY-packetloom.txt)
CREVIEW_BENCH_KEY=$K uv run bench.py unseal --corpus packetloom
uv run bench.py score --run ~/runs/my-run
CREVIEW_BENCH_KEY=$K uv run bench.py seal --corpus packetloom
```

`--allow-incomplete-findings` admits findings missing `description`/`title` that still carry
other graded text. It records the waived ids and prints a DEGRADED warning. **It changes the
number** — say so wherever you quote one collected with it.

**Reporting rules.** Recall and precision separately, never F1. Name the token basis on every
table. Break recall down by bug class and tier. Report unique true positives. State the
variance floor *before* any ranking. Show gate-invalid cells struck through with the
violation quoted, and exclude them from every comparison.

---

## Traps that have each cost a real cell

1. **The driver's collect step fails inside the container.** `drive.py` shells out to a
   hardcoded host path. The arm itself completes and writes its result; collect on the host.
2. **The assemble agent can die with the run intact.** Every part file is on disk. Assemble
   by hand — the documented path, not a workaround — but pass the workflow's own `--expect`
   list from its log, or the document will report `agent_failures: []` for a run that lost a
   slice. Without `--expect` the assembler now says so out loud.
   ```sh
   uv run ../../plugins/c-review/scripts/assemble_findings.py --run-dir <outdir> \
     --threat-model BOTH --severity-filter all --no-judge
   ```
3. **`threatModel` is c-review's enum**, not the recipe's prose. `plan` maps one onto the
   other and refuses to guess; pasting the prose throws before a single agent spawns.
4. **Say nothing about the threat model, bug count, or corpus provenance anywhere else.** A
   hint about the base project undoes the de-identification.
5. **A blocked network attempt is not disqualifying.** The anti-cheat separates *attempted
   and denied* from *attempted and succeeded* and reports the former as `BLOCKED`. A cell
   that voids did so for a real reason; read which one before rerunning.

---

## What the harness checks, so you do not have to

`bench.py verify` builds both variants and runs ten checks. **A check that inspects zero
items fails** — this repository has shipped a validator that matched nothing and reported
every plugin valid.

| Check | What it establishes |
|---|---|
| `compile[bench]`, `compile[control]` | both variants compile; object count equals source count |
| `behaviour[bench]`, `behaviour[control]` | a benign-input smoke test passes **with every bug applied** — a bug that breaks normal operation is not latent |
| `warnings` | no warning in the bench tree the control tree does not also produce, so no injection announces itself to the compiler |
| `reachability` | every bug has a syntactic call chain from a declared entry point |
| `decoys` | every decoy sits in a function holding no bug and ≥3 lines from one |
| `deidentified` | either de-identification ran, or the recipe states why it is not required |
| `ground_truth` | every bug's anchor is real and its own mechanism text matches its own keyword groups |
| `mechanism_discrim` | co-located bugs' keyword groups reject each other's mechanism text |
| `variants` | the bench and control trees differ only where they should |

---

## Adding a corpus

1. Write the clean, bug-free tree under `corpora/<id>/clean/`.
2. Write `corpora/<id>/recipe.json`: bugs and decoys as anchor→replacement patches, each with
   `mechanism_all_of` keyword groups, a `call_path` from a declared entry point, and a
   `difficulty` assigned before any arm runs. Decoys need a `decoy_kind` and a
   `safe_because` naming the dominating check.
3. `uv run bench.py verify --corpus <id>` and iterate. **Do not loosen a keyword group to
   make the gate pass** — narrow the other bug's instead.
4. `uv run bench.py seal --corpus <id> --mint-key`, and store the key. **It is the only
   copy**; without it the ground truth is unrecoverable.

An authored corpus is strongly preferred: de-identification does not survive model recall.
See MEASUREMENTS.md §3 for the corpus that proved it.

---

## Tests

```sh
uv run pytest tests -q
```

**~40 failures while a corpus is sealed is expected**, not a regression: those tests need the
ground truth. Unseal to run them for real.
