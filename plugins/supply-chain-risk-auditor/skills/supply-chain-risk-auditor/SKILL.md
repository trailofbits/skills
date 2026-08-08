---
name: supply-chain-risk-auditor
description: "Audits a project's dependencies for supply-chain risk: version-matched advisories for direct dependencies and the full lockfile tree, abandoned or archived upstreams, npm publisher concentration, and install-time script execution. Use when asked to audit dependencies, assess supply-chain or third-party package risk, or review a dependency tree before an engagement."
allowed-tools: Read Write Bash Glob Grep
---

# Supply Chain Risk Auditor

Generates a supply-chain risk report for a project's direct dependencies (npm, PyPI,
Go), plus an advisory sweep of everything its lockfile resolves. Two deterministic
scripts do the measuring; your job is the judgment they refuse to automate.

## Why the scripts do the measuring, not you

Every figure in this report is a claim about somebody else's project, and hand-collected
figures were measured wrong before this skill was rebuilt around scripts: GitHub
contributor counts said five-plus people maintain `lodash` where npm's ACL says one, and
`gh` saw zero downloads for a package that moves 164 million a week. Do not estimate
maintainer counts, downloads, staleness, or CVE history from `gh`, web search, or
memory — run the collector, and quote what it measured.

The scripts enforce two rules worth knowing before you read their output:

- **Unavailable data is never evidence of risk.** Every criterion resolves to
  assessed-clean, assessed-flagged, or unassessable-with-a-reason.
- **An absent measurement is never a clean verdict.** A run that measured nothing exits
  non-zero instead of printing a report that finds nothing.

## Workflow

1. Confirm the target directory has manifests: `package.json`, `pyproject.toml`,
   `requirements*.txt`, or `go.mod`. If none exist, say so and stop — do not audit an
   ecosystem this collector does not parse by hand. Lockfiles read for exact versions
   and the transitive sweep: `package-lock.json`/`npm-shrinkwrap.json`, `uv.lock`, and
   a go 1.17+ `go.mod`. `yarn.lock`, `pnpm-lock.yaml`, and `poetry.lock` are not read —
   the report says so when they are present, and versions fall back to pins or the
   latest release.
2. Check `gh auth status`. Unauthenticated GitHub allows 60 requests/hour against 5,000,
   and the collector makes several per dependency; expect repository criteria to come
   back unassessable without it. Say so rather than fixing it silently.
3. Collect, then render. Put outputs somewhere outside the audited repository unless
   asked otherwise:

   ```sh
   uv run {baseDir}/scripts/collect.py <project-dir> --json <out-dir>/findings.json
   uv run {baseDir}/scripts/render.py <out-dir>/findings.json --out <out-dir>/report.md
   ```

   Expect a few minutes for ~50 dependencies — several HTTP requests per dependency,
   more with many Go modules, and slower without authenticated `gh`. If `collect.py`
   exits non-zero, it is refusing to report — relay its message verbatim instead of
   retrying or working around it.
4. Read `report.md` and `findings.json`. The report is the deliverable; the JSON carries
   the datum behind every verdict when you need to cite one.
5. Add what the collector cannot, clearly separated from what it measured:
   - A short narrative for this reader: what to act on first, and why.
   - Upgrade paths for advisory findings — check whether the fix is a patch or a major
     version away.
   - Replacement candidates for abandoned or archived dependencies. Verify a candidate
     exists in the registry before naming it, and label these as judgment, not
     measurement.
   - For flagged install scripts: whether `npm ci --ignore-scripts` is viable for this
     project's build.

## Style for what you add

Write added prose the way a security report reads, and apply the same register to the
report addendum and the final reply alike — replies get pasted into tickets and reports
verbatim. State the finding, the datum behind it, and the action.

- Impersonal and declarative: no first or second person ("I ran the collector", "you
  should upgrade"), no contractions, no exclamation points.
- Active voice, with the subject matter as the actor: "upgrading to 1.19.0 clears all
  25 advisories", not "it is recommended that axios be upgraded".
- Objective: no intensifiers or subjective framing ("very", "significant",
  "fortunately"), and no guesses about why the project chose what it chose.
- Tense: past for what the audit did, present for the state of the dependencies,
  future for the consequences of acting or not.
- Constructive: a recommendation names the action and its cost, never a culprit.

If the `report-writing:writing-style` skill is available in the session, follow it —
it is the full version of this register.

The rendered report carries facts only. The interpretive rules below are instructions
to you, not content for the reader — do not copy them into the deliverable as caveats
or framing.

## Reading the report

- **Unassessable is not risk.** PyPI publishes no maintainer ACL and Go has no registry;
  those rows say what could not be known, not what is wrong.
- **The coverage table bounds every claim.** "No advisories" means "none among what was
  assessed" — check the assessed count before repeating a clean verdict.
- **Quote figures verbatim.** Do not re-derive, round, or embellish the report's
  numbers; every one is reproducible from the artifact.
- **Absence from the findings is not endorsement.** A dependency with no findings was
  measured against these criteria only.

## Rationalizations to reject

- "`gh` can give me maintainer counts faster than the collector." Measured wrong — repo
  contributors and registry publish rights are different populations.
- "No findings, so the dependencies are safe." Read the coverage table; on PyPI and Go,
  half the criteria are structurally unassessable.
- "The unassessable rows would just confuse the reader; I'll drop them." They are the
  boundary of every claim in the report. Dropping them turns partial coverage into a
  clean bill of health, which is the failure this skill was rebuilt to prevent.
- "The version is probably close enough." A range checked at latest-release and a
  lockfile-resolved version are different claims; the report labels which one it makes.
  Keep the label.

## When not to use

- License compliance auditing.
- Scanning the target's own source for vulnerabilities or secrets — this skill never
  reads dependency source, only registry, advisory, and repository metadata.
- Judging whether the project installs or builds. The audit is designed to work from
  nothing more than the dependency list — manifests and lockfiles — and never installs,
  builds, or executes anything. Broken installs and import-time breakage are out of
  scope, and worth saying so if the user seems to expect them.
- Ecosystems other than npm, PyPI, and Go; say the ecosystem is unsupported rather than
  improvising an audit for it.
