export const meta = {
  name: "audit-pipeline",
  description:
    "Pipeline behind /insecure-defaults:audit. Invoke the command, not this.",
  whenToUse:
    "Do not invoke directly; run /insecure-defaults:audit instead. Called without its inputs, this pipeline stops immediately.",
  phases: [
    {
      title: "Recon",
      detail: "classify scope, profile frameworks and deploy manifests",
      model: "sonnet",
    },
    {
      title: "Discover",
      detail: "one agent per detection category, tailored to the recon profile",
      model: "sonnet",
    },
    {
      title: "Verify",
      detail: "refuting agents batched by category, 16 findings each",
      model: "opus",
    },
    {
      title: "Report",
      detail: "severity assignment and report assembly",
      model: "sonnet",
    },
  ],
};

const MODELS = {
  recon: "sonnet",
  discover: "sonnet",
  verify: "opus",
  report: "sonnet",
};

// One guard: nothing at all, a bare string, an array, or an object missing the
// field all arrive here the same way and have the same remedy.
const pluginRoot = String(args?.pluginRoot || "")
  .trim()
  .replace(/\/+$/, "");

if (!pluginRoot) {
  return {
    status: "missing-plugin-root",
    note:
      "This pipeline needs { scope, pluginRoot }; without pluginRoot the example " +
      "corpus cannot be located, so nothing was audited. " +
      "Run /insecure-defaults:audit instead.",
  };
}

const scope = String(args.scope || ".").trim() || ".";
const examplesDir = pluginRoot + "/references";

// Each agent gets only its own category's corpus. Existence is not pre-checked: the
// sweep reports whether it could read the file, and one failure aborts below.
const examplesFor = (categoryId) => `${examplesDir}/${categoryId}.md`;

const dirOf = (f) => {
  const i = f.lastIndexOf("/");
  return i === -1 ? "." : f.slice(0, i);
};

// Each phase allowlists the profile fields it uses; the run's bookkeeping stays out.
// A field recon omitted becomes an empty list rather than vanishing, so the shape an
// agent sees does not depend on recon.
const contextFor = (fields, source) =>
  `<context>\n${JSON.stringify(
    Object.fromEntries(fields.map((k) => [k, source[k] ?? []])),
    null,
    2,
  )}\n</context>`;

// ==========================================================================
// Detection categories
//
// Two files define a category, loaded by the sweep agent because this script cannot
// read them: references/<id>.json (title + seed patterns) and references/<id>.md
// (Report when / Skip when + vulnerable/secure pairs). Adding a category means a row
// below plus both files, agreeing on id and title.
// ==========================================================================

const CATEGORIES = [
  { id: "fallback-secrets", title: "Fallback secrets" },
  { id: "default-credentials", title: "Default credentials" },
  { id: "fail-open-security", title: "Fail-open security switches" },
  { id: "weak-crypto", title: "Weak cryptographic defaults" },
  { id: "permissive-access", title: "Permissive access defaults" },
  { id: "debug-features", title: "Debug and introspection defaults" },
];

// Shorthands, so the description text the agents read stays one field to a line.
const T = (type, description, extra) => ({
  type,
  ...(description ? { description } : {}),
  ...extra,
});
const STR = T("string");
const INT = T("integer");
const STRS = T("array", null, { items: STR });
const str = (d) => T("string", d);
const int = (d) => T("integer", d);
const bool = (d) => T("boolean", d);
const strs = (d) => T("array", d, { items: STR });
const enm = (values, d) => T("string", d, { enum: values });
const obj = (required, properties) => T("object", null, { required, properties });
const objs = (required, properties, d) =>
  T("array", d, { items: obj(required, properties) });

const RECON_SCHEMA = obj(
  ["scope_exists", "languages", "config_locations", "deploy_manifests", "exclude_paths"],
  {
    scope_exists: bool("Whether the requested scope exists on disk. False stops the run: a missing path must not be reported as clean."),
    languages: STRS,
    frameworks: objs(["name", "settings_paths"], { name: STR, settings_paths: STRS }),
    config_locations: STRS,
    config_accessors: objs(
      ["idiom", "where"],
      {
        idiom: str("Callable or accessor, e.g. get_config('X') or settings.FOO."),
        where: str("file:line where it is defined or a representative call site."),
        supplies_default: bool("True if the accessor itself can return a default when the key is absent; those are the fail-open ones."),
      },
      "How THIS project reads configuration: project-local wrappers, settings objects, and framework accessors, not just raw os.environ. The sweeps build their real patterns from these.",
    ),
    deploy_manifests: strs("Files that supply environment variables in production."),
    exclude_paths: strs("Non-production paths: tests, fixtures, examples, docs, vendored code."),
  },
);

const CANDIDATES_SCHEMA = obj(
  ["corpus_read", "patterns_loaded", "files_scanned", "derived_patterns", "candidates"],
  {
    corpus_read: bool("True only if you read the corpus file named in your instructions; false if it was missing or unreadable. Say so rather than sweeping without it: its counter-examples are what keep false positives out."),
    patterns_loaded: bool("True only if you read the seed patterns from <category>.json; false if that file was missing or unparseable."),
    files_scanned: int("How many files the searches actually matched against. 0 means the search failed, not that the repo is clean."),
    seed_patterns_run: strs("The seed patterns from <category>.json that you ran, verbatim."),
    derived_patterns: strs("Patterns you wrote yourself for THIS stack, beyond the seeds. An empty list means the sweep only looked for generic idioms, which is reported as a coverage gap."),
    candidates: objs(["file", "line", "snippet", "why_suspicious"], {
      file: STR,
      line: INT,
      snippet: STR,
      symbol: str("Variable, constant, or key being defaulted."),
      why_suspicious: STR,
    }),
  },
);

const VERDICTS_SCHEMA = obj(["verdicts"], {
  verdicts: objs(["file", "line", "refuted", "rationale"], {
    file: STR,
    line: INT,
    refuted: T("boolean"),
    refuted_at_step: {
      type: ["integer", "null"],
      description: "Which refutation step killed it (1-5), or null if confirmed.",
    },
    shape: enm(
      ["configurable", "unconditional"],
      "Which branch of step 2 applied. A confirmed 'configurable' finding is fail-open by construction, since step 2 refutes the fail-secure ones; 'unconditional' means no configuration was involved at all.",
    ),
    sink: str("file:line where the value reaches a security decision."),
    deployment_supplies_var: enm(
      ["always", "sometimes", "never", "unknown"],
      "Configurable candidates only, from the manifests in deploy_manifests: whether every one of them supplies the variable, only some, none, or you could not tell. Drives severity, so 'unknown' must mean you looked and could not establish it.",
    ),
    severity: enm(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    exploitation: STR,
    rationale: STR,
  }),
});

// ==========================================================================
// Phase 1 - Recon
// ==========================================================================

phase("Recon");

const recon = await agent(
  `You are the recon pass of an insecure-defaults security audit of \`${scope}\`.

Report only what you observed. An empty list is a valid answer; a guessed one is not.

**1. Check the scope is there.**

    test -e '${scope}' && echo present

Set \`scope_exists\` from that test, not from the path's shape. A missing path stops the run rather than sweeping nothing and reading as clean.

**2. Profile the target** so the category sweeps can be tailored to it. A single file is profiled together with the configuration machinery it depends on (its imports, the config wrapper it calls, the settings module it reads from), not the whole repository:

- Languages present, with the file extensions to search.
- Web/app frameworks and the concrete paths of their settings modules: Django \`settings.py\`, Rails \`config/environments/*.rb\`, Spring \`application*.yml\`, Express app bootstrap, Go \`main.go\` flag setup.
- Where configuration lives: config directories, \`.env*\` files, the functions this codebase uses to read environment variables (a project-local \`get_config()\` wrapper matters more than raw \`os.environ\`).
- **Deployment manifests that supply env vars in production**: Dockerfile, \`docker-compose*.yml\`, Kubernetes manifests, Helm values, Terraform, CI workflow files, systemd units, Procfile. This list decides whether a fallback is reachable in production, so be thorough.
- Paths to **exclude** as non-production: test and fixture directories, \`*.example\` / \`*.template\` / \`*.sample\`, docs, vendored dependencies, generated code, build output. **Never exclude \`${scope}\` itself or anything inside it.** The caller pointed there, so it is the target however test-like it looks; excluding it would sweep nothing and report a clean result. Exclusions describe what to skip *outside* the requested scope.`,
  { label: "recon", phase: "Recon", model: MODELS.recon, schema: RECON_SCHEMA },
);
if (!recon) {
  return {
    status: "recon-failed",
    note: "Recon returned nothing; no search profile to fan out from.",
  };
}

if (recon.scope_exists === false) {
  return {
    status: "scope-missing",
    note: `\`${scope}\` does not exist on disk. Nothing was audited.`,
  };
}

log(
  `Recon: ${(recon.languages || []).join(", ") || "no languages identified"} | ` +
    `${(recon.config_accessors || []).length} config accessors | ` +
    `${(recon.deploy_manifests || []).length} deploy manifests`,
);

// Everything an agent may be shown. `scope_exists` is spent by now; the rest is
// allowlisted per phase below.
const profile = { ...recon, scope };

const sweepContext = contextFor(
  [
    "languages",
    "frameworks",
    "config_locations",
    "config_accessors",
    "deploy_manifests",
    "exclude_paths",
  ],
  profile,
);

// A verifier needs exclude_paths (step 1) and deploy_manifests (step 5) and nothing
// else; the accessor inventory would only invite it to hunt new candidates.
const verifyContext = contextFor(
  ["scope", "exclude_paths", "deploy_manifests"],
  profile,
);

// ===========================================================================
// Phase 2 - Discover
//
// The barrier is deliberate: cross-category duplicates must collapse before verify
// pays for them, and the batching needs the complete candidate set.
// ===========================================================================

phase("Discover");

const sweeps = (
  await parallel(
    CATEGORIES.map(
      (cat) => () =>
        agent(
          `You are the **${cat.title}** sweep of an insecure-defaults audit of \`${scope}\`.

## Step 0: load your category definition

Read both files before anything else:

- \`${examplesDir}/${cat.id}.json\` holds the \`seeds\` to run.
- \`${examplesFor(cat.id)}\` holds **Report when** / **Skip when**, plus vulnerable/secure pairs across several languages with the reason each falls on its side of the line. It covers **only your category**. Those two lines are the rule for what counts as a candidate; apply them literally, and lean on the **SECURE** section to drop candidates rather than filing them.

Set \`patterns_loaded\` and \`corpus_read\` from whether you actually read each one. If either is missing or unparseable, set that flag \`false\` and **stop without sweeping**: the seeds say what to look for and the corpus says what to discard, and guessing at either produces noise that reads like a finding.

${sweepContext}

**Search target: \`${scope}\`.** Search it recursively; \`grep -rE\` covers a directory and a single file alike. Only lines **inside \`${scope}\`** are candidates, though you may read imports and the config helpers it calls to fill in \`symbol\`.

The caller named this path, so it is never out of scope: report candidates in it even if it sits under a tests or examples directory, noting the location in \`why_suspicious\` so the verifier can weigh it. Skip what the recon \`exclude_paths\` list names, but keep a path that looks production-reachable despite a suspicious-looking directory and say why in \`why_suspicious\`.

## Step 1: derive the patterns for *this* stack

The seeds in your \`.json\` are a **floor, not the search**: written without knowing this project, they miss whatever idiom dominates it. Before searching, write your category's patterns for the stack in the profile above, drawing on:

- **\`config_accessors\`**: the project's own wrappers. A codebase reading everything through \`get_setting("X", "default")\` barely matches raw \`os.environ.get\`, and its real findings are all at that wrapper's call sites. \`supplies_default: true\` marks where fail-open lives.
- **\`frameworks\`**: the settings keys that framework uses for *your* category (Django \`SECRET_KEY\`/\`DEBUG\`, Spring \`server.ssl.*\`/\`management.endpoints.*\`, Rails \`force_ssl\`/\`secret_key_base\`).
- **\`languages\`**: per-language shapes such as \`System.getProperty(k, d)\`, \`ENV.fetch\`, \`flag.String\`, \`\${VAR:-default}\`.
- **\`config_locations\` and \`deploy_manifests\`**: the same bug expressed in config syntax, such as a \`default =\` in an HCL \`variable {}\`, a literal in \`values.yaml\`, an \`ENV\` line in a Dockerfile. No code-shaped seed finds these.

Keep patterns POSIX-ERE safe: \`[[:space:]]\` and \`[0-9]\`, never \`\\s\`, \`\\d\`, or \`\\b\`. Some \`grep\` builds silently fail to match those, and a pattern matching nothing looks exactly like a clean result.

## Step 2: run them and collect

Run the \`.json\` seeds too, reporting them in \`seed_patterns_run\` and your own in \`derived_patterns\`. Keeping the two apart is the point: an empty \`derived_patterns\` says this sweep only looked for generic idioms, which is recorded as a coverage gap.

**Collect candidates, do not adjudicate them.** Do not spend turns tracing whether the app crashes without the config; a separate verifier does that with the whole file in context. Read enough around each match to fill in \`snippet\` and \`symbol\`, then move on. Over-collecting is cheap here; missing a line is not.

Many real findings involve **no configuration at all**: a hardcoded credential, a weak primitive, a public ACL, a stack trace written into a response. File those, and do not skip a candidate because there is no environment variable or fallback in sight.

Report \`files_scanned\`: how many files your searches actually matched against. 0 means the search failed, and it must not be reported as a clean result.`,
          {
            label: `sweep:${cat.id}`,
            phase: "Discover",
            model: MODELS.discover,
            schema: CANDIDATES_SCHEMA,
          },
        ).then((r) => (r ? { ...r, category: cat.id } : null)),
    ),
  )
).filter(Boolean);

// A sweep that could not read its corpus judged candidates without the
// counter-examples. Abort, since in a merged report nothing would distinguish it.
const corpusFailures = sweeps
  .filter((s) => s.corpus_read === false || s.patterns_loaded === false)
  .map((s) => s.category);
if (corpusFailures.length > 0) {
  return {
    status: "corpus-unreadable",
    note:
      `${corpusFailures.length}/${CATEGORIES.length} sweeps could not load their category definition from ${examplesDir}: ` +
      `${corpusFailures.join(", ")}. Nothing was audited; check the plugin installed completely, since every ` +
      `category needs its own <category>.json and <category>.md.`,
    examples_dir: examplesDir,
    categories_affected: corpusFailures,
  };
}

// Zero-item guard: a search that matched no files must not return a clean bill.
const totalScanned = sweeps.reduce((n, s) => n + (s.files_scanned || 0), 0);
if (sweeps.length === 0 || totalScanned === 0) {
  return {
    status: "search-failed",
    note: `${sweeps.length}/${CATEGORIES.length} sweeps returned, and they scanned ${totalScanned} files in total. This is a search failure, NOT a clean audit. Do not report the target as free of insecure defaults.`,
    sweeps: sweeps.map((s) => ({
      category: s.category,
      files_scanned: s.files_scanned,
      patterns_run:
        (s.seed_patterns_run || []).length + (s.derived_patterns || []).length,
    })),
  };
}

// The guard above is on the sum, so five failed searches beside one that worked clear
// it. Per category, then: 0 files (or a sweep that never returned) is a search that did
// not happen, and `categories_run` lists a category because its sweep returned, not
// because it searched.
const scannedByCategory = Object.fromEntries(
  CATEGORIES.map((c) => [
    c.id,
    sweeps.find((s) => s.category === c.id)?.files_scanned || 0,
  ]),
);
const unsearchedCategories = CATEGORIES.filter((c) => !scannedByCategory[c.id]).map(
  (c) => c.id,
);

if (unsearchedCategories.length > 0) {
  log(
    `Note: ${unsearchedCategories.length}/${CATEGORIES.length} sweeps scanned no files at all: ` +
      `${unsearchedCategories.join(", ")}. Those categories are NOT covered by this run.`,
  );
}

// Dedup keyed on `<category>:<file>:<line>`, so two patterns in one category hitting
// a line collapse, but a line flagged by *different* categories stays one candidate
// per category, each judged against its own discriminator and corpus. It also gives
// every candidate exactly one category, which is what lets Verify batch by category.
// The cost: a genuinely multi-category line is traced more than once.
const byLocation = new Map();
for (const sweep of sweeps) {
  for (const c of sweep.candidates || []) {
    const key = `${sweep.category}:${c.file}:${c.line}`;
    // Two patterns in one category hitting one line: first wins, same finding.
    if (!byLocation.has(key))
      byLocation.set(key, { ...c, category: sweep.category });
  }
}

const candidates = [...byLocation.values()];
const rawCount = sweeps.reduce((n, s) => n + (s.candidates || []).length, 0);

// A sweep that derived nothing searched for generic idioms in a codebase that may use
// none of them. That is a coverage gap; it goes in the report.
const seedOnlySweeps = sweeps
  .filter((s) => (s.derived_patterns || []).length === 0)
  .map((s) => s.category);

if (seedOnlySweeps.length > 0) {
  log(
    `Note: ${seedOnlySweeps.length}/${CATEGORIES.length} sweeps ran only the generic seed patterns and derived ` +
      `nothing for this stack: ${seedOnlySweeps.join(", ")}. Their coverage is weaker than the rest.`,
  );
}

log(
  `Discover: ${rawCount} raw candidates across ${totalScanned} files scanned → ` +
    `${candidates.length} unique locations after cross-category dedup`,
);

if (candidates.length === 0) {
  return {
    status: "no-candidates",
    note:
      `${CATEGORIES.length - unsearchedCategories.length}/${CATEGORIES.length} sweeps scanned ${totalScanned} files ` +
      `without flagging a candidate. Those searches executed, so this is a genuine negative result for them rather ` +
      `than a failure, but it is an absence of pattern matches, not proof of absence.` +
      (unsearchedCategories.length > 0
        ? ` It says nothing about ${unsearchedCategories.join(", ")}: those sweeps scanned no files, so those categories were not audited.`
        : ""),
    scanned: totalScanned,
    files_scanned_by_category: scannedByCategory,
    unsearched_categories: unsearchedCategories,
  };
}

// ===========================================================================
// Phase 3 - Verify
// ===========================================================================

phase("Verify");

// ---------------------------------------------------------------------------
// Batching: by category, chunked at 16 findings.
//
// One category per verifier means one corpus and one discriminator for the whole
// batch, where a per-file agent could be juggling six. The cap is because a category
// can flag hundreds of lines, and an agent that hits its tool-call limit partway
// returns a partial verdict list, which reads as "the rest were fine". Only
// per-agent size is capped; every batch runs.
// ---------------------------------------------------------------------------

const MAX_FINDINGS_PER_BATCH = 16;

const byCategory = new Map();
for (const c of candidates) {
  if (!byCategory.has(c.category)) byCategory.set(c.category, []);
  byCategory.get(c.category).push(c);
}

// Pack by directory, lexicographically, keeping a directory whole whenever it fits:
// its files usually share imports, a config module and framework conventions, so a
// verifier that traced one carries that into the next. A directory over the cap is
// split on its own rather than dragging unrelated ones into the split.
const batches = [];
for (const [category, group] of byCategory) {
  const byDir = new Map();
  for (const c of group) {
    const d = dirOf(c.file);
    if (!byDir.has(d)) byDir.set(d, []);
    byDir.get(d).push(c);
  }
  const dirs = [...byDir.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  for (const [, items] of dirs)
    items.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

  // First-fit over whole directories, in order.
  const packed = [];
  let current = [];
  for (const [, items] of dirs) {
    if (items.length > MAX_FINDINGS_PER_BATCH) {
      if (current.length) {
        packed.push(current);
        current = [];
      }
      for (let i = 0; i < items.length; i += MAX_FINDINGS_PER_BATCH)
        packed.push(items.slice(i, i + MAX_FINDINGS_PER_BATCH));
      continue;
    }
    if (current.length + items.length > MAX_FINDINGS_PER_BATCH) {
      packed.push(current);
      current = [];
    }
    current.push(...items);
  }
  if (current.length) packed.push(current);

  packed.forEach((cands, i) =>
    batches.push({
      category,
      candidates: cands,
      dirs: [...new Set(cands.map((c) => dirOf(c.file)))].sort(),
      chunk: i + 1,
      chunks: packed.length,
    }),
  );
}

const distinctFiles = new Set(candidates.map((c) => c.file)).size;

const singleDirBatches = batches.filter((b) => b.dirs.length === 1).length;

log(
  `Queued: ${candidates.length} candidates across ${distinctFiles} files → ` +
    `${batches.length} verify agent(s) over ${byCategory.size} categor${byCategory.size === 1 ? "y" : "ies"}` +
    (batches.length > byCategory.size
      ? `, ${batches.length - byCategory.size} of them extra chunks (cap ${MAX_FINDINGS_PER_BATCH} findings each)`
      : "") +
    `; ${singleDirBatches}/${batches.length} batch(es) cover a single directory`,
);

const verdictSets = (
  await parallel(
    batches.map((batch) => {
      const corpus = `${examplesDir}/${batch.category}.md`;
      const label =
        batch.chunks > 1
          ? `verify:${batch.category}-${batch.chunk}`
          : `verify:${batch.category}`;

      // Grouped by file so the agent reads each file once, seeing all its candidates.
      const byFile = {};
      for (const c of batch.candidates) {
        (byFile[c.file] ||= []).push({
          line: c.line,
          snippet: c.snippet,
          symbol: c.symbol,
          why_suspicious: c.why_suspicious,
        });
      }
      const fileCount = Object.keys(byFile).length;

      return () =>
        agent(
          `You are refuting **${batch.category}** candidates across ${fileCount} file${fileCount === 1 ? "" : "s"}${
            batch.dirs.length === 1
              ? ` in \`${batch.dirs[0]}\``
              : ` in ${batch.dirs.length} directories`
          }.${
            batch.dirs.length === 1
              ? `\n\nThey are all in one directory, so they most likely share imports, a config module, and the same framework conventions. Trace the first one, then reuse what you learned instead of re-deriving it per file.`
              : ""
          }

${verifyContext}

<candidates>
${JSON.stringify(byFile, null, 2)}
</candidates>

Every candidate here is **${batch.category}**, so one corpus covers the batch. Read \`${corpus}\` first: it draws the line between report-this and skip-this for this category, with worked vulnerable/secure pairs. No other category's corpus is relevant.

**Your default answer is \`refuted: true\`.** A pattern sweep produced these; most pattern matches are not vulnerabilities. Confirm one only when you can cite the code that makes it exploitable.

Work one file at a time: read it, then adjudicate every candidate listed for it before moving on. For each candidate work these steps **in order and stop at the first one that refutes it**, recording which step killed it in \`refuted_at_step\`:

1. **Is this file reachable in production?** A path under \`exclude_paths\`, dead code, a branch only taken under a dev flag, a script never packaged → refuted.
2. **Is the insecure value the one that actually runs?** Which question that is depends on the candidate's shape, so classify it first:

   - **Configurable**: the value comes from a config lookup with a fallback. Trace what happens when the configuration is absent. Anything that stops the process (a raising lookup, a startup validator, a schema rejecting missing values) is **fail-secure → refuted**. Booting and carrying on with the literal is fail-open; keep going.
   - **Unconditional**: no configuration is in the picture; the insecure value is written in the code. **This step cannot refute an unconditional candidate**: the insecure value is the only value, so there is no fail-secure path to find and no missing variable to reason about. Record the shape and move to step 3.

   Do **not** refute an unconditional candidate for "no configuration found", and do not record it as \`trace incomplete\` on those grounds. Roughly half of what this audit exists to find has no config fallback at all. Your corpus's **VULNERABLE** section shows which shapes this category takes in practice.
3. **Is the value actually insecure?** The **Skip when** line is the rule, and the **SECURE** section shows what a benign match looks like. For a configurable candidate the insecure state must be the *unconfigured* state; for an unconditional one, judge the value as written.
4. **Does the value reach a security decision?** Trace it to its sink and cite \`file:line\`. Signing, encryption, authentication, authorisation, credential comparison, transport verification. A config value read and never consulted at an enforcement point → refuted.
5. **Does deployment always supply the variable?** Configurable candidates only; unconditional ones have no variable to supply and nothing about deployment can mitigate them. Check every manifest in \`deploy_manifests\` and report which case holds in \`deployment_supplies_var\`. **No value here refutes anything**, it only moves severity:

   - \`always\` (every manifest sets it): the code-level defect stands but is far less exploitable. Confirm at lowered severity.
   - \`never\`: the CRITICAL case. The fallback is what production runs on.
   - \`sometimes\` (some do, some do not): treat it as reachable at full severity and name the manifests that leave it unset, since those are the exposed deployments.
   - \`unknown\`: you looked and could not establish it. Treat it as reachable and say in the rationale which manifests you could not resolve. Do not use it to mean you skipped the step.

Follow imports and callers wherever a trace leads, but only the \`file\`/\`line\` pairs listed above belong in your output. Do not hunt new candidates: six sweeps have already searched, and anything you turn up now would skip dedup and arrive unverified.

Return a verdict for **every** candidate listed, refutations included: one you omit is recorded as unverified and reported as a coverage gap, which is worse than a refutation with a reason. If you cannot complete a trace, return \`refuted: true\` with rationale \`"trace incomplete: <what blocked you>"\`.

Assign a \`severity\` to every candidate you confirm, CRITICAL through LOW, on the evidence. Do not withhold low-severity confirmations; filtering happens downstream, and a finding you decline to report is one nobody can review.

Cite \`file:line\` for every claim.`,
          { label, phase: "Verify", model: MODELS.verify, schema: VERDICTS_SCHEMA },
        );
    }),
  )
);

// NOT filtered: the array stays index-aligned with `batches` so each verdict can be
// stamped with the category its batch was judging. Verifiers return file/line only,
// and without the category an omission by one category is masked by another
// category's verdict for the same line, which is silently unverified.
const verdicts = verdictSets.flatMap((set, i) =>
  (set?.verdicts || []).map((v) => ({ ...v, category: batches[i].category })),
);
const batchesVerified = verdictSets.filter(Boolean).length;
const confirmed = verdicts.filter((v) => !v.refuted);
const refuted = verdicts.filter((v) => v.refuted);

// Candidates handed to a verifier that came back without a verdict. Keyed exactly as
// the candidates were, category included.
const adjudicated = new Set(
  verdicts.map((v) => `${v.category}:${v.file}:${v.line}`),
);
const unadjudicated = candidates.filter(
  (c) => !adjudicated.has(`${c.category}:${c.file}:${c.line}`),
);

log(
  `Verify: ${confirmed.length} confirmed, ${refuted.length} refuted, ` +
    `${unadjudicated.length} unadjudicated across ${batchesVerified}/${batches.length} batches`,
);

const coverage = {
  scope,
  files_scanned: totalScanned,
  categories_run: sweeps.map((s) => s.category),
  files_scanned_by_category: scannedByCategory,
  unsearched_categories: unsearchedCategories,
  patterns_run: sweeps.reduce(
    (n, s) => n + (s.seed_patterns_run || []).length + (s.derived_patterns || []).length,
    0,
  ),
  seed_only_sweeps: seedOnlySweeps,
  raw_candidates: rawCount,
  unique_candidates: candidates.length,
  files_with_candidates: distinctFiles,
  batches_run: batches.length,
  batches_verified: batchesVerified,
  // Keyed like the candidates, so a gap names the rule and not just a location.
  unadjudicated: unadjudicated.map((c) => `${c.category}:${c.file}:${c.line}`),
};

// Zero-item guard: nothing adjudicated is a verify failure, not a clean audit.
if (unadjudicated.length === candidates.length) {
  return {
    status: "verify-failed",
    note:
      `${batchesVerified}/${batches.length} verify batches returned and not one of the ` +
      `${candidates.length} candidates was adjudicated. This is a verification failure, NOT a clean ` +
      `audit: every candidate is still unjudged, so the target has neither been cleared nor found ` +
      `wanting. Re-run the audit.`,
    coverage,
    candidates: coverage.unadjudicated,
  };
}

// ===========================================================================
// Phase 4 - Report
// ===========================================================================

phase("Report");

const report = await agent(
  `Assemble the final report for an insecure-defaults audit of \`${scope}\`.

<confirmed_findings>
${JSON.stringify(
  // These are the survivors, so `refuted: false` / `refuted_at_step: null` are on
  // every entry and carry no information.
  confirmed.map(({ refuted, refuted_at_step, ...keep }) => keep),
  null,
  2,
)}
</confirmed_findings>

<refuted>
${JSON.stringify(
  refuted.map(({ category, file, line, refuted_at_step, rationale }) => ({ category, file, line, refuted_at_step, rationale })),
  null,
  2,
)}
</refuted>

<coverage>
${JSON.stringify(coverage, null, 2)}
</coverage>

Write markdown. Do not re-adjudicate the verdicts; the verifiers held the file context and you do not. Your job is presentation, grouping, and honest coverage accounting.

Length follows the evidence. A finding's section runs as long as its trace needs and no longer: cite what establishes it, then move on. Do not restate in the summary what a finding section already says, pad one section to match another's length, or add sections beyond the five below.

Structure:

1. **Summary**: count by severity, and one sentence on what the actual exposure is for this codebase. Note the split between configurable findings (a fallback the deployment may or may not override) and unconditional ones (insecure as written, with nothing to configure); they need different fixes and carry different urgency.
2. **Findings**, ordered by severity, one section each, in this format:

       Finding: <title>
       Location: <file>:<line>
       Pattern: <the offending line>

       Verification: <what the trace established, with the sink at file:line>
       Production Impact: <for a configurable finding, whether deployment supplies the variable per the manifests checked; for an unconditional one, say so plainly, since no configuration can mitigate it>
       Exploitation: <the concrete attack, or "not exploitable as configured" with why>

   Where several findings share one root cause (one config module, one wrapper function), group them under that cause and list the locations rather than repeating the analysis.
3. **Remediation**: grouped by fix, not by finding. \`env['X']\` over \`env.get('X', default)\`, a startup validator, a secrets backend. Name the specific files to change.
4. **Coverage and limits**: mandatory, and blunt. State the \`scope\`, files scanned, categories run, how many distinct patterns actually ran (\`patterns_run\`; a number close to the seed count means the sweeps barely adapted to this stack), and candidates found versus refuted. Every file holding a candidate was verified, so these four are the gaps, each stated explicitly when non-empty:

   - \`unsearched_categories\`: those categories scanned 0 files (see \`files_scanned_by_category\`), so their search did not run. They appear in \`categories_run\` because the sweep returned, not because it searched. Name them under a "**Not searched**" heading and say the audit covers nothing in those categories. Never present them as clean or as having found nothing.
   - \`unadjudicated\`: candidates handed to a verifier that came back without a verdict, listed as \`category:file:line\` so the rule is named alongside the location. Put them under a "**Not verified**" heading and say they may contain real findings.
   - \`batches_verified\` below \`batches_run\`: a verify batch died, taking up to 16 candidates with it. Name the shortfall; the affected candidates appear in \`unadjudicated\`.
   - \`seed_only_sweeps\`: those categories ran only the generic seed patterns and derived nothing for this stack, so their coverage is thinner. Name them.

   A reader must not be able to mistake a partial run for a complete one.
5. **Refuted candidates**: a compact table (location, step, one-line reason). This is the audit trail for why a pattern match was dropped, and it is what makes the run reviewable.

Return the markdown itself, nothing else.`,
  { label: "report", phase: "Report", model: MODELS.report },
);

// agent() returns null on terminal failure, and the caller prints `report`.
if (!report) {
  return {
    status: "report-failed",
    note:
      `The audit ran to completion and ${confirmed.length} finding(s) survived verification, but the report agent ` +
      `returned nothing. Present the findings from \`findings\`, \`refuted\` and \`coverage\` below. Do not re-run the ` +
      `audit and do not report the target as clean.`,
    coverage,
    findings: confirmed,
    refuted,
  };
}

return {
  status: confirmed.length > 0 ? "findings" : "no-findings-confirmed",
  coverage,
  findings: confirmed,
  refuted,
  report,
};
