#!/usr/bin/env node
// Exercises workflows/improve.js with every agent stubbed. The runtime injects globals
// and wraps the body in an async function; that is reproduced here by stripping the
// `export` and wrapping, so every loop guard is testable offline.
//
//   node workflow-harness.js <path-to-improve.js> [--self-test]
//
// --self-test mutates the workflow and requires each mutation to turn a scenario red, so a
// harness that stopped checking anything cannot still report success.

"use strict";

const fs = require("fs");

const workflowPath = process.argv[2];
const selfTest = process.argv.includes("--self-test");
if (!workflowPath) {
  console.error("usage: node workflow-harness.js <path-to-improve.js> [--self-test]");
  process.exit(2);
}
const SOURCE = fs.readFileSync(workflowPath, "utf8");

function compile(src) {
  const body = src.replace(/^export const meta/m, "const meta");
  return new Function(
    "agent",
    "parallel",
    "pipeline",
    "phase",
    "log",
    "args",
    "budget",
    "workflow",
    `return (async () => {\n${body}\n})()`,
  );
}

// ---------------------------------------------------------------- fixtures
const SKILL = "/repo/plugins/demo/skills/demo";
const BASELINE = {
  ok: true,
  error: "",
  skill_dir: SKILL,
  plugin_dir: "/repo/plugins/demo",
  plugin_version: "1.0.0",
  git_root: "/repo",
  git_initialized: false,
  head_sha: "abc123def456",
  untracked: [],
  out_dir: "/work/.skill-improver/demo",
  out_rel: "",
  prior_ledger_json: "",
  metrics_script: "/plug/scripts/collect_metrics.py",
  default_scope: ["plugins/demo/**"],
};
const CLEAN_SCOPE = { changed: ["plugins/demo/skills/demo/SKILL.md"], untracked: [] };
const FINALIZE_OK = { narration_sites_removed: 0, version: "1.0.1", metrics_ok: true, notes: "" };

// Finding / reply builders. Ids follow the workflow's `<file>:<line>:<class>` shape.
const F = (file, line, cls, severity, extra = {}) => ({
  id: `${file}:${line}:${cls}`,
  file,
  line,
  class: cls,
  severity,
  title: `${cls} at ${file}:${line}`,
  evidence: "observed in the file",
  ...extra,
});
const fid = (f) => `${f.file}:${f.line}:${f.class}`;
const REV = (findings = [], verified = []) => ({ findings, verified_fixed: verified, summary: "s" });
const FIX = (verdicts, round = 1) => ({ verdicts, diff_file: `fixes-round-${round}.diff`, notes: "" });
const V = (f, verdict, extra = {}) => ({
  id: typeof f === "string" ? f : fid(f),
  verdict,
  reason: "because",
  pin: "none: prose-only change",
  ...extra,
});

// Common findings.
const A = F("plugins/demo/skills/demo/SKILL.md", 3, "dangling-reference", "critical");
const B = F("plugins/demo/skills/demo/SKILL.md", 10, "second-person-voice", "major");
const C = F("plugins/demo/README.md", 5, "stale-usage-example", "critical");
const D = F("plugins/demo/skills/demo/SKILL.md", 20, "weak-trigger-description", "critical");
const M = F("plugins/demo/skills/demo/SKILL.md", 40, "verbose-line", "minor");
const T = F("plugins/demo/skills/demo/SKILL.md", 1, "non-gerund-name", "major");

// Scripted run. Reviews and fixes must be fully scripted; an unscripted round throws,
// so a mutated loop that runs longer than the scenario intended cannot look green.
async function run(src, opts = {}) {
  const {
    args = { skill: SKILL },
    baseline = BASELINE,
    reviews = [],
    fixes = [],
    scopes = [],
    finalScope,
    finalize = FINALIZE_OK,
  } = opts;
  const calls = [];
  const prompts = {};
  const agentOpts = {};
  const logs = [];
  let ri = 0;
  let fi = 0;
  let si = 0;
  const agent = async (prompt, o = {}) => {
    const label = o.label || "?";
    calls.push(label);
    prompts[label] = prompt;
    agentOpts[label] = o;
    if (label === "baseline") return baseline;
    if (label.startsWith("review:") || label === "final-review") {
      if (ri >= reviews.length) throw new Error(`unscripted review at ${label}`);
      return reviews[ri++];
    }
    if (label.startsWith("fix:")) {
      if (fi >= fixes.length) throw new Error(`unscripted fix at ${label}`);
      return fixes[fi++];
    }
    if (label.startsWith("scope:")) return si < scopes.length ? scopes[si++] : CLEAN_SCOPE;
    if (label === "final-scope") return finalScope === undefined ? CLEAN_SCOPE : finalScope;
    if (label === "persist") return "persisted";
    if (label === "finalize") return finalize;
    throw new Error(`unexpected agent label: ${label}`);
  };
  const parallel = async (thunks) => Promise.all(thunks.map((t) => Promise.resolve().then(t).catch(() => null)));
  const pipeline = async () => {
    throw new Error("pipeline is not used by this workflow");
  };
  const budget = { total: null, spent: () => 12345, remaining: () => Infinity };
  const workflow = async () => {
    throw new Error("nested workflow is not used");
  };
  const out = await compile(src)(agent, parallel, pipeline, () => {}, (m) => logs.push(m), args, budget, workflow);
  return { out, calls, prompts, agentOpts, logs };
}

async function throws(src, opts) {
  try {
    await run(src, opts);
    return null;
  } catch (e) {
    return e.message;
  }
}

// The ledger travels inside ```json fences: fence 0 of a review/fix prompt is the
// persisted ledger, fence 1 of a fix prompt is the dispatched-findings list.
const fences = (prompt) =>
  [...String(prompt || "").matchAll(/```json\n([\s\S]*?)\n```/g)].map((m) => JSON.parse(m[1]));

let PASS = 0;
const FAILURES = [];
const ok = (cond, msg) => {
  if (cond) PASS++;
  else FAILURES.push(msg);
};

// ---------------------------------------------------------------- scenarios
const SCENARIOS = {
  // T7 — clean review round 2: converged, one finalize, ledger ends on the clean review.
  "a clean review converges and finalizes exactly once": async (src) => {
    const { out, calls, prompts } = await run(src, {
      reviews: [REV([A, M]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const ledger = fences(prompts.finalize)[0];
    const last = ledger.rounds[ledger.rounds.length - 1];
    return [
      [out && out.converged === true, "the run must be converged"],
      [out && out.capped === false, "a converged run is not capped"],
      [calls.filter((c) => c.startsWith("review:") || c === "final-review").length === 2, "exactly two reviews must run"],
      [calls.filter((c) => c === "finalize").length === 1, "exactly one finalize must be dispatched"],
      [out && out.open_minor_count === 1, "the un-dispatched minor finding must survive in the result"],
      [last && last.type === "review" && last.open.critical + last.open.major === 0, "the ledger's last entry must be the clean review"],
      [calls.indexOf("final-scope") < calls.indexOf("finalize"), "the untracked-files check must run before finalize"],
      [ledger.findings[fid(A)].status === "fixed" && ledger.findings[fid(A)].verified === true, "the verified fix must be recorded as verified"],
    ];
  },

  // T1 — a rejected finding is not re-litigated and not re-dispatched.
  "a rejected finding is not re-litigated without new evidence": async (src) => {
    const { out, calls, prompts } = await run(src, {
      reviews: [REV([A, T]), REV([T, B], [fid(A)]), REV([], [fid(B)])],
      fixes: [
        FIX([V(A, "fixed"), V(T, "rejected", { reason: "documented deliberate: fixture AGENTS.md keeps the name for compatibility" })], 1),
        FIX([V(B, "fixed")], 2),
      ],
    });
    const dispatched2 = fences(prompts["fix:2"])[1].map((d) => d.id);
    const ledger = fences(prompts.finalize)[0];
    return [
      [/documented deliberate/.test(prompts["review:2"]), "the round-2 reviewer must be given the rejection and its reason"],
      [dispatched2.includes(fid(B)), "the new finding must be dispatched to the fixer"],
      [!dispatched2.includes(fid(T)), "the re-filed rejected finding must NOT be dispatched again"],
      [ledger.findings[fid(T)].status === "rejected", "the trap must still be rejected in the ledger"],
      [ledger.findings[fid(T)].refiled_after_verdict === 1, "the re-file must be counted, once"],
      [out && out.converged === true, "the run must still converge"],
      [calls.filter((c) => c.startsWith("fix:")).length === 2, "no extra fix round may be spent on the rejected finding"],
    ];
  },

  // T2 — the cap ends on a review-only round and exits loudly.
  "the cap dispatches one final review-only round and exits loudly": async (src) => {
    const A2 = F("plugins/demo/skills/demo/SKILL.md", 7, "invalid-frontmatter", "critical");
    const { out, calls, prompts } = await run(src, {
      args: { skill: SKILL, maxRounds: 2 },
      reviews: [REV([A, A2]), REV([C], [fid(A), fid(A2)]), REV([D], [fid(C)])],
      fixes: [FIX([V(A, "fixed"), V(A2, "fixed")], 1), FIX([V(C, "fixed")], 2)],
    });
    const reviews = calls.filter((c) => c.startsWith("review:") || c === "final-review");
    const persisted = fences(prompts.persist)[0];
    return [
      [reviews.length === 3 && reviews[2] === "final-review", "the cap must add exactly one review-only round"],
      [calls.filter((c) => c.startsWith("fix:")).length === 2, "no fixer may run after the final review"],
      [out && out.converged === false, "a capped run must not report convergence"],
      [out && out.capped === true, "a capped run must say it was capped"],
      [out && out.open_blocking.some((f) => f.id === fid(D)), "the open findings must be listed in the result"],
      [/NOT converged/.test(prompts.persist), "the persisted status must say NOT converged"],
      [persisted.findings[fid(D)].status === "open", "the final review's findings must reach the persisted ledger"],
      [/collect_metrics\.py/.test(prompts.persist), "the capped exit must still collect metrics"],
    ];
  },

  // T3 — a non-decreasing blocking count over 3 rounds escalates before round 4.
  "a non-decreasing blocking count escalates before round 4": async (src) => {
    const E1 = F("plugins/demo/skills/demo/SKILL.md", 50, "bypassable-check-a", "critical");
    const E2 = F("plugins/demo/skills/demo/SKILL.md", 60, "bypassable-check-b", "critical");
    const { out, calls } = await run(src, {
      reviews: [REV([A, B]), REV([C, D], [fid(A), fid(B)]), REV([E1, E2], [fid(C), fid(D)])],
      fixes: [FIX([V(A, "fixed"), V(B, "fixed")], 1), FIX([V(C, "fixed"), V(D, "fixed")], 2)],
    });
    return [
      [out && out.escalation && out.escalation.type === "counts-non-decreasing", "the counts detector must fire"],
      [out && out.escalation && out.escalation.finding_ids.includes(fid(E1)), "the escalation must name the open findings"],
      [calls.filter((c) => c.startsWith("review:")).length === 3, "the loop must stop before round 4"],
      [calls.filter((c) => c.startsWith("fix:")).length === 2, "no fix may run after the escalation"],
      [calls.includes("persist"), "the escalation must persist the ledger"],
      [out && /design decision/.test(out.escalation.message), "the escalation must ask for a design decision"],
    ];
  },

  // Same finding open for 3 consecutive rounds escalates even while counts decrease.
  "a finding recurring for 3 consecutive rounds escalates": async (src) => {
    const { out, calls } = await run(src, {
      reviews: [REV([A, B]), REV([A], [fid(B)]), REV([A])],
      fixes: [FIX([V(B, "fixed"), V(A, "deferred")], 1), FIX([V(A, "deferred")], 2)],
    });
    return [
      [out && out.escalation && out.escalation.type === "recurrence", "the recurrence detector must fire"],
      [out && out.escalation && out.escalation.finding_ids.includes(fid(A)), "the recurring finding must be named"],
      [calls.filter((c) => c.startsWith("review:")).length === 3, "the loop must stop at the third sighting"],
    ];
  },

  // T4 — a finding "fixed" twice is a relocation, caught right after the second fix.
  "a re-fixed finding escalates as relocation, not at round N+2": async (src) => {
    const { out, calls } = await run(src, {
      reviews: [REV([A]), REV([A], []), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1), FIX([V(A, "fixed")], 2)],
    });
    return [
      [out && out.escalation && out.escalation.type === "relocation", "the relocation detector must fire"],
      [out && out.escalation && out.escalation.finding_ids.includes(fid(A)), "the re-fixed finding must be named"],
      [calls.filter((c) => c.startsWith("review:")).length === 2, "no third review may run — escalate at the second fix"],
      [out && /UNREVIEWED/.test(out.escalation.message), "the escalation must say the last fix is unreviewed"],
    ];
  },

  // T5 — a dead fixer marks the round failed; the next action is a review.
  "a dead fixer fails the round and the next action is a review": async (src) => {
    const { out, calls, prompts } = await run(src, {
      reviews: [REV([A]), REV([A]), REV([], [fid(A)])],
      fixes: [null, FIX([V(A, "fixed")], 2)],
    });
    const ledger = fences(prompts.finalize)[0];
    const failedRound = ledger.rounds.find((r) => r.type === "fix" && r.round === 1);
    const i = calls.indexOf("fix:1");
    return [
      [out && out.fixer_failed_rounds.length === 1 && out.fixer_failed_rounds[0] === 1, "the result must flag the failed round"],
      [failedRound && failedRound.failed === true && failedRound.verdicts.fixed === 0, "the ledger must record the round as failed with zero fixes"],
      [calls[i + 1] === "scope:1", "the scope guard must still run over a dead fixer's partial edits"],
      [calls[i + 2] === "review:2", "the next action after a dead fixer must be a review, not another fix"],
      [out && out.notes.some((n) => /died/.test(n)), "the result must say the fixer died"],
      [out && out.converged === true, "the loop must still be able to converge afterwards"],
    ];
  },

  // T6 — an out-of-scope change halts the round, immediately.
  "an out-of-scope change halts the loop at that round": async (src) => {
    const { out, calls, prompts } = await run(src, {
      reviews: [REV([A])],
      fixes: [FIX([V(A, "fixed")], 1)],
      scopes: [{ changed: ["plugins/demo/skills/demo/SKILL.md", "plugins/other/thing.md"], untracked: [] }],
    });
    return [
      [out && out.halted === "scope-violation", "the run must halt on the violation"],
      [out && out.violations.includes("plugins/other/thing.md"), "the violating path must be in the result"],
      [calls.filter((c) => c.startsWith("review:")).length === 1, "no further round may run after the violation"],
      [calls[calls.length - 1] === "persist", "the halt must end with the persisted ledger, nothing else"],
      [/scope violation/i.test(prompts.persist), "the persisted status must name the violation"],
      [out && out.converged === false, "a halted run must not report convergence"],
    ];
  },

  // Completion requires no unregistered new files in scope (fix E).
  "an unregistered new file in scope blocks completion": async (src) => {
    const newFile = "plugins/demo/skills/demo/notes.md";
    const blocked = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      finalScope: { changed: CLEAN_SCOPE.changed, untracked: [newFile] },
    });
    const preexisting = await run(src, {
      baseline: { ...BASELINE, untracked: [newFile] },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      finalScope: { changed: CLEAN_SCOPE.changed, untracked: [newFile] },
    });
    return [
      [blocked.out && blocked.out.converged === false, "a new untracked file in scope must block completion"],
      [blocked.out && blocked.out.halted === "untracked-files-in-scope", "the result must say why"],
      [blocked.out && blocked.out.new_untracked_files.includes(newFile), "the file must be named"],
      [!blocked.calls.includes("finalize"), "finalize must not run on a blocked completion"],
      [preexisting.out && preexisting.out.converged === true, "a file untracked since the baseline must not block completion"],
    ];
  },

  // The artifact directory and baseline-era untracked files are exempt from the guard.
  "the artifact directory is exempt from the scope guard": async (src) => {
    const { out } = await run(src, {
      baseline: { ...BASELINE, out_rel: ".skill-improver/demo", untracked: ["junk-preexisting.txt"] },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      scopes: [{ changed: CLEAN_SCOPE.changed, untracked: [".skill-improver/demo/ledger.json", "junk-preexisting.txt"] }],
    });
    return [
      [out && out.halted === "" && out.converged === true, "the run's own artifacts must not read as violations"],
    ];
  },

  // The reviewer contract: persistence, ledger discipline, report-everything.
  "the reviewer prompt carries persistence and the ledger discipline": async (src) => {
    const { prompts, agentOpts } = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const p = prompts["review:1"];
    return [
      [/STEP 0 — before anything else, persist the ledger/.test(p), "the review must persist the ledger before anything else"],
      [p.includes("/work/.skill-improver/demo/ledger.json"), "the persist step must name the ledger path"],
      [/verbatim/.test(p), "the persist step must forbid reformatting"],
      [/Do not withhold or pre-filter low-severity findings/.test(p), "the reviewer must be told to report everything"],
      [/new_evidence=true/.test(p), "the re-file discipline must reach the reviewer"],
      [/verified_fixed/.test(p), "the fix-verification duty must reach the reviewer"],
      [agentOpts["review:1"].agentType === "skill-improver:reviewer", "the reviewer must run as the plugin's reviewer agent"],
      [/review-only round/.test(prompts["review:1"]) === false, "an ordinary round must not claim to be final"],
    ];
  },

  // The fixer contract: git safety, pins, scope, no narration.
  "the fixer prompt carries the safety contract": async (src) => {
    const { prompts, agentOpts } = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const p = prompts["fix:1"];
    return [
      [/NEVER run `git checkout --`, `git stash`, `git reset`, `git clean`, or `git commit`/.test(p), "the git prohibitions must reach the fixer"],
      [/fails against the pre-fix code/.test(p), "the pin requirement must reach the fixer"],
      [p.includes("plugins/demo/**"), "the scope globs must reach the fixer"],
      [p.includes(`fixes-round-1.diff`), "the round diff artifact must be requested"],
      [/git add -N/.test(p), "new files must be registered so the guard can see them"],
      [/No narration/.test(p), "the no-narration rule must reach the fixer"],
      [/weaken a documented guarantee/.test(p), "the no-silent-weakening rule must reach the fixer"],
      [agentOpts["fix:1"].agentType === "skill-improver:fixer", "the fixer must run as the plugin's fixer agent"],
    ];
  },

  // Baseline guards: everything the loop stands on must be verified or fatal.
  "a broken baseline stops the run before any review": async (src) => {
    const dead = await throws(src, { baseline: null });
    const notOk = await throws(src, { baseline: { ...BASELINE, ok: false, error: "no SKILL.md at the target" } });
    const relRoot = await throws(src, { baseline: { ...BASELINE, git_root: "repo" } });
    const noSha = await throws(src, { baseline: { ...BASELINE, head_sha: "" } });
    const relOut = await throws(src, { baseline: { ...BASELINE, out_dir: "out" } });
    const noScope = await throws(src, { baseline: { ...BASELINE, default_scope: [] } });
    return [
      [dead && /baseline phase returned nothing/.test(dead), "a dead baseline must stop the run"],
      [notOk && /no SKILL\.md at the target/.test(notOk), "the baseline's own error must reach the message"],
      [relRoot && /non-absolute git root/.test(relRoot), "a relative git root must be fatal"],
      [noSha && /HEAD sha/.test(noSha), "a missing baseline sha must be fatal"],
      [relOut && /artifact directory/.test(relOut), "a relative artifact directory must be fatal"],
      [noScope && /no scope/.test(noScope), "an empty scope must be fatal"],
    ];
  },

  "args parse from a prose string, a bare path, and reject bad shapes": async (src) => {
    const prose = await run(src, {
      args: "skill: /x/skills/y; maxRounds: 3",
      reviews: [REV([])],
    });
    const bare = await run(src, { args: "/x/skills/y", reviews: [REV([])] });
    const missing = await throws(src, { args: {} });
    const badRounds = await throws(src, { args: { skill: SKILL, maxRounds: 0 } });
    const nanRounds = await throws(src, { args: { skill: SKILL, maxRounds: "lots" } });
    return [
      [prose.prompts.baseline.includes("/x/skills/y"), "a prose args string must still set the skill"],
      [bare.prompts.baseline.includes("/x/skills/y"), "a bare path must become the skill"],
      [missing && /args\.skill is required/.test(missing), "a missing skill must throw"],
      [badRounds && /maxRounds/.test(badRounds), "a zero round cap must throw"],
      [nanRounds && /maxRounds/.test(nanRounds), "a non-numeric round cap must throw"],
    ];
  },

  "the user's escalation decision reaches reviewer and fixer": async (src) => {
    const { prompts } = await run(src, {
      args: { skill: SKILL, decision: "keep the blocklist, document the limitation" },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    return [
      [/keep the blocklist/.test(prompts["review:1"]), "the decision must reach the reviewer"],
      [/keep the blocklist/.test(prompts["fix:1"]), "the decision must reach the fixer"],
      [/binding/.test(prompts["fix:1"]), "the decision must be marked binding"],
    ];
  },

  // A continued run reloads verdicts but not round bookkeeping (fix A + decision Q3).
  "a prior ledger reloads verdicts without tripping the oscillation checks": async (src) => {
    const O = F("plugins/demo/skills/demo/SKILL.md", 8, "dead-script-path", "critical");
    const priorFinding = (f, extra) => ({
      id: fid(f),
      coarse: `${f.file}::${f.class}`,
      file: f.file,
      line: f.line,
      class: f.class,
      severity: f.severity,
      title: f.title,
      evidence: f.evidence,
      status: "open",
      verdict_reason: "",
      verified: false,
      first_round: 1,
      last_round: 3,
      rounds_seen: [2, 3],
      fixed_rounds: [1],
      refiled_after_verdict: 0,
      notes: [],
      ...extra,
    });
    const prior = {
      version: 1,
      skill: SKILL,
      scope: ["plugins/demo/**"],
      decisions: ["prior ruling"],
      prior_rounds: [],
      rounds: [{ round: 1, type: "review" }],
      findings: {
        [fid(T)]: priorFinding(T, { status: "rejected", verdict_reason: "documented deliberate trap", refiled_after_verdict: 1, fixed_rounds: [] }),
        [fid(O)]: priorFinding(O),
      },
      result: null,
    };
    const { out, prompts } = await run(src, {
      baseline: { ...BASELINE, prior_ledger_json: JSON.stringify(prior) },
      reviews: [REV([T, O]), REV([], [fid(O)])],
      fixes: [FIX([V(O, "fixed")], 1)],
    });
    const dispatched = fences(prompts["fix:1"])[1].map((x) => x.id);
    const ledger = fences(prompts.finalize)[0];
    return [
      [out && out.converged === true && !out.escalation, "stale round numbers must not trip the oscillation checks"],
      [!dispatched.includes(fid(T)), "a rejection from the prior run must still bind"],
      [dispatched.includes(fid(O)), "an open finding from the prior run must be dispatched"],
      [ledger.findings[fid(T)].refiled_after_verdict === 2, "the re-file counter must accumulate across runs"],
      [/prior ruling/.test(prompts["review:1"]), "prior decisions must reach the reviewer"],
    ];
  },

  // Finalize contract: narration strip, exactly one bump, metrics.
  "the finalize prompt carries the residue-removal contract": async (src) => {
    const withMetrics = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const noMetrics = await run(src, {
      baseline: { ...BASELINE, metrics_script: "" },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const p = withMetrics.prompts.finalize;
    return [
      [/Exactly one version bump/.test(p), "the one-bump rule must reach finalize"],
      [p.includes("`1.0.0`"), "the baseline version must be named so the bump is checkable"],
      [/narration/.test(p), "the narration strip must reach finalize"],
      [p.includes("/plug/scripts/collect_metrics.py"), "the resolved collector path must be used"],
      [/--tokens 12345/.test(p), "the spent-token count must reach the collector"],
      [/ledger\.md/.test(p), "the human-readable ledger must be rendered"],
      [/No metrics collector was found/.test(noMetrics.prompts.finalize), "a missing collector must be loud, not silent"],
      [noMetrics.out.notes.some((n) => /collect_metrics/.test(n)), "the missing collector must reach the result notes"],
    ];
  },

  "a dead reviewer halts and persists rather than guessing": async (src) => {
    const { out, calls } = await run(src, { reviews: [null] });
    return [
      [out && out.halted === "reviewer-failed", "a dead reviewer must halt the run"],
      [calls.includes("persist"), "the halt must persist the ledger"],
      [!calls.some((c) => c.startsWith("fix:")), "no fix may run without a review"],
    ];
  },

  "the baseline prompt pins the commit identity and reads the prior ledger": async (src) => {
    const { prompts } = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const p = prompts.baseline;
    return [
      [/user\.name='skill-improver-baseline'/.test(p), "an auto-init commit must carry an explicit identity"],
      [/git ls-files --others/.test(p), "the untracked snapshot must be taken"],
      [/ledger\.json/.test(p), "the prior ledger must be looked for"],
      [/git_initialized/.test(p), "creating a repository must be reported, loudly"],
    ];
  },

  "a finding the fixer never addressed stays open": async (src) => {
    const { out, prompts } = await run(src, {
      reviews: [REV([A, B]), REV([B], [fid(A)]), REV([], [fid(B)])],
      fixes: [FIX([V(A, "fixed")], 1), FIX([V(B, "fixed")], 2)],
    });
    const ledger = fences(prompts.finalize)[0];
    const fix1 = ledger.rounds.find((r) => r.type === "fix" && r.round === 1);
    return [
      [fix1 && fix1.unaddressed.includes(fid(B)), "the unaddressed finding must be recorded"],
      [out && out.converged === true, "the loop must recover by dispatching it again"],
    ];
  },
};

// ---------------------------------------------------------------- mutations
// Each removes one guard. --self-test requires every one to turn a scenario red.
const MUTATIONS = [
  ["drop the final review-only round at the cap", (s) => s.replace("round <= MAX_FIX_ROUNDS + 1", "round <= MAX_FIX_ROUNDS")],
  ["ignore a non-decreasing blocking count", (s) => s.replace("if (nonDecreasingOver3(countsHistory)) {", "if (false) {")],
  ["ignore a recurring finding", (s) => s.replace("} else if (recurringBlocking().length) {", "} else if (false) {")],
  ["ignore a re-fixed finding", (s) => s.replace("if (refixed().length) {", "if (false) {")],
  ["treat a dead fixer as a clean round", (s) => s.replace("if (!fixed) {", "if (false) {")],
  ["continue past a scope violation", (s) => s.replace("if (violations.length) {", "if (false) {")],
  ["re-litigate rejected findings", (s) => s.replace("if (ex.status === 'rejected' && !raw.new_evidence) {", "if (false) {")],
  ["complete with unregistered new files", (s) => s.replace("} else if (newUntracked.length) {", "} else if (false) {")],
  ["stop persisting the ledger before each round", (s) => s.replace("STEP 0 — before anything else, persist the ledger", "Context: the ledger")],
  ["drop the git prohibitions from the fixer contract", (s) => s.replace(/- NEVER run \\`git checkout --\\`.*\n/, "")],
  ["let the reviewer pre-filter", (s) => s.replace("Do not withhold or pre-filter low-severity findings", "Use judgement about which findings to report")],
  ["dispatch the reviewer without its agent definition", (s) => s.replace(", agentType: 'skill-improver:reviewer' }", " }")],
  ["drop the one-bump rule from finalize", (s) => s.replace("Exactly one version bump.", "Version handling:")],
  ["keep stale round numbers on ledger reload", (s) => s.replace("rounds_seen: [],", "rounds_seen: f.rounds_seen || [],")],
  ["keep stale fix rounds on ledger reload", (s) => s.replace("fixed_rounds: [],\n      fixed_prior", "fixed_rounds: f.fixed_rounds || [],\n      fixed_prior")],
  ["strip the artifact-directory exemption", (s) => s.replace("const isArtifact = (p) => OUT_REL && (p === OUT_REL || p.startsWith(`${OUT_REL}/`))", "const isArtifact = () => false")],
  ["let every path match the scope", (s) => s.replace("return new RegExp(`^${esc}$`)", "return /^/")],
];

(async () => {
  for (const [name, fn] of Object.entries(SCENARIOS)) {
    let results;
    try {
      results = await fn(SOURCE);
    } catch (e) {
      FAILURES.push(`${name}: threw unexpectedly: ${e.message}`);
      continue;
    }
    for (const [cond, msg] of results) ok(cond, `${name}: ${msg}`);
  }

  if (selfTest) {
    let bitten = 0;
    for (const [label, mutate] of MUTATIONS) {
      const mutated = mutate(SOURCE);
      if (mutated === SOURCE) {
        FAILURES.push(`self-test: mutation "${label}" changed nothing — it no longer matches the source`);
        continue;
      }
      let red = false;
      for (const fn of Object.values(SCENARIOS)) {
        try {
          const results = await fn(mutated);
          if (results.some(([cond]) => !cond)) {
            red = true;
            break;
          }
        } catch {
          red = true;
          break;
        }
      }
      if (red) bitten++;
      else FAILURES.push(`self-test: no scenario caught the mutation "${label}"`);
    }
    ok(bitten === MUTATIONS.length, `self-test: ${bitten}/${MUTATIONS.length} mutations caught`);
  }

  if (FAILURES.length) {
    for (const f of FAILURES) console.error(`  FAIL: ${f}`);
    console.error(`${FAILURES.length} failed, ${PASS} passed`);
    process.exit(1);
  }
  if (PASS === 0) {
    console.error("no assertions ran — discovery is broken");
    process.exit(1);
  }
  console.log(`${PASS} assertions passed`);
})();
