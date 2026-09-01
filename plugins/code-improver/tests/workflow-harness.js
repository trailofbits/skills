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
const RV = { kind: "agent", name: "plugin-dev:skill-reviewer" };
const RV_SKILL = { kind: "skill", name: "pr-review-toolkit:review-pr" };
const BASELINE = {
  ok: true,
  error: "",
  target_dir: SKILL,
  plugin_dir: "/repo/plugins/demo",
  plugin_version: "1.0.0",
  marketplace_file: "",
  git_root: "/repo",
  git_initialized: false,
  head_sha: "abc123def456",
  untracked: [],
  untracked_digests: [],
  out_dir: "/work/.code-improver/demo",
  out_rel: "",
  prior_ledger_json: "",
  metrics_script: "/plug/scripts/collect_metrics.py",
  default_scope: ["plugins/demo/**"],
  reviewer_available: true,
  reviewer_probe: "",
};
const CLEAN_SCOPE = { changed: ["plugins/demo/skills/demo/SKILL.md"], untracked: [] };
const FINALIZE_OK = { narration_sites_removed: 0, version: "1.0.1", notes: "" };
const CHECK_OK = { ...CLEAN_SCOPE, regressions: [], metrics_ok: true };

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
const DIRECT = (findings = [], verified = []) => ({ mode: "direct", findings, verified_fixed: verified, summary: "s", agents: [] });
const DISPATCH = (agents, summary = "dispatching specialists") => ({ mode: "dispatch", findings: [], verified_fixed: [], summary, agents });
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
    args = { target: SKILL, reviewer: RV },
    baseline = BASELINE,
    reviews = [],
    fixes = [],
    scopes = [],
    specialists = [],
    finalScope,
    finalize = FINALIZE_OK,
    finalizeCheck,
  } = opts;
  const calls = [];
  const prompts = {};
  const agentOpts = {};
  const logs = [];
  let ri = 0;
  let fi = 0;
  let si = 0;
  let spi = 0;
  const agent = async (prompt, o = {}) => {
    const label = o.label || "?";
    calls.push(label);
    prompts[label] = prompt;
    agentOpts[label] = o;
    if (label === "baseline") return baseline;
    if (label.startsWith("review:") || label === "final-review") {
      if (ri >= reviews.length) throw new Error(`unscripted review at ${label}`);
      const r = reviews[ri++];
      if (r && r.__throw) throw new Error(r.__throw);
      return r;
    }
    if (label.startsWith("fix:")) {
      if (fi >= fixes.length) throw new Error(`unscripted fix at ${label}`);
      return fixes[fi++];
    }
    if (label.startsWith("specialist:")) {
      if (spi >= specialists.length) throw new Error(`unscripted specialist at ${label}`);
      const s = specialists[spi++];
      if (s && s.__throw) throw new Error(s.__throw);
      return s;
    }
    if (label.startsWith("scope:")) return si < scopes.length ? scopes[si++] : CLEAN_SCOPE;
    if (label === "final-scope") return finalScope === undefined ? CLEAN_SCOPE : finalScope;
    if (label === "persist" || label.startsWith("persist:")) return "persisted";
    if (label === "finalize") return finalize;
    if (label === "finalize-check") return finalizeCheck === undefined ? CHECK_OK : finalizeCheck;
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
      [calls.indexOf("finalize") < calls.indexOf("finalize-check"), "finalize's own edits must be checked after it runs"],
      [calls[calls.length - 1] === "finalize-check", "no agent may touch the tree after the finalize check"],
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

  // The reviewer is told to re-report under the exact ledger id, so the id it returns is
  // what matches: two findings of one class in one file defeat the coarse fallback.
  "a rejected finding re-reported at a shifted line is matched by its id": async (src) => {
    const T1 = F("plugins/demo/skills/demo/SKILL.md", 10, "second-person-voice", "major");
    const T2 = F("plugins/demo/skills/demo/SKILL.md", 40, "second-person-voice", "major");
    const shifted = (f, line) => ({ ...f, line });
    const { out, calls, prompts } = await run(src, {
      reviews: [
        REV([A, T1, T2]),
        REV([shifted(T1, 12), shifted(T2, 42)], [fid(A)]),
      ],
      fixes: [
        FIX([V(A, "fixed"), V(T1, "rejected", { reason: "documented deliberate: the fixture's voice is quoted from a spec" }), V(T2, "rejected", { reason: "documented deliberate: same spec quote" })], 1),
      ],
    });
    const ledger = fences(prompts.finalize)[0];
    return [
      [out && out.converged === true, "the run must converge — nothing was left open"],
      [calls.filter((c) => c.startsWith("fix:")).length === 1, "no second fix round may be spent re-litigating the rejections"],
      [Object.keys(ledger.findings).length === 3, "a shifted re-report must not spawn duplicate findings"],
      [ledger.findings[fid(T1)] && ledger.findings[fid(T1)].status === "rejected", "the first rejection must stand"],
      [ledger.findings[fid(T2)] && ledger.findings[fid(T2)].status === "rejected", "the second rejection must stand"],
      [ledger.findings[fid(T1)] && ledger.findings[fid(T1)].refiled_after_verdict === 1, "the re-file must be counted against the right finding"],
      [ledger.findings[fid(T2)] && ledger.findings[fid(T2)].refiled_after_verdict === 1, "and against the other one too"],
    ];
  },

  // T2 — the cap ends on a review-only round and exits loudly.
  "the cap dispatches one final review-only round and exits loudly": async (src) => {
    const A2 = F("plugins/demo/skills/demo/SKILL.md", 7, "invalid-frontmatter", "critical");
    const { out, calls, prompts } = await run(src, {
      args: { target: SKILL, reviewer: RV, maxRounds: 2 },
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

  // A blocking finding rejected as structurally unsatisfiable escalates to the user
  // instead of converging past a broken promise.
  "a structurally unsatisfiable demand escalates instead of converging": async (src) => {
    const { out, calls, prompts } = await run(src, {
      reviews: [REV([A, T])],
      fixes: [
        FIX(
          [
            V(A, "rejected", { structural: true, reason: "docs demand the impossible and are marked frozen" }),
            V(T, "rejected", { reason: "documented deliberate" }),
          ],
          1,
        ),
      ],
    });
    return [
      [out && out.escalation && out.escalation.type === "structural-rejection", "the structural rejection must escalate"],
      [out && out.escalation.finding_ids.includes(fid(A)), "the unsatisfiable finding must be named"],
      [out && !out.escalation.finding_ids.includes(fid(T)), "an ordinary rejection must not be swept into the escalation"],
      [calls.filter((c) => c.startsWith("review:")).length === 1, "no further round may run — the user rules first"],
      [out && out.converged === false, "a structural rejection is not convergence"],
      [/structural=true/.test(prompts["fix:1"]), "the structural-flag contract must reach the fixer"],
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
      [calls.slice(i + 2).filter((c) => c.startsWith("review:") || c.startsWith("fix:"))[0] === "review:2", "the next action after a dead fixer must be a review, not another fix"],
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

  // `git diff` cannot see what happens to a file git does not track, so out-of-scope
  // untracked files are guarded by content hash instead.
  "an out-of-scope untracked file is guarded by its content": async (src) => {
    const DECOY = "DECOY-NOTES.txt";
    const digest = (sha) => ({ untracked_digests: [{ path: DECOY, sha }] });
    const guarded = { ...BASELINE, untracked: [DECOY], ...digest("aaa111") };
    const round = (scope) => ({
      baseline: guarded,
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      scopes: [scope],
      finalizeCheck: { ...CHECK_OK, untracked: [DECOY], ...digest("aaa111") },
    });
    const intact = await run(src, round({ ...CLEAN_SCOPE, untracked: [DECOY], ...digest("aaa111") }));
    const rewritten = await run(src, round({ ...CLEAN_SCOPE, untracked: [DECOY], ...digest("bbb222") }));
    const deleted = await run(src, round({ ...CLEAN_SCOPE, untracked: [], ...digest("MISSING") }));
    const silent = await run(src, round({ ...CLEAN_SCOPE, untracked: [DECOY] }));
    const atFinalize = await run(src, {
      ...round({ ...CLEAN_SCOPE, untracked: [DECOY], ...digest("aaa111") }),
      finalizeCheck: { ...CHECK_OK, untracked: [DECOY], ...digest("ccc333") },
    });
    const unhashed = await run(src, {
      baseline: { ...BASELINE, untracked: [DECOY] },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const named = (r, what) => r.out && r.out.violations.some((v) => v.includes(DECOY) && v.includes(what));
    return [
      [intact.out && intact.out.converged === true, "an untouched guarded file must not halt the run"],
      [intact.prompts["scope:1"].includes(`hash-object -- "${DECOY}"`), "the guard must ask for the hash every round"],
      [intact.prompts["finalize-check"].includes(`hash-object -- "${DECOY}"`), "and again after finalize"],
      [rewritten.out && rewritten.out.halted === "scope-violation", "a rewritten out-of-scope untracked file must halt the loop"],
      [named(rewritten, "modified"), "the violation must name the file and what happened"],
      [deleted.out && deleted.out.halted === "scope-violation" && named(deleted, "deleted"), "a deleted one must halt too — it vanishes from every diff"],
      [silent.out && silent.out.halted === "scope-violation" && named(silent, "unverified"), "a hash the check never reported must not read as unchanged"],
      [atFinalize.out && atFinalize.out.converged === false && atFinalize.out.halted === "scope-violation", "the finalize pass is guarded the same way"],
      [unhashed.out && unhashed.out.converged === true, "a file with no baseline hash cannot be guarded, so it cannot halt"],
      [unhashed.out && unhashed.out.notes.some((n) => n.includes(DECOY) && /cannot be guarded/.test(n)), "but the gap must be said out loud"],
      [!unhashed.prompts["scope:1"].includes("hash-object"), "and nothing unguardable may be asked about"],
    ];
  },

  // The artifact directory and baseline-era untracked files are exempt from the guard.
  "the artifact directory is exempt from the scope guard": async (src) => {
    const { out } = await run(src, {
      baseline: { ...BASELINE, out_rel: ".code-improver/demo", untracked: ["junk-preexisting.txt"] },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      scopes: [{ changed: CLEAN_SCOPE.changed, untracked: [".code-improver/demo/ledger.json", "junk-preexisting.txt"] }],
    });
    return [
      [out && out.halted === "" && out.converged === true, "the run's own artifacts must not read as violations"],
    ];
  },

  // The reviewer contract: pre-dispatch persistence, ledger discipline, report-everything.
  "the ledger is persisted before each review and the reviewer never writes": async (src) => {
    const { calls, prompts, agentOpts } = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const p = prompts["review:1"];
    const pp = prompts["persist:1"];
    return [
      [calls.indexOf("persist:1") !== -1 && calls.indexOf("persist:1") < calls.indexOf("review:1"), "the ledger must be persisted before the first review dispatch"],
      [calls.indexOf("persist:2") !== -1 && calls.indexOf("persist:2") < calls.indexOf("review:2"), "the ledger must be persisted before every later review dispatch"],
      [pp && pp.includes("/work/.code-improver/demo/ledger.json") && /verbatim/.test(pp), "the persist agent must be given the ledger path and forbidden to reformat"],
      [pp && fences(pp)[0] && fences(pp)[0].findings !== undefined, "the persist agent must be given the full ledger"],
      [!/Write tool/.test(p) && !/STEP 0/.test(p), "the reviewer must not be asked to write — it may be read-only"],
      [p.includes("/work/.code-improver/demo/ledger.json"), "the reviewer must be told where the ledger lives"],
      [fences(p)[0] && fences(p)[0].findings !== undefined, "the ledger must reach the reviewer as context"],
      [/Do not withhold or pre-filter low-severity findings/.test(p), "the reviewer must be told to report everything"],
      [/new_evidence=true/.test(p), "the re-file discipline must reach the reviewer"],
      [/verified_fixed/.test(p), "the fix-verification duty must reach the reviewer"],
      [agentOpts["review:1"].agentType === RV.name, "the reviewer must run as the configured reviewer agent"],
      [/Do not edit or fix anything/.test(p), "the reviewer must be told it never edits"],
      [/critical\|major\|minor\|info/.test(p), "the severity mapping must reach the reviewer"],
      [/review-only round/.test(prompts["review:1"]) === false, "an ordinary round must not claim to be final"],
    ];
  },

  // Reviewer dispatch is pluggable (kind: agent | skill); unavailable halts, never improvises.
  "a skill reviewer is dispatched through a Skill wrapper, not an agentType": async (src) => {
    const { prompts, agentOpts } = await run(src, {
      args: { target: SKILL, reviewer: { ...RV_SKILL, notes: "review the branch as a PR" } },
      reviews: [REV([])],
    });
    const p = prompts["review:1"];
    return [
      [agentOpts["review:1"].agentType === undefined, "a skill reviewer must not set an agentType"],
      [p.includes(`skill="${RV_SKILL.name}"`), "the wrapper must name the skill to invoke"],
      [/REVIEWER-UNAVAILABLE:/.test(p), "the wrapper must carry the no-improvisation sentinel contract"],
      [/review the branch as a PR/.test(p), "the caller's reviewer notes must reach the reviewer"],
      [prompts.baseline.includes(RV_SKILL.name), "the baseline must be told which skill to probe for"],
      [/Do NOT invoke the skill/.test(prompts.baseline), "the baseline probe must not run the review"],
    ];
  },

  "a reviewer skill missing from the session halts before any review": async (src) => {
    const { out, calls } = await run(src, {
      args: { target: SKILL, reviewer: RV_SKILL },
      baseline: { ...BASELINE, reviewer_available: false, reviewer_probe: "not listed" },
    });
    return [
      [out && out.halted === "reviewer-unavailable", "the run must halt on the missing reviewer"],
      [!calls.some((c) => c.startsWith("review:") || c.startsWith("fix:")), "no review or fix may run"],
      [calls.includes("persist"), "the halt must persist the (empty) ledger"],
      [out && out.notes.some((n) => /Install the plugin/.test(n)), "the halt must say what to install"],
      [out && out.converged === false, "an unavailable reviewer is not convergence"],
    ];
  },

  "an unresolvable reviewer agent halts instead of improvising": async (src) => {
    const { out, calls } = await run(src, {
      args: { target: SKILL, reviewer: { kind: "agent", name: "ghost:reviewer" } },
      reviews: [{ __throw: "agent({agentType}): agent type 'ghost:reviewer' not found. Available agents: ..." }],
    });
    return [
      [out && out.halted === "reviewer-unavailable", "the dispatch throw must become a loud halt"],
      [!calls.some((c) => c.startsWith("fix:")), "no fix may run without a review"],
      [calls.includes("persist"), "the halt must persist the ledger"],
      [out && out.notes.some((n) => /never substitutes an inline review/.test(n)), "the halt must forbid improvisation"],
    ];
  },

  "a wrapper that could not load its skill does not improvise": async (src) => {
    const { out, calls } = await run(src, {
      args: { target: SKILL, reviewer: RV_SKILL },
      reviews: [{ findings: [], verified_fixed: [], summary: "REVIEWER-UNAVAILABLE: Skill not found" }],
    });
    return [
      [out && out.halted === "reviewer-unavailable", "the sentinel summary must halt the run"],
      [!calls.some((c) => c.startsWith("fix:")), "a sentinel review must never reach the fixer"],
      [calls.includes("persist"), "the halt must persist the ledger"],
    ];
  },

  // The sentinel is checked on every reviewer return, not just the first: a continuation
  // that lost its skill returns an empty review that would read as a clean bill.
  "a continuation that lost its skill does not improvise": async (src) => {
    const { out, calls, prompts } = await run(src, {
      args: { target: SKILL, reviewer: RV_SKILL },
      reviews: [
        DISPATCH([{ agentType: "review-panel:todo-auditor", prompt: "audit todo markers", label: "todo" }]),
        { mode: "direct", findings: [], verified_fixed: [], summary: "REVIEWER-UNAVAILABLE: Skill tool returned an error", agents: [] },
      ],
      specialists: ["todo report: clean"],
    });
    return [
      [out && out.halted === "reviewer-unavailable", "a continuation sentinel must halt the run"],
      [out && out.converged === false, "an empty continuation must never read as a clean review"],
      [!calls.some((c) => c.startsWith("fix:")), "a sentinel continuation must never reach the fixer"],
      [!calls.includes("finalize"), "nothing may be finalized on a halted run"],
      [calls.includes("persist"), "the halt must persist the ledger"],
      [/REVIEWER-UNAVAILABLE:/.test(prompts["review:1.2"]), "the continuation must carry the sentinel contract"],
    ];
  },

  // Reviewer skills that orchestrate specialists: the wrapper cannot spawn agents, so
  // it returns the dispatches and the loop trampolines them.
  "a skill reviewer's dispatch plan is executed and merged": async (src) => {
    const wave = DISPATCH([
      { agentType: "review-panel:naming-auditor", prompt: "audit naming of the target", label: "naming" },
      { agentType: "review-panel:todo-auditor", prompt: "audit todo markers", label: "todo" },
    ]);
    const { out, calls, prompts, agentOpts } = await run(src, {
      args: { target: SKILL, reviewer: RV_SKILL },
      reviews: [wave, DIRECT([A]), DIRECT([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      specialists: ["naming report: clean", "todo report: FIXME at line 3"],
    });
    const cont = prompts["review:1.2"];
    return [
      [/mode "dispatch"/.test(prompts["review:1"]), "the trampoline contract must reach the wave-0 reviewer"],
      [calls.includes("specialist:1.1.naming") && calls.includes("specialist:1.1.todo"), "both planned specialists must be dispatched"],
      [agentOpts["specialist:1.1.naming"].agentType === "review-panel:naming-auditor", "the specialist must run as the planned agent type"],
      [prompts["specialist:1.1.todo"] === "audit todo markers", "the planned prompt must reach the specialist verbatim"],
      [/todo report: FIXME at line 3/.test(cont), "the specialist reports must reach the continuation"],
      [/new_evidence=true/.test(cont), "the ledger discipline must reach the continuation"],
      [/wave\(s\) remain/.test(cont), "the continuation must know its remaining wave budget"],
      [calls.includes("fix:1"), "the merged findings must be dispatched to the fixer"],
      [out && out.converged === true, "the trampolined round must still converge"],
    ];
  },

  "a reviewer that never finishes its waves is capped and halts": async (src) => {
    const w = () => DISPATCH([{ agentType: "x:y", prompt: "p", label: "l" }]);
    const { out, calls } = await run(src, {
      args: { target: SKILL, reviewer: RV_SKILL },
      reviews: [w(), w(), w(), w()],
      specialists: ["r1", "r2", "r3"],
    });
    return [
      [out && out.halted === "reviewer-failed", "an unfinished trampoline must halt, not converge"],
      [out && out.notes.some((n) => /wave cap/.test(n)), "the halt must name the wave cap"],
      [calls.filter((c) => c.startsWith("specialist:")).length === 3, "exactly the capped number of waves may run"],
      [!calls.some((c) => c.startsWith("fix:")), "no fix may run on an incomplete review"],
      [calls.includes("persist"), "the halt must persist the ledger"],
    ];
  },

  "an unresolvable planned specialist halts instead of degrading": async (src) => {
    const { out, calls } = await run(src, {
      args: { target: SKILL, reviewer: RV_SKILL },
      reviews: [DISPATCH([{ agentType: "ghost:aud", prompt: "p", label: "g" }])],
      specialists: [{ __throw: "agent({agentType}): agent type 'ghost:aud' not found. Available agents: ..." }],
    });
    return [
      [out && out.halted === "reviewer-unavailable", "a missing specialist is a missing reviewer dependency"],
      [out && out.notes.some((n) => /ghost:aud/.test(n)), "the halt must name the unresolvable agent type"],
      [!calls.includes("review:1.2"), "no continuation may run on a partial wave"],
      [!calls.some((c) => c.startsWith("fix:")), "no fix may run"],
    ];
  },

  "a dead specialist is reported to the continuation, not dropped": async (src) => {
    const { out, prompts } = await run(src, {
      args: { target: SKILL, reviewer: RV_SKILL },
      reviews: [
        DISPATCH([
          { agentType: "a:b", prompt: "p1", label: "one" },
          { agentType: "c:d", prompt: "p2", label: "two" },
        ]),
        DIRECT(),
      ],
      specialists: ["fine report", null],
    });
    const cont = prompts["review:1.2"];
    return [
      [/SPECIALIST FAILED: returned nothing/.test(cont), "the dead specialist must be named as failed"],
      [/fine report/.test(cont), "the surviving report must still be delivered"],
      [out && out.converged === true, "the round must still be able to finish"],
    ];
  },

  "an empty dispatch wave halts instead of converging on nothing": async (src) => {
    const { out, calls } = await run(src, {
      args: { target: SKILL, reviewer: RV_SKILL },
      reviews: [DISPATCH([])],
    });
    return [
      [out && out.halted === "reviewer-failed", "a dispatch with no agents is an unfinishable review"],
      [out && out.notes.some((n) => /empty agent list/.test(n)), "the halt must say why"],
      [!calls.some((c) => c.startsWith("specialist:")), "nothing may be dispatched"],
      [out && out.converged === false, "an empty wave must never read as a clean review"],
    ];
  },

  // Finalize is data-driven (§ finalize args): plugin detection and caller opt-outs.
  "finalize sections follow the finalize config": async (src) => {
    const plugin = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const notPlugin = await run(src, {
      baseline: { ...BASELINE, plugin_dir: "", plugin_version: "" },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const optedOut = await run(src, {
      args: { target: SKILL, reviewer: RV, finalize: { version_bump: false, narration_strip: false, docs_pass: false } },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    return [
      [/Exactly one version bump/.test(plugin.prompts.finalize), "a plugin target must get the one-bump rule by default"],
      [/Version handling is disabled/.test(notPlugin.prompts.finalize), "a non-plugin target must not get a version bump"],
      [/Version handling is disabled/.test(optedOut.prompts.finalize), "an explicit version_bump=false must win"],
      [/Narration stripping is disabled/.test(optedOut.prompts.finalize), "an explicit narration_strip=false must win"],
      [!/Docs-match-code/.test(optedOut.prompts.finalize), "an explicit docs_pass=false must drop the docs pass"],
      [/Docs-match-code/.test(plugin.prompts.finalize), "the docs pass must run by default"],
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
      [/STEP 0 — before anything else, persist the ledger/.test(p), "the fixer must persist the post-review ledger before editing"],
      [/NEVER run `git checkout --`, `git stash`, `git reset`, `git clean`, or `git commit`/.test(p), "the git prohibitions must reach the fixer"],
      [/fails against the pre-fix code/.test(p), "the pin requirement must reach the fixer"],
      [p.includes("plugins/demo/**"), "the scope globs must reach the fixer"],
      [p.includes(`fixes-round-1.diff`), "the round diff artifact must be requested"],
      [/git add -N/.test(p), "new files must be registered so the guard can see them"],
      [/No narration/.test(p), "the no-narration rule must reach the fixer"],
      [/weaken a documented guarantee/.test(p), "the no-silent-weakening rule must reach the fixer"],
      [agentOpts["fix:1"].agentType === "code-improver:fixer", "the fixer must run as the plugin's fixer agent"],
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

  "args parse aliases and reject bad shapes": async (src) => {
    const skillAlias = await run(src, {
      args: { skill: "/x/skills/y", reviewer: RV },
      reviews: [REV([])],
    });
    // Prose and bare-path forms parse the target but cannot express a reviewer, so
    // they must fail on the reviewer requirement — not on a missing target.
    const prose = await throws(src, { args: "skill: /x/skills/y; maxRounds: 3" });
    const missing = await throws(src, { args: {} });
    const noReviewer = await throws(src, { args: { target: SKILL } });
    const badKind = await throws(src, { args: { target: SKILL, reviewer: { kind: "hook", name: "x" } } });
    const noName = await throws(src, { args: { target: SKILL, reviewer: { kind: "agent", name: " " } } });
    const badRounds = await throws(src, { args: { target: SKILL, reviewer: RV, maxRounds: 0 } });
    const nanRounds = await throws(src, { args: { target: SKILL, reviewer: RV, maxRounds: "lots" } });
    return [
      [skillAlias.prompts.baseline.includes("/x/skills/y"), "the skill alias must still set the target"],
      [prose && /args\.reviewer is required/.test(prose), "a prose string must fail on the reviewer, proving the target parsed"],
      [missing && /args\.target is required/.test(missing), "a missing target must throw"],
      [noReviewer && /args\.reviewer is required/.test(noReviewer), "a missing reviewer must throw — there is no bundled fallback"],
      [badKind && /args\.reviewer is required/.test(badKind), "an unknown reviewer kind must throw"],
      [noName && /args\.reviewer is required/.test(noName), "a blank reviewer name must throw"],
      [badRounds && /maxRounds/.test(badRounds), "a zero round cap must throw"],
      [nanRounds && /maxRounds/.test(nanRounds), "a non-numeric round cap must throw"],
    ];
  },

  "the user's escalation decision reaches reviewer and fixer": async (src) => {
    const { prompts } = await run(src, {
      args: { target: SKILL, reviewer: RV, decision: "keep the blocklist, document the limitation" },
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
    const c = withMetrics.prompts["finalize-check"];
    return [
      [/Exactly one version bump/.test(p), "the one-bump rule must reach finalize"],
      [p.includes("`1.0.0`"), "the baseline version must be named so the bump is checkable"],
      [/narration/.test(p), "the narration strip must reach finalize"],
      [p.includes("post-finalize.diff"), "finalize must snapshot its own edits for the check"],
      [c.includes("/plug/scripts/collect_metrics.py"), "the resolved collector path must be used"],
      [/uv run --no-project "/.test(c), "the collector must be invoked the way the modern-python shims allow"],
      [!/python3 "/.test(c), "a bare `python3 <script>` is refused by the shims and collects nothing"],
      [/--tokens 12345/.test(c), "the spent-token count must reach the collector"],
      [/ledger\.md/.test(c), "the human-readable ledger must be rendered"],
      [fences(c)[0] && fences(c)[0].finalize !== undefined, "the ledger written last must record finalize's own outcome"],
      [/No metrics collector was found/.test(noMetrics.prompts["finalize-check"]), "a missing collector must be loud, not silent"],
      [noMetrics.out.notes.some((n) => /collect_metrics/.test(n)), "the missing collector must reach the result notes"],
    ];
  },

  // Finalize edits the tree after the last review and the last scope check, so the
  // pass is itself scope-checked and read before the run may report success.
  "the finalize pass is checked before the run reports success": async (src) => {
    const clean = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    const regressed = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      finalizeCheck: {
        ...CLEAN_SCOPE,
        regressions: [{ file: "plugins/demo/README.md", line: 12, why: 'rewrote "round 2 of the tournament", which is documented content' }],
        metrics_ok: true,
      },
    });
    const outOfScope = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      finalizeCheck: { changed: [...CLEAN_SCOPE.changed, "plugins/other/thing.md"], untracked: [], regressions: [], metrics_ok: true },
    });
    const newFile = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      finalizeCheck: { changed: CLEAN_SCOPE.changed, untracked: ["plugins/demo/notes.md"], regressions: [], metrics_ok: true },
    });
    const dead = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      finalizeCheck: null,
    });
    const c = clean.prompts["finalize-check"];
    return [
      [clean.out && clean.out.converged === true, "a clean finalize check still converges"],
      [/pre-finalize\.diff/.test(clean.prompts["final-scope"]), "the pre-finalize snapshot must be taken before the pass"],
      [/pre-finalize\.diff/.test(c) && /post-finalize\.diff/.test(c), "the check must be pointed at both snapshots"],
      [/regressions/.test(c) && /round 2 of the tournament/.test(c), "the check must be told what a narration-strip regression looks like"],
      [regressed.out && regressed.out.converged === false, "a finalize regression must not report convergence"],
      [regressed.out && regressed.out.halted === "finalize-regression", "the result must say why"],
      [regressed.out && regressed.out.finalize_regressions.some((r) => r.file === "plugins/demo/README.md"), "the regressed site must be named in the result"],
      [regressed.calls.includes("persist"), "a failed finalize check must persist the honest ledger"],
      [outOfScope.out && outOfScope.out.converged === false && outOfScope.out.halted === "scope-violation", "an out-of-scope finalize edit must halt like any other"],
      [outOfScope.out && outOfScope.out.violations.includes("plugins/other/thing.md"), "the out-of-scope path must be named"],
      [newFile.out && newFile.out.converged === false && newFile.out.halted === "untracked-files-in-scope", "an unregistered file finalize created must block completion"],
      [dead.out && dead.out.converged === false && dead.out.halted === "finalize-check-failed", "an unchecked finalize pass must not certify the run"],
      [dead.calls.includes("persist"), "a dead check must still persist the ledger"],
    ];
  },

  // A dead finalize leaves partial edits: they get checked, not waved through.
  "a dead finalize is still checked, and the ledger still lands": async (src) => {
    const { out, calls, prompts } = await run(src, {
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      finalize: null,
    });
    const ledger = fences(prompts["finalize-check"])[0];
    return [
      [calls.includes("finalize-check"), "a dead finalize's partial edits must still be checked"],
      [out && out.notes.some((n) => /finalize agent died/.test(n)), "the death must reach the result notes"],
      [ledger && ledger.result && ledger.result.converged === true, "the ledger written last must carry the run result"],
      [/post-finalize\.diff\` is missing/.test(prompts["finalize-check"]), "the check must know what to do without the snapshot"],
      [out && out.converged === true, "a checked-clean tree still converges"],
    ];
  },

  // A plugin's version lives in two files; a bump the scope cannot reach ships a mismatch.
  "the version bump reaches the marketplace entry": async (src) => {
    const MK = ".claude-plugin/marketplace.json";
    const withMk = await run(src, {
      baseline: { ...BASELINE, marketplace_file: MK },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
      scopes: [{ changed: [...CLEAN_SCOPE.changed, MK], untracked: [] }],
      finalizeCheck: { changed: [...CLEAN_SCOPE.changed, MK], untracked: [], regressions: [], metrics_ok: true },
    });
    const optedOut = await run(src, {
      args: { target: SKILL, reviewer: RV, finalize: { version_bump: false } },
      baseline: { ...BASELINE, marketplace_file: MK },
      reviews: [REV([A]), REV([], [fid(A)])],
      fixes: [FIX([V(A, "fixed")], 1)],
    });
    return [
      [withMk.out && withMk.out.converged === true, "editing the marketplace entry must not read as a scope violation"],
      [withMk.prompts["fix:1"].includes(MK), "the widened scope must reach the fixer"],
      [withMk.prompts.finalize.includes(MK), "finalize must be told to bump the marketplace entry too"],
      [withMk.out && withMk.out.notes.some((n) => n.includes(MK)), "widening the scope must be said out loud"],
      [withMk.prompts["finalize-check"].includes(MK), "the check must verify the two versions agree"],
      [!optedOut.prompts.finalize.includes(MK), "no version bump means no marketplace edit"],
      [!optedOut.out.notes.some((n) => n.includes(MK)), "and no widened scope"],
      [!withMk.prompts.finalize.includes("any marketplace entry inside scope"), "the bump must name the file, not hope one is in scope"],
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
      [/user\.name='code-improver-baseline'/.test(p), "an auto-init commit must carry an explicit identity"],
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
  ["converge past a structural rejection", (s) => s.replace("if (structural.length) {", "if (false) {")],
  ["treat a dead fixer as a clean round", (s) => s.replace("if (!fixed) {", "if (false) {")],
  ["continue past a scope violation", (s) => s.replace("if (violations.length) {", "if (false) {")],
  ["re-litigate rejected findings", (s) => s.replace("if (ex.status === 'rejected' && !raw.new_evidence) {", "if (false) {")],
  ["complete with unregistered new files", (s) => s.replace("} else if (newUntracked.length) {", "} else if (false) {")],
  ["stop persisting the ledger before each fix", (s) => s.replace("STEP 0 — before anything else, persist the ledger", "Context: the ledger")],
  ["skip the pre-review ledger persist", (s) => s.replace("await persistLedger(`persist:${round}`)", "void 0")],
  ["drop the git prohibitions from the fixer contract", (s) => s.replace(/- NEVER run \\`git checkout --\\`.*\n/, "")],
  ["let the reviewer pre-filter", (s) => s.replace("Do not withhold or pre-filter low-severity findings", "Use judgement about which findings to report")],
  ["dispatch the reviewer without its agent type", (s) => s.replace("...(REVIEWER.kind === 'agent' ? { agentType: REVIEWER_NAME } : {})", "...{}")],
  ["improvise when the reviewer skill is missing", (s) => s.replace("if (REVIEWER.kind === 'skill' && !baseline.reviewer_available) {", "if (false) {")],
  ["swallow an unresolvable reviewer agent", (s) => s.replace("if (/agent type .* not found/i.test(e.message || '')) {", "if (false) {")],
  ["let the wrapper's failure sentinel pass as a review", (s) => s.replace("/^REVIEWER-UNAVAILABLE:/.test((r && r.summary) || '')", "false")],
  ["check the sentinel only on the first reviewer return", (s) => s.replace("      if (unavailableSentinel(review)) {\n        await reviewerUnavailable(clip(review.summary, 300))\n        trampolineHalted = true", "      if (false) {\n        await reviewerUnavailable(clip(review.summary, 300))\n        trampolineHalted = true")],
  ["force every reviewer through the agent path", (s) => s.replace("const reviewerLeadIn =\n    REVIEWER.kind === 'skill'", "const reviewerLeadIn =\n    false")],
  ["skip the baseline reviewer probe step", (s) => s.replace("const SKILL_PROBE_STEP =\n  REVIEWER.kind === 'skill'", "const SKILL_PROBE_STEP =\n  false")],
  ["ignore the caller's finalize opt-outs", (s) => s.replace("version_bump: FIN_ARGS.version_bump === undefined ? !!baseline.plugin_version : !!FIN_ARGS.version_bump,", "version_bump: true,")],
  ["drop the reviewer requirement", (s) => s.replace("if (\n  !REVIEWER ||", "if (\n  false && (\n  !REVIEWER ||").replace("!REVIEWER.name.trim()\n) {", "!REVIEWER.name.trim())\n) {")],
  ["treat a dispatch plan as a finished review", (s) => s.replace("while (review && review.mode === 'dispatch' && !trampolineHalted) {", "while (false) {")],
  ["lift the specialist wave cap", (s) => s.replace("if (wave > MAX_DISPATCH_WAVES) {", "if (false) {")],
  ["swallow an unresolvable planned specialist", (s) => s.replace("if (unresolvable) {", "if (false) {")],
  ["hide specialist failures from the merge", (s) => s.replace("`SPECIALIST FAILED: ${(r && r.error) || 'returned nothing'}`", "'report unavailable'")],
  ["converge on an empty specialist dispatch", (s) => s.replace("if (!requested.length) {", "if (false) {")],
  ["drop the one-bump rule from finalize", (s) => s.replace("Exactly one version bump.", "Version handling:")],
  ["keep stale round numbers on ledger reload", (s) => s.replace("rounds_seen: [],", "rounds_seen: f.rounds_seen || [],")],
  ["keep stale fix rounds on ledger reload", (s) => s.replace("fixed_rounds: [],\n      fixed_prior", "fixed_rounds: f.fixed_rounds || [],\n      fixed_prior")],
  ["strip the artifact-directory exemption", (s) => s.replace("const isArtifact = (p) => OUT_REL && (p === OUT_REL || p.startsWith(`${OUT_REL}/`))", "const isArtifact = () => false")],
  ["let every path match the scope", (s) => s.replace("return new RegExp(`^${esc}$`)", "return /^/")],
  ["certify a finalize pass nobody checked", (s) => s.replace("if (!check) {", "if (false) {")],
  ["accept finalize regressions", (s) => s.replace("} else if (checkRegressions.length) {", "} else if (false) {")],
  ["let finalize edit outside scope", (s) => s.replace("} else if (checkViolations.length || checkUntracked.length) {", "} else if (false) {")],
  ["snapshot nothing for the finalize check", (s) => s.replace('git -C "${GIT_ROOT}" diff ${BASE_SHA} > "${OUT}/post-finalize.diff"', "true")],
  ["bump plugin.json without the marketplace entry", (s) => s.replace("SCOPE.push(MARKETPLACE_FILE)", "void 0")],
  ["ignore the ledger id the reviewer returns", (s) => s.replace("if (given && ledger.findings[given]) return ledger.findings[given]", "if (false) return null")],
  ["merge two same-class findings into one", (s) => s.replace("(x) => x.coarse === ck && !(x.rounds_seen || []).includes(round),", "(x) => x.coarse === ck,")],
  ["call the metrics collector the way the shims refuse", (s) => s.replace('`uv run --no-project "${baseline.metrics_script}"', '`python3 "${baseline.metrics_script}"')],
  ["ignore a tampered out-of-scope untracked file", (s) => s.replace(", ...tamperedUntracked(scopeRep)]", "]")],
  ["read an unverified guarded file as unchanged", (s) => s.replace("if (now === undefined) bad.push(", "if (false) bad.push(")],
  ["stop asking for the guarded hashes", (s) => s.replace("const guardedCommands = GUARDED_UNTRACKED.length", "const guardedCommands = 0")],
  ["let finalize touch a guarded untracked file", (s) => s.replace("...(check ? tamperedUntracked(check) : [])", "...[]")],
  ["leave the marketplace bump to chance", (s) => s.replace("` \\`${MARKETPLACE_FILE}\\` repeats this plugin's version", "` (and any marketplace entry inside scope)")],
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
