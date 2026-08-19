#!/usr/bin/env node
// Exercises workflows/codeql-build.js with every agent stubbed. The runtime injects globals and
// wraps the body in an async function; that is reproduced here by stripping the `export` and
// wrapping, so the ladder and every phase guard are testable offline.
//
//   node codeql_build_harness.js <path-to-codeql-build.js> [--self-test]
//
// --self-test mutates the workflow and requires each mutation to turn a scenario red, so a
// harness that stopped checking anything cannot still report success.

"use strict";

const fs = require("fs");

const workflowPath = process.argv[2];
const selfTest = process.argv.includes("--self-test");
if (!workflowPath) {
  console.error("usage: node codeql_build_harness.js <path-to-codeql-build.js> [--self-test]");
  process.exit(2);
}
const SOURCE = fs.readFileSync(workflowPath, "utf8");

function compile(src) {
  const body = src.replace(/^export const meta/m, "const meta");
  return new Function("agent", "parallel", "phase", "log", "args", `return (async () => {\n${body}\n})()`);
}

// An installed plugin, deliberately: the path the workflow used to hardcode was relative to a
// checkout of the marketplace repo, so a stub using that path would agree with the bug.
const SKILL_DIR = "/home/u/.claude/plugins/cache/trailofbits/static-analysis/skills/codeql";
const DETECT = {
  ok: true,
  skillDir: SKILL_DIR,
  lang: "cpp",
  target: "/proj",
  outputDir: "/proj/static_analysis_codeql_1",
  dbPath: "/proj/static_analysis_codeql_1/codeql.db",
  isMacosArm64e: false,
  buildSystem: "make",
  buildCommand: "make clean && make -j4",
  error: "",
};
const OK_BUILD = { ok: true, resolved: true, attempts: 1, fixesApplied: [], error: "" };
const BAD_BUILD = { ok: false, resolved: false, attempts: 2, fixesApplied: ["clean build cache"], error: "exit 1: no rule to make target" };
const ASSESS = { exitCode: 0, passed: true, baselineLoc: 1200, projectFiles: 40, errorRatio: 0.5, improvements: [] };

// `build` decides per rung: a function of the rung id, or a single reply for every rung.
async function run(src, { args, detect = DETECT, build = () => OK_BUILD, assess = ASSESS } = {}) {
  const logs = [];
  const prompts = {};
  const order = [];
  const agent = async (prompt, opts = {}) => {
    const label = opts.label || "?";
    prompts[label] = prompt;
    if (label === "detect") return detect;
    if (label === "assess") return assess;
    if (label.startsWith("build:")) {
      const rung = label.slice("build:".length);
      order.push(rung);
      return typeof build === "function" ? build(rung) : build;
    }
    throw new Error(`unexpected agent label: ${label}`);
  };
  const parallel = async (thunks) => Promise.all(thunks.map((t) => Promise.resolve().then(t).catch(() => null)));
  const out = await compile(src)(agent, parallel, () => {}, (m) => logs.push(m), args);
  return { out, logs, prompts, order };
}

let PASS = 0;
const FAILURES = [];
const ok = (cond, msg) => (cond ? PASS++ : FAILURES.push(msg));

const SCENARIOS = {
  "a first-rung success stops the ladder": async (src) => {
    const { out, order } = await run(src, {});
    return [
      [out && out.status === "built", "a healthy build must report status built"],
      [order.length === 1 && order[0] === "1", "later rungs must not run once one succeeds"],
      [out && out.dbPath === DETECT.dbPath, "the database path must be returned"],
    ];
  },

  "the ladder escalates rung by rung": async (src) => {
    const { out, order } = await run(src, { build: (r) => (r === "3" ? OK_BUILD : BAD_BUILD) });
    return [
      [order.join(",") === "1,2,3", `cpp must escalate 1 -> 2 -> 3, got ${order.join(",")}`],
      [out && out.status === "built", "a later rung succeeding is still a success"],
      [out && /Method 3/.test(out.method), "the winning method must be named"],
    ];
  },

  // Method 4 is not a fallback for these: CodeQL rejects --build-mode=none outright, so
  // attempting it spends a rung to reach the same failure.
  "go and swift never reach the no-build fallback": async (src) => {
    for (const lang of ["go", "swift"]) {
      const { order } = await run(src, { detect: { ...DETECT, lang }, build: () => BAD_BUILD });
      if (order.includes("4")) return [[false, `${lang} must not attempt Method 4, got ${order.join(",")}`]];
    }
    return [[true, ""]];
  },

  "a language with a none fallback does reach Method 4": async (src) => {
    const { order } = await run(src, { build: () => BAD_BUILD });
    return [[order.includes("4"), `cpp must end at Method 4, got ${order.join(",")}`]];
  },

  // Trying 1 and 2 on an affected Mac spends two rungs arriving at the same SIGKILL.
  "macOS arm64e skips Methods 1 and 2": async (src) => {
    const { order } = await run(src, { detect: { ...DETECT, isMacosArm64e: true }, build: () => BAD_BUILD });
    return [
      [order[0] === "2m", `the ladder must start at 2m, got ${order.join(",")}`],
      [!order.includes("1") && !order.includes("2"), "Methods 1 and 2 must be skipped entirely"],
    ];
  },

  "an interpreted language uses one extraction, not the ladder": async (src) => {
    const { order, prompts } = await run(src, { detect: { ...DETECT, lang: "python" } });
    return [
      [order.join(",") === "interpreted", `python must not walk the ladder, got ${order.join(",")}`],
      [/--codescanning-config/.test(prompts["build:interpreted"]), "the exclusion config must be used"],
    ];
  },

  "every rung failing returns a status rather than a database": async (src) => {
    const { out } = await run(src, { build: () => BAD_BUILD });
    return [
      [out && out.status === "no-method-succeeded", "all rungs failing must report no-method-succeeded"],
      [out && out.dbPath === "", "no database path may be returned when none was built"],
      [out && out.attempts.length > 0, "the attempts must be returned so the caller can see what was tried"],
      [out && out.attempts.every((a) => a.error), "each failed attempt must carry its error"],
    ];
  },

  // The most important negative: a build command exiting 0 is not a database.
  "a build that does not resolve is a failure": async (src) => {
    const { out } = await run(src, { build: () => ({ ...OK_BUILD, ok: true, resolved: false }) });
    return [[out && out.status === "no-method-succeeded", "ok=true with resolved=false must not count as built"]];
  },

  "a dead build agent is a failed rung, not a success": async (src) => {
    const { out } = await run(src, { build: () => null });
    return [[out && out.status === "no-method-succeeded", "an agent returning nothing must not pass the rung"]];
  },

  "a database below the quality threshold is reported, not hidden": async (src) => {
    const { out } = await run(src, { assess: { exitCode: 3, passed: false, baselineLoc: 900, projectFiles: 20, errorRatio: 12.5, improvements: ["forced clean rebuild"] } });
    return [
      [out && out.status === "built-below-threshold", "a failing gate must be its own status"],
      [out && out.dbPath === DETECT.dbPath, "the database still exists and its path must be returned"],
      [out && out.quality && out.quality.errorRatio === 12.5, "the metrics must reach the caller"],
    ];
  },

  "detect failures stop the run before any build": async (src) => {
    const dead = await run(src, { detect: null });
    const notOk = await run(src, { detect: { ...DETECT, ok: false, error: "codeql not installed" } });
    const relative = await run(src, { detect: { ...DETECT, dbPath: "codeql.db" } });
    return [
      [dead.out && dead.out.status === "detect-failed", "a dead detect agent must stop the run"],
      [notOk.out && /codeql not installed/.test(notOk.out.error), "the detect error must be carried out"],
      [relative.out && relative.out.status === "detect-failed", "a relative dbPath must stop the run"],
      [dead.order.length === 0, "no build may be attempted after a failed detect"],
    ];
  },

  // The skill path was hardcoded as 'plugins/static-analysis/skills/codeql', which resolves
  // only in a checkout of this repo. Installed, every rung sourced a build_log.sh that was not
  // there and exited 127 — four build failures for a project that builds fine.
  "the skill directory comes from the run, not from this repo's layout": async (src) => {
    const { prompts } = await run(src, {});
    const build = prompts["build:1"];
    return [
      [!/plugins\/static-analysis\/skills\/codeql/.test(build), "no prompt may carry a repo-relative skill path"],
      [build.includes(`${SKILL_DIR}/scripts/build_log.sh`), "the build prompt must source the helpers from the resolved directory"],
      [build.includes(`${SKILL_DIR}/workflows/build-database.md`), "the method detail must point at the resolved directory"],
      [prompts.assess.includes(`${SKILL_DIR}/scripts/check_db_quality.py`), "the quality gate must run from the resolved directory"],
      [/build_log\.sh/.test(prompts.detect), "detect must validate its candidate against a marker file, not just take one"],
    ];
  },

  "an unresolved skill directory stops the run": async (src) => {
    const relative = await run(src, { detect: { ...DETECT, skillDir: "plugins/static-analysis/skills/codeql" } });
    const empty = await run(src, { detect: { ...DETECT, skillDir: "" } });
    return [
      [relative.out && relative.out.status === "detect-failed", "a relative skillDir must stop the run"],
      [relative.order.length === 0, "no build may be attempted with an unresolved skill directory"],
      [empty.out && empty.out.status === "detect-failed", "an empty skillDir must stop the run"],
    ];
  },

  "the build prompt carries what a fresh shell loses": async (src) => {
    const { prompts } = await run(src, {});
    const p = prompts["build:1"];
    return [
      [/build_log\.sh/.test(p), "each rung must re-source the log helpers"],
      [/127/.test(p), "the prompt must name the command-not-found failure that reads as a failed build"],
      [/build-fixes\.md/.test(p), "the rung must be pointed at the fix catalogue"],
      [/caller owns the ladder/.test(p), "the agent must not escalate to another method itself"],
      [/resolve database/.test(p), "the rung must verify with codeql resolve database"],
    ];
  },

  "the assess prompt refuses to move the goalposts": async (src) => {
    const { prompts } = await run(src, {});
    return [
      [/Do not raise --max-error-ratio/.test(prompts.assess), "the agent must not raise the threshold to pass itself"],
      [/not overridable/.test(prompts.assess), "exit 1 must be marked as not a judgement call"],
      [/quality-assessment\.md/.test(prompts.assess), "improvements must come from the reference"],
    ];
  },

  "args parse from a prose string": async (src) => {
    const { prompts } = await run(src, { args: "target: /srv/app; lang: java" });
    return [
      [/\/srv\/app/.test(prompts.detect), "a prose args string must still set the target"],
      [/java/.test(prompts.detect), "a prose args string must still set the language"],
    ];
  },
};

const MUTATIONS = [
  ["let go reach Method 4", (s) => s.replace("if (!NO_NONE_FALLBACK.has(lang)) rungs.push('4')", "rungs.push('4')")],
  ["try 1 and 2 on arm64e", (s) => s.replace("const rungs = isMacosArm64e ? ['2m'] : ['1', '2']", "const rungs = ['1', '2']")],
  ["accept a build that does not resolve", (s) => s.replace("const ok = Boolean(result && result.ok && result.resolved)", "const ok = Boolean(result && result.ok)")],
  ["treat a failing gate as a pass", (s) => s.replace("status: passed ? 'built' : 'built-below-threshold',", "status: 'built',")],
  ["drop the absolute-path guard", (s) => s.replace(/for \(const \[name, value\] of \[\n[\s\S]*?\n\}\n/, "")],
  ["hardcode the skill path again", (s) => s.replace("const SKILL_DIR = String(detected.skillDir)", "const SKILL_DIR = 'plugins/static-analysis/skills/codeql'")],
  ["keep walking the ladder after a success", (s) => s.replace("    built = rung\n    break", "    built = rung")],
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
