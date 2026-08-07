#!/usr/bin/env node
// Exercises workflows/semgrep-scan.js with every agent stubbed. The runtime injects globals
// and wraps the body in an async function; that is reproduced here by stripping the `export`
// and wrapping, so each phase guard is testable offline.
//
//   node workflow-harness.js <path-to-semgrep-scan.js> [--self-test]
//
// --self-test mutates the workflow and requires each mutation to turn a scenario red, so a
// harness that stopped checking anything cannot still report success.

"use strict";

const fs = require("fs");

const workflowPath = process.argv[2];
const selfTest = process.argv.includes("--self-test");
if (!workflowPath) {
  console.error("usage: node workflow-harness.js <path-to-semgrep-scan.js> [--self-test]");
  process.exit(2);
}
const SOURCE = fs.readFileSync(workflowPath, "utf8");

function compile(src) {
  const body = src.replace(/^export const meta/m, "const meta");
  return new Function(
    "agent",
    "parallel",
    "phase",
    "log",
    "args",
    `return (async () => {\n${body}\n})()`,
  );
}

// An installed-plugin path on purpose. Every later phase must splice in the value the detect
// phase resolved, and a repo-relative constant would still look right against a repo checkout.
const SKILL_DIR = "/home/u/.claude/plugins/cache/trailofbits/static-analysis/1.3.0/skills/semgrep";

const DETECT = {
  target: "/proj",
  outputDir: "/proj/static_analysis_semgrep_1",
  skillDir: SKILL_DIR,
  pro: false,
  proReason: "",
  languages: [{ name: "python", files: 12 }],
  frameworks: ["django"],
};
const SELECT = { rulesetsPath: "/proj/static_analysis_semgrep_1/rulesets.json", counts: { baseline: 2, language: 2, thirdParty: 1 } };
const SCAN = { ok: true, scansJson: "/proj/static_analysis_semgrep_1/scans.json", succeeded: 4, failed: 0, skipped: 0, error: "" };
const REPORT = { ok: true, resultsSarif: "/proj/static_analysis_semgrep_1/results/results.sarif", total: 7, report: "# Semgrep Scan Complete", error: "" };

// Each phase's reply is overridable; `null` stands for an agent that returned nothing.
async function run(src, { args, detect = DETECT, select = SELECT, scan = SCAN, report = REPORT } = {}) {
  const logs = [];
  const prompts = {};
  const replies = { detect, select, scan, report };
  const agent = async (prompt, opts = {}) => {
    const label = opts.label || "?";
    prompts[label] = prompt;
    if (!(label in replies)) throw new Error(`unexpected agent label: ${label}`);
    return replies[label];
  };
  const parallel = async (thunks) =>
    Promise.all(thunks.map((t) => Promise.resolve().then(t).catch(() => null)));
  const out = await compile(src)(agent, parallel, () => {}, (m) => logs.push(m), args);
  return { out, logs, prompts };
}

async function throws(src, opts) {
  try {
    await run(src, opts);
    return null;
  } catch (e) {
    return e.message;
  }
}

let PASS = 0;
const FAILURES = [];
const ok = (cond, msg) => {
  if (cond) PASS++;
  else FAILURES.push(msg);
};

// ---------------------------------------------------------------- scenarios
// Each returns a list of [condition, message]. --self-test re-runs them against mutated
// sources and requires that at least one goes red, which is what proves they bite.
const SCENARIOS = {
  "happy path returns the assembled result": async (src) => {
    const { out, prompts } = await run(src, { args: { target: "/proj" } });
    return [
      [out && out.total === 7, "the merged finding total must be returned"],
      [out && out.outputDir === DETECT.outputDir, "the resolved output directory must be returned"],
      [out && out.succeeded === 4, "the scan counts must be carried through"],
      [Object.keys(prompts).length === 4, "all four phases must run"],
    ];
  },

  "args parse from a prose string": async (src) => {
    const { out } = await run(src, { args: "target: /proj; mode: important-only" });
    return [[out && out.mode === "important-only", "a prose args string must still set the mode"]];
  },

  // A bare path carries no `key:` for the prose parser to find, and it is the natural way to
  // invoke this. Parsing it to {} left the target empty and the run scanned cwd, reporting a
  // full result set for a tree the caller never named.
  "a bare path is taken as the target rather than falling back to cwd": async (src) => {
    const plain = await run(src, { args: "/some/other/proj" });
    const spaced = await run(src, { args: "/Users/me/My Project" });
    const relative = await run(src, { args: "~/code/app" });
    return [
      [/Target: \/some\/other\/proj/.test(plain.prompts.detect), "a bare path must become the target"],
      [!/current working directory/.test(plain.prompts.detect), "cwd must not be the target when a path was given"],
      [/Target: \/Users\/me\/My Project/.test(spaced.prompts.detect), "a path containing a space must survive"],
      [/Target: ~\/code\/app/.test(relative.prompts.detect), "a ~ path must become the target"],
    ];
  },

  "an args string that names no path stops the run rather than scanning cwd": async (src) => {
    const prose = await throws(src, { args: "please scan the repo for bugs" });
    const brokenJson = await throws(src, { args: '{"target": "/proj"' });
    return [
      [prose && /could not parse args/.test(prose), "prose that names no path must throw"],
      [brokenJson && /could not parse args/.test(brokenJson), "malformed JSON must throw, not become a target"],
    ];
  },

  "an unknown mode is rejected before any agent runs": async (src) => {
    const msg = await throws(src, { args: { mode: "everything" } });
    return [[msg && /mode must be one of/.test(msg), "an unknown mode must throw"]];
  },

  "a non-integer jobs is rejected": async (src) => {
    const msg = await throws(src, { args: { jobs: "lots" } });
    return [[msg && /jobs must be a positive integer/.test(msg), "a non-integer --jobs must throw"]];
  },

  // The guards below all protect the same thing: a later phase acting on a path an earlier
  // phase did not actually resolve, which silently scans or deletes the wrong tree.
  "a relative target from detect is rejected": async (src) => {
    const msg = await throws(src, { detect: { ...DETECT, target: "proj" } });
    return [[msg && /non-absolute target/.test(msg), "a relative target must throw rather than reach the scan"]];
  },

  "an output directory equal to the target is rejected": async (src) => {
    const msg = await throws(src, { detect: { ...DETECT, outputDir: "/proj" } });
    return [[msg && /scan target/.test(msg), "an output directory equal to the target must throw"]];
  },

  "a dead detect phase stops the run": async (src) => {
    const msg = await throws(src, { detect: null });
    return [[msg && /no scan ran/.test(msg), "a detect agent that returned nothing must stop the run"]];
  },

  "a select phase with no ruleset file stops the run": async (src) => {
    const msg = await throws(src, { select: { rulesetsPath: "", counts: {} } });
    return [[msg && /no scan ran/.test(msg), "an empty ruleset path must stop the run"]];
  },

  // The most important negative: a failed scan must not reach the report as an empty result.
  "a failed scan stops the run rather than reporting zero findings": async (src) => {
    const msg = await throws(src, { scan: { ...SCAN, ok: false, succeeded: 0, error: "semgrep exited 7" } });
    return [
      [msg && /no scan succeeded/.test(msg), "a failed scan must throw"],
      [msg && /semgrep exited 7/.test(msg), "the script's own error must be carried into the message"],
    ];
  },

  "a dead report phase names where the raw output is": async (src) => {
    const msg = await throws(src, { report: null });
    return [[msg && /raw/.test(msg), "a dead merge phase must still point at the raw scan output"]];
  },

  // The mirror of the failed-scan guard. Without a failure channel in REPORT_SCHEMA the agent
  // has to fill in a total, and total 0 with an unwritten results.sarif path is what a scan
  // that genuinely found nothing looks like.
  "a failed merge stops the run rather than returning zero findings": async (src) => {
    const msg = await throws(src, {
      report: { ok: false, resultsSarif: "", total: -1, report: "", error: "merge_sarif.py exited 1" },
    });
    return [
      [msg && /merge failed/.test(msg), "a failed merge must throw"],
      [msg && /merge_sarif\.py exited 1/.test(msg), "the merge's own error must reach the message"],
      [msg && /raw/.test(msg), "the message must still point at the raw scan output"],
    ];
  },

  // Dropping a dead scan's output is what keeps one crashed scan from denying every healthy
  // scan a merged result, so the flag has to actually reach the command.
  "the merge is told which scans failed": async (src) => {
    const { prompts } = await run(src, {});
    const merge = prompts.report.split("\n").find((l) => l.includes("merge_sarif.py")) || "";
    return [
      [/--scans/.test(prompts.report), "the merge must be passed the scans.json it should read"],
      [prompts.report.includes(`--scans "${SCAN.scansJson}"`), "the path must be the one the scan phase reported"],
      [/merge_sarif\.py/.test(merge), "the merge command must still be one pasteable line"],
    ];
  },

  "pro reaches the scan command only when detected": async (src) => {
    const off = await run(src, {});
    const on = await run(src, { detect: { ...DETECT, pro: true } });
    return [
      [!/--pro/.test(off.prompts.scan), "--pro must be absent when Pro was not available"],
      [/--pro/.test(on.prompts.scan), "--pro must be passed when Pro was detected"],
    ];
  },

  "jobs reaches the scan command only when given": async (src) => {
    const without = await run(src, {});
    const with_ = await run(src, { args: { jobs: 8 } });
    return [
      [!/--jobs/.test(without.prompts.scan), "--jobs must be absent unless asked for"],
      [/--jobs 8/.test(with_.prompts.scan), "--jobs must reach the command when given"],
    ];
  },

  "the scan phase calls the script and nothing else": async (src) => {
    const { prompts } = await run(src, {});
    return [
      [/run-scans\.sh/.test(prompts.scan), "the scan phase must invoke run-scans.sh"],
      [/--rulesets "\/proj\/static_analysis_semgrep_1\/rulesets\.json"/.test(prompts.scan), "the ruleset file from the select phase must be passed through"],
      [/Do not add rulesets/.test(prompts.scan), "the agent must be told not to compose its own commands"],
    ];
  },

  // The skill directory is wherever the plugin was installed. A constant only resolves inside a
  // checkout of this repo, so for a marketplace install every scripted command would run against
  // a path that does not exist.
  "the detect phase resolves the skill directory rather than assuming one": async (src) => {
    const { prompts } = await run(src, {});
    return [
      [/CLAUDE_PLUGIN_ROOT/.test(prompts.detect), "the search must try $CLAUDE_PLUGIN_ROOT first"],
      [/plugins\/cache/.test(prompts.detect), "the search must cover a marketplace install"],
      [/run-scans\.sh/.test(prompts.detect), "the search must anchor on the script, so a stale install cannot match"],
    ];
  },

  "the resolved skill directory is what later phases use": async (src) => {
    const { prompts } = await run(src, {});
    const repoRelative = /(^|[^/\w])plugins\/static-analysis\/skills\/semgrep/;
    return [
      [prompts.scan.includes(`${SKILL_DIR}/scripts/run-scans.sh`), "the scan must run the resolved script path"],
      [prompts.select.includes(`${SKILL_DIR}/references/rulesets.md`), "the catalogue must be read from the resolved path"],
      [prompts.report.includes(`${SKILL_DIR}/scripts/merge_sarif.py`), "the merge must use the resolved script path"],
      [!repoRelative.test(prompts.scan), "no repo-relative path may survive into the scan prompt"],
      [!repoRelative.test(prompts.select), "no repo-relative path may survive into the select prompt"],
      [!repoRelative.test(prompts.report), "no repo-relative path may survive into the report prompt"],
    ];
  },

  "an unresolved skill directory stops the run": async (src) => {
    const empty = await throws(src, { detect: { ...DETECT, skillDir: "" } });
    const relative = await throws(src, { detect: { ...DETECT, skillDir: "plugins/static-analysis/skills/semgrep" } });
    return [
      [empty && /skill directory/.test(empty), "a skill directory that could not be found must throw"],
      [empty && /no scan ran/.test(empty), "the message must say no scan ran"],
      [relative && /skill directory/.test(relative), "a relative skill directory must throw rather than reach the scan"],
    ];
  },

  "an explicit skill argument replaces the search": async (src) => {
    const { prompts } = await run(src, { args: { skill: "/opt/sa/skills/semgrep" } });
    return [
      [/\/opt\/sa\/skills\/semgrep\/scripts\/run-scans\.sh/.test(prompts.detect), "the given directory must be confirmed, not searched for"],
      [!/CLAUDE_PLUGIN_ROOT/.test(prompts.detect), "the four-step search must be skipped when the path was given"],
    ];
  },

  "the select phase is pointed at the shared catalogue": async (src) => {
    const { prompts } = await run(src, {});
    return [
      [/references\/rulesets\.md/.test(prompts.select), "ruleset selection must read rulesets.md rather than memory"],
      [/third_party/.test(prompts.select), "the required third-party rules must be named"],
    ];
  },

  // The JSON post-filter reads .results[].extra.metadata, which SARIF does not have, so the
  // merged SARIF cannot be filtered by re-running it — results.sarif is the primary deliverable
  // and would keep everything the mode exists to exclude while the JSON side was filtered.
  "important-only filters the merged SARIF through the merge script": async (src) => {
    const { prompts } = await run(src, { args: { mode: "important-only" } });
    const merge = prompts.report.split("\n").find((l) => l.includes("merge_sarif.py")) || "";
    return [
      [/--mode important-only/.test(prompts.scan), "the mode must reach the scan command"],
      [/scan-modes\.md/.test(prompts.report), "important-only must post-filter before the merge"],
      [/--important/.test(merge), "the merge command itself must carry --important"],
      [/Cannot iterate over null/.test(prompts.report), "the report must say why jq cannot filter the SARIF"],
    ];
  },

  "run-all does not filter the merge": async (src) => {
    const { prompts } = await run(src, {});
    return [
      [!/--important/.test(prompts.report), "--important must be absent in run-all mode"],
      [!/scan-modes\.md/.test(prompts.report), "run-all must not post-filter"],
    ];
  },

  "the report is told to count from the merged SARIF": async (src) => {
    const { prompts } = await run(src, {});
    return [
      [/Never sum the per-scan findings counts/.test(prompts.report), "the report must not sum per-scan counts"],
      [/Did Not Run/.test(prompts.report), "failed and skipped rulesets must get their own section"],
      [/rm -rf/.test(prompts.report), "the cloned rule repos must be deleted after the merge"],
      // A ruleset that opened no file reports 0 findings like any other. Left out of the
      // report, a plan aimed at the wrong languages is indistinguishable from a clean scan.
      [/coveredNothing/.test(prompts.report), "rulesets that matched no file must be reported"],
      // The merge drops an unparseable SARIF and exits 0. That scan is a success in scans.json,
      // so unless the report carries the line, the shortfall has nothing pointing at it.
      [/unparseable/.test(prompts.report), "SARIF files missing from the merge must be reported"],
      [/excludePattern/.test(prompts.report), "the pattern excluded from every scan must be reported"],
    ];
  },
};

// Mutations the scenarios must notice. Each removes one guard or one flag.
const MUTATIONS = [
  ["drop the absolute-target guard", (s) => s.replace(/if \(!target \|\| !target\.startsWith\('\/'\)\).*\n/, "")],
  ["drop the output-dir-equals-target guard", (s) => s.replace(/if \(outputDir\.replace[\s\S]*?\n\}\n/, "")],
  ["treat a failed scan as success", (s) => s.replace("if (!scanned || !scanned.ok) {", "if (false) {")],
  ["always pass --pro", (s) => s.replace("${detected.pro ? ' \\\\\\n    --pro' : ''}", "' \\\\\\n    --pro'")],
  ["drop the mode validation", (s) => s.replace(/if \(!MODES\.has\(mode\)\) \{[\s\S]*?\n\}\n/, "")],
  ["drop the dead-detect guard", (s) => s.replace("if (!detected) throw new Error('the detect phase returned nothing; no scan ran')", "if (!detected) return {}")],
  ["hardcode the skill directory back to a repo-relative path", (s) => s.replace(/^const SKILL_DIR = .*$/m, "const SKILL_DIR = 'plugins/static-analysis/skills/semgrep'")],
  ["accept an unresolved skill directory", (s) => s.replace("if (!SKILL_DIR || !SKILL_DIR.startsWith('/')) {", "if (false) {")],
  ["drop --important from the important-only merge", (s) => s.replace("mode === 'important-only' ? ' --important' : ''", "''")],
  ["ignore a bare path and scan cwd", (s) => s.replace("if (bare) return { target: text }", "if (false) return { target: text }")],
  ["accept unparseable args instead of refusing", (s) => s.replace("  throw new Error(`could not parse args", "  return {}\n  throw new Error(`could not parse args")],
  ["treat a failed merge as success", (s) => s.replace("if (!reported.ok) {", "if (false) {")],
  ["drop --scans from the merge", (s) => s.replace(/\n\s*`\s*--scans "\$\{scanned\.scansJson[\s\S]*?`,/, "")],
  ["stop reporting rulesets that covered nothing", (s) => s.replace(/\n\s*'\s*\.coveredNothing gets its own section[\s\S]*?clean audit\.',/, "")],
  ["stop reporting unparseable SARIF", (s) => s.replace(/\n\s*'6\. Read the merge command[\s\S]*?not in the merge\.',/, "")],
  ["stop reporting the exclude pattern", (s) => s.replace(/\n\s*'7\. If \.excludePattern[\s\S]*?clean coverage\.',/, "")],
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
