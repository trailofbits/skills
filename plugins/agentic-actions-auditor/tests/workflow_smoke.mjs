// Drives workflows/audit-agentic.js with stubbed agents and checks each exit.
//
// The exits are the part worth testing. Three of the four are refusals: an unreadable
// target, a repository with no agent in it, and a sweep that found nothing. Each of
// those has to be reachable and has to be distinguishable from the others, because a
// run that silently fell through to "ok" with an empty report would read as a clean
// audit. The no-agent exit is also what makes eval case 05 pass structurally rather
// than by asking the model nicely.
//
//     node workflow_smoke.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "workflows", "audit-agentic.js");

// The runner supplies args/agent/phase/log and wraps the module so top-level return
// works. Reproduce that shape rather than importing, which would reject the return.
const body = readFileSync(SRC, "utf8").replace(/^export const meta/m, "const meta");

const run = async ({ args = {}, replies = {} }) => {
  const calls = [];
  const agent = async (_prompt, opts) => {
    calls.push(opts.label);
    return Object.prototype.hasOwnProperty.call(replies, opts.label) ? replies[opts.label] : {};
  };
  const fn = new Function(
    "args",
    "agent",
    "phase",
    "log",
    `return (async () => { ${body} })()`,
  );
  const result = await fn(args, agent, () => {}, () => {});
  return { result, calls };
};

const AGENT_STEP = {
  file: ".github/workflows/triage.yml",
  action: "anthropics/claude-code-action@v1",
  triggers: ["issues"],
};
const FINDING = {
  vector: "B",
  file: ".github/workflows/triage.yml",
  claim: "issue body is interpolated into the prompt",
  attacker_input: "github.event.issue.body",
};

const CASES = [
  {
    name: "unreadable target stops before any sweep",
    replies: { discover: { scope_exists: false, workflows: [], agent_steps: [] } },
    status: "scope-missing",
    sweeps: false,
  },
  {
    name: "discovery returning nothing is not treated as a clean audit",
    replies: { discover: null },
    status: "discovery-failed",
    sweeps: false,
  },
  {
    name: "no agent step stops and names the boundary",
    replies: {
      discover: {
        scope_exists: true,
        workflows: [".github/workflows/label.yml"],
        agent_steps: [],
        no_agent_reason: "the workflow only edits labels",
      },
    },
    status: "no-agent",
    sweeps: false,
    expect: (r) => /zizmor/.test(r.note) && /do not apply/.test(r.note),
  },
  {
    name: "agent present but nothing found still reports a conclusion",
    replies: {
      discover: { scope_exists: true, workflows: ["a.yml"], agent_steps: [AGENT_STEP] },
      dataflow: { findings: [] },
      context: { findings: [] },
      config: { findings: [] },
      sinks: { findings: [] },
    },
    status: "no-findings",
    sweeps: true,
    expect: (r) => /found no path/.test(r.note),
  },
  {
    name: "a finding reaches the report with its vector kept",
    replies: {
      discover: { scope_exists: true, workflows: ["a.yml"], agent_steps: [AGENT_STEP] },
      dataflow: { findings: [FINDING] },
      context: { findings: [] },
      config: { findings: [] },
      sinks: { findings: [] },
      report: "written",
    },
    status: "ok",
    sweeps: true,
    expect: (r) => r.vectors.B === 1 && r.findings.length === 1 && r.report === "written",
  },
];

let failed = 0;
for (const c of CASES) {
  const { result, calls } = await run({ replies: c.replies });
  const swept = calls.includes("dataflow");
  const problems = [];
  if (result.status !== c.status) problems.push(`status ${result.status}, expected ${c.status}`);
  if (swept !== c.sweeps) problems.push(swept ? "swept when it should have stopped" : "did not sweep");
  if (c.expect && !c.expect(result)) problems.push("payload check failed");
  if (problems.length) {
    failed++;
    console.log(`  FAIL ${c.name}: ${problems.join("; ")}`);
  }
}

// All four sweeps must run, or a vector family silently stops being audited.
const { calls } = await run({
  replies: {
    discover: { scope_exists: true, workflows: ["a.yml"], agent_steps: [AGENT_STEP] },
    report: "x",
  },
});
const missing = ["dataflow", "context", "config", "sinks"].filter((f) => !calls.includes(f));
if (missing.length) {
  failed++;
  console.log(`  FAIL sweep families not dispatched: ${missing.join(", ")}`);
}

// A sweep that returns nothing has to say so. Silently dropping it leaves a whole vector
// family unaudited while the report reads as complete.
const lines = [];
{
  const agent = async (_p, o) => (o.label === "config" ? null : { findings: [] });
  const body = readFileSync(SRC, "utf8").replace(/^export const meta/m, "const meta");
  const fn = new Function("args", "agent", "phase", "log", `return (async () => { ${body} })()`);
  await fn(
    {},
    async (p, o) =>
      o.label === "discover"
        ? { scope_exists: true, workflows: ["a.yml"], agent_steps: [AGENT_STEP] }
        : agent(p, o),
    () => {},
    (m) => lines.push(m),
  );
}
if (!lines.some((l) => /no result from .*config/.test(l))) {
  failed++;
  console.log("  FAIL a sweep family returning nothing was not reported");
}

const total = CASES.length + 2;
console.log(`  ${total - failed}/${total} checks passed`);
process.exit(failed ? 1 : 0);
