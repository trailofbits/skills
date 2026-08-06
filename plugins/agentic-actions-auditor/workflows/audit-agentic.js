// Ships as /agentic-actions-auditor:audit-agentic. Plugin workflows are namespaced by
// the plugin's `name` field, so the prefix is fixed; meta.name supplies the rest.
export const meta = {
  name: "audit-agentic",
  description:
    "Audit GitHub Actions workflows for attack paths into AI coding agents: discovery, cross-file resolution, one sweep per vector family, report",
  whenToUse:
    'When workflows invoke an AI coding agent (Claude Code Action, Gemini CLI, Codex, GitHub AI Inference) and you want the paths by which attacker-controlled input reaches the agent. Pass args as a JSON OBJECT, not prose: {"scope": "...", "repo": "owner/name@ref", "out": "..."}. scope is a local directory and defaults to cwd; repo audits a remote repository instead; out is the report path. If no AI action is present the run stops and says so rather than producing an agentic report about a workflow that has no agent.',
  phases: [
    { title: "Discover", detail: "Collect workflow files, find the steps that invoke an AI agent, and follow uses: into composite actions and reusable workflows that may hide one" },
    { title: "Sweep", detail: "One agent per vector family over the workflows that carry an agent" },
    { title: "Report", detail: "Merge findings, drop the ones general tooling already owns, write the report" },
  ],
};

// One model throughout. The peer workflows reach for a stronger one on their
// judgement phase, but a pilot of these vectors showed sonnet already reproduces the
// reference material unaided, so paying for opus here would buy nothing measurable.
const MODEL = "sonnet";

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------
// args = {
//   scope: string (optional) local directory to audit; defaults to cwd
//   repo:  string (optional) owner/name[@ref] to audit instead of a local path
//   out:   string (optional) report path
//   pluginRoot: string (supplied by the runner) where references/ lives
// }
// Prose args killed a sibling workflow on its first line before any agent started,
// so accept the shape a model actually produces as well as the documented one.
const parseArgs = (raw) => {
  if (!raw) return {};
  if (typeof raw === "object") return raw;
  if (typeof raw !== "string") return {};
  const text = raw.trim();
  if (text.startsWith("{")) {
    try {
      return JSON.parse(text);
    } catch {
      // fall through rather than dying on a malformed brace
    }
  }
  const KEYS = ["scope", "repo", "out", "pluginRoot"];
  const out = {};
  let key = null;
  for (const part of text.split(/[;\n]/)) {
    const m = part.match(/^\s*(\w+)\s*:\s*(.*)$/);
    if (m && KEYS.includes(m[1])) {
      key = m[1];
      out[key] = m[2].trim();
    } else if (key) {
      out[key] += " " + part.trim();
    }
  }
  return out;
};

const opts = parseArgs(args);
const pluginRoot = String(opts.pluginRoot || "");
const refDir = pluginRoot + "/skills/agentic-actions-auditor/references";
const scope = String(opts.scope || ".").trim() || ".";
const repo = String(opts.repo || "").trim();
const outPath = String(opts.out || "").trim();

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
const T = (type, description, extra) => ({
  type,
  ...(description ? { description } : {}),
  ...extra,
});
const STR = T("string");
const str = (d) => T("string", d);
const bool = (d) => T("boolean", d);
const strs = (d) => T("array", d, { items: STR });
const obj = (required, properties) => T("object", null, { required, properties });
const objs = (required, properties, d) => T("array", d, { items: obj(required, properties) });

const DISCOVER_SCHEMA = obj(["scope_exists", "workflows", "agent_steps"], {
  scope_exists: bool("Whether the audited path or repository could actually be read"),
  workflows: strs("Every workflow file found, as paths"),
  agent_steps: objs(
    ["file", "action"],
    {
      file: str("Workflow file holding the step"),
      action: str("The uses: value that invokes the AI agent"),
      triggers: strs("The on: events that can reach this job"),
      indirect: bool("True when the agent was reached through a composite action or reusable workflow"),
    },
    "One entry per step that invokes an AI coding agent, including ones reached indirectly",
  ),
  no_agent_reason: str("When agent_steps is empty, what was found instead"),
});

const SWEEP_SCHEMA = obj(["findings"], {
  findings: objs(
    ["vector", "file", "claim", "attacker_input"],
    {
      vector: str("Vector letter from the reference set, A through I"),
      file: str("Workflow file"),
      step: str("Which step, by name or by the uses: value"),
      claim: str("What reaches the agent and how, in one sentence"),
      attacker_input: str("The specific event field an outside party controls"),
      confidence: str("high when the path is visible in the YAML, lower when it depends on runtime behaviour"),
    },
    "Empty is a valid answer; a guessed finding is not",
  ),
});

// Vector families are swept together where they share evidence, so one agent reads a
// file once instead of four agents reading it four times.
const FAMILIES = [
  {
    id: "dataflow",
    title: "Data flow into the prompt",
    refs: [
      "vector-a-env-var-intermediary.md",
      "vector-b-direct-expression-injection.md",
      "vector-c-cli-data-fetch.md",
    ],
    focus:
      "How attacker text reaches the prompt: directly as an expression, indirectly through an env: entry the prompt names, or by the prompt telling the agent to fetch it at runtime. The env case is the one reviewers miss, because the prompt holds no expression at all.",
  },
  {
    id: "context",
    title: "Trigger and execution context",
    refs: ["vector-d-pr-target-checkout.md", "vector-e-error-log-injection.md"],
    focus:
      "Whether the workflow runs with secrets against attacker-modified code, and whether CI output that an attacker can shape is fed back to the agent as context.",
  },
  {
    id: "config",
    title: "Sandbox, tools and gating",
    refs: [
      "vector-f-subshell-expansion.md",
      "vector-h-dangerous-sandbox-configs.md",
      "vector-i-wildcard-allowlists.md",
    ],
    focus:
      "Settings that widen the blast radius rather than narrow it: allowlist entries that can spawn a subshell, flags that disable the approval boundary, and user gating set to a wildcard.",
  },
  {
    id: "sinks",
    title: "What consumes the agent's output",
    refs: ["vector-g-eval-of-ai-output.md"],
    focus:
      "Steps after the agent that pass its output through a shell, eval, or any other execution sink. The weakness lives in the consuming step, not in the agent step.",
  },
];

// ==========================================================================
// Phase 1 - Discover
// ==========================================================================
phase("Discover");

const target = repo ? `the remote repository \`${repo}\`` : `\`${scope}\``;
const howToRead = repo
  ? "Use `gh api repos/{owner}/{repo}/contents/.github/workflows` to list the directory and `--jq '.content | @base64d'` to read each file. Append `?ref=` when the input carries one."
  : `Read \`.github/workflows\` under the scope. Confirm the path exists with \`test -e '${scope}' && echo present\` before concluding anything about it.`;

const discovered = await agent(
  `You are the discovery pass of an agentic actions audit of ${target}.

${howToRead}

Report only what you observed. An empty list is a valid answer; a guessed one is not.

**1. Confirm the target is readable.** Set \`scope_exists\` from that check, not from the shape of the path. A missing target must stop the run rather than sweep nothing and read as clean.

**2. List every workflow file** you found.

**3. Find the steps that invoke an AI coding agent.** The action profiles are in ${refDir}/action-profiles.md; read it rather than matching on the word "claude". An agent can also be reached indirectly, through a composite action or a reusable workflow named in \`uses:\`; ${refDir}/cross-file-resolution.md describes how to follow those. Set \`indirect: true\` on anything you reached that way.

**4. Record the triggers** that can reach each agent step, including triggers inherited from the job or workflow level.

If you find no AI agent step at all, say so in \`no_agent_reason\` and name what the workflows do instead. That is a real answer and the rest of the run depends on it being accurate.`,
  { label: "discover", phase: "Discover", model: MODEL, schema: DISCOVER_SCHEMA },
);

if (!discovered) {
  return {
    status: "discovery-failed",
    note: "Discovery returned nothing; there is no workflow inventory to sweep.",
  };
}

if (discovered.scope_exists === false) {
  return { status: "scope-missing", note: `${target} could not be read. Nothing was audited.` };
}

const agentSteps = discovered.agent_steps || [];
const workflows = discovered.workflows || [];

// The skill's own "When NOT to Use" puts a workflow with no AI action out of scope, and
// the honest end of the run is here. Continuing would produce a findings report organised
// by agentic vectors about a workflow that has no agent, which is worse than no answer:
// it buries whatever general Actions problems the file does have under the wrong heading.
if (agentSteps.length === 0) {
  return {
    status: "no-agent",
    note:
      `Audited ${workflows.length} workflow file${workflows.length === 1 ? "" : "s"} in ${target} and found no step that invokes an AI coding agent, so the vectors this skill covers do not apply. ` +
      (discovered.no_agent_reason ? `${discovered.no_agent_reason} ` : "") +
      "Ordinary Actions weaknesses can still be present here; zizmor and actionlint cover that ground and this run deliberately does not claim it.",
    workflows,
  };
}

log(
  `Discover: ${workflows.length} workflows, ${agentSteps.length} agent step${agentSteps.length === 1 ? "" : "s"}` +
    (agentSteps.some((s) => s.indirect) ? ", including one reached through another file" : ""),
);

// ==========================================================================
// Phase 2 - Sweep
// ==========================================================================
// The cross-file walk is part of discovery, not a phase of its own: it needs the files
// discovery already read, and a second pass over them bought nothing except another
// chance to disagree with the first about what counts as an agent step.
const carriers = [...new Set(agentSteps.map((s) => s.file))];

phase("Sweep");

const stepList = agentSteps
  .map(
    (s) =>
      `- ${s.file}: ${s.action}${s.indirect ? " (reached indirectly)" : ""}${
        s.triggers?.length ? ` on ${s.triggers.join(", ")}` : ""
      }`,
  )
  .join("\n");

const sweeps = (
  await Promise.all(
    FAMILIES.map((family) =>
      agent(
        `You are the ${family.title.toLowerCase()} sweep of an agentic actions audit of ${target}.

These workflow files carry an AI agent step:

${stepList}

Read only those files, plus anything they reference that you need to decide a claim.

${family.focus}

Read these references before deciding anything, and use their vector letters:

${family.refs.map((r) => `- ${refDir}/${r}`).join("\n")}

${refDir}/foundations.md lists which event contexts an outside party actually controls. A field nobody outside the repository can set is not attacker input, and reporting it as one costs the whole report its credibility.

Report a finding only when you can name the specific event field an attacker controls and the path it takes. Empty is a valid answer.

Two things are out of scope for this sweep and must not be reported here. Unpinned action references, over-broad \`permissions:\` blocks and credential persistence are general Actions hygiene that zizmor already reports, so leave them to it. So is template injection into a \`run:\` step that no agent reads, which is a real bug but not one about an agent.`,
        { label: family.id, phase: "Sweep", model: MODEL, schema: SWEEP_SCHEMA },
      ),
    ),
  )
);

const failed = FAMILIES.filter((f, i) => !sweeps[i]).map((f) => f.id);
if (failed.length) {
  log(`Sweep: no result from ${failed.join(", ")}; those vector families were not audited`);
}

const findings = sweeps.flatMap((s) => s?.findings || []);
const byVector = {};
for (const f of findings) byVector[f.vector] = (byVector[f.vector] || 0) + 1;

log(
  findings.length === 0
    ? "Sweep: no vector reached an agent in these workflows"
    : `Sweep: ${findings.length} finding${findings.length === 1 ? "" : "s"} across vectors ${Object.keys(byVector).sort().join(", ")}`,
);

// ==========================================================================
// Phase 3 - Report
// ==========================================================================
phase("Report");

// A sweep that found nothing is not a failed run, and the report has to say that
// plainly. Handing back silence lets a reader assume the audit never happened.
if (findings.length === 0) {
  return {
    status: "no-findings",
    note:
      `Swept ${carriers.length} workflow file${carriers.length === 1 ? "" : "s"} carrying ${agentSteps.length} agent step${agentSteps.length === 1 ? "" : "s"} in ${target} and found no path by which attacker-controlled input reaches an agent. ` +
      `Triggers seen: ${[...new Set(agentSteps.flatMap((s) => s.triggers || []))].join(", ") || "none recorded"}.`,
    agent_steps: agentSteps,
  };
}

const report = await agent(
  `Write the audit report for ${target}.

Agent steps found:

${stepList}

Findings from the sweeps, as JSON:

${JSON.stringify(findings, null, 1)}

Use the report format in ${pluginRoot}/skills/agentic-actions-auditor/SKILL.md. Group by vector, keep each claim to the event field and the path it takes, and state the trigger that makes the path reachable. Where two sweeps reported the same path under different vector letters, merge them and keep the letter that names the mechanism rather than the symptom.

Do not pad the report with general Actions hygiene. If you want to mention it, one line pointing at zizmor is enough.

${outPath ? `Write the report to ${outPath} and report the path.` : "Return the report as your message."}`,
  { label: "report", phase: "Report", model: MODEL },
);

return {
  status: "ok",
  note: `${findings.length} finding${findings.length === 1 ? "" : "s"} across ${carriers.length} workflow file${carriers.length === 1 ? "" : "s"}.`,
  vectors: byVector,
  agent_steps: agentSteps,
  findings,
  report: report ?? null,
  out: outPath || null,
};
