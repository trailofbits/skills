#!/usr/bin/env node
// Checks the category data files against each other and against the workflow.
//
// A category is defined by three places that must agree:
//
//   workflows/audit.js     a { id, title } row, all the script knows
//   references/<id>.json   title + seed patterns
//   references/<id>.md     Report when / Skip when + worked examples
//
// Nothing at runtime can verify this: the workflow has no filesystem access, so it
// cannot read either file, and a sweep handed a missing or mismatched definition
// reports a failure only after the run has already started. So the correspondence is
// checked here.
//
// It also checks that every VULNERABLE example in a corpus is matched by at least
// one seed in its .json. Those two drifted apart silently once: 8 of 18 documented
// examples matched no seed at all, including `getenv(K, "default")`, the most common
// shape in Python. Nothing could notice, because a pattern that matches nothing
// returns the same empty result as a clean repo.
//
// Seeds are POSIX ERE, so matching goes through `grep -E` rather than JS RegExp
// (which has no [[:space:]]), the same way an agent running `grep -rE` would.
//
// Usage: node seed-coverage.js <plugin-root>
// Exits non-zero on any mismatch, and on finding nothing to check.

"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFileSync } = require("child_process");

const root = process.argv[2] || ".";
const refs = path.join(root, "references");
const workflow = path.join(root, "workflows/audit.js");

for (const p of [refs, workflow]) {
  if (!fs.existsSync(p)) {
    console.error(`FAIL: missing ${p}`);
    process.exit(2);
  }
}

const problems = [];
const src = fs.readFileSync(workflow, "utf8");

// --- the workflow's view -----------------------------------------------------
const rows = [
  ...src.matchAll(/^ {2}\{ id: "([a-z-]+)", title: "([^"]+)" \},$/gm),
].map((m) => ({ id: m[1], title: m[2] }));

if (rows.length === 0) {
  console.error("FAIL: parsed 0 category rows from workflows/audit.js, so there is nothing to check");
  process.exit(1);
}

// --- the files' view ---------------------------------------------------------
const jsonFiles = fs.readdirSync(refs).filter((f) => f.endsWith(".json"));
const mdFiles = fs.readdirSync(refs).filter((f) => f.endsWith(".md"));

// Orphans in either direction. A stray file is as wrong as a missing one: it looks
// like a category that will never be swept.
for (const f of jsonFiles)
  if (!rows.some((r) => `${r.id}.json` === f))
    problems.push(`references/${f} has no matching category row in audit.js`);
for (const f of mdFiles)
  if (!rows.some((r) => `${r.id}.md` === f))
    problems.push(`references/${f} has no matching category row in audit.js`);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "seed-coverage-"));
const snippetFile = path.join(tmp, "snippet.txt");
const matches = (pattern, code) => {
  fs.writeFileSync(snippetFile, code);
  try {
    execFileSync("grep", ["-Eq", pattern, snippetFile], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
};

let examples = 0;
let hardGaps = 0;
let viaSibling = 0;

// Every seed from every category, for the sibling-category fallback below.
const allSeeds = [];
for (const r of rows) {
  const jf = path.join(refs, `${r.id}.json`);
  if (!fs.existsSync(jf)) continue;
  try {
    for (const s of JSON.parse(fs.readFileSync(jf, "utf8")).seeds || [])
      allSeeds.push([r.id, s]);
  } catch {
    /* reported per-category below */
  }
}

for (const r of rows) {
  const jf = path.join(refs, `${r.id}.json`);
  const mf = path.join(refs, `${r.id}.md`);

  if (!fs.existsSync(jf)) {
    problems.push(`${r.id}: no references/${r.id}.json`);
    continue;
  }
  if (!fs.existsSync(mf)) {
    problems.push(`${r.id}: no references/${r.id}.md`);
    continue;
  }

  // --- the .json ---
  let data;
  try {
    data = JSON.parse(fs.readFileSync(jf, "utf8"));
  } catch (e) {
    problems.push(`${r.id}.json does not parse: ${e.message}`);
    continue;
  }
  if (data.id !== r.id) problems.push(`${r.id}.json declares id "${data.id}"`);
  if (data.title !== r.title)
    problems.push(
      `${r.id}.json title "${data.title}" != audit.js title "${r.title}": the sweep prompt uses the audit.js one, so they must agree`,
    );
  const seeds = data.seeds || [];
  if (seeds.length === 0) problems.push(`${r.id}.json has no seeds`);
  for (const s of seeds) {
    if (/\\[sdb]/.test(s))
      problems.push(
        `${r.id}.json seed uses \\s, \\d or \\b, which some grep builds silently fail to match: ${s}`,
      );
  }

  // --- the .md ---
  const md = fs.readFileSync(mf, "utf8");
  if (!/^\*\*Report when:\*\* \S/m.test(md))
    problems.push(`${r.id}.md has no "**Report when:**" rule`);
  if (!/^\*\*Skip when:\*\* \S/m.test(md))
    problems.push(`${r.id}.md has no "**Skip when:**" rule`);
  if (!/^# \S/m.test(md)) problems.push(`${r.id}.md has no heading`);

  // --- documented examples vs seeds ---
  const vulnerable = md.split(/^## .*SECURE/m)[0];
  const blocks = [
    ...vulnerable.matchAll(/\*\*(.+?)\*\*[^\n]*\n+```[a-z]*\n([\s\S]*?)```/g),
  ];
  if (blocks.length === 0) {
    problems.push(`${r.id}.md documents 0 vulnerable examples`);
    continue;
  }
  console.log(`\n${r.id}: ${seeds.length} seeds, ${blocks.length} examples`);
  for (const [, label, code] of blocks) {
    examples++;
    if (seeds.some((s) => matches(s, code))) {
      console.log(`  ok   ${label}`);
      continue;
    }
    // Acceptable: sweeps run in parallel and dedup keys on category:file:line, so a
    // sibling category finding the line still gets it verified, under that category.
    const via = [
      ...new Set(allSeeds.filter(([, s]) => matches(s, code)).map(([c]) => c)),
    ].filter((c) => c !== r.id);
    if (via.length > 0) {
      viaSibling++;
      console.log(`  via  ${label}: caught by ${via.join(", ")}`);
    } else {
      hardGaps++;
      console.log(`  GAP  ${label}: NO SEED IN ANY CATEGORY MATCHES THIS`);
      problems.push(`${r.id}: "${label}" is documented but no seed matches it`);
    }
  }
}

fs.rmSync(tmp, { recursive: true, force: true });

console.log(
  `\n${rows.length} categories, ${examples} documented examples\n` +
    `${viaSibling} matched only by a sibling category (acceptable, dedup keys on category)\n` +
    `${hardGaps} matched by no seed at all`,
);

if (examples === 0) {
  console.error("\nFAIL: checked 0 examples. The extraction is broken, not the corpus clean");
  process.exit(1);
}

if (problems.length > 0) {
  console.error(`\nFAIL:\n${problems.map((p) => `  - ${p}`).join("\n")}`);
  process.exit(1);
}

console.log("\nOK: categories, patterns and corpora all correspond");
