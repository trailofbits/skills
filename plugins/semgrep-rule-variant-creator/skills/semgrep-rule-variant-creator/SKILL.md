---
name: semgrep-rule-variant-creator
description: Creates language variants of existing Semgrep rules. Use when porting a Semgrep rule to specified target languages. Takes an existing rule and target languages as input, produces independent rule+test directories for each language.
allowed-tools: Bash Read Write Edit Glob Grep WebFetch Workflow
---

# Semgrep Rule Variant Creator

Port an existing Semgrep rule to other languages, one independent test-driven cycle per
language.

For a new rule rather than a port, use `semgrep-rule-creator` — it takes a bug pattern
description where this skill takes a finished rule. That skill is also the reference for
rule-writing fundamentals: taint mode versus pattern matching, why tests come first, and
how to narrow a rule once it passes. Porting applies those same judgments in a new
language, so start there when the rule structure itself is the open question.

## Run it as a workflow

Porting is the same four phases repeated per language, so the orchestration ships as a
dynamic workflow rather than as instructions to re-follow each run:

```
/semgrep-rule-variant-creator:port-rule-to-languages
```

Pass all four arguments. One language per entry: `"Go and Java"` ports a single language
named after the phrase, and the script rejects it.

```json
{
  "rulePath": "<path to the rule being ported>",
  "languages": ["Go", "Java"],
  "referencesDir": "{baseDir}/references",
  "outputDir": "<where the variant directories should land>"
}
```

A workflow script cannot resolve `{baseDir}` itself, and an installed plugin does not sit in
the user's project, so `referencesDir` is the only route by which the references below reach
the phase agents. The script rejects a run without it rather than porting without them, since
a port made without this guidance still reports every language as passed. `outputDir` is the
one optional argument, defaulting to the working directory, which is rarely what you want
inside a repository.

It reads the rule once, then runs each language through the full cycle independently, and
reports which languages passed, which failed validation, which it judged not applicable, which
Semgrep cannot analyze at all, and which it stopped on — a language key it does not recognize,
two entries resolving to one directory, or a refuter that never reported back. A stop names
what to change and will happen again on a re-run, which is what separates it from an agent that
died. The rule travels as a path, not as text: every phase
reads the file, because an agent asked to repeat a rule back verbatim does not — one
HTML-escaped `<` and `>` and broke the `<... ...>` operator for every phase downstream.

If a run dies partway — session limit, API outage — relaunch it with
`Workflow({scriptPath: "…", resumeFromRunId: "<runId>", args: {…}})`, passing the same
arguments again. Arguments are not saved with a run, so a resume that omits them fails the
pre-flight check above before replaying anything; with them, languages that finished replay
from cache and only the unfinished ones re-run.

A run id that no longer exists is not an error. The workflow starts from scratch under that
id and re-runs every language at full cost, so check the id is still there before counting on
a resume — `ls -d ~/.claude/projects/*/*/subagents/workflows/*/` lists every run that can be
resumed. If it is gone, re-invoke with the same arguments and point `outputDir` somewhere
fresh: the script never deletes a directory, so a language that flipped to `NOT_APPLICABLE`
on the second run leaves the first run's variant behind.

The script is `workflows/port-rule-to-languages.js` at the plugin root. It pins a
reasoning effort per phase — cheap to read the rule, highest for translation and for the
fix-until-green loop — and encodes the phase order, so a rule cannot be written before
the tests that specify it. It also keeps the two decisions that have no oracle out of any
single agent's hands: a `NOT_APPLICABLE` verdict goes to an independent refuter before the
language is dropped, and failed validation is retried up to three times rather than
trusting one agent to iterate until green.

Run the phases by hand when you are porting to a single language and want to stay in the
loop, or when a port is already half-finished and you only need one phase. The workflow is
the only delegation a port needs: one agent to read the rule, and four per language when
the port goes green first try — a refuted verdict adds one, and so does each validation
retry. Nothing else here is large or independent enough to be worth its own agent, so
running a phase by hand means doing it yourself rather than handing it to a subagent.

## The four phases

Each language runs all four before its variant is finished. A language that fails
validation is unfinished; a language judged not applicable produces no directory.

**1. Applicability analysis** — decide whether the pattern belongs in the target language
at all: does the vulnerability class exist there, does an equivalent construct exist for
each source, sink, and sanitizer, and would the ported rule detect real risk rather than
a surface syntax match. Verdict is `APPLICABLE`, `APPLICABLE_WITH_ADAPTATION`, or
`NOT_APPLICABLE`. `NOT_APPLICABLE` is the one verdict nothing downstream can contradict —
it produces no tests, no rule, and no directory — so it earns a second opinion before you
act on it. Answered separately, by running Semgrep: can Semgrep read this language at all?
Perl has no frontend and Elixir's parser is Pro-only, and in both cases the bug class is
present while the rule is ungradeable — a different finding from `NOT_APPLICABLE`, which
claims the bug class is absent. See
[applicability-analysis.md]({baseDir}/references/applicability-analysis.md)
for worked examples of each verdict.

**2. Test creation** — write the test file first, in idiomatic target-language code. At
least two `ruleid:` cases and two `ok:` cases, each annotation on the line immediately
above the code it grades. Include the safe form that is the language's own idiom for
doing the thing correctly, since that is the false positive a port most often invents.

**3. Rule translation** — dump the AST for the target language and translate against what
it shows, because pattern shape follows AST shape rather than source resemblance. Keep the
original's detection intent and mode; change the id to `<original-id>-<language>`, the
`languages` key, and add `original-rule` and `ported-from` metadata. See
[language-syntax-guide.md]({baseDir}/references/language-syntax-guide.md).

**4. Validation** — `semgrep --test` is the acceptance criterion, and it must report that
all tests passed. Missed lines mean the pattern is narrower than the vulnerability;
incorrect lines mean it is broader. The test file is the specification, so fix the rule to
satisfy it. Stopping while tests still fail leaves the language unfinished, not done. See
[workflow.md]({baseDir}/references/workflow.md) for reading a test failure and for
troubleshooting when a pattern will not match or taint will not propagate.

The acceptance criterion is one specific Semgrep: the version recorded when the rule was
read. Switching binaries to get a green is the failure this guards against — an agent that
could not pass its Elixir tests installed the last OSS build shipping the Elixir parser and
reported its genuine "All tests passed" for a port that is red here. Two other greens mean
nothing: a rule Semgrep *skipped* still ends its run in "All tests passed", and so does a
test file whose extension Semgrep does not associate with the rule's language, since it
graded zero tests either way.

## Output

One directory per applicable language, holding the ported rule and its test file:

```
python-command-injection-go/
├── python-command-injection-go.yaml
└── python-command-injection-go.go
```

`All tests passed` means the rule and its test file agree with each other; it is not
evidence that the vulnerability class is exploitable in the target language, since the same
cycle wrote both, so treat a finished variant as a candidate for review rather than a
validated rule.

## Scope and reporting

Port the rule you were handed to the languages you were asked for. Do not repair the
original, widen it to catch a nearby bug class, or add a language nobody named; if the
original looks wrong or an obvious target is missing, say so in one sentence and carry on
with the port as asked. Every language you were given gets finished — a port is done when
its tests pass, not when its files exist.

Keep prose short and spend it on the result. Before the first tool call, say in one
sentence what you are about to do. While a port runs, speak up when a verdict changes,
when the target needs a pattern shape the original does not have, or when the tests will
not go green — not on every `semgrep --test` iteration. Then lead with the outcome: the
first sentence says which languages passed, which failed validation, which were not
applicable, and which Semgrep cannot analyze, with the detail after it. Correct an earlier statement when the error changes
the rule, the verdict, or what to do next, then keep going; a slip that changes nothing
needs no note.

Rule and test files are the size of the problem. A test file earns its length from
distinct constructs and distinct safe forms rather than from restatements of the same
case, and neither file needs comments repeating what the code already says.

## Rationalizations to Reject

| Rationalization | Why It Fails | Correct Approach |
|-----------------|--------------|------------------|
| "Pattern structure is identical" | Different ASTs across languages | Always dump AST for target language |
| "Same vulnerability, same detection" | Data flow differs between languages | Analyze target language idioms |
| "Rule doesn't need tests since original worked" | Language edge cases differ | Write NEW test cases for target |
| "Skip applicability - it obviously applies" | Some patterns are language-specific | Complete applicability analysis first |
| "I'll create all variants then test" | Errors compound, hard to debug | Finish each language before the next |
| "Library equivalent is close enough" | Surface similarity hides differences | Verify API semantics match |
| "Just translate the syntax 1:1" | Languages have different idioms | Research target language patterns |
| "Most tests pass" | A partial rule reports partial truth | `All tests passed`, or the port is unfinished |
| "An older semgrep still parses this language" | A green nobody can reproduce on the semgrep the rule must run under | Report the failing output and say the parser is Pro-only |
| "The class exists there, so the rule ports" | Semgrep has no Perl frontend and Elixir's is Pro-only; taint no-ops silently | Confirm semgrep can read the language before porting |
| "Semgrep said all tests passed" | It says that over zero graded tests, for a rule it skipped or a file it never matched | Check the rule ran and the test file's extension matches |

## Quick Reference

| Task | Command |
|------|---------|
| Run tests | `semgrep --test --config rule.yaml test-file` |
| Validate YAML | `semgrep --validate --config rule.yaml` |
| Dump AST | `semgrep --dump-ast -l <lang> <file>` |
| Debug taint flow | `semgrep --dataflow-traces -f rule.yaml file` |

## Documentation

- [Pattern Syntax](https://semgrep.dev/docs/writing-rules/pattern-syntax) — metavariables and matching
- [Pattern Examples](https://semgrep.dev/docs/writing-rules/pattern-examples) — per-language references, the most useful page when translating
- [Testing Rules](https://semgrep.dev/docs/writing-rules/testing-rules) — annotation semantics
- [Trail of Bits Testing Handbook](https://appsec.guide/docs/static-analysis/semgrep/advanced/) — advanced taint patterns
