# Audit Context Building

Understand a codebase before you go looking for bugs in it.

**Author:** Omar Inuwa

## What it does

It reads the code function by function and writes up three things about each one: what it assumes is already
true, what it promises to whatever calls it, and what it depends on elsewhere. Those write-ups go into files.
You get back a short summary and a list of the spots worth a closer look.

It does not report vulnerabilities. That is the next job, and it goes much better once this one is done.

## Why this exists

Claude can already read a function and explain it well. This plugin is not here to teach it that. It is here
for three things Claude cannot do for itself:

**You don't have to remember it exists.** A workflow only runs when someone types its name. This skill
notices the situation instead — you are starting an audit, or opening a codebase nobody on the team knows —
and starts the right one for you.

**It splits the work up.** One helper runs per function, all at the same time, each writing its notes
straight to a file. Ask Claude to do the same job directly and it works through the functions one at a time,
filling its working memory with the notes until there is no room left to actually use them.

**Every write-up comes out the same shape.** That matters most in one specific case: when the code counts on
something being true and nothing anywhere checks it. That always gets recorded the same way, with the words
`nothing found`. So you can search a whole codebase for that one phrase and get every such spot in a list.
Claude finds those spots on its own just fine — but describes each one differently, and forty differently
worded notes do not add up to a list.

If you are changing this plugin, keep that order in mind. The guidance in `SKILL.md` and `resources/` is
sound practice and worth keeping, but it is not what makes the plugin useful. The value is in the workflow,
the fixed write-up format, and the fact that it starts itself.

## When to use it

At the start of an audit, a threat model, or an architecture review — any time the code is unfamiliar and
somebody is about to go looking for problems in it.

Also useful when an earlier review turned up issues nobody could judge, because no one had mapped out how the
system fits together.

## How to run it

```
/audit-context-building:audit-context <path> [--focus <module>]
```

That runs the [workflow](workflows/audit-context.js), in three steps:

1. **Get oriented.** Map out the pieces of the system, the ways in from outside, who can reach them, and the
   data that sticks around between calls. Then pick the functions that carry the most weight.
2. **Analyze.** One helper per function. Each writes its full notes to `audit-context/functions/` and hands
   back only a short record.
3. **Pull it together.** Work out the rules that span several functions — the ones no single write-up could
   state on its own — and save the result to `audit-context/DOSSIER.md`.

For a single function, you can run the `audit-context-building:function-analyzer` helper on its own. Either
way the reading happens in a helper, not in your own session.

### Why it works this way

Analyzing a function properly takes a lot of words. If those words come back into the conversation, they
crowd out the very understanding they were meant to build.

Asking politely does not fix this. A skill can say "save it to a file and just summarize" and still get the
whole thing back in the reply. The workflow fixes it because each helper is only allowed to hand back a fixed
set of fields. There is no slot for a wall of text, so none comes back.

The skill points you at the workflow. The workflow is what actually holds the line.

## What you get back

Understanding, not verdicts. The write-ups cover how the code is put together, what must always be true for
it to work, and what it takes on faith. They do not name vulnerabilities, suggest fixes, write exploits, or
rate severity — that is the next phase's job, done with the whole picture in hand.

The most useful thing in the output is the list of things the code counts on that nothing actually checks,
each with the line where the check should have been.

The second most useful thing is the open questions. An honest list of what is still unclear beats a confident
answer that turns out to be wrong.

## Installation

```
/plugin install trailofbits/skills/plugins/audit-context-building
```

## Tests

```bash
claude plugin eval plugins/audit-context-building --judge-model sonnet
```

Run it against the plugin **by name**. That way the tests run twice — once with the plugin and once without —
so you can see what it actually adds. Pointing at a folder path instead only runs it once.

Five tests, covering the three kinds of target this plugin gets used on.

**`dispatches-not-inlines`** — asks for audit context on a small C codebase with no way to hand the work off,
so the only correct move is to say what to run and stop. It fails if the reply contains the analysis instead.
This is the test aimed at what the plugin actually changes, rather than at what the model can already do.

Its `max_turns` was raised from 20 to 40 after the plugin arm was being truncated before it could answer,
which scored as a routing failure. It has not been re-measured since. Run it before relying on its number.

**`routes-to-workflow`** — the same C parser, graded on the tool call rather than the reply: does the run
actually reach for `/audit-context-building:audit-context`? The case above withholds every dispatch tool and
reads the prose, so it measures whether the skill *names* the mechanism, and a skill can describe the right
routing without taking it. `Workflow` is kept out of `allowed_tools` here too, so the per-function fan-out
never runs and the grader counts the attempt.

Scored 1.00 over three runs. Two things that does not establish. No with-plugin-versus-without arm has been
run, so nothing yet shows the case can go red. And because `tool_used` counts attempts while the Workflow
tool does not execute inside an eval run at all, a frontmatter restriction that blocked execution rather than
the attempt would be invisible to it — adding and removing `Workflow` from the skill's `allowed-tools` scored
1.00 either way. Do not read a green score here as proof that line is correct.

**`contract-continuity`** — Solidity. `release()` looks like `require(_charge(...))` confirms the buyer had
enough credit. It doesn't: for whitelisted accounts, `_charge` subtracts and returns true without ever
comparing. The test also checks that `feeSink.notify()` gets treated as untrusted, since nothing in the file
says what it does.

**`decompiled-continuity`** — Ghidra output from a firmware image. The length used to copy data into a
512-byte buffer comes from a function that isn't in the file at all, so nothing visible limits it. A check
near the top looks like it bounds the copy but only bounds the header. Claiming that an unnamed function
"is `memcpy`" fails the test — it looks like `memcpy`, and the listing never confirms it.

**`continuity-across-calls`** — C. The check that keeps a copy in bounds sits two calls away, on only one of
two branches, while the header file promises a limit that branch never applies.

The last three confirm the behavior still works rather than proving the plugin causes it — a capable model
scores 1.00 on the Solidity and Ghidra cases with no plugin loaded. Worth remembering before reading a
passing run as proof.

One measured cost worth knowing: the plugin arm uses roughly twice the turns of a bare agent on the same
prompt, because `SKILL.md` points at three reference files that get read before any work starts.

## Related Skills

- `entry-point-analyzer` — lists the functions that change state; a good input to step 1
- `spec-to-code-compliance` — checks what the code does against what the spec says it should
- `trailmark` — call graphs and data-flow tracing, for the structural picture this builds on
