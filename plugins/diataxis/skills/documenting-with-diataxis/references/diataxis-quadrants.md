# Quadrant discipline

The framework itself is cloned at run time and distilled by the framework agent. This file is the part no distillation gives you: **how to decide where a given piece of writing belongs, and how to keep four agents from writing the same page four times.**

Everything below is judgment, not summary. Read it before writing or reviewing any quadrant.

## The one decision that matters

Diátaxis is two axes crossed:

|                     | Serves *doing*  | Serves *thinking* |
|---------------------|-----------------|-------------------|
| **Studying** (acquisition) | Tutorial   | Explanation       |
| **Working** (application)  | How-to     | Reference         |

Almost every misfiled page comes from confusing the *rows*, not the columns. "Serves doing vs. thinking" is easy. "Is the reader studying or working?" is the hard one, and it is the question to ask first.

A reader who is **studying** does not yet have a goal of their own — you supply one. A reader who is **working** arrived with a goal already; you must not replace it with yours.

## Decision tests

Apply in order. The first one that answers, wins.

**1. Does the reader already have a specific goal?**
Yes → how-to or reference. No → tutorial or explanation.

This is why "Getting Started" is so often broken. If it says *"we will build a small blog to learn the API"* it is a tutorial: the goal is supplied. If it says *"to install and configure the client"* it is a how-to: the reader came with that goal. A page that does both serves neither.

**2. Can the reader fail?**
A tutorial must not let the reader fail. Every command is given, every output is shown, every choice is made for them. If your draft says "configure your database appropriately" it is not a tutorial — a beginner cannot act on "appropriately."

A how-to *may* let the reader fail, because a competent user can recover. How-tos branch ("if you use Postgres… if you use SQLite…"); tutorials never branch.

**3. Would the reader read this end to end?**
Tutorials and explanations are read through. How-tos are read through *once, while doing*. Reference is never read through — it is looked *up*. If a reference page needs to be read in order to be understood, it has explanation smuggled into it.

**4. Is the statement true regardless of what the reader wants?**
Yes → reference (it describes the machinery). No, it depends on their goal → how-to. `timeout: int, seconds to wait, default 30` is reference. "Set `timeout` higher when running behind a slow proxy" is a how-to.

**5. Does removing it lose no capability, only understanding?**
That is explanation. Explanation is the only quadrant a reader can skip entirely and still use the software. That is not a reason to skip writing it — it is the test for what belongs in it.

## Where the boundaries actually leak

These are the four failures to check for, in rough order of frequency.

**Explanation leaking into tutorial.** The single most common. An author writing a tutorial cannot resist saying *why*. Every "note that this works because…" aside breaks the learner's flow and gives them something to think about at the exact moment they should be typing. Move it to explanation and link it at the end. A tutorial may say *what* is happening ("you should now see three rows"), never *why the design is this way*.

**Tutorial leaking into how-to.** Shows up as tone: "we'll now add authentication." A how-to addresses a competent adult with a job — "Add authentication" — and does not narrate. If the how-to teaches, it is doing the tutorial's job badly.

**How-to leaking into reference.** Reference pages that grow a "Usage" section with worked scenarios. Reference states what is; the moment it recommends, it is a how-to. One minimal example per symbol showing *form* is fine; a scenario is not.

**Reference leaking everywhere.** Parameter tables pasted into tutorials and how-tos "for convenience." They are guaranteed to fall out of date, because the real reference is generated from the code and these copies are not. Link instead.

## What each agent does with out-of-quadrant material

**Never absorb it. Never drop it.** Each writer records it in its return manifest under `redirected`, naming the quadrant it belongs to and summarizing the content. The assemble phase surfaces it. A quadrant agent that quietly keeps material outside its remit is the whole failure mode this structure exists to prevent.

## Acceptance checks per quadrant

Reject a draft that fails any of these.

**Tutorial**
- A beginner who follows it literally, top to bottom, succeeds — no judgment calls, no branches, no "as appropriate."
- Every command shows its expected output, so the reader can tell whether they are on track.
- It produces something visible and real. Not a toy that does nothing.
- It contains no explanation of design rationale, and no exhaustive option lists.
- It is written in the first person plural or the imperative and stays there.

**How-to**
- The title starts with a verb and names a real goal: "Deploy to Kubernetes", not "Kubernetes".
- It assumes competence: no explanation of what a container is.
- It handles the realistic variations of the task, and omits the unrealistic ones.
- It does not teach and does not justify.
- It ends when the goal is met, not when the topic is exhausted.

**Reference**
- Generated from the source wherever the language permits, so it cannot drift.
- Complete over the public surface — every exported symbol, every config key, every CLI flag.
- Structured to mirror the code, so a reader can navigate it by knowing the code.
- Austere: describes, does not instruct, does not explain, does not persuade.
- Every statement stays true no matter what the reader is trying to do.

**Explanation**
- Titled around a topic or question: "Why the parser is two-pass", "Architecture of the scheduler".
- Discusses alternatives that were rejected and why — this is the part that is genuinely irreplaceable, because it is the only place the reasoning survives.
- Admits its own limits and disagreements rather than presenting one settled truth.
- Contains no instructions the reader is expected to follow.
- Can be read away from the keyboard.

## A note on sizing

Four quadrants does not mean four pages. It means four *kinds*. A small library may warrant one tutorial, three how-tos, a generated reference, and two explanations. Do not pad a quadrant to look balanced — an explanation written because the structure demanded one is worse than none, and a reader learns quickly which sections are filler.

Do not, however, skip a quadrant because the material "isn't there." If a project has no explanation to offer, that usually means the rationale exists only in maintainers' heads and in commit messages, which is exactly the case where writing it down is most valuable.
