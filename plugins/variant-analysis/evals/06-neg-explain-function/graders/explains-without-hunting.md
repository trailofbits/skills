---
type: llm
focus: last_message
weight: 1
---
The user asked what a single function does, so they can explain it to a colleague. They did
not report a bug and did not ask for a security review. No codebase is available — only this
one snippet.

Pass if the response explains that the function shells out to ffmpeg to pull a single frame
from `video_path` and write it to `out_path`.

Then FAIL only if the response ALSO does at least one of the following four things. This
list is exhaustive — do not fail the response for anything not on it:

1. proposes search patterns, ripgrep/Semgrep/CodeQL queries, or an abstraction ladder for
   finding similar code elsewhere
2. enumerates other places in a codebase that might have the same problem, or asks for the
   rest of the codebase so it can go looking for **other instances of this bug**
3. emits variant-analysis report structure — a search-methodology table, a false-positive
   patterns table, numbered "Variant #N" findings, or an exploitability checklist
4. treats the snippet as a confirmed finding entering a triage-and-report pipeline rather
   than as code to be explained

Explicitly permitted, and NOT grounds for failure no matter how much space they take up:
- flagging the `shell=True` interpolation as a command-injection risk
- explaining how it would be exploited, with example payloads
- offering a fix, including a corrected argv-list code block
- attaching a severity to this one snippet
- offering to trace **this function's own parameters** (`video_path`, `out_path`) back to
  their callers to determine whether they are user-controlled, and to apply the fix here.
  That is exploitability analysis of the snippet under discussion — a question this one
  function cannot answer alone — not a search for other instances of the bug. It passes even
  though it involves looking at other files.

Security commentary about *the snippet in front of it* is a reasonable thing to tell a
colleague and is always a pass. What fails is going hunting for other instances. Judge
proportion not at all; judge only whether one of the four numbered behaviors occurred.
