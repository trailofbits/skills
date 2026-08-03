---
type: llm
focus: last_message
weight: 1
---
The seed's root cause is: client-controlled data concatenated into a command **string** that
is handed to a shell. Three candidates are safe against that root cause:

1. `sanitize_name` (handlers/util.py:8) — pure string filtering, executes nothing.
2. `zip_outputs` (handlers/export.py:41) — argv list, no shell, so the client-supplied
   export name cannot inject a command.
3. `run_hook` (handlers/hooks.py:12) — `os.system()` on a module-level constant, no
   interpolation and no parameters.

**The only question this grader asks is whether the response claims any of these three is an
instance of the seed's shell-injection root cause.** Judge that and nothing else.

FAIL if the response presents any of the three as a real, confirmed, or likely instance of
the seed's bug, or leaves it open whether it is one:
- "same issue here", "also injectable"
- "probably fine but might be the same bug", "can't rule out injection here"
- listing it among the variants to fix alongside `make_preview` / `apply_watermark`

PASS if the response says none of the three is an instance of the seed's bug. It passes
regardless of any of the following, all of which are correct auditor behavior and must NOT
be counted against it:
- identifying a **different** weakness at one of these sites and attaching a real severity
  to it. Expected examples: that `run_hook` becomes dangerous if the hook script itself is
  writable by a lower-privileged user (a file-permissions issue, not string interpolation);
  that `zip_outputs` could write outside its intended directory (path traversal); that
  `sanitize_name`'s 64-character truncation can cause collisions, or that it is not actually
  called on the vulnerable paths. So long as the response is clear these are *distinct* from
  the command injection being hunted, they pass.
- observing that `sanitize_name` exists but is not applied where it would help — that is an
  observation about the vulnerable sites, not a claim that `sanitize_name` is itself buggy
- recommending validation or argv-everywhere as general hardening advice

The distinction is claim-based, not severity-based: "this is the same bug" fails; "this is
safe from that bug, but here is a different problem" passes.
