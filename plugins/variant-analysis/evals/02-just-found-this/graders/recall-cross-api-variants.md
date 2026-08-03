---
type: llm
focus: last_message
weight: 1
---
The seed bug concatenates a client-controlled filename into a command string passed to
`os.system()`. Two of the five candidates realize the same root cause through a different
sink API. Check whether the response found both.

Pass only if BOTH of these hold:

1. `make_preview` (handlers/preview.py:19) is identified as a real instance of the same
   bug — an uploaded filename interpolated into a command string with
   `subprocess.run(..., shell=True)`.
2. `apply_watermark` (handlers/watermark.py:66) is identified as a real instance of the
   same bug — a user-editable config value interpolated into a command string passed to
   `os.popen()`.

Both must be presented as genuine findings that need fixing, not as hedged maybes. Naming
only one of the two fails.

Note on candidate 2: the response may observe that `watermark_path` requires an
authenticated project member to control, and may rate it lower severity than the
anonymous upload path. That is fine and does not fail this grader — the requirement is
that it is called a real instance of the bug, not that it is rated critical.

The prompt is casual and does not ask for a report. Do not require any particular format,
structure, or headings.
