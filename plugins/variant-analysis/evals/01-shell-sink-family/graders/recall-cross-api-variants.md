---
type: llm
focus: last_message
weight: 1
---
The seed bug interpolates client-controlled data into a command **string** run through a
shell (`subprocess.run(..., shell=True)`). Two of the six candidates realize that same
root cause through a *different* sink API. Check whether the response found both.

Pass only if BOTH of these hold:

1. `archive_labels` (media/labels.py:44) is identified as a real instance of the same
   bug. It concatenates a user-submitted label into a command string passed to
   `os.system()`.
2. `stream_probe` (media/probe.py:31) is identified as a real instance of the same bug.
   It concatenates a query-string parameter into a command string passed to `os.popen()`.

Both must be presented as genuine findings — confirmed, exploitable, needs fixing — not
as "worth a look" or "possibly". A response that names only one of the two fails. A
response that finds neither fails.

Do not require any particular severity label, section heading, or report format. Do not
credit merely quoting or restating a candidate; the response must reach a verdict that
it is the same bug.
