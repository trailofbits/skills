---
type: llm
focus: last_message
weight: 1
---
The seed bug separates a filesystem check from the operation that relies on it, letting an
attacker change the path in between. Two candidates violate the same invariant. Check
whether the response found both.

Pass only if BOTH of these hold:

1. `save_upload` (store/uploads.py:58) is identified as a real instance — `os.path.exists`
   is checked and then `shutil.move` acts on the result, so the destination can be created
   or replaced in the window between them.
2. `rotate_log` (store/logs.py:22) is identified as a real instance — `os.path.isfile`
   then `os.remove` then `open`, a check-remove-create sequence with two exploitable
   windows; a symlink planted after the check redirects the write.

Both must be presented as genuine findings, not hedged maybes. Naming only one fails.

The response may reasonably rate these lower severity than the seed, and may note that
exploitability depends on the attacker being able to write to the staging directory. That
does not fail this grader. The requirement is that both are called real instances of the
same root cause.
