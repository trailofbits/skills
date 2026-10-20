# Fresh Codex cold run

Use a new, empty workspace. Install `plugins/patching-bugs` and its
`regression-hunt` dependency in Codex.

Copy `plugins/patching-bugs/tests/fixtures/planted-bug/{app.py,build.py,poc.py}`
into `workspace/target/`. Initialize `target` as a Git repository on branch
`patch`, commit those three unchanged files, and write that commit's full SHA
to `workspace/baseline-sha.txt`. Keep `workspace/run/` outside `target`.

In a fresh Codex session rooted at `workspace`, request:

> Use the patching-bugs skill on the path traversal bug in target/app.py's
> save(name, data). The PoC is target/poc.py. The initial commit is in
> baseline-sha.txt. Keep records and reports in run/, outside the tracked
> target tree. Produce one new local patch commit on target's patch branch.
> Run the supplied PoC and retain a separate case that calls the built
> `app.save("../other.txt", ...)` on both commits; check a valid upload.
> Do not push or open a PR.

`build.py` only copies `app.py`; builds alone do not exercise either input.
The supplied PoC covers only `../escape.txt`. Accept only if both traversal
inputs escape on the baseline, neither escapes on the patch, and `allowed.txt`
still lands in `uploads/`. Inspect retained commands and receipts for both
cases against the built `app.save`, `finding.json`'s repair scope, the patch
diff, and regression decisions under `run/`. A `READY` verdict and both reports
for the patch commit are additional checks; they do not replace this review.
