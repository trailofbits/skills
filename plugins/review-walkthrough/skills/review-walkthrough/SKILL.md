---
name: review-walkthrough
description: Generates an interactive HTML walkthrough for reviewing code changes. Use only when explicitly called.
disable-model-invocation: true
---

# Review Walkthrough

Generate a self-contained HTML walkthrough of the current branch, with the final
diff split into logical steps, explanations, and critical review findings. Choose
the grouping and reading order for comprehension; commit order need not dictate
either. Invoke as `/review-walkthrough:review-walkthrough` in Claude Code or
`$review-walkthrough` in Codex.

## Capture the branch diff

Respect a user-specified base. Otherwise, use the current open PR's base when PR
metadata is available. Without a PR, discover the repository's default branch
from `git symbolic-ref --quiet --short refs/remotes/origin/HEAD` or the configured
remote's equivalent. Do not assume it is `main`. If the selected base is missing
or ambiguous, ask for it rather than silently choosing another branch.

Resolve the base and `HEAD` to commit IDs with
`git rev-parse --verify --end-of-options "${ref}^{commit}"`, then compute their
merge base with `git merge-base`. Capture the complete patch using
`git diff --no-ext-diff --no-textconv --no-color --src-prefix=a/ --dst-prefix=b/ "$merge_base" "$head_sha" --`.
Initialize variables and run the commands that consume them in the same shell
invocation; shell variables do not persist between tool calls. Save the patch to
a temporary file outside the checkout and retain its actual path. Stop on a Git
error or an empty patch and explain the result.

This scope includes committed changes through the captured `HEAD`. Mention any
uncommitted work that is excluded. Do not change branches, reset the checkout,
or alter source files to prepare the review. Keep generated data and HTML outside
the checkout unless the user requests a particular output location; generated
review artifacts never belong in the captured patch.

For a GitHub PR, collect `owner`, `repo`, `pr_number`, and `head_sha` from its
metadata. Include them only when the PR head matches the captured `HEAD` and the
chosen base matches the PR base. Otherwise use `null` and explain why comment
export is unavailable. A failed authentication or network request is not evidence
that no PR exists; report the failure and ask for the base if it cannot be
determined. GitHub access is optional when the user supplies the base or confirms
there is no PR.

## Shape the review

Read the changed files and the surrounding source, tests, configuration, and
dependency metadata needed to judge them. Keep the review read-only; do not run
the project's tests or install its dependencies merely to build the walkthrough.

Group related files into steps covering one concept each. Put definitions before
their consumers, wiring after the components it connects, and tests after or
beside their subjects. Copy each complete per-file diff from the captured patch
verbatim into exactly one step. Reordering files between steps is allowed;
splitting, rewriting, omitting, or inventing their patches is not. Preserve
rename, binary, and mode-change entries even when they have no text hunks.
Binary summaries identify changed files; their payloads are outside this review.

Write one explanation per step, usually 50–150 words, covering the change's
purpose, design choices, trade-offs, and connections to other steps. Refer to
actual identifiers. Write one review list per step covering bugs, security,
validation, API design, or performance issues supported by the code. Report
findings with severity rather than suppressing minor issues. Use an empty list
for a step with no findings.

Explanations and review bodies are HTML fragments. Use `<p>`, `<strong>`, `<em>`,
`<code>`, `<pre>`, and `<ul>`/`<li>` for structure. Write literal `<` and `>` in
prose or snippets as `&lt;` and `&gt;`. Backticks and Markdown fences are literal
text here. Supported inline tags also include `<sup>`, `<sub>`, `<kbd>`, `<del>`,
and `<a href="https://…">`. The page sanitizes fragments and converts them to
Markdown when preparing a PR comment. Only safe link targets survive; arbitrary
attributes, scripts, and images do not. Keep exported findings in prose, lists,
and code blocks; tables render on the page but lose their table structure when
converted to Markdown.

Anchor findings to a file in the same step and a line in that file's displayed
diff. Use `side: "RIGHT"` for additions or new-file context and `side: "LEFT"`
for deletions or old-file context. For a range, `line` and `end_line` use that
same side within one hunk. A finding spanning multiple steps belongs with the
file it addresses, or remains unanchored. An unanchored finding is still
displayed but cannot become an inline PR comment.

## Render the artifact

Use a file-writing tool to create a JSON object with the fields below. Preserve
the literal patch as JSON string data, with no shell expansion.

| Field | Value |
|-------|-------|
| `title` | Feature or review title |
| `steps` | Array of objects with `sha` (step ID such as `step-1`), `message` (step title), `files` (paths in patch order), and `diff` (complete per-file patches) |
| `explanations` | HTML strings, one per step |
| `reviews` | Arrays of findings, one per step; each finding has `severity` (`high`, `medium`, or `low`), `title`, and HTML `body` |
| `pr_meta` | Object with `owner`, `repo`, `pr_number`, and `head_sha`, or `null` |

An anchored finding also has `file`, `line`, and `side`, plus optional `end_line`.
The three arrays have equal lengths and corresponding entries. File paths match
the diff headers without their `a/` or `b/` prefix; a renamed file uses its new
path. Set `side` explicitly so lines that occur on both sides are unambiguous.

Run the bundled renderer with the actual paths created for this review:

```bash
uv run --no-project {baseDir}/scripts/render_walkthrough.py \
  --input /tmp/data.json \
  --diff /tmp/captured.patch \
  --output /tmp/walkthrough.html
```

The renderer validates the data, compares every step's patches with the complete
captured diff, checks anchors, and safely embeds the result in the bundled
template. Fix reported input errors rather than bypassing the renderer or
generating an alternative page.

Open the output with `open` on macOS or `xdg-open` on Linux when a browser is
available, and tell the user its path. In a headless run, report the file without
opening it. When PR metadata is present, the page lets the user copy a `gh api`
command for their selected comments. It does not execute the command or post
anything to GitHub.
