# Review Walkthrough

Generates an interactive HTML walkthrough of committed changes on the current
branch. It groups the final diff into logical steps, explains the design, and
places review findings beside the relevant code.

## Quick Start

```text
/review-walkthrough:review-walkthrough
/review-walkthrough:review-walkthrough compare this branch against origin/develop
```

The `review-walkthrough` skill runs only when explicitly invoked. Claude Code uses
the namespaced command above; Codex uses `$review-walkthrough`.

The skill uses the base you specify, the current PR's base, or the repository's
default branch. It compares the merge base with the current committed `HEAD` and
reports unresolved refs or an empty diff. It leaves the checkout unchanged.

## Walkthrough Features

- Logical review steps with colored unified diffs.
- Explanation and Review tabs, with severity labels and anchors to diff lines.
- A progress bar and arrow-key navigation.
- Editable comments and a copyable `gh api` command when matching PR metadata is
  available. The page does not submit a review; the user executes the command.

The output is a self-contained HTML file outside the checkout. The skill opens it
in the browser when one is available and otherwise reports the path. Review input
is passed to the bundled renderer as JSON. The renderer checks that the steps
preserve the captured diff and that findings point to valid lines, then embeds
the data safely in the page.

## Requirements

- Git for capturing the branch diff, resolving the base, and rendering patches.
- `uv` and Python 3.11 or later for the bundled renderer. It has no third-party
  Python dependencies.
- GitHub CLI (`gh`) for optional PR metadata and for executing a copied review
  command.

## Development

`make check` includes the renderer's Python tests and the page's `node:test`
suite. CI also runs DOM and sanitization checks in Chrome. Run those locally with
`node plugins/review-walkthrough/tests/browser-check.mjs /path/to/chromium`.
The model evaluation in [evals/README.md](evals/README.md) checks ordering,
review substance, and the generated HTML against a fixture repository.

## Author

Facundo Tuesca, Trail of Bits.
