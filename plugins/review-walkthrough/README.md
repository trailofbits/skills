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

Comment and Request Changes require a review summary before the command can be
copied. Approve permits an empty summary.

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

## Calcifier recipe for `review-walkthrough`

The [`review-walkthrough` Python recipe](skills/review-walkthrough/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/review-walkthrough/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/review-walkthrough/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `repository` | `str` | Required |
| `base` | `str` | `''` |
| `github` | `Literal['auto', 'skip', 'no-pr']` | `'auto'` |
| `remote` | `str` | `'origin'` |
| `allow_repository_output` | `bool` | `False` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
