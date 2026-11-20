# Preflight

Run both checks at the start of every review, before asking questions,
and in parallel when the tool interface supports it. Neither check may
block a review: on any failure, note it in one line and continue.

## Plugin version

Provider CLIs and model names change faster than most users update
plugins, and an outdated copy of this skill can recommend a model the
provider has retired. Compare the installed version with the latest
version in the plugin's marketplace.

This check uses the `claude` CLI. When it is missing (for example, when
the skill runs under another agent), skip the check silently.

```bash
read -r plugin_id installed < <(claude plugin list --json 2>/dev/null \
  | jq -r '.[] | select(.id | startswith("second-opinion@"))
      | "\(.id) \(.version)"' | head -1)
marketplace=${plugin_id#*@}
```

If `marketplace` is empty, the skill was not installed as a marketplace
plugin; skip the check. Otherwise refresh that marketplace's catalog and
read its published version. Name the marketplace explicitly: without a
name, `claude plugin marketplace update` refreshes every marketplace.

```bash
claude plugin marketplace update "$marketplace" > "$refresh_log" 2>&1
catalog_dir=$(claude plugin marketplace list --json \
  | jq -r --arg m "$marketplace" '.[] | select(.name == $m) | .installLocation')
latest=$(jq -r '.plugins[] | select(.name == "second-opinion") | .version' \
  "$catalog_dir/.claude-plugin/marketplace.json")
```

The refresh updates the marketplace catalog only; it does not change
installed plugins. Compare the two versions with `sort -V`. If
`latest` is newer, ask with `AskUserQuestion`:

```
header: "Plugin update"
question: "second-opinion <installed> is installed; <latest> is available.
  Update before running the review?"
options:
  - "Update now (Recommended)": update, then restart and re-run
  - "Continue with <installed>": review with the installed version
```

For "Update now", run `claude plugin update "$plugin_id"` and show its
result. The update takes effect only after a restart, so stop here: tell
the user to restart Claude Code and invoke the skill again. Do not
continue the review with the instructions already loaded.

When `AskUserQuestion` is unavailable, report that an update is
available and continue with the installed version.

## Model catalogs

Read each candidate provider's model list now, so the model questions
reflect what the provider offers today rather than what this skill
shipped with. Candidates are every provider the user might choose: the
named provider if one was named, otherwise Codex and Antigravity. A
provider whose CLI is missing is skipped here and reported when chosen.

Use the listing commands from the model-selection reference. Save each
catalog to its own file and reuse it for the model questions; do not
fetch it twice.

A catalog can list a model that the installed CLI is too old to run.
Codex reports this as a model that "requires a newer version of Codex".
Treat it as a recoverable failure: offer `codex update` (or `agy update`
for Antigravity), and ask before running it.
