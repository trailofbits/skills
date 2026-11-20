# Model and Effort Selection

Model names change faster than this skill ships, and the models an account
can use differ by plan. Read the selected CLI's live catalog, recommend one
model and effort, and let the user override either. A slug written into
this file goes stale; a catalog read at run time does not.

## When to ask

Ask once per selected provider, after the provider is known. Skip any
question the user already answered ("use gpt-6.2-astra at high"), and
validate an explicit choice against the catalog instead of asking.

Ask in one `AskUserQuestion` call: a model question and an effort question
for each provider, which fits the four-question limit for two providers.
Put the recommendation first and label it `(Recommended)`. Offer at most
four options per question; the built-in "Other" answer covers any other
catalog entry the user types.

When `AskUserQuestion` is unavailable, use the recommendations and state
them in the results. When catalog discovery fails, use the default in the
provider reference, say that discovery failed, and still let the user
type a model.

## Codex

The account's catalog is available as JSON:

```bash
codex debug models > "$catalog_file" 2> "$stderr_log"
```

It refreshes from the service, so it reflects the signed-in account. Each
entry in `models` has `slug`, `display_name`, `description`, `visibility`,
`priority`, `default_reasoning_level`, and `supported_reasoning_levels`
(a list of objects with an `effort` field). This command is a debugging
interface; if it fails or the fields are missing, fall back to the
reference default rather than guessing slugs.

- **Model options:** entries with `visibility` of `list`, sorted by
  ascending `priority`. Recommend the first one. Offer the next three, using
  `display_name` and `description` for the option text.
- **Effort options:** the recommended model's `supported_reasoning_levels`.
  Recommend `xhigh` when the model supports it, because a review benefits
  from deeper reasoning more than an interactive turn does; otherwise
  recommend the highest supported level below `max`. Offer `high`,
  `medium`, and the next level above the recommendation. Explain that
  `max` and `ultra`, when listed, cost more and take longer.
- **Compatibility:** if the chosen model does not support the chosen
  effort, use its nearest lower supported level and disclose the change.

Pass the choices as `-c model='"<slug>"'` and
`-c model_reasoning_effort='"<effort>"'`.

## Antigravity

```bash
PATH="$HOME/.local/bin:$PATH" agy models > "$catalog_file" 2> "$stderr_log"
```

Each line is a slug and a display name separated by a tab. The first
line can be a progress message, so keep only lines that contain a tab.
Effort is part of many slugs: `gemini-3.8-flash-low`, `-medium`, and
`-high` are one model at three efforts.

- **Model options:** group slugs by the family left after removing a
  trailing `-low`, `-medium`, or `-high`. Recommend the first Gemini family
  whose name contains `pro`, and otherwise the first listed Gemini family.
  Offer up to three other families, including non-Gemini families the
  account lists.
- **Effort options:** the selected family's suffixes. Recommend `high`.
  A family with fewer than two suffixes, such as a slug ending in
  `-thinking` or a model listed at a single effort, has a fixed effort;
  skip the effort question for it and say so.
- **Invocation:** pass the full suffixed slug, such as
  `--model gemini-3.8-flash-high`. Do not add `--effort` to a suffixed
  slug: `agy` 1.5.13 rejects the combination as conflicting, and rejects
  `--effort` outright for some models.

## Gemini CLI

Gemini CLI has no model-listing command. Use the reference default unless
the user names a model; do not ask an effort question.
