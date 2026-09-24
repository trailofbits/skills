---
name: semgrep-rule-creator
description: Creates and tests a custom Semgrep rule for a specific bug or security pattern. Use for new rule YAML and positive and negative Semgrep tests, not for running existing rulesets.
allowed-tools: Bash Read Write Edit Glob Grep WebFetch
---

# Semgrep Rule Creator

Create one specific, test-first Semgrep rule. Do not use this to run an existing ruleset or perform
general static analysis.

## Required workflow

1. Identify the target language, vulnerable pattern, safe alternatives, and whether untrusted data
   reaches a sink. Prefer taint mode for source-to-sink problems; use pattern matching for a simple
   syntactic pattern.
2. Make `<rule-id>/` containing exactly `<rule-id>.yaml` and `<rule-id>.<ext>`. Write positive
   `ruleid:` and negative `ok:` cases before the rule. Include safe, sanitized, boundary, nested,
   and unrelated cases where relevant. Never use `todook` or `todoruleid` annotations.
3. Use `semgrep --dump-ast --lang <language> <rule-id>.<ext>` when syntax is uncertain. Write the
   rule with one rule per YAML file; do not use `languages: generic` for a language-specific task.
4. Run both checks from the rule directory after every meaningful change:

   ```bash
   semgrep --validate --config <rule-id>.yaml
   semgrep --test --config <rule-id>.yaml <rule-id>.<ext>
   ```

   Do not finish until every test passes. Only then remove genuinely redundant patterns and rerun
   both commands. Finally run `semgrep --config <rule-id>.yaml <rule-id>.<ext>` and ensure the
   message is concise and has no unbound metavariables.

## Rule design

Read [quick-reference.md](references/quick-reference.md) for pattern, metavariable, annotation,
or command syntax. Read [workflow.md](references/workflow.md) for detailed test design and
debugging. Read [semgrep-docs-digest.md](references/semgrep-docs-digest.md) only for a taint-mode,
constant-propagation, or advanced-rule question that the quick reference does not answer. The digest
links to the official full documentation when the bundled summary is insufficient.

## Rationalizations to Reject

| Shortcut | Required response |
| --- | --- |
| “The pattern looks complete.” | Run `semgrep --test`; hidden false positives and negatives matter. |
| “It matches the vulnerable case.” | Prove safe cases do not match. |
| “Taint mode is overkill.” | Use it when user-controlled data reaches a dangerous sink. |
| “One test is enough.” | Include variations, sanitized inputs, safe alternatives, and boundaries. |
| “I will optimize first.” | Establish correct behavior first, then re-test every simplification. |
| “The AST is too complex.” | Use the AST dump to see the syntax Semgrep actually matches. |
