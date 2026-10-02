---
name: semgrep-rule-creator
description: Creates and tests custom Semgrep rules for bugs, security, code quality, coding standards, and code patterns. Use for rule YAML and positive/negative tests, not for running existing rulesets.
allowed-tools: Bash Read Write Edit Glob Grep WebFetch
---

# Semgrep Rule Creator

Create one specific, test-first Semgrep rule. Do not use this to run an existing ruleset or perform
general static analysis; use the `semgrep` skill in the `static-analysis` plugin for that.

## Required workflow

1. Identify the target language, vulnerable pattern, safe alternatives, and whether untrusted data
   reaches a sink. Prefer taint mode for source-to-sink problems; use pattern matching for a simple
   syntactic pattern. Switch approaches if tests expose a poor fit. Check the installed engine's
   capabilities before relying on interprocedural or other edition-specific analysis; report any
   coverage limitation rather than silently replacing required data flow with a weaker pattern.
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

   Require at least one graded positive and one negative case for this rule ID, no missed or
   incorrect lines, and a nonzero passing test count. Exit 0 or "No unit tests found" alone is
   not success. Confirm annotations bind the intended rule and lines; a deliberately nonmatching
   copy of the rule must fail the positive cases. Keep that control outside the deliverable.
   `--validate` may fetch registry lint rules: retain its diagnostics and report validation as
   blocked if networking or authentication prevents it. Do not report a skipped check as passed.
5. After tests pass, remove only genuinely redundant patterns and rerun validation and tests.
6. Run `semgrep --config <rule-id>.yaml <rule-id>.<ext>`. Compare all findings with the annotated
   positive lines and confirm none appear on negative lines. Ensure the message is concise and
   contains no unbound metavariables. Deliver the rule, tests, checks run, and remaining limitations.

## Rule design

Read [quick-reference.md](references/quick-reference.md) for pattern, metavariable, annotation,
or command syntax. Read [workflow.md](references/workflow.md) for detailed test design and
debugging. Read [semgrep-docs-digest.md](references/semgrep-docs-digest.md) only for a taint-mode,
constant-propagation, or advanced-rule question. For propagators, labels/`requires`, side effects,
or `taint_assume_safe_*`, use its capability index and read the linked official section before
choosing those semantics. Do not assume an abbreviated example covers every engine or language.

## Rationalizations to Reject

| Shortcut | Required response |
| --- | --- |
| “The pattern looks complete.” | Run `semgrep --test`; hidden false positives and negatives matter. |
| “It matches the vulnerable case.” | Prove safe cases do not match. |
| “Taint mode is overkill.” | Test source-to-sink behavior; change modes only if required coverage survives. |
| “One test is enough.” | Include variations, sanitized inputs, safe alternatives, and boundaries. |
| “I will optimize first.” | Establish correct behavior first, then re-test every simplification. |
| “The AST is too complex.” | Use the AST dump to see the syntax Semgrep actually matches. |
