# Semgrep Rule Variant Creator

A Claude Code skill for porting existing Semgrep rules to new target languages with proper applicability analysis and test-driven validation.

## Overview

This skill takes an existing Semgrep rule and one or more target languages, then generates independent rule variants for each applicable language. Each variant goes through a complete 4-phase cycle:

1. **Applicability Analysis** - Determine if the vulnerability pattern applies to the target language
2. **Test Creation** - Write test-first with vulnerable and safe cases
3. **Rule Creation** - Translate patterns and adapt for target language idioms
4. **Validation** - Ensure all tests pass before proceeding

## Components

| Component | Purpose |
|---|---|
| `semgrep-rule-variant-creator` skill | Which rule, which languages, whether a `NOT_APPLICABLE` verdict is right, and the by-hand path for a single language |
| `/semgrep-rule-variant-creator:port-rule-to-languages` workflow | Applicability, test-first authoring, AST-guided translation, and the fix-until-green loop — one independent chain per language |

The split follows what needs a person. Which rule to port, which languages to target, and
whether to accept a language being dropped are decisions the skill puts to you, and a
workflow cannot ask questions mid-run — which is exactly why those questions come first.
Everything after that is the same four phases over many languages, so it runs as a
workflow, with the phase order and the retry bound held in code rather than in prose.

## Prerequisites

- [Semgrep](https://semgrep.dev/docs/getting-started/) installed and available in PATH
- Existing Semgrep rule to port (in YAML)
- Target languages specified
- Dynamic workflows enabled (Claude Code 2.1.154+, paid plan). Where they are unavailable
  the slash command does not exist and the skill falls back to running phases by hand

## Usage

Porting is the same four phases repeated per language, so the orchestration ships as a
dynamic workflow:

```
/semgrep-rule-variant-creator:port-rule-to-languages
```

| Field | Default | Purpose |
|---|---|---|
| `rulePath` | required | Path to the Semgrep rule YAML being ported |
| `languages` | required | One target language per entry: `["Go", "Java"]`. A phrase like `"Go and Java"` is rejected rather than ported as a single language named after the phrase |
| `referencesDir` | required | This plugin's `references/` directory, resolved by the skill from `{baseDir}`. A workflow script cannot resolve `{baseDir}` itself, and an installed plugin does not sit in your project, so this is the only route by which the guidance reaches the phase agents. The script rejects a run without it: a port made without the references still reports every language as passed, so a warning would be the one signal that can be ignored for free |
| `outputDir` | working directory | Where the variant directories land |

It reads the rule once, then runs each language through its own applicability, test,
translation, and validation cycle, and reports which languages passed, which failed
validation, which were not applicable, and which Semgrep cannot analyze at all — Perl has no
frontend and Elixir's parser is Pro-only, and in both cases the bug class is present while
the rule is ungradeable. Validation is measured against one specific Semgrep, the version
recorded when the rule was read, because "All tests passed" is also what Semgrep prints for a
rule it skipped and for a test file it never matched. The script pins a reasoning effort per phase and
encodes the phase order, so a rule cannot be written before the tests that specify it. It
also sends a `NOT_APPLICABLE` verdict to an independent refuter before dropping a language,
and retries failed validation up to three times instead of trusting one agent to iterate
until the tests pass.

The skill also triggers on a plain request, for porting a single language by hand:

```
Port the sql-injection.yaml Semgrep rule to Go and Java
```

```
Create Semgrep rule variants of my-rule.yaml for TypeScript, Rust, and C#
```

```
Create the same Semgrep rule for JavaScript and Ruby
```

```
Port this Semgrep rule to Golang
```

## Output Structure

For each applicable target language, the skill produces:

```
<original-rule-id>-<language>/
├── <original-rule-id>-<language>.yaml     # Ported rule
└── <original-rule-id>-<language>.<ext>    # Test file
```

## Example

**Input:**
- Rule: `python-command-injection.yaml`
- Target languages: Go, Java

**Output:**
```
python-command-injection-go/
├── python-command-injection-go.yaml
└── python-command-injection-go.go

python-command-injection-java/
├── python-command-injection-java.yaml
└── python-command-injection-java.java
```

## Key Differences from semgrep-rule-creator

| Aspect | semgrep-rule-creator | semgrep-rule-variant-creator |
|--------|---------------------|------------------------------|
| Input | Bug pattern description | Existing rule + target languages |
| Output | Single rule+test | Multiple rule+test directories |
| Workflow | Single creation cycle | Independent cycle per language |
| Phase 1 | Problem analysis | Applicability analysis |

## Skill Files

- `workflows/port-rule-to-languages.js` - The orchestration, one cycle per language
- `skills/semgrep-rule-variant-creator/SKILL.md` - Main entry point
- `skills/semgrep-rule-variant-creator/references/applicability-analysis.md` - Phase 1 guidance
- `skills/semgrep-rule-variant-creator/references/language-syntax-guide.md` - Pattern translation guidance
- `skills/semgrep-rule-variant-creator/references/workflow.md` - Per-phase mechanics and troubleshooting
- `tests/test_workflow_contract.py` - Properties the workflow runtime requires of any script
- `tests/test_port_rule_workflow.py` - Golden variants graded by `semgrep --test`, and their metadata and annotation contract
- `tests/test_skill_describes_the_workflow.py` - The skill and the script must agree on the command, the args and the references
- `tests/workflow-functions.test.mjs` - Unit tests for the script's deterministic functions
- `tests/workflow-failure-paths.test.mjs` - The real script driven with stubbed runtime globals, one case per failure path
- `tests/fixtures/` - Golden variants graded by `semgrep --test`

## Testing

```sh
make python-tests                                            # everything below
cd plugins/semgrep-rule-variant-creator/tests && \
  uv run --no-project --with pytest python3 -m pytest -q --import-mode=importlib .
node --test plugins/semgrep-rule-variant-creator/tests/*.test.mjs   # the node suites alone
```

`test_node_suites_pass` runs both node suites from pytest, so the first two commands already
cover them; the third is for iterating on them directly. Name the files rather than the
directory — `node --test <dir>` resolves the directory as a module and errors.

Needs `semgrep` and `node` on PATH. Without semgrep the golden-fixture grader skips; without
node the parse check, the schema validation and both node suites skip.

### The mutation battery

Passing tests only prove the code runs. These 24 mutations are the evidence the tests
*detect* anything — each is a parametrized case, so `make check` runs the whole battery and
names any that stops firing.

| Mutation | Caught by |
|---|---|
| Spawn no agents at all | `check_script_has_work_to_inspect` |
| Compute a `meta` field instead of writing a literal | `check_meta_is_a_pure_literal` |
| Read a script constant from inside `meta` | `test_meta_isolation_rejects_a_field_that_reads_the_script` |
| Rename a phase in the body only | `check_phases_match_meta` |
| Drop a schema from an agent call | `check_every_agent_call_has_a_schema` |
| Add an unschema'd agent call above a schema'd one | `check_every_agent_call_has_a_schema` |
| Name a `required` field that is not a property | `test_schema_validation_rejects_a_required_field_that_does_not_exist` |
| Reach for `Math.random()` | `check_no_nondeterministic_builtins` |
| Introduce a syntax error | `test_the_parse_check_rejects_a_syntax_error` |
| Guess the test file extension | `check_no_guessed_test_file_extension` |
| Document a command the plugin does not define | `check_documented_command_matches_the_script` |
| Rename the workflow without updating the docs | `check_documented_command_matches_the_script` |
| Drop an argument name from the skill | `check_every_arg_the_script_reads_is_documented` |
| Rename an argument without updating the docs | `check_every_arg_the_script_reads_is_documented` |
| Drop the `referencesDir` instruction | `check_the_skill_hands_over_its_references` |
| Link a `{baseDir}` reference that does not exist | `check_basedir_paths_resolve` |
| Rename a reference in the skill but not the script | `check_references_the_script_uses_are_linked` |
| Rewrite the description into something vague | `test_description_check_rejects_a_vague_description` |
| Cap the validation retry at one round | 2 of 16 failure-path cases |
| Trust the agent's self-reported pass | 6 of 16 failure-path cases |
| Guess the extension (failure-path view) | 1 of 16 failure-path cases |
| Pass a relative reference path | 1 of 16 failure-path cases |
| Unpin an effort level | 1 of 16 failure-path cases |
| Let a run proceed without the references | 1 of 16 failure-path cases |

The last six run the real script against a mutated copy, so the gate additionally requires
that some cases still pass and that nothing raised a `SyntaxError` — a mutation that merely
stops the script compiling fails everything and would otherwise look like proof.

Stage order, the `NOT_APPLICABLE` short-circuit, the refuter, the variant directory shape, and
batching languages behind a barrier are asserted directly by `workflow-failure-paths.test.mjs`,
which executes the script and checks what it spawned and returned, so they are covered without
a mutation row of their own — swapping `pipeline()` for `parallel()` fails 10 of its 16 cases.

## Related Skills

- **semgrep-rule-creator** - Create new Semgrep rules from scratch
- **static-analysis** - Run existing Semgrep rules against code
