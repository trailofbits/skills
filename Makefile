# Every target here mirrors a CI job. If `make check` passes and CI does not, that is a
# bug in this file — fix it here rather than working around it, or the local signal stops
# being trustworthy and everyone goes back to pushing and waiting.
#
# CI jobs covered: Lint (pre-commit: ruff, shellcheck, shfmt), Shell (bats),
# Python tests, and Validate plugins and skills.
#
# RUFF_VERSION must match the ruff-pre-commit rev in .pre-commit-config.yaml. The
# validator self-test asserts that; bump both together.
RUFF_VERSION := 0.14.13

.DEFAULT_GOAL := check
.NOTPARALLEL:
.PHONY: check self-test eval-self-tests lint shell bats shell-suites python-tests \
	js-tests evals validate fix help

## check: most of what CI runs (this is the one you want)
check: self-test eval-self-tests lint shell bats python-tests js-tests validate
	@echo ""
	@echo "✓ check passed — most of CI, but not the loadability checks, the"
	@echo "  version-increment check, or the non-ruff pre-commit hooks."

## self-test: prove the validators still detect what they exist to detect
# Runs before validate, deliberately. A checker that has silently stopped matching
# reports a clean repo forever; that failure mode has shipped here more than once.
self-test:
	@echo "→ validator self-test"
	@uv run --no-project python3 .github/scripts/validate_plugin_metadata.py --self-test

## eval-self-tests: prove each plugin's eval harness still measures what it claims
# Same reasoning as the target above, applied to evals rather than validators. An
# eval that has stopped discriminating reports a passing skill forever.
#
# Discovered rather than listed, so a new plugin's evals are covered the day they
# land. Only scripts advertising --self-test are invoked: running a trigger eval for
# real costs dozens of Claude sessions, so this must never shell out to one blindly.
# Zero found is a failure — these guards are why an eval result can be trusted.
#
# The glob is 'evals*', not 'evals', so it also covers 'evals-extra' — harnesses whose
# real sweeps are too slow or too expensive to belong in any automated run and are
# invoked by hand. Their --self-test is still free and still the thing that proves the
# harness discriminates, so it stays in `check` even though the sweep never runs here.
#
# Run under `uv run`, which puts a real interpreter ahead of the modern-python
# plugin's `python3` shim (#207). Discovery is repo-wide, so a bare `python3` in any
# one plugin's harness would fail the whole build. Harnesses should still call uv
# themselves — that is what makes them runnable by hand, which is how sweeps are run.
eval-self-tests:
	@echo "→ eval self-tests"
	@scripts=$$(find plugins -type f -path '*/evals*/*.sh' \
		-exec grep -l -- '--self-test' {} \; | sort); \
	if [ -z "$$scripts" ]; then \
		echo "  ✗ no eval self-tests found — discovery is broken"; \
		exit 1; \
	fi; \
	for s in $$scripts; do \
		echo "  → $$s"; \
		uv run --no-project bash "$$s" --self-test >/dev/null \
			|| { echo "  ✗ $$s failed"; exit 1; }; \
	done; \
	echo "  ran $$(printf '%s\n' $$scripts | wc -l | tr -d ' ') eval self-test(s)"

## lint: ruff check + format, pinned to the version CI uses
lint:
	@echo "→ ruff check"
	@uvx ruff@$(RUFF_VERSION) check --output-format=concise
	@echo "→ ruff format --check"
	@uvx ruff@$(RUFF_VERSION) format --check

## shell: shellcheck + shfmt over every shell script
# plugins/ AND .github/scripts/ — globbing only plugins/ left the repo's own scripts
# unchecked locally, which is where they are most likely to be edited.
#
# No --severity filter, deliberately. The pre-commit hook CI runs is plain
# `shellcheck -x`, so a --severity=warning here hides every info-level finding that
# will still fail the Lint job — SC1091 (unresolvable `source`) most of all, which is
# exactly the class a local run should catch. That gap shipped a red build once.
shell:
	@echo "→ shellcheck"
	@find plugins .github/scripts -name '*.sh' -type f \
		-exec shellcheck -x {} +
	@echo "→ shfmt"
	@find plugins .github/scripts -name '*.sh' -type f -exec shfmt -i 2 -ci -d {} +

## bats: run plugin bats suites
# Fails when the glob matches nothing: this repo has bats suites, so finding none means
# the discovery broke, not that the shell code is clean.
bats:
	@echo "→ bats"
	@files=$$(find plugins -name '*.bats' -type f); \
	if [ -z "$$files" ]; then \
		echo "  ✗ no .bats files found — discovery is broken (this repo ships bats suites)"; \
		exit 1; \
	fi; \
	echo "$$files" | xargs bats

## shell-suites: run plugin shell regression suites (CI only, see note)
# Deliberately NOT in `check` because it is slow, not because it is broken: it passes
# with modern-python >= 1.6.0 installed. A machine still on the 1.5.3 shim will fail
# it, since that version refuses the `python3 -` zeroize-audit's suite uses (#207).
#
# find, not a glob: `**` needs globstar and degrades to `*` without it, so a suite
# one directory deeper would stop running with no signal.
shell-suites:
	@echo "→ shell regression suites"
	@suites=$$(find plugins -type f -path '*/tests/*' -name 'run_*.sh'); \
	if [ -z "$$suites" ]; then \
		echo "  ✗ no shell regression suites found — discovery is broken"; \
		exit 1; \
	fi; \
	for s in $$suites; do echo "  → $$s"; bash "$$s" || exit 1; done

## python-tests: run plugin Python test files
# pytest, not `python3 <file>` in a loop: a file with no `if __name__ == "__main__"`
# block exits 0 under the loop having run nothing, which reads as a pass.
# --import-mode=importlib is required — c-review and rust-review both ship
# scripts/test_split.py, and the default import mode collides on the basename.
# evals*/fixture is excluded: those files are deliberately defective sample code
# that a skill's eval measures against, so they are meant to fail — property-based-
# testing's fixture ships a vacuous `assume()` test that raises FailedHealthCheck by
# design. The glob covers 'evals-extra' as well, and it has to: drop the wildcard and
# pytest collects that fixture and fails the build. The zero-discovery guard below
# stays armed, so this cannot silently empty the run.
python-tests:
	@echo "→ python tests"
	@dirs=$$(find plugins -type f \( -name 'test_*.py' -o -name '*_test.py' \) \
		-not -path '*/evals*/fixture/*' \
		-exec dirname {} \; | sort -u); \
	if [ -z "$$dirs" ]; then \
		echo "  ✗ no Python test files found — discovery is broken"; \
		exit 1; \
	fi; \
	failed=0; ran=0; \
	for d in $$dirs; do \
		echo "  → $$d"; \
		( cd "$$d" && uv run --no-project --with pytest python3 -m pytest -q \
			--import-mode=importlib . ) || failed=1; \
		ran=$$((ran + 1)); \
	done; \
	echo "  ran $$ran test director(ies)"; \
	exit $$failed

## js-tests: node suites a plugin ships as *.test.mjs
# Two guards, because discovery and execution fail independently. An empty glob is a
# failure, as in python-tests. And `node <file>` runs a file that asserts nothing just
# as happily as one that asserts everything — the same shape python-tests moved away
# from — so each suite must also report at least one passing assertion.
#
# Two report formats count, because the repo has two kinds of suite and a guard that
# only knew one would fail an honest suite for using the other convention:
#   `<mark> pass <n>`        — node:test, as semgrep-rule-variant-creator writes them
#   `<n> assertions passed`  — a hand-rolled suite, as git-cleanup writes them
# A suite that stops running its own body stops emitting either line.
#
# The node:test branch is deliberately byte-agnostic about the leading mark. That mark
# is a multi-byte character, and this recipe runs under /bin/sh in whatever locale the
# machine has; `^.` matches one BYTE in the C locale, so anchoring on it passes locally
# and fails in CI.
js-tests:
	@echo "→ js tests"
	@files=$$(find plugins -type f -name '*.test.mjs' | sort); \
	if [ -z "$$files" ]; then \
		echo "  ✗ no .test.mjs files found — discovery is broken"; \
		exit 1; \
	fi; \
	failed=0; ran=0; \
	for f in $$files; do \
		echo "  → $$f"; \
		out=$$(node "$$f" 2>&1) || failed=1; \
		echo "$$out"; \
		if ! echo "$$out" | grep -qE '(^[1-9][0-9]* assertions passed$$|^[^0-9]*[[:space:]]pass [1-9][0-9]*$$)'; then \
			echo "  ✗ $$f reported no passing assertions — it ran nothing"; \
			failed=1; \
		fi; \
		ran=$$((ran + 1)); \
	done; \
	echo "  ran $$ran js suite(s)"; \
	exit $$failed

## evals: run a plugin's eval suite against the real model (COSTS API CALLS)
# Deliberately NOT in `check` and not in CI. Pass PLUGIN=<name> to pick the suite, and
# ARGS='--case 01-mixed-repo --arm with' to narrow a run while iterating.
PLUGIN ?= git-cleanup
ARGS ?=
evals:
	@if [ ! -x plugins/$(PLUGIN)/evals/run-evals.sh ]; then \
		echo "✗ plugins/$(PLUGIN)/evals/run-evals.sh not found or not executable"; \
		exit 1; \
	fi
	@echo "→ evals: $(PLUGIN) (this makes real API calls)"
	@bash plugins/$(PLUGIN)/evals/run-evals.sh $(ARGS)

## validate: plugin metadata, structure, and cross-references
# Scans every plugin, exactly as CI does — the validator is never scoped down there;
# `--base-ref` only turns on the version-increment check, which is the one part limited
# to the plugins a branch touched. Do not add a scoping flag here: the zero-reference
# guard only arms on a full scan, so a narrowed run would disarm it.
validate:
	@echo "→ validate plugin metadata"
	@uv run --no-project python3 .github/scripts/validate_plugin_metadata.py

## fix: apply the formatting CI would otherwise reject
fix:
	@uvx ruff@$(RUFF_VERSION) check --fix || true
	@uvx ruff@$(RUFF_VERSION) format
	@find plugins -name '*.sh' -type f -exec shfmt -i 2 -ci -w {} +

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
