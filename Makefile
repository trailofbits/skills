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
.PHONY: check self-test lint shell bats shell-suites python-tests js-tests eval-selftest evals validate fix help

## check: most of what CI runs (this is the one you want)
check: self-test lint shell bats python-tests js-tests eval-selftest validate
	@echo ""
	@echo "✓ check passed — most of CI, but not the loadability checks, the"
	@echo "  version-increment check, or the non-ruff pre-commit hooks."

## self-test: prove the validators still detect what they exist to detect
# Runs before validate, deliberately. A checker that has silently stopped matching
# reports a clean repo forever; that failure mode has shipped here more than once.
self-test:
	@echo "→ validator self-test"
	@uv run --no-project python3 .github/scripts/validate_plugin_metadata.py --self-test

## lint: ruff check + format, pinned to the version CI uses
lint:
	@echo "→ ruff check"
	@uvx ruff@$(RUFF_VERSION) check --output-format=concise
	@echo "→ ruff format --check"
	@uvx ruff@$(RUFF_VERSION) format --check

## shell: shellcheck + shfmt over every shell script
# plugins/ AND .github/scripts/ — globbing only plugins/ left the repo's own scripts
# unchecked locally, which is where they are most likely to be edited.
shell:
	@echo "→ shellcheck"
	@find plugins .github/scripts -name '*.sh' -type f \
		-exec shellcheck --severity=warning -x {} +
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
# Deliberately NOT in `check`. zeroize-audit's suite pipes a script to `python3 -`,
# which the modern-python plugin's shim intercepts and rejects, so this target fails
# on any machine with that plugin installed — for reasons that have nothing to do
# with the code under test. CI has no shims and runs it there. See the tracking
# issue: #207.
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
python-tests:
	@echo "→ python tests"
	@dirs=$$(find plugins -type f \( -name 'test_*.py' -o -name '*_test.py' \) \
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
# from — so each suite must also print a `<n> assertions passed` line, and n must be
# greater than zero. A suite that stops running its own body stops emitting that line.
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
		if ! echo "$$out" | grep -qE '^[1-9][0-9]* assertions passed$$'; then \
			echo "  ✗ $$f reported no passing assertions — it ran nothing"; \
			failed=1; \
		fi; \
		ran=$$((ran + 1)); \
	done; \
	echo "  ran $$ran js suite(s)"; \
	exit $$failed

## eval-selftest: prove the eval graders still detect what they exist to detect
# Same reasoning as `self-test` above, applied to the eval suites. No API calls, so it
# belongs in `check`: the paid suite (`make evals`) runs rarely, and a grader whose
# pattern silently stopped matching would report a clean bill of health indefinitely.
#
# Each suite must print an `<n> assertions passed` line with n > 0, as in js-tests — a
# self-test that stops running its own body would otherwise exit 0 having proved
# nothing.
eval-selftest:
	@echo "→ eval grader self-tests"
	@suites=$$(find plugins -type f -path '*/evals/selftest/run-selftest.sh' | sort); \
	if [ -z "$$suites" ]; then \
		echo "  ✗ no eval self-tests found — discovery is broken"; \
		exit 1; \
	fi; \
	failed=0; ran=0; \
	for s in $$suites; do \
		echo "  → $$s"; \
		out=$$(bash "$$s" 2>&1) || failed=1; \
		echo "$$out"; \
		if ! echo "$$out" | grep -qE '^[1-9][0-9]* assertions passed$$'; then \
			echo "  ✗ $$s reported no passing assertions — it ran nothing"; \
			failed=1; \
		fi; \
		ran=$$((ran + 1)); \
	done; \
	echo "  ran $$ran eval self-test(s)"; \
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
# Scans every plugin. CI scopes to the plugins a PR touches, so local is a strict
# superset and cannot pass where CI fails. Do not narrow it to match: the
# zero-reference guard only arms on a full scan.
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
