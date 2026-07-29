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
.PHONY: check self-test lint shell bats shell-suites python-tests validate fix help

## check: most of what CI runs (this is the one you want)
check: self-test lint shell bats python-tests validate
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
