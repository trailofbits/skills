#!/usr/bin/env bash
# Writes the case's target into the eval's empty working directory.
# The eval runs each case in a fresh scaffold dir, so a repo-relative path
# in the prompt resolves to nothing; the fixture has to be materialised here.
#
# This copy is kept byte-identical to fixtures/case3_handler/handler.go by
# tests/test_eval_suite.py::test_scaffold_fixture_matches_the_checked_in_copy.
set -euo pipefail
cat >handler.go <<'CONCEPT_PROVER_FIXTURE_EOF'
// Command items serves the catalogue item listing over HTTP.
package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// parseRange splits a "lo-hi" range specification into its two bounds.
// Both bounds are required and are read as base-10 integers.
func parseRange(spec string) (int, int) {
	parts := strings.SplitN(spec, "-", 2)
	lo, err := strconv.Atoi(parts[0])
	if err != nil {
		panic(fmt.Sprintf("bad range lower bound: %q", parts[0]))
	}
	hi, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(fmt.Sprintf("bad range upper bound: %q", parts[1]))
	}
	return lo, hi
}

// rangeHandler answers GET /items?range=lo-hi.
func rangeHandler(w http.ResponseWriter, r *http.Request) {
	lo, hi := parseRange(r.URL.Query().Get("range"))
	fmt.Fprintf(w, "range %d..%d\n", lo, hi)
}

func main() {
	http.HandleFunc("/items", rangeHandler)
	_ = http.ListenAndServe(":8080", nil)
}
CONCEPT_PROVER_FIXTURE_EOF

# Committed, for the reason integration-cap's scaffold gives: build-poc runs its
# builder with `isolation: 'worktree'`, and a worktree is cut from HEAD, so an
# uncommitted file is simply absent from the directory the builder works in.
#
# This case reaches Phase 4. tests/README.md used to say the first three cases
# never do — true of should-not-fire and blocked-attack-path, which halt, but
# not of this one: the panic is real, reachable and in scope, so the gate
# returns PROCEED and only the *severity* is corrected downward. Both of its
# graders read last_message, so a Phase 4 that failed for want of a repository
# would not have shown up in the score.
git -c init.defaultBranch=main init -q
git add -A
GIT_AUTHOR_DATE='2026-06-18T09:41:00+00:00' \
  GIT_COMMITTER_DATE='2026-06-18T09:41:00+00:00' \
  git -c user.name='Catalogue Team' -c user.email='catalogue@example.invalid' \
  -c commit.gpgsign=false \
  commit -q -m 'feat(items): serve the catalogue item listing over HTTP'
