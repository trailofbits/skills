#!/usr/bin/env python3
"""Gate the eval's own JSON output. Deterministic; no model.

`claude plugin eval ... --json out.json` reports scores. This rejects a result
that only looks green:

  - partial != false        the run did not complete
  - casesTotal < 1          a checker that inspected nothing must not pass
  - passed != total         some case failed
  - score != 1              a case scraped through below full marks
  - ablation delta <= 0     the plugin did not beat the no-plugin baseline,
                            so it is not doing anything

Usage:
    validate_eval_result.py RESULT.json
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

# Three suites, and a result JSON belongs to exactly one of them. `--tag static`
# is the seven-case mean quoted against concept-prover; `--tag online` is Stage 2,
# whose ground truth is public record; `--tag batch` is the multi-finding case,
# whose answer is a statement about a PAIR of findings. None of the three is ever
# averaged with another — the static fixtures carry no public evidence for Stage 2
# to read, Stage 2's own rule is to stop when offline, and no static case has a
# second finding for the batch case's question to be asked of.
#
# Split rather than unioned so that a run of ONE suite still has a complete-set
# check. A single union would have made every `--tag static` result look like it
# had skipped the online case, and the obvious fix for that — dropping the
# completeness check — is what let this list go stale the first time.
CASE_SUITES = {
    "static": {
        "already-fixed",
        "blocked-attack-path",
        "dead-route",
        "inflated-impact",
        "integration-cap",
        "should-not-fire",
        "wrong-parameter",
    },
    "online": {
        "online-known-duplicate",
    },
    "batch": {
        "chained-findings",
    },
}

EXPECTED_CASES = {name for cases in CASE_SUITES.values() for name in cases}

MIN_RUNS = 3


def _get(d: dict, *names, default=None):
    """Read the first present key. The result schema is early access and moves."""
    for name in names:
        if name in d:
            return d[name]
    return default


# Plugins the baseline arm may carry. Empty: the no-plugin arm must have NONE, and
# the whole ablation rests on that.
#
# c-review's bench hit the opposite: its host cells ran with 20 plugins and 48
# skills reaching every arm, including c-review's own skill leaking into the arm
# that was supposed to be without it, which voided a real run. They built a Docker
# container to fix it. `claude plugin eval` turns out to scope plugins already —
# verified on sweep251, `plugins: []` in the baseline and exactly one in the other
# — so the container is unnecessary here and this assertion is what it was worth.
def _init_records(result):
    """Every session-init record, from the trace files --keep-temp preserved.

    Yields (case, arm, plugin_names, skill_names) once per init record, NOT once
    per run. A trace carries one init per session, and a run that dispatches
    subagents has several — fixtures/run.stream.jsonl has two. This used to
    `break` after the first, so the subagent sessions went uninspected, and those
    are half of what c-review measured the leak in.

    Silently skips a run whose trace is gone: without --keep-temp the temp dir is
    deleted, and that is a legitimate state rather than a failure.
    """
    for case in _get(result, "cases", default=[]) or []:
        name = _get(case, "name", "case", default="?")
        arms = _get(case, "arms", default={}) or {}
        for arm, runs in arms.items() if isinstance(arms, dict) else []:
            for run in runs or []:
                trace = _get(run, "tracePath")
                if not trace or not Path(trace).is_file():
                    continue
                try:
                    with open(trace, encoding="utf-8") as fh:
                        for line in fh:
                            # Substring pre-filter before the parse. Now that every
                            # line is read rather than stopping at the first init,
                            # json.loads on each one of a multi-MB transcript is the
                            # whole cost of this check; the init record is a handful
                            # of lines in it.
                            if '"init"' not in line:
                                continue
                            try:
                                event = json.loads(line)
                            except (ValueError, TypeError):
                                continue
                            if event.get("subtype") != "init":
                                continue
                            plugins = event.get("plugins") or []
                            skills = event.get("skills") or []
                            names = [
                                p.get("name", "?") if isinstance(p, dict) else str(p)
                                for p in plugins
                            ]
                            skill_names = [
                                s.get("name", "?") if isinstance(s, dict) else str(s)
                                for s in skills
                            ]
                            yield (name, arm, names, skill_names)
                except OSError:
                    continue


# A skill is the unit the leak actually travels in, and `plugins` does not track it.
# In a real init record (fixtures/run.stream.jsonl) every plugin-provided skill is
# namespaced `<plugin>:<skill>` and every built-in is a bare name — checked there:
# 23 namespaced skills, every namespace present in `plugins`, 15 bare. So the
# namespace is the evidence, and it can appear with no matching entry in `plugins`:
# a skill in ~/.claude/skills, or one from a plugin installed globally rather than
# by the eval, reaches the session without the plugin being listed. That is exactly
# the shape of c-review's leak, and the plugins-only check could not see it.
def _foreign_skills(plugins, skills):
    """Skills whose owning plugin is not one this arm loaded."""
    loaded = set(plugins)
    return sorted(
        skill for skill in skills if ":" in skill and skill.split(":", 1)[0] not in loaded
    )


BASELINE_ARM_NAMES = ("without", "baseline", "none")

# The two arm classes, counted separately because "verified" has to mean BOTH were
# read. See check_ablation_isolation's return value.
ARM_CLASSES = ("baseline", "plugin")


def check_ablation_isolation(result, problems):
    """The baseline arm must load no plugins, and the plugin arm exactly one.

    Neither arm may carry a skill from a plugin it did not load, which is the
    check's whole motivation: c-review's void was its own SKILL reaching the arm
    meant to be without it.

    A contaminated baseline makes the delta a measure of what else was installed
    on the machine that day. Checked from the traces rather than assumed, and
    reported as UNVERIFIED rather than passed when no trace survives — the two are
    not the same, and this file exists because they kept being conflated.

    Returns a Counter over ARM_CLASSES, NOT one scalar total. A single total let
    the conflation back in through the side door: any surviving trace read as
    verified, so a run whose `with` arm kept a trace while the baseline temp dirs
    were reaped printed `isolation verified on 1 session(s)` for an ablation whose
    no-plugin arm — the only arm this check exists to police — was never opened.
    """
    checked = Counter()
    for case, arm, plugins, skills in _init_records(result):
        baseline = arm in BASELINE_ARM_NAMES
        checked["baseline" if baseline else "plugin"] += 1
        if baseline:
            if plugins:
                problems.append(
                    f"{case}/{arm}: the no-plugin arm loaded {sorted(plugins)}. The delta is "
                    f"then a measure of what else was installed, not of this plugin"
                )
        elif len(plugins) != 1:
            problems.append(
                f"{case}/{arm}: the plugin arm loaded {sorted(plugins) or 'nothing'}; exactly "
                f"one is expected, and anything else means the arms differ by more than the "
                f"plugin under test"
            )
        foreign = _foreign_skills(plugins, skills)
        if foreign:
            problems.append(
                f"{case}/{arm}: loaded skill(s) {', '.join(foreign)} belonging to no plugin this "
                f"arm loaded. A skill reaches a session from ~/.claude/skills or a globally "
                f"installed plugin without appearing in `plugins`, so the arms differ by more "
                f"than the plugin under test"
            )
    return checked


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_eval_result.py RESULT.json", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    try:
        result = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"error: cannot read eval result {path}: {error}", file=sys.stderr)
        return 1

    problems: list[str] = []

    if _get(result, "partial") is not False:
        problems.append("result is partial; the run did not complete")

    agg = _get(result, "aggregates", "aggregate", default={}) or {}
    total = _get(agg, "casesTotal", "totalCases")
    passed = _get(agg, "casesPassed", "passedCases")
    score = _get(agg, "overallScore", "score")

    if not isinstance(total, int) or total < 1:
        problems.append(f"casesTotal is {total!r}; refusing to report success on zero cases")
    elif passed != total:
        problems.append(f"{passed}/{total} cases passed")

    # Absence is "unknown", not "fine". `score is not None and score != 1` made a
    # renamed key read as full marks: rename `overallScore` to `meanScore` in a
    # passing result, set it to 0.6, and the gate printed `OK: 5/5 cases passed`
    # and exited 0. Every sibling reader above already records a problem when its
    # key is missing, and the ablation-delta read below says the schema has moved
    # before — which is exactly the trigger.
    if score is None:
        problems.append(
            "no overall score under any known key (overallScore, score); "
            "the result schema is early access, and a rename must not read as full marks"
        )
    elif score != 1:
        problems.append(f"overallScore is {score!r}, not 1")

    cases = _get(result, "cases", default=[]) or []
    # `or ""`, not just the default: `_get` returns the VALUE of the first present
    # key, so an explicit `"name": null` yields None rather than falling back. A
    # set mixing None and str then raises TypeError inside `sorted()` two lines
    # down — a traceback instead of the clean "no known case ran" message this
    # file exists to print. An unnamed case is an empty name, which `{""}` below
    # already discounts.
    seen = {str(_get(c, "name", "case", default="") or "") for c in cases}

    # Which suite this result is, decided by what it contains rather than by a
    # flag the caller could get wrong.
    present = {name: cases_ for name, cases_ in CASE_SUITES.items() if seen & cases_}
    if len(present) > 1:
        problems.append(
            f"this result mixes the {' and '.join(sorted(present))} suites, whose means are "
            f"not comparable and must never be averaged. Re-run with a single --tag"
        )
    elif not present:
        problems.append(
            f"no known case ran: saw {sorted(seen) or 'nothing'}. Every case name is "
            f"unrecognised, so this result cannot be checked for completeness at all"
        )
    else:
        suite, expected = next(iter(present.items()))
        missing = expected - seen
        if missing:
            problems.append(f"the {suite} suite did not run: {', '.join(sorted(missing))}")
    unknown = seen - EXPECTED_CASES - {""}
    if unknown:
        problems.append(
            f"unrecognised case(s) {', '.join(sorted(unknown))}; add them to CASE_SUITES or "
            f"this result is being checked against the wrong expectations"
        )

    # A run that errored produced no answer, but its graders still scored it —
    # as zero. So a dead arm looks like a arm that answered badly, and the
    # ablation delta silently becomes a measure of which arm survived.
    #
    # This is not hypothetical. On 2026-08-04 a sweep lost 22 of 30 runs to
    # `exit 1: (no stderr)` at turn 1 for $0.00 each, most likely a usage limit
    # reached mid-sweep. `partial` was still **false**, every case still
    # reported runsPerCase 3, and blocked-attack-path showed a +0.47 delta
    # purely because all three no-plugin runs were dead while two with-plugin
    # runs had completed before the wall. Nothing above this block noticed:
    # `partial` was false, the case count was 5, and the run counts were 3.
    errored = []
    for case in cases:
        name = _get(case, "name", "case", default="<unnamed>")
        arms = _get(case, "arms", default={}) or {}
        for arm_name, runs in arms.items() if isinstance(arms, dict) else []:
            for i, run in enumerate(runs or [], start=1):
                if isinstance(run, dict) and run.get("error"):
                    errored.append(f"{name}/{arm_name}/run{i}: {str(run['error'])[:60]}")
    if errored:
        problems.append(
            f"{len(errored)} run(s) errored, so their graders scored an absent answer as 0 "
            f"and any delta reflects which arm survived: {'; '.join(errored[:6])}"
            + (f" (+{len(errored) - 6} more)" if len(errored) > 6 else "")
        )

    for case in cases:
        name = _get(case, "name", "case", default="<unnamed>")
        # `runsPerCase` is what the CLI actually emits — see the checked-in
        # fixtures/eval-result-2026-07-30.json. This read the two spellings it
        # does NOT emit, so `runs` was None for every case, `isinstance(None,
        # int)` was False, and the loop checked nothing: a 1-run eval passed the
        # validator that exists to require three.
        runs = _get(case, "runsPerCase", "runs", "runCount")
        if isinstance(runs, list):
            runs = len(runs)
        if not isinstance(runs, int):
            problems.append(
                f"case {name} reports no run count under any known key; "
                f"cannot confirm it ran the {MIN_RUNS} times a pass rate needs"
            )
        elif runs < MIN_RUNS:
            problems.append(f"case {name} ran {runs} time(s); {MIN_RUNS} is the minimum")

    # The ablation delta is the number that says the plugin does anything at all.
    # The CLI reports it as aggregates.meanDelta; the other spellings are kept as
    # fallbacks because the result schema is early access and has moved before.
    delta = _get(agg, "meanDelta", "ablationDelta", "delta")
    if delta is None:
        delta = _get(result, "ablationDelta", "delta")
    if delta is None:
        ablation = _get(result, "ablation", default={}) or {}
        delta = _get(ablation, "delta", "scoreDelta")
    if delta is None:
        problems.append(
            "no ablation delta in the result. Pass --ablation with-without explicitly: "
            "for a PATH target it silently defaults to none and you get no baseline."
        )
    elif delta <= 0:
        problems.append(
            f"ablation delta is {delta}; the plugin did not beat the no-plugin baseline"
        )

    isolation_checked = check_ablation_isolation(result, problems)

    if problems:
        print(f"FAIL: {path}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"OK: {passed}/{total} cases passed, ablation delta {delta}")
    # Both arms, or nothing: an arm with no surviving trace was not inspected, and
    # the baseline is the one the whole check is for. Traces are reaped per temp
    # dir, so half a sweep surviving is an ordinary state rather than a contrived
    # one, and `if isolation_checked:` certified it.
    unread = [arm for arm in ARM_CLASSES if not isolation_checked[arm]]
    if not unread:
        # "session(s)", not "run(s)": a run that dispatches subagents contributes
        # one init record per session and all of them are inspected, so the count
        # is of sessions and saying "runs" would overstate nothing but mislabel it.
        print(
            f"    ablation isolation verified on {sum(isolation_checked.values())} "
            f"session(s) from their traces"
        )
    else:
        print(
            f"    ablation isolation NOT verified: no trace survives for the "
            f"{' and '.join(unread)} arm(s), so a contaminated baseline would not have "
            f"been detected. Re-run with --keep-temp to check it."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
