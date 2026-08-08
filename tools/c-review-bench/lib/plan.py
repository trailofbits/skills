"""Plan a run: which arms on which corpora, what it should cost, and one packet each.

Three tiers, and the difference between them is money:

| Tier | Corpora | Arms | What it is for |
|---|---|---|---|
| `smoke` | small | c-review | proves the pipeline and the grader work end to end |
| `standard` | small + medium | all four | the regression gate |
| `full` | + large + patched control | all four, plus control cells | the full picture, opt-in |

The estimate is a **model, not a measurement**, and it says so wherever it prints.
It is anchored on the real 2026-08-06 zstream (9.26 KLOC) cells in
tools/c-review-bench/README.md — roughly 610 K tokens for one bare agent, 332 K per
agent across a 13-agent fan-out, 214 K per agent across c-review's ~25 — and scaled by
corpus size with a floor, because an agent pays for its own prompt before it reads a
single line. The previous anchor (one 2026-08-04 cell on an unrelated 13 KLOC corpus)
measured **5.4x low** against these actuals, and real cost still varies 1.2-1.7x cell to
cell at fixed arm and corpus, so this is a correction, not a promise that the model is
now exact. Actual cost comes back from `collect`, and `score` prints estimate and
actual side by side so the model can be corrected rather than believed.

`plan` refuses a corpus that has no verification stamp. That is the ordering the
harness enforces: no arm runs against a corpus whose bugs have not been shown to
compile, to be reachable, and to be de-identified.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

TIERS: dict[str, dict[str, Any]] = {
    "smoke": {
        "corpus_tiers": ["small"],
        "arms": ["c-review", "bare"],
        "control_arms": [],
        # Two arms, because the two cheap questions are different: `--arm bare` alone
        # is the sub-100K check that the pipeline and the grader work end to end, and
        # `c-review` is the only cell that exercises the artifact actually under test.
        # c-review cannot be run under 100K tokens — it spawns roughly twenty agents —
        # so the budget and the subject are separated rather than pretended to be one.
        "why": "the cheap end-to-end check: `--arm bare` is minutes and well under 100K "
        "tokens; the c-review cell costs what c-review costs",
    },
    "standard": {
        "corpus_tiers": ["small", "medium"],
        "arms": ["c-review", "bare", "fanout", "taxonomy"],
        "control_arms": [],
        "why": "the regression gate: every arm on the two cheaper corpora",
    },
    "full": {
        "corpus_tiers": ["small", "medium", "large"],
        "arms": ["c-review", "bare", "fanout", "taxonomy"],
        "control_arms": ["c-review", "bare"],
        "why": "adds the large corpus and the patched control; expensive on purpose",
    },
}

# Anchored on the 2026-08-06 zstream (9.26 KLOC) cells in tools/c-review-bench/README.md —
# the mean of the measured cells per arm (2 for bare/taxonomy/fanout, the 4 post-judge-removal
# cells for c-review; the two 37-38-agent pre-removal cells are excluded as a superseded
# architecture, matching the runbook's own exclusion). The previous anchor was one 2026-08-04
# cell on an unrelated 13 KLOC corpus (libexpat) and measured **5.4x low** against these
# actuals — a `standard`-tier plan printed low-single-digit millions for a run that actually
# cost 45-50M. Real cost still varies ~1.2-1.7x cell to cell at fixed arm and corpus (bare
# zstream alone: 472,786 and 747,633 across two runs), so this remains a model to be corrected
# again, not a number to trust to the token.
ARM_MODEL: dict[str, dict[str, Any]] = {
    "c-review": {
        "agents": 25,
        "per_agent": 214_000,
        "note": "1 detect + 4-14 reviewers + 2 sweep + 0-1 dedup + persist; no judge",
    },
    "bare": {"agents": 1, "per_agent": 610_000, "note": "one agent, one prompt"},
    "fanout": {
        "agents": None,
        "per_agent": 332_500,
        "note": "N generic agents partitioned by region",
    },
    "taxonomy": {
        "agents": 1,
        "per_agent": 890_000,
        "note": "one agent holding the whole class catalogue",
    },
}
REFERENCE_KLOC = 9.26  # zstream, the corpus the anchor cells above were measured on
FLOOR_SHARE = 0.4  # of a reference agent's cost is prompt and orientation, not reading


class PlanError(Exception):
    """The run cannot be planned. Callers exit non-zero."""


def extract_taxonomy(workflow_js: Path) -> list[dict[str, str]]:
    """Pull c-review's bug-class catalogue out of the workflow, for the taxonomy arm.

    Read from the shipped workflow rather than copied into this directory, so the
    arm is handed what the plugin actually uses. Zero classes extracted is a hard
    error: the taxonomy arm's whole point is holding the catalogue, and an empty
    catalogue would silently turn it into a second bare arm.
    """
    if not workflow_js.is_file():
        raise PlanError(f"cannot read the taxonomy: {workflow_js} does not exist")
    text = workflow_js.read_text(encoding="utf-8")
    block = re.search(r"const CLASSES = \{(.*?)\n\}\n", text, re.S)
    if not block:
        raise PlanError(
            f"{workflow_js}: could not find `const CLASSES = {{`; the workflow changed shape"
        )
    entries = re.findall(
        r"'([a-z0-9-]+)':\s*\{\s*prefix:\s*'[^']*',\s*title:\s*'([^']*)',\s*brief:\s*\n?\s*'((?:[^'\\]|\\.)*)'",
        block.group(1),
    )
    classes = [
        {"id": name, "title": title, "brief": brief.replace("\\'", "'").replace("\\\\", "\\")}
        for name, title, brief in entries
    ]
    if not classes:
        raise PlanError(
            f"{workflow_js}: extracted zero bug classes. The taxonomy arm must not run on an "
            f"empty catalogue — that would measure a bare prompt and label it a taxonomy."
        )
    return classes


def partition(tree: Path, n: int) -> list[list[tuple[str, int, int]]]:
    """Split the corpus into n regions of comparable size, deterministically.

    Regions are contiguous line ranges, so a large file is divided rather than
    handed whole to one agent. This is what makes the fan-out arm a *strong*
    baseline: n agents each reading a different part of the code, not n copies of
    the same prompt.
    """
    if n < 1:
        raise PlanError("a fan-out of fewer than one region is not a fan-out")
    files = [
        (
            str(p.relative_to(tree)),
            len(p.read_text(encoding="utf-8", errors="replace").splitlines()),
        )
        for p in sorted(tree.rglob("*"))
        if p.is_file() and p.suffix in {".c", ".h"}
    ]
    if not files:
        raise PlanError(f"no C sources under {tree}; there is nothing to partition")
    total = sum(lines for _, lines in files)
    if total == 0:
        raise PlanError(f"the sources under {tree} hold zero lines")
    target = max(1, total // n)

    groups: list[list[tuple[str, int, int]]] = []
    current: list[tuple[str, int, int]] = []
    used = 0
    for path, lines in files:
        start = 1
        while start <= lines:
            room = target - used if len(groups) < n - 1 else lines
            take = min(lines - start + 1, max(1, room))
            current.append((path, start, start + take - 1))
            used += take
            start += take
            if used >= target and len(groups) < n - 1:
                groups.append(current)
                current = []
                used = 0
    if current:
        groups.append(current)
    while len(groups) < n and any(len(g) > 1 for g in groups):
        biggest = max(range(len(groups)), key=lambda i: len(groups[i]))
        groups.append([groups[biggest].pop()])
    return groups


def estimate_tokens(arm: str, kloc: float, fanout_n: int | None) -> tuple[int, int]:
    model = ARM_MODEL.get(arm)
    if model is None:
        raise PlanError(f"no cost model for arm {arm!r}")
    agents = model["agents"] or fanout_n
    if not agents:
        raise PlanError(f"arm {arm!r} needs an agent count; pass --fanout-n")
    scale = FLOOR_SHARE + (1 - FLOOR_SHARE) * (kloc / REFERENCE_KLOC)
    return agents, int(agents * model["per_agent"] * scale)


_THREAT_MODEL_ENUM = {
    "REMOTE": "REMOTE",
    "LOCAL_UNPRIVILEGED": "LOCAL_UNPRIVILEGED",
    "BOTH": "BOTH",
}


def threat_model_enum(prose: str) -> str:
    """c-review's `threatModel` argument, which is an enum, not prose.

    A recipe's `threat_model` is written for a human reviewer's prompt — `sigil`'s is
    "REMOTE and LOCAL_UNPRIVILEGED". The baselines take that verbatim, but c-review
    validates the same string against ['REMOTE', 'LOCAL_UNPRIVILEGED', 'BOTH'] and
    throws, so the c-review cell on `sigil` died at argument validation before spawning
    a single agent while every baseline ran.

    Unmappable values raise. Defaulting to REMOTE would hand c-review a narrower threat
    model than the baselines got and bias the comparison in a direction nothing prints.
    """
    key = prose.strip().upper()
    if key in _THREAT_MODEL_ENUM:
        return _THREAT_MODEL_ENUM[key]
    remote = "REMOTE" in key
    local = "LOCAL_UNPRIVILEGED" in key or "LOCAL UNPRIVILEGED" in key
    if remote and local:
        return "BOTH"
    if remote:
        return "REMOTE"
    if local:
        return "LOCAL_UNPRIVILEGED"
    raise PlanError(
        f"threat_model {prose!r} does not map onto c-review's threatModel enum "
        f"(REMOTE, LOCAL_UNPRIVILEGED, BOTH). Guessing would give the arm under test a "
        f"different threat model from every baseline; fix the recipe instead."
    )


def _render(template: str, values: dict[str, str]) -> str:
    out = template
    for key, value in values.items():
        out = out.replace("{{" + key + "}}", value)
    leftover = re.findall(r"\{\{([A-Z_]+)\}\}", out)
    if leftover:
        raise PlanError(f"packet template has unfilled placeholder(s): {sorted(set(leftover))}")
    return out


def plugin_root() -> Path:
    """The c-review plugin, resolved explicitly.

    The harness deliberately lives OUTSIDE the plugin: `pluginRoot` is handed to
    c-review's own agents, so a benchmark under it would give the arm under test the
    parent directory of its own answer key while no baseline had it. Do not move the
    harness back in, and do not derive this from __file__'s ancestry.
    """
    here = Path(__file__).resolve()
    for base in here.parents:
        cand = base / "plugins" / "c-review"
        if (cand / "workflows" / "c-review.js").is_file():
            return cand
    raise PlanError(
        "cannot locate the c-review plugin from " + str(here) + "; expected a "
        "plugins/c-review/workflows/c-review.js above the harness"
    )


def build_plan(
    tier: str,
    recipes: dict[str, dict[str, Any]],
    workroot: Path,
    run_dir: Path,
    packet_dir: Path,
    fanout_n: int | None = None,
    arms: list[str] | None = None,
    corpora: list[str] | None = None,
    allow_missing: bool = False,
) -> dict[str, Any]:
    """Write plan.json plus one packet per cell, and return the plan."""
    if tier not in TIERS:
        raise PlanError(f"unknown tier {tier!r}; have {', '.join(sorted(TIERS))}")
    spec = TIERS[tier]
    wanted_arms = [a for a in spec["arms"] if not arms or a in arms]
    wanted_control = [a for a in spec["control_arms"] if not arms or a in arms]
    chosen = {
        name: recipe
        for name, recipe in recipes.items()
        if recipe["tier"] in spec["corpus_tiers"] and (not corpora or name in corpora)
    }
    if not chosen:
        raise PlanError(
            f"tier {tier!r} wants corpus tier(s) {spec['corpus_tiers']} and no corpus matches. "
            f"A plan with zero corpora would produce zero cells and score nothing."
        )
    # A tier that silently covers one size instead of three still prints "tier standard"
    # over its results, and the missing corpus is invisible in every number downstream.
    # Requested corpora are excluded from the check: restricting on purpose is not drift.
    if not corpora:
        missing = sorted(set(spec["corpus_tiers"]) - {r["tier"] for r in chosen.values()})
        if missing and not allow_missing:
            raise PlanError(
                f"tier {tier!r} covers corpus size(s) {missing} and no corpus of that size "
                f"exists, so this run would be labelled {tier!r} while measuring less than the "
                f"tier means. Add the corpus, restrict with --corpus, or pass "
                f"--allow-missing-corpora to record a deliberately reduced run."
            )
    if not wanted_arms and not wanted_control:
        raise PlanError("no arms selected, so the plan would measure nothing")

    stamps: dict[str, dict[str, Any]] = {}
    for name in chosen:
        stamp_path = workroot / name / "verified.json"
        if not stamp_path.is_file():
            raise PlanError(
                f"corpus {name!r} has no verification stamp at {stamp_path}. Run "
                f"`bench.py verify --corpus {name}` first — an unverified corpus can have "
                f"unreachable bugs, a broken build or surviving upstream identifiers, and every "
                f"arm's number would absorb that silently."
            )
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        if not stamp.get("verified"):
            raise PlanError(f"corpus {name!r} has a stamp that says verified=false; fix the corpus")
        stamps[name] = stamp

    taxonomy = extract_taxonomy(plugin_root() / "workflows" / "c-review.js")
    taxonomy_text = "\n".join(f"- **{c['id']}** ({c['title']}): {c['brief']}" for c in taxonomy)

    run_dir = Path(run_dir)
    (run_dir / "packets").mkdir(parents=True, exist_ok=True)
    (run_dir / "results").mkdir(parents=True, exist_ok=True)

    cells: list[dict[str, Any]] = []
    for name, recipe in sorted(chosen.items()):
        stamp = stamps[name]
        kloc = stamp["lines_of_code"] / 1000.0
        for arm, variant in [(a, "bench") for a in wanted_arms] + [
            (a, "control") for a in wanted_control
        ]:
            tree = workroot / name / variant
            n_regions = fanout_n or ARM_MODEL["c-review"]["agents"] - 7
            agents, tokens = estimate_tokens(arm, kloc, n_regions)
            result_path = run_dir / "results" / f"{arm}__{name}__{variant}.result.json"
            meta_path = run_dir / "results" / f"{arm}__{name}__{variant}.meta.json"
            packet_template = packet_dir / f"{arm}.md"
            if not packet_template.is_file():
                raise PlanError(f"no packet template for arm {arm!r} at {packet_template}")
            regions = ""
            if arm == "fanout":
                if not tree.is_dir():
                    raise PlanError(f"{tree} is missing; re-run verify for corpus {name!r}")
                regions = "\n".join(
                    f"{index}. " + ", ".join(f"`{p}` lines {a}-{b}" for p, a, b in group)
                    for index, group in enumerate(partition(tree, n_regions), 1)
                )
            packet = _render(
                packet_template.read_text(encoding="utf-8"),
                {
                    "ARM": arm,
                    "CORPUS": name,
                    "VARIANT": variant,
                    "TREE": str(tree),
                    "SCOPE": recipe.get("scope_subpath", "."),
                    "THREAT_MODEL": recipe.get("threat_model", "REMOTE"),
                    "THREAT_MODEL_ENUM": threat_model_enum(recipe.get("threat_model", "REMOTE")),
                    "PLUGIN_ROOT": str(plugin_root()),
                    "ATTACKER_CONTROLS": recipe.get("attacker_controls", ""),
                    "LOC": str(stamp["lines_of_code"]),
                    "RESULT_PATH": str(result_path),
                    "META_PATH": str(meta_path),
                    "N": str(n_regions),
                    "REGIONS": regions,
                    "TAXONOMY": taxonomy_text,
                    "ESTIMATE": (
                        f"{tokens:,} tokens across {agents} agent(s) (modelled, not measured)"
                    ),
                },
            )
            packet_path = run_dir / "packets" / f"{arm}__{name}__{variant}.md"
            packet_path.write_text(packet, encoding="utf-8")
            cells.append(
                {
                    "arm": arm,
                    "corpus": name,
                    "variant": variant,
                    "tree": str(tree),
                    "private": str(workroot / name / f"{variant}-private"),
                    "packet": str(packet_path),
                    "result_path": str(result_path),
                    "meta_path": str(meta_path),
                    "estimated_agents": agents,
                    "estimated_tokens": tokens,
                    "lines_of_code": stamp["lines_of_code"],
                    "bugs": stamp["counts"]["bugs"],
                }
            )

    covered = sorted({r["tier"] for r in chosen.values()})
    plan = {
        "tier": tier,
        "why": spec["why"],
        "corpus_sizes_covered": covered,
        "corpus_sizes_expected": spec["corpus_tiers"],
        "reduced": covered != sorted(set(spec["corpus_tiers"])),
        "workroot": str(workroot),
        "run_dir": str(run_dir),
        "taxonomy_classes": len(taxonomy),
        "estimated_tokens_total": sum(c["estimated_tokens"] for c in cells),
        "cells": cells,
        "cost_model": {
            "reference_kloc": REFERENCE_KLOC,
            "floor_share": FLOOR_SHARE,
            "arms": ARM_MODEL,
            "provenance": (
                "2026-08-06 zstream measurement (tools/c-review-bench/README.md); scaled by "
                "corpus size, not re-measured. The prior anchor (2026-08-04, an unrelated 13 "
                "KLOC corpus) was 5.4x low against these actuals; real per-cell cost still "
                "varies ~1.2-1.7x run to run at fixed arm and corpus, so treat this as an "
                "order of magnitude, not a budget."
            ),
        },
    }
    (run_dir / "plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    return plan


def format_plan(plan: dict[str, Any]) -> str:
    lines = [
        f"tier {plan['tier']}: {plan['why']}",
    ]
    if plan.get("reduced"):
        lines.append(
            f"REDUCED RUN: covers corpus size(s) {plan['corpus_sizes_covered']} of "
            f"{plan['corpus_sizes_expected']}. Do not compare its numbers with a full "
            f"{plan['tier']} run."
        )
    lines += [
        f"taxonomy extracted from the shipped workflow: {plan['taxonomy_classes']} bug classes",
        "",
        f"{'ARM':<16} {'CORPUS':<12} {'VARIANT':<8} {'LOC':>7} {'BUGS':>5} "
        f"{'AGENTS':>7} {'EST TOKENS':>12}",
        f"{'-' * 16} {'-' * 12} {'-' * 8} {'-' * 7} {'-' * 5} {'-' * 7} {'-' * 12}",
    ]
    for cell in plan["cells"]:
        lines.append(
            f"{cell['arm']:<16} {cell['corpus']:<12} {cell['variant']:<8} "
            f"{cell['lines_of_code']:>7} "
            f"{cell['bugs']:>5} {cell['estimated_agents']:>7} {cell['estimated_tokens']:>12,}"
        )
    lines += [
        "",
        f"ESTIMATED TOTAL: {plan['estimated_tokens_total']:,} tokens. This is a model anchored on "
        f"the 2026-08-06 zstream cells (tools/c-review-bench/README.md), not a measurement of "
        f"these corpora — and that anchor itself varied ~1.2-1.7x cell to cell, so treat this "
        f"as an order of magnitude, not a budget.",
        f"packets: {plan['run_dir']}/packets/   results go to {plan['run_dir']}/results/",
        "",
        "Run each packet exactly as written, then `bench.py collect` each result and "
        "`bench.py score --run` the whole run.",
    ]
    return "\n".join(lines)
