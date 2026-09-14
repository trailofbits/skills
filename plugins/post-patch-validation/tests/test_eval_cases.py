from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

EVALS = Path(__file__).resolve().parents[1] / "evals"
EXPECTED = {"complete-fix", "missed-variant", "behavior-regression"}
GOLDENS = {
    "complete-fix": (
        '{"code": "S1"} | `03-variant` | variant | pass | pass |',
        '{"code": "S3"} | `03-variant` | variant | pass | fail |',
    ),
    "missed-variant": (
        '{"code": "S3"} | `03-variant` | variant | pass | fail |',
        '{"code": "S1"} | `03-variant` | variant | pass | pass |',
    ),
    "behavior-regression": (
        '{"code": "S2"}\n| `04-behavior` | behavior | pass | pass | changed |',
        '{"code": "S1"}\n| `04-behavior` | behavior | pass | pass | same |',
    ),
}

# The shape that broke the original result.json grader: a variant that PASSED on the patch,
# followed by an unrelated check that failed. `[\s\S]*?` backtracks across the check boundary,
# so the old pattern read this as "the variant failed". Report rows cannot span checks.
SPANNING_DEFECT = """\
| `02-exploit-original` | exploit | pass | pass | — |
| `03-variant-repeated` | variant | pass | pass | — |
| `05-regression-empty` | regression | pass | fail | — |
"""


def test_three_outcome_evals_have_deterministic_graders() -> None:
    cases = sorted(EVALS.glob("*/case.yaml"))
    assert {path.parent.name for path in cases} == EXPECTED
    for path in cases:
        case = yaml.safe_load(path.read_text())
        assert case["name"] == path.parent.name
        assert case["runs"] == 3
        assert case["execution"]["timeout_seconds"] == 1800
        graders = case["graders"]
        assert any(grader["type"] == "file_exists" for grader in graders)
        assert any(grader["type"] == "regex" for grader in graders)
        assert all(grader["type"] != "llm" for grader in graders)


def test_eval_regexes_accept_goldens_and_reject_defects() -> None:
    asserted = 0
    for path in sorted(EVALS.glob("*/case.yaml")):
        case = yaml.safe_load(path.read_text())
        golden, defective = GOLDENS[case["name"]]
        for grader in case["graders"]:
            if grader["type"] != "regex":
                continue
            pattern = re.compile(grader["pattern"])
            assert pattern.search(golden), grader["name"]
            assert not pattern.search(defective), grader["name"]
            asserted += 1
    assert asserted == 6


def test_variant_graders_cannot_match_across_check_boundaries() -> None:
    """A passing variant plus any later failing check must not read as an unfixed variant."""
    old_pattern = r'"kind":\s*"variant"[\s\S]*?"patched":\s*\{[\s\S]*?"matched":\s*false'
    spanning_json = (
        '"kind": "variant", "runs": {"patched": {"matched": true}}, '
        '"kind": "regression", "runs": {"patched": {"matched": false}}'
    )
    assert re.search(old_pattern, spanning_json), "fixture no longer reproduces the old defect"

    case = yaml.safe_load((EVALS / "missed-variant" / "case.yaml").read_text())
    patterns = [g["pattern"] for g in case["graders"] if g["type"] == "regex"]
    variant = [p for p in patterns if "variant" in p]
    assert variant, "missed-variant lost its variant grader"
    genuine = SPANNING_DEFECT.replace("variant | pass | pass", "variant | pass | fail")
    for pattern in variant:
        assert not re.search(pattern, SPANNING_DEFECT)
        assert re.search(pattern, genuine)


def test_behavior_grader_accepts_either_s2_signal() -> None:
    case = yaml.safe_load((EVALS / "behavior-regression" / "case.yaml").read_text())
    pattern = next(
        grader["pattern"]
        for grader in case["graders"]
        if grader["name"] == "behavior-row-shows-regression"
    )
    for row in (
        "| `04-behavior` | behavior | pass | pass | changed |",
        "| `04-behavior` | behavior | pass | fail | same |",
        "| `04-behavior` | behavior | pass | fail | changed |",
    ):
        assert re.search(pattern, row)
    assert not re.search(pattern, "| `04-behavior` | behavior | pass | pass | same |")


def test_eval_scaffolds_create_clean_two_commit_repositories(tmp_path: Path) -> None:
    ran = 0
    for directory in sorted(path.parent for path in EVALS.glob("*/case.yaml")):
        workdir = tmp_path / directory.name
        workdir.mkdir()
        subprocess.run(["bash", str(directory / "scaffold.sh")], cwd=workdir, check=True)
        base = subprocess.run(
            ["git", "rev-parse", "vulnerable"],
            cwd=workdir,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workdir,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--short"],
            cwd=workdir,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
        assert base != head
        assert status == ""
        ran += 1
    assert ran == 3
