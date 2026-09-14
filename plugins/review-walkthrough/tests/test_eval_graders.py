"""Exercise the shipped regex graders on rendered and deliberately broken artifacts."""

import copy
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest
import yaml

PLUGIN = Path(__file__).resolve().parents[1]
CASE = PLUGIN / "evals/rate-limit-walkthrough"
SPEC = importlib.util.spec_from_file_location(
    "eval_walkthrough_renderer", PLUGIN / "skills/review-walkthrough/scripts/render_walkthrough.py"
)
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)
REGEX_NAMES = {
    "definitions-before-wiring",
    "no-placeholder-survives",
    "review-anchored-to-bucket",
    "steps-carry-real-diffs",
    "subject-before-its-test",
}


def load_graders():
    graders = {}
    for path in sorted((CASE / "graders").glob("*.md")):
        frontmatter = path.read_text().split("---", 2)[1]
        config = yaml.safe_load(frontmatter)
        if config["type"] == "regex":
            assert config["target"] == {"source": "file", "path": "walkthrough.html"}
            assert config["pattern"].strip(), f"{path.name} has an empty pattern"
            assert config["match"] in {"contains", "not_contains"}
            graders[path.stem] = config
    assert set(graders) == REGEX_NAMES, "Regex grader discovery changed"
    return graders


def grade_artifact(directory):
    """Use JavaScript's regex engine, with the file target declared by each grader."""
    cases = [
        {"name": name, "text": (directory / config["target"]["path"]).read_text(), **config}
        for name, config in load_graders().items()
    ]
    result = subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            """
import { readFileSync } from 'node:fs';
const cases = JSON.parse(readFileSync(0, 'utf8'));
const results = Object.fromEntries(cases.map(test => {
  const matches = new RegExp(test.pattern, test.flags ?? '').test(test.text);
  return [test.name, test.match === 'contains' ? matches : !matches];
}));
process.stdout.write(JSON.stringify(results));
""",
        ],
        input=json.dumps(cases),
        text=True,
        capture_output=True,
        check=True,
    )
    results = json.loads(result.stdout)
    assert set(results) == REGEX_NAMES
    return results


@pytest.fixture(scope="module")
def fixture_data(tmp_path_factory):
    repo = tmp_path_factory.mktemp("eval-fixture")
    subprocess.run(["bash", str(CASE / "scaffold.sh")], cwd=repo, check=True, capture_output=True)
    patch = subprocess.check_output(
        ["git", "diff", "--no-ext-diff", "--no-textconv", "--no-color", "origin/main", "HEAD"],
        cwd=repo,
        text=True,
    )
    blocks = renderer.split_diff(patch)
    paths = renderer.patch_paths(patch, len(blocks))
    by_path = dict(zip(paths, blocks, strict=True))
    order = [
        "ratelimit/__init__.py",
        "ratelimit/config.py",
        "ratelimit/bucket.py",
        "tests/__init__.py",
        "tests/test_bucket.py",
        "app/middleware.py",
        "app/server.py",
    ]
    assert set(order) == set(by_path)
    data = {
        "title": "Rate limiter review",
        "steps": [{"message": path, "files": [path], "diff": by_path[path]} for path in order],
        "explanations": ["<p>Explain the implementation.</p>" for _ in order],
        "reviews": [[] for _ in order],
        "pr_meta": None,
    }
    data["reviews"][2] = [
        {
            "severity": "medium",
            "title": "Unbounded refill",
            "body": "<p>Idle clients accrue unlimited tokens.</p>",
            "file": "ratelimit/bucket.py",
            "line": 26,
            "side": "RIGHT",
        }
    ]
    return patch, data


def write_artifact(tmp_path, data, patch):
    page = renderer.render(data, patch)
    (tmp_path / "walkthrough.html").write_text(page)
    return page


@pytest.mark.parametrize("empty_file_first", [True, False])
def test_graders_accept_complete_rendered_artifact(tmp_path, fixture_data, empty_file_first):
    patch, original = fixture_data
    data = copy.deepcopy(original)
    if not empty_file_first:
        for key in ("steps", "explanations", "reviews"):
            data[key].append(data[key].pop(0))
    else:
        assert "@@" not in data["steps"][0]["diff"]
    write_artifact(tmp_path, data, patch)
    results = grade_artifact(tmp_path)
    assert all(results.values()), results


def test_graders_allow_definitions_and_consumers_in_one_step(tmp_path, fixture_data):
    patch, original = fixture_data
    data = copy.deepcopy(original)
    bucket = data["steps"][2]
    middleware = data["steps"][5]
    # Git's path order puts app/middleware.py first within the combined step.
    bucket["files"] = middleware["files"] + bucket["files"]
    bucket["diff"] = middleware["diff"] + bucket["diff"]
    for key in ("steps", "explanations", "reviews"):
        data[key].pop(5)
    write_artifact(tmp_path, data, patch)
    results = grade_artifact(tmp_path)
    assert all(results.values()), results


@pytest.mark.parametrize(
    "defect,grader",
    [
        ("consumer_first", "definitions-before-wiring"),
        ("test_first", "subject-before-its-test"),
        ("missing_anchor", "review-anchored-to-bucket"),
        ("fake_first_diff", "steps-carry-real-diffs"),
        ("placeholder", "no-placeholder-survives"),
    ],
)
def test_each_grader_rejects_its_defect(tmp_path, fixture_data, defect, grader):
    patch, original = fixture_data
    data = copy.deepcopy(original)
    if defect in {"consumer_first", "test_first"}:
        index = 5 if defect == "consumer_first" else 4
        for key in ("steps", "explanations", "reviews"):
            data[key].insert(0, data[key].pop(index))
    elif defect == "missing_anchor":
        data["reviews"] = [[] for _ in data["steps"]]
    page = write_artifact(tmp_path, data, patch)
    if defect == "fake_first_diff":
        # Later steps still have real hunks; they must not rescue a fabricated first step.
        original_diff = json.dumps(data["steps"][0]["diff"])
        assert original_diff in page
        page = page.replace(original_diff, '"Prose instead of a patch"', 1)
    elif defect == "placeholder":
        assert "<h1>Rate limiter review</h1>" in page
        page = page.replace("<h1>Rate limiter review</h1>", "<h1>TITLE_PLACEHOLDER</h1>")
    (tmp_path / "walkthrough.html").write_text(page)
    assert not grade_artifact(tmp_path)[grader]


def test_graders_reject_empty_artifact_and_fail_on_missing_artifact(tmp_path):
    with pytest.raises(FileNotFoundError):
        grade_artifact(tmp_path)
    (tmp_path / "walkthrough.html").write_text("")
    assert not all(grade_artifact(tmp_path).values())
    artifact_grader = yaml.safe_load(
        (CASE / "graders/artifact-written.md").read_text().split("---", 2)[1]
    )
    assert artifact_grader["type"] == "file_exists"
    assert artifact_grader["path"] == "walkthrough.html"
    assert artifact_grader["exists"] is True
