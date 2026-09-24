#!/usr/bin/env bash
# Regression test for audit-augmentation's one-process graph workflow.
#
# This is deliberately deterministic and does not call a model.  It proves the
# shipped helper keeps --out complete while limiting stdout, retains matched
# findings, and rejects input combinations Trailmark would overwrite.
set -euo pipefail

command -v uv >/dev/null 2>&1 || {
  echo "run_audit_augmentation_tests.sh: uv is required" >&2
  exit 1
}

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$PLUGIN_ROOT/skills/audit-augmentation/scripts/augment_context.py"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/audit-augmentation-tests.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

TARGET="$WORK/project"
mkdir -p "$TARGET"
printf 'def entrypoint(value):\n    return value + 1\n' >"$TARGET/main.py"

cat >"$WORK/findings.sarif" <<'JSON'
{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "test", "rules": [{"id": "T1", "defaultConfiguration": {"level": "error"}}]}},
    "results": [{"ruleId": "T1", "message": {"text": "test finding"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.py"}, "region": {"startLine": 1}}}]}]
  }]
}
JSON

cat >"$WORK/findings.weaudit" <<'JSON'
{
  "treeEntries": [{
    "label": "test audit finding",
    "entryType": 0,
    "author": "tester",
    "details": {"severity": "High", "difficulty": "Low", "type": "Test", "description": "test", "exploit": "", "recommendation": ""},
    "locations": [{"path": "main.py", "startLine": 0, "endLine": 0, "label": "test", "description": ""}]
  }],
  "resolvedEntries": []
}
JSON

cat >"$WORK/binary.json" <<'JSON'
{
  "artifact": {"name": "test-binary", "architecture": "x86_64"},
  "functions": [{"symbol": "entrypoint", "source": {"file": "main.py", "line": 1}}],
  "calls": [{"source": "entrypoint", "target": "external_test", "confidence": "inferred"}]
}
JSON

uv run --with trailmark "$SCRIPT" \
  --target "$TARGET" --sarif "$WORK/findings.sarif" --weaudit "$WORK/findings.weaudit" \
  --binary "$WORK/binary.json" --out "$WORK/result.json" --summary-out "$WORK/summary.json" \
  >"$WORK/stdout.json"
cmp "$WORK/stdout.json" "$WORK/result.json"

uv run --no-project python3 - "$WORK/result.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1]))
assert data["augmentation"]["sarif"]["matched_findings"] == 1
assert data["augmentation"]["sarif"]["unmatched_findings"] == 0
assert data["augmentation"]["weaudit"]["matched_findings"] == 1
assert data["augmentation"]["binary"]["binary_nodes"] == 1
assert any(name.startswith("sarif:") for name in data["subgraphs"])
assert any(name.startswith("weaudit:") for name in data["subgraphs"])
assert any(name.startswith("binary:") for name in data["subgraphs"])
assert data["target"].endswith("/project")
PY

uv run --no-project python3 - "$WORK/summary.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1]))
assert data["sarif"]["matched_findings"] == 1
assert data["weaudit"]["matched_findings"] == 1
assert data["binary"]["binary_nodes"] == 1
assert set(data) == {
    "sarif",
    "weaudit",
    "binary",
    "error_on_tainted",
    "findings_on_high_blast_radius",
    "findings_on_privilege_boundary",
}
PY

if uv run --with trailmark "$SCRIPT" --target "$TARGET" \
  --sarif "$WORK/findings.sarif" --sarif "$WORK/findings.sarif" \
  >"$WORK/duplicate.out" 2>"$WORK/duplicate.err"; then
  echo "expected duplicate SARIF inputs to fail" >&2
  exit 1
fi
grep -Fq 'would replace earlier sarif augmentation' "$WORK/duplicate.err"

(cd "$WORK" && uv run --with trailmark "$SCRIPT" --target project --sarif findings.sarif \
  >"$WORK/relative-target.json")
uv run --no-project python3 - "$WORK/relative-target.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1]))
assert data["target"].endswith("/project")
assert data["augmentation"]["sarif"]["matched_findings"] == 1
PY

cat >"$WORK/unmatched.sarif" <<'JSON'
{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test"}},"results":[{"level":"error","message":{"text":"outside project"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"outside.py"},"region":{"startLine":1}}}]}]}]}
JSON
uv run --with trailmark "$SCRIPT" --target "$TARGET" --sarif "$WORK/unmatched.sarif" \
  >"$WORK/unmatched.json"
uv run --no-project python3 - "$WORK/unmatched.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1]))
assert data["augmentation"]["sarif"]["matched_findings"] == 0
assert data["augmentation"]["sarif"]["unmatched_findings"] == 1
assert "sarif:error" not in data["subgraphs"]
PY

if uv run --with trailmark "$SCRIPT" --target "$WORK/missing" --sarif "$WORK/findings.sarif" \
  >"$WORK/missing.out" 2>"$WORK/missing.err"; then
  echo "expected missing target to fail" >&2
  exit 1
fi
grep -Fq 'target is not a directory' "$WORK/missing.err"

uv run --with trailmark python - "$SCRIPT" "$WORK" <<'PY'
import contextlib
import importlib.util
import io
import itertools
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from trailmark.query.api import QueryEngine

script, work = map(Path, sys.argv[1:])
target = work / "project"
inputs = {
    "sarif": work / "findings.sarif",
    "weaudit": work / "findings.weaudit",
    "binary": work / "binary.json",
}


def compare(root, selected, *, limit=0, language="auto"):
    """Compare every helper field with the original in-process API workflow."""
    engine = QueryEngine.from_directory(str(root.resolve()), language=language)
    preanalysis = engine.preanalysis()
    stats = {
        kind: getattr(engine, f"augment_{kind}")(str(path))
        for kind, path in selected.items()
    }
    names = engine.subgraph_names()
    groups = {name: {node["id"] for node in engine.subgraph(name)} for name in names}
    findings = {
        node for name, nodes in groups.items()
        if name.startswith(("sarif:", "weaudit:")) for node in nodes
    }
    signals = {"tainted", "high_blast_radius", "privilege_boundary"}
    ranked = [
        {
            "node": node,
            "signals": sorted(
                name for name, nodes in groups.items()
                if node in nodes and (
                    name.startswith(("sarif:", "weaudit:")) or name in signals
                )
            ),
        }
        for node in findings
    ]
    ranked.sort(key=lambda item: (-len(item["signals"]), item["node"]))
    expected = {
        "target": str(root.resolve()),
        "preanalysis": preanalysis,
        "augmentation": stats,
        "subgraphs": {name: len(nodes) for name, nodes in groups.items()},
        "priority_nodes": ranked,
    }
    expected_summary = {
        **stats,
        "error_on_tainted": sorted(groups.get("sarif:error", set()) & groups.get("tainted", set())),
        "findings_on_high_blast_radius": sorted(findings & groups.get("high_blast_radius", set())),
        "findings_on_privilege_boundary": sorted(findings & groups.get("privilege_boundary", set())),
    }
    command = [
        sys.executable, str(script), "--target", str(root), "--language", language,
        "--limit", str(limit), "--out", str(work / "complete.json"),
        "--summary-out", str(work / "compact.json"),
    ]
    for kind, path in selected.items():
        command.extend([f"--{kind}", str(path)])
    result = subprocess.run(command, text=True, capture_output=True, check=True)
    assert json.loads((work / "complete.json").read_text()) == expected
    assert json.loads((work / "compact.json").read_text()) == expected_summary
    expected_stdout = {
        **expected, "priority_nodes": ranked[:limit] if limit else ranked,
    }
    assert json.loads(result.stdout) == expected_stdout
    # Original per-node queries remain available in this same engine.
    annotated = engine.findings()
    assert all(node["findings"] for node in annotated)
    assert all(engine.annotations_of(node["id"]) for node in annotated)
    return expected


for count in (1, 2, 3):
    for kinds in itertools.combinations(inputs, count):
        compare(target, {kind: inputs[kind] for kind in kinds}, limit=1)
print("PASS: exact full payloads for all seven source combinations")

empty_inputs = {
    "sarif": {"version": "2.1.0", "runs": []},
    "weaudit": {"treeEntries": [], "resolvedEntries": []},
    "binary": {"artifact": {"name": "empty"}, "functions": [], "calls": []},
}
for kind, value in empty_inputs.items():
    path = work / f"empty-{kind}.json"
    path.write_text(json.dumps(value))
    compare(target, {kind: path})
print("PASS: empty imports retain complete source statistics")

large = work / "large-project"
large.mkdir()
(large / "main.py").write_text("".join(
    f"def handler_{index}(value):\n    return value + {index}\n\n"
    for index in range(105)
))
sarif = json.loads(inputs["sarif"].read_text())
sarif["runs"][0]["results"] = [
    {
        "ruleId": "T1", "level": "error", "message": {"text": f"finding {index}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "main.py"},
            "region": {"startLine": index * 3 + 1},
        }}],
    }
    for index in range(105)
]
many = work / "many.sarif"
many.write_text(json.dumps(sarif))
for limit in (0, 1, 100):
    complete = compare(large, {"sarif": many}, limit=limit, language="python")
    assert len(complete["priority_nodes"]) > 100
print("PASS: >100-node fixture keeps --out complete at limits 0, 1 and 100")

malformed = work / "malformed.json"
malformed.write_text("{")
for kind in inputs:
    for path in (malformed, work / "nonexistent.json"):
        result = subprocess.run(
            [sys.executable, str(script), "--target", str(target), f"--{kind}", str(path)],
            text=True, capture_output=True,
        )
        assert result.returncode != 0 and not result.stdout
    result = subprocess.run(
        [
            sys.executable, str(script), "--target", str(target),
            f"--{kind}", str(inputs[kind]), f"--{kind}", str(inputs[kind]),
        ],
        text=True, capture_output=True,
    )
    assert result.returncode == 2
    expected_error = "programmatic API" if kind == "binary" else "would replace earlier"
    assert expected_error in result.stderr

for extra in ([], ["--sarif", str(inputs["sarif"]), "--limit", "-1"]):
    result = subprocess.run(
        [sys.executable, str(script), "--target", str(target), *extra],
        text=True, capture_output=True,
    )
    assert result.returncode == 2 and not result.stdout

empty_target = work / "empty-project"
empty_target.mkdir()
result = subprocess.run(
    [sys.executable, str(script), "--target", str(empty_target), "--sarif", str(many)],
    text=True, capture_output=True,
)
assert result.returncode != 0 and not result.stdout

spec = importlib.util.spec_from_file_location("augment_context", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LegacyEngine:
    @classmethod
    def from_directory(cls, *args, **kwargs):
        return cls()

    def preanalysis(self):
        return {}


error = io.StringIO()
with patch.object(module, "QueryEngine", LegacyEngine), patch.object(
    sys, "argv",
    [str(script), "--target", str(target), "--binary", str(inputs["binary"])],
), contextlib.redirect_stderr(error):
    assert module.main() == 2
assert "requires Trailmark >= 0.4.0" in error.getvalue()
print("PASS: invalid inputs, duplicate sources, empty target and binary version gate")
PY

echo "PASS: audit augmentation helper (complete outputs, sources, matching, and error guards)"
