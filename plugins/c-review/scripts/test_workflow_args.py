"""The workflow's argument preamble, exercised through node against the real file.

Why this exists. `args` reaches the workflow from a model emitting a tool call, and that
model serialises the object one extra time often enough to matter — the Workflow tool's own
documentation warns about it. The preamble used to reject a JSON-encoded string outright,
which throws away the whole run: a bench cell is ~2.5M tokens and ~45 minutes, and the
failure surfaces as "no args" long after anyone is watching. That is exactly how the first
containerised cell was lost on 2026-08-07.

The load-bearing assertion is the last one: the object form and the string form must resolve
to *identical* configuration. If they ever diverge, the leniency has started changing what
the pipeline measures, which is worse than the refusal it replaced.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "c-review.js"

# The preamble runs standalone; everything after this marker needs the workflow runtime
# (agent/parallel/phase), which is not available under plain node.
PREAMBLE_START = "const REQUIRED_ARGS"
PREAMBLE_END = "// The class axis is exactly two agents"

VALID = {
    "outputDir": "/o",
    "pluginRoot": "/p",
    "threatModel": "BOTH",
    "severityFilter": "all",
    "workerModel": "sonnet",
}

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _preamble() -> str:
    src = WORKFLOW.read_text(encoding="utf-8")
    return src[src.index(PREAMBLE_START) : src.index(PREAMBLE_END)]


def resolve(args_literal: str, tmp_path: Path) -> tuple[bool, str]:
    """Run the real preamble with `args` bound to `args_literal`; return (accepted, output)."""
    script = tmp_path / "probe.mjs"
    script.write_text(
        "import fs from 'fs';\n"
        f"const pre = fs.readFileSync({json.dumps(str(tmp_path / 'pre.js'))}, 'utf8');\n"
        "const fn = new Function('args', pre + '\\nreturn JSON.stringify("
        "{OUTPUT_DIR, PLUGIN_ROOT, THREAT_MODEL, SEVERITY_FILTER, SCOPE, CONTEXT_ROOTS, "
        "WORKER_MODEL, LINES_PER_AGENT});');\n"
        f"try {{ process.stdout.write('OK' + fn({args_literal})); }}\n"
        "catch (e) { process.stdout.write('ERR' + e.message); }\n",
        encoding="utf-8",
    )
    (tmp_path / "pre.js").write_text(_preamble(), encoding="utf-8")
    out = subprocess.run(["node", str(script)], capture_output=True, text=True, check=True).stdout
    return out.startswith("OK"), out[2:] if out.startswith("OK") else out[3:]


def test_an_args_object_is_accepted(tmp_path):
    ok, _ = resolve(json.dumps(VALID), tmp_path)
    assert ok


def test_a_json_encoded_args_string_is_accepted(tmp_path):
    """The shape that lost a cell. A model that stringifies once too often is not an error."""
    ok, _ = resolve(json.dumps(json.dumps(VALID)), tmp_path)
    assert ok


def test_both_forms_resolve_to_identical_configuration(tmp_path):
    """The one that matters: accepting the string form must not change the measurement."""
    ok_obj, as_obj = resolve(json.dumps(VALID), tmp_path)
    ok_str, as_str = resolve(json.dumps(json.dumps(VALID)), tmp_path)
    assert ok_obj and ok_str
    assert json.loads(as_obj) == json.loads(as_str)


@pytest.mark.parametrize(
    ("literal", "because"),
    [
        ('"{not json"', "a string that is not JSON"),
        ('"[1,2,3]"', "a JSON array, which is not an args object"),
        ("null", "no args at all"),
        ("undefined", "no args at all"),
        ('JSON.stringify({outputDir: "/o"})', "a string missing required keys"),
    ],
)
def test_bad_args_are_still_refused(literal, because, tmp_path):
    """Leniency about the *encoding* must not become leniency about the *content*."""
    ok, message = resolve(literal, tmp_path)
    assert not ok, f"{because} was accepted: {message}"
    assert "c-review:" in message


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
