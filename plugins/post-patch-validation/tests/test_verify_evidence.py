from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

VERIFY = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "post-patch-validation"
    / "scripts"
    / "verify_evidence.py"
)


def write_evidence(root: Path) -> Path:
    helper = root / "helpers" / "probe"
    helper.parent.mkdir()
    helper.write_text("print('project code')\n")
    digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    result = {
        "checks": [
            {
                "id": "control",
                "runs": {
                    "base": {
                        "argv_files": [{"index": 1, "sha256": digest, "artifact": "helpers/probe"}]
                    },
                    "patched": {
                        "argv_files": [{"index": 1, "sha256": digest, "artifact": "helpers/probe"}]
                    },
                },
            }
        ]
    }
    result_path = root / "result.json"
    result_path.write_text(json.dumps(result))
    manifest = {
        "files": [
            {"path": "helpers/probe", "sha256": digest},
            {
                "path": "result.json",
                "sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
            },
        ]
    }
    (root / "artifact-manifest.json").write_text(json.dumps(manifest))
    return helper


def run_verify(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFY), "--results", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_verify_evidence_accepts_matching_manifest_and_helper(tmp_path: Path) -> None:
    write_evidence(tmp_path)
    result = run_verify(tmp_path)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["valid"] is True
    assert summary["helper_files_checked"] == 2


def test_verify_evidence_rejects_changed_archived_helper(tmp_path: Path) -> None:
    helper = write_evidence(tmp_path)
    helper.write_text("print('tampered')\n")
    result = run_verify(tmp_path)
    assert result.returncode == 1
    summary = json.loads(result.stdout)
    assert summary["valid"] is False
    assert any("hash differs" in error for error in summary["errors"])


def test_verify_evidence_reports_unarchived_file_for_human_review(
    tmp_path: Path,
) -> None:
    write_evidence(tmp_path)
    result_path = tmp_path / "result.json"
    result = json.loads(result_path.read_text())
    result["checks"][0]["runs"]["base"]["argv_files"] = [
        {
            "index": 2,
            "sha256": "a" * 64,
            "artifact": None,
            "archive_reason": "outside isolated roots",
        }
    ]
    result_path.write_text(json.dumps(result))
    manifest = json.loads((tmp_path / "artifact-manifest.json").read_text())
    manifest["files"][1]["sha256"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    (tmp_path / "artifact-manifest.json").write_text(json.dumps(manifest))
    outcome = run_verify(tmp_path)
    assert outcome.returncode == 0
    assert json.loads(outcome.stdout)["warnings"]
