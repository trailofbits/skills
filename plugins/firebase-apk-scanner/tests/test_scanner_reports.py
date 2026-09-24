"""Exercise the report workflow with local apktool/curl mocks only."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parents[1] / "skills" / "firebase-apk-scanner"
SCANNER = SKILL_DIR / "scanner.sh"
CONFIG = {
    "project_info": {
        "project_id": "report-test",
        "firebase_url": "https://report-test.firebaseio.com",
        "storage_bucket": "report-test.appspot.com",
        "project_number": "123456789012",
    },
    "client": [{"api_key": [{"current_key": "AIza" + "A" * 35}]}],
}


@pytest.fixture
def scan(tmp_path):
    for program in ("bash", "jq", "unzip", "strings"):
        assert shutil.which(program), f"required test dependency is missing: {program}"
    binaries = tmp_path / "bin"
    binaries.mkdir()
    apktool = binaries / "apktool"
    apktool.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        '[[ "$REPORT_TEST_MODE" != failed ]] || exit 1\n'
        "while (($#)); do\n"
        '  if [[ "$1" == -o ]]; then output=$2; break; fi\n'
        "  shift\n"
        "done\n"
        'mkdir -p "$output"\n'
        'if [[ "$REPORT_TEST_MODE" == configured ]]; then\n'
        '  cp "$REPORT_TEST_CONFIG" "$output/google-services.json"\n'
        "fi\n"
    )
    curl = binaries / "curl"
    curl.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'printf "%s\\n" "$*" >> "$REPORT_TEST_REQUESTS"\n'
        'if [[ " $* " == *" %{http_code} "* ]]; then\n'
        '  if [[ "$*" == *cloudfunctions.net* ]]; then\n'
        "    printf '404'\n"
        "  else\n"
        '    printf \'{"error":"Permission denied"}\\nHTTP_CODE:403\'\n'
        "  fi\n"
        "else\n"
        '  printf \'{"error":{"message":"OPERATION_NOT_ALLOWED"}}\'\n'
        "fi\n"
    )
    apktool.chmod(0o755)
    curl.chmod(0o755)
    config = tmp_path / "config.json"
    config.write_text(json.dumps(CONFIG))

    def run(mode):
        work = tmp_path / mode
        work.mkdir()
        (work / "application.apk").touch()
        stale = work / "firebase_scan_20000101_000000"
        stale.mkdir()
        (stale / "scan_report.json").write_text('{"stale":true}')
        (stale / "scan_report.txt").write_text("STALE REPORT\n")
        requests = work / "requests.txt"
        result = subprocess.run(
            ["bash", str(SCANNER), "application.apk"],
            cwd=work,
            env={
                **os.environ,
                "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
                "REPORT_TEST_MODE": mode,
                "REPORT_TEST_CONFIG": str(config),
                "REPORT_TEST_REQUESTS": str(requests),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        match = re.search(r"^Results saved to: (.+)$", result.stdout, re.MULTILINE)
        assert match, result.stdout + result.stderr
        directory = work / match.group(1)
        report = directory / "scan_report.json"
        assert report.is_file()
        assert (directory / "scan_report.txt").is_file()
        return result, json.loads(report.read_text()), report, requests

    return run


@pytest.mark.parametrize(
    ("mode", "status", "failed", "untested", "exit_code"),
    [
        ("configured", "SECURE", 0, 0, 0),
        ("empty", "NO_CONFIG", 0, 1, 1),
        ("failed", "DECOMPILE_FAILED", 1, 0, 1),
    ],
)
def test_reports_survive_nonzero_exit_and_exclude_stale_scan(
    scan, mode, status, failed, untested, exit_code
):
    result, payload, report, requests = scan(mode)
    assert result.returncode == exit_code
    assert payload["total_apks"] == 1
    assert payload["vulnerable_apks"] == 0
    assert payload["total_vulnerabilities"] == 0
    assert payload["failed_apks"] == failed
    assert payload["untested_apks"] == untested
    assert payload["results"][0]["status"] == status
    assert requests.exists() == (mode == "configured")

    skill = (SKILL_DIR / "SKILL.md").read_text()
    projection = re.search(r"jq '([\s\S]*?)' \"\$report\"", skill)
    assert projection, "the documented projection must use the current report path"
    projected = subprocess.run(
        ["jq", projection.group(1), str(report)],
        check=True,
        capture_output=True,
        text=True,
    )
    summary = json.loads(projected.stdout)
    assert summary["results"][0]["status"] == status
    assert summary["failed_apks"] == failed
    assert summary["untested_apks"] == untested
    assert len(summary["results"]) == 1
    assert json.loads(report.read_text()) == payload
    if mode == "configured":
        evidence = summary["results"][0]["config"]
        assert evidence["api_keys"] == ["AIza" + "A" * 35]
        assert evidence["project_ids"] == ["report-test"]
        assert payload["results"][0]["config"]["messaging_sender_ids"] == ["123456789012"]
