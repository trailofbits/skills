from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import SCRIPT


def command(
    *args: str, cwd: Path | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        text=True,
        capture_output=True,
        check=check,
    )


def git(repo: Path, *args: str) -> str:
    return command("git", "-c", "commit.gpgsign=false", *args, cwd=repo).stdout.strip()


def create_repo(root: Path, patch_body: str | None = None) -> tuple[Path, str, str]:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    (repo / "app.py").write_text(
        "def sanitize(value):\n    if value is None:\n        return None\n    return value\n"
    )
    scripts = repo / "scripts"
    scripts.mkdir()
    helper = scripts / "verify.sh"
    helper.write_text("#!/bin/sh\nexit 0\n")
    helper.chmod(0o755)
    git(repo, "add", "app.py", "scripts/verify.sh")
    git(repo, "commit", "-q", "-m", "vulnerable")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "vulnerable")
    (repo / "app.py").write_text(
        patch_body
        or "def sanitize(value):\n"
        "    if value is None:\n"
        "        return None\n"
        "    return value.replace('<', '&lt;')\n"
    )
    git(repo, "add", "app.py")
    git(repo, "commit", "-q", "-m", "fix sanitizer")
    patched = git(repo, "rev-parse", "HEAD")
    return repo, base, patched


def checks() -> list[dict[str, object]]:
    python = sys.executable
    return [
        {
            "id": "01-control-import",
            "kind": "control",
            "rationale": "The module imports and benign input is accepted on both revisions.",
            "covers": ["app.sanitize benign harness"],
            "argv": [python, "-c", "import app; assert app.sanitize('safe') == 'safe'"],
        },
        {
            "id": "02-exploit-original",
            "kind": "exploit",
            "rationale": "The original unsafe character must be escaped.",
            "covers": ["app.sanitize single unsafe character"],
            "argv": [
                python,
                "-c",
                "import app; print('PPV_REACHED', flush=True); assert app.sanitize('<') == '&lt;'",
            ],
        },
        {
            "id": "03-variant-repeated",
            "kind": "variant",
            "rationale": "Repeated unsafe characters exercise the root cause independently.",
            "covers": ["app.sanitize repeated unsafe characters"],
            "argv": [
                python,
                "-c",
                "import app; print('PPV_REACHED', flush=True); "
                "assert app.sanitize('<<') == '&lt;&lt;'",
            ],
        },
        {
            "id": "04-behavior-safe",
            "kind": "behavior",
            "rationale": "Safe input output must remain byte-identical.",
            "covers": ["app.sanitize safe input"],
            "argv": [python, "-c", "import app; print(app.sanitize('safe'))"],
            "compare_stream": "stdout",
        },
        {
            "id": "05-regression-empty",
            "kind": "regression",
            "rationale": "Empty input remains supported.",
            "covers": ["app.sanitize empty input"],
            "argv": [python, "-c", "import app; assert app.sanitize('') == ''"],
        },
        {
            "id": "06-security-none",
            "kind": "security",
            "rationale": "The patch must preserve the sentinel ownership contract.",
            "covers": ["app.sanitize None sentinel"],
            "argv": [python, "-c", "import app; assert app.sanitize(None) is None"],
        },
        {
            "id": "07-suite-compile",
            "kind": "suite",
            "rationale": "The patched module must compile under the project interpreter.",
            "covers": ["project compile gate"],
            "argv": [python, "-m", "py_compile", "app.py"],
        },
    ]


def scaffold(repo: Path, plan: Path, *, patch_file: Path | None = None) -> dict[str, object]:
    argv = [
        sys.executable,
        str(SCRIPT),
        "scaffold",
        "--repo",
        str(repo),
        "--base-ref",
        "vulnerable",
        "--finding-id",
        "TEST-1",
        "--finding-summary",
        "sanitize returns unsafe markup unchanged",
        "--evidence-level",
        "runtime",
        "--output",
        str(plan),
    ]
    if patch_file:
        argv.extend(["--patch-file", str(patch_file)])
    else:
        argv.extend(["--patched-ref", "HEAD"])
    result = command(*argv)
    assert "patch_sha256" in result.stdout
    value = json.loads(plan.read_text())
    value["checks"] = checks()
    plan.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return value


def run(plan: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return command(
        sys.executable,
        str(SCRIPT),
        "run",
        "--plan",
        str(plan),
        "--output",
        str(output),
        check=False,
    )


def test_complete_ref_patch_is_s1_and_reproducible(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan = tmp_path / "case" / "plan.json"
    scaffold(repo, plan)

    first = tmp_path / "first"
    second = tmp_path / "second"
    assert run(plan, first).returncode == 0
    assert run(plan, second).returncode == 0

    result = json.loads((first / "result.json").read_text())
    assert result["verdict"]["code"] == "S1"
    assert result["verdict"]["human_review_required"] is True
    assert all(result["coverage"][kind] >= 1 for kind in result["coverage"])
    for name in ["result.json", "report.md", "artifact-manifest.json"]:
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_patch_file_mode_applies_in_isolated_worktree(tmp_path: Path) -> None:
    repo, base, patched = create_repo(tmp_path)
    patch_file = tmp_path / "fix.patch"
    patch_file.write_bytes(
        subprocess.run(
            ["git", "diff", "--binary", "--full-index", base, patched, "--"],
            cwd=repo,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
    )
    plan = tmp_path / "patch-case" / "plan.json"
    scaffold(repo, plan, patch_file=patch_file)
    assert run(plan, tmp_path / "patch-results").returncode == 0
    assert (
        json.loads((tmp_path / "patch-results" / "result.json").read_text())["verdict"]["code"]
        == "S1"
    )
    assert git(repo, "status", "--short") == ""


@pytest.mark.parametrize(
    "summary", ["ASCII finding", "Unicode finding: \u2018quote\u2019 \u6f0f\u6d1e"]
)
def test_s2_plan_and_report_use_utf8_with_ascii_locale(tmp_path: Path, ppv, summary: str) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan)
    value["finding"]["summary"] = summary
    behavior = next(check for check in value["checks"] if check["kind"] == "behavior")
    behavior["argv"] = [sys.executable, "-c", "import app; print(app.sanitize('<'))"]
    ppv.write_json(plan, value)
    output = tmp_path / "results"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "run", "--plan", str(plan), "--output", str(output)],
        env={
            **os.environ,
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
            "LC_ALL": "C",
        },
        capture_output=True,
    )
    assert result.returncode == 2, result.stderr.decode("utf-8", errors="replace")
    evidence = json.loads((output / "result.json").read_text(encoding="utf-8"))
    assert evidence["verdict"]["code"] == "S2"
    assert evidence["finding"]["summary"] == summary
    assert summary in (output / "report.md").read_text(encoding="utf-8")


def test_plan_rejects_shell_strings_and_missing_categories(tmp_path: Path, ppv) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    value["checks"][0]["argv"] = "python -c 'import app'"
    with pytest.raises(ppv.PlanError, match="argv array"):
        ppv.validate_plan(value)

    value = json.loads(plan_path.read_text())
    value["checks"][0]["argv"] = ["bash", "-c", "python -m pytest | tee output.txt"]
    with pytest.raises(ppv.PlanError, match="shell command string"):
        ppv.validate_plan(value)

    value = json.loads(plan_path.read_text())
    value["checks"] = [check for check in value["checks"] if check["kind"] != "variant"]
    with pytest.raises(ppv.PlanError, match="missing check kinds: variant"):
        ppv.validate_plan(value)

    value = json.loads(plan_path.read_text())
    del value["evidence_level"]
    with pytest.raises(ppv.PlanError, match="evidence_level"):
        ppv.validate_plan(value)

    value = json.loads(plan_path.read_text())
    del value["submodules"]
    with pytest.raises(ppv.PlanError, match="submodules"):
        ppv.validate_plan(value)


def observation(
    kind: str, *, base: bool = True, patched: bool = True, marker: bool = True
) -> dict[str, object]:
    needs_marker = kind in {"exploit", "variant"}
    runs: dict[str, dict[str, object]] = {}
    if kind != "suite":
        runs["base"] = {"status": "completed", "matched": base}
    runs["patched"] = {"status": "completed", "matched": patched}
    for run in runs.values():
        run["marker"] = marker if needs_marker else None
    result: dict[str, object] = {"id": f"check-{kind}", "kind": kind, "runs": runs}
    if kind == "behavior":
        result["comparison"] = {"matched": patched}
    return result


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({}, "S1"),
        ({"behavior": False}, "S2"),
        ({"variant": False}, "S3"),
        ({"security": False}, "S4"),
        ({"variant": False, "security": False}, "S5"),
    ],
)
def test_classification_matrix(ppv, changes: dict[str, bool], expected: str) -> None:
    evidence = [observation(kind, patched=changes.get(kind, True)) for kind in ppv.KINDS]
    assert ppv.classify(evidence)["code"] == expected


def test_baseline_mismatch_is_inconclusive(ppv) -> None:
    evidence = [observation(kind, base=kind != "exploit") for kind in ppv.KINDS]
    assert ppv.classify(evidence)["code"] == "INCONCLUSIVE"


@pytest.mark.parametrize("kind", ["exploit", "variant"])
def test_unmarked_assertion_is_inconclusive_not_evidence(ppv, kind: str) -> None:
    """A nonzero base exit without the marker is a broken harness, not a reproduction.

    Without this the runner cannot tell `assert` from `ModuleNotFoundError`, so a harness that
    never reached its assertion on base and happens to exit zero on patch reads as a clean fix.
    """
    evidence = [observation(other, marker=other != kind) for other in ppv.KINDS]
    verdict = ppv.classify(evidence)
    assert verdict["code"] == "INCONCLUSIVE"
    assert f"check-{kind}:base:marker_missing" in verdict["reasons"][0]


def test_broken_patched_control_is_inconclusive_not_s2(ppv) -> None:
    """If the benign harness stops working on the patched side, nothing there is trustworthy."""
    evidence = [observation(kind, patched=kind != "control") for kind in ppv.KINDS]
    verdict = ppv.classify(evidence)
    assert verdict["code"] == "INCONCLUSIVE"
    assert "check-control:patched:control_failed" in verdict["reasons"][0]


def test_suite_failure_is_still_s2(ppv) -> None:
    """The control carve-out must not swallow the ordinary non-security regression signal."""
    evidence = [observation(kind, patched=kind != "suite") for kind in ppv.KINDS]
    assert ppv.classify(evidence)["code"] == "S2"


def test_shell_command_strings_are_rejected_behind_env(ppv) -> None:
    """Matching only argv[0] let `env bash -c` through, which is the obvious way around it."""
    for argv in (
        ["bash", "-c", "make test"],
        ["env", "bash", "-c", "make test"],
        ["/usr/bin/env", "FOO=1", "sh", "-c", "make test"],
        ["env", "-u", "HOME", "sh", "-c", "make test"],
        ["env", "pwsh", "-Command", "Invoke-Build"],
        # Flag bundling: bash takes -xc, -lc, -ic and any other single-letter cluster.
        ["bash", "-xc", "make test"],
        ["/bin/sh", "-ec", "make test"],
        # csh and tcsh were simply missing from the shell list.
        ["/bin/csh", "-c", "make test"],
        ["tcsh", "-c", "make test"],
        # Common process wrappers must not turn the executable-only check into a bypass.
        ["timeout", "5", "sh", "-c", "make test"],
        ["timeout", "--signal=KILL", "5", "env", "sh", "-c", "make test"],
        ["nohup", "bash", "-c", "make test"],
        ["nice", "-n", "5", "sh", "-c", "make test"],
        ["xargs", "-n", "1", "sh", "-c", "make test"],
        ["stdbuf", "-o0", "sh", "-c", "make test"],
        ["setsid", "bash", "-c", "make test"],
        ["busybox", "sh", "-c", "make test"],
        ["flock", "/tmp/lock", "sh", "-c", "make test"],
        ["/usr/bin/time", "sh", "-c", "make test"],
        ["sudo", "sh", "-c", "make test"],
        ["script", "-qec", "make test | tee out"],
    ):
        with pytest.raises(ppv.PlanError, match="shell command string"):
            ppv.reject_shell_string(argv, "checks[0].argv")
    # env --split-string re-splits its argument into a command line: same hazard, different door.
    for argv in (
        ["/usr/bin/env", "-S", "sh -c 'make test'"],
        ["env", "--split-string", "sh -c 'make test'"],
        ["env", "--split-string=sh -c 'make test'"],
    ):
        with pytest.raises(ppv.PlanError, match="split-string"):
            ppv.reject_shell_string(argv, "checks[0].argv")
    for argv in (
        [sys.executable, "-c", "import app"],
        ["env", "PYTHONPATH=.", sys.executable, "-m", "pytest"],
        ["./scripts/run-suite.sh"],
    ):
        ppv.reject_shell_string(argv, "checks[0].argv")


def test_marker_must_be_a_bare_stdout_line(ppv, tmp_path: Path) -> None:
    """A SyntaxError traceback echoes the source, so stderr and substrings cannot count.

    `python3 -c "print('PPV_REACHED') NOT_VALID"` executes nothing and exits nonzero, but the
    traceback quotes the marker back. Scanning stderr for a substring accepted that as proof
    the harness reached its assertion.
    """
    accepted = tmp_path / "ok.stdout"
    accepted.write_bytes(b"setting up\nPPV_REACHED\n")
    assert ppv.marker_present(accepted)

    for content in (
        b"  File \"<string>\", line 1\n    print('PPV_REACHED') NOT_VALID\nSyntaxError: invalid\n",
        b"usage: harness [--emit PPV_REACHED]\n",
        b"prefixPPV_REACHEDsuffix\n",
    ):
        echoed = tmp_path / "echo.stdout"
        echoed.write_bytes(content)
        assert not ppv.marker_present(echoed)


def test_exploit_checks_may_not_see_which_revision_they_run_on(ppv, tmp_path: Path) -> None:
    """The cheapest fake reproduction is `assert PPV_SIDE == "patched"`, so deny the oracle."""
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    base = scaffold(repo, plan_path)

    for mutate in (
        lambda check: check.update(
            {"argv": [sys.executable, "-c", "import os; os.environ['PPV_SIDE']"]}
        ),
        lambda check: check.update({"env": {"WHICH": "{side}"}}),
    ):
        value = json.loads(plan_path.read_text())
        exploit = next(c for c in value["checks"] if c["kind"] == "exploit")
        mutate(exploit)
        with pytest.raises(ppv.PlanError, match="may not reference the revision"):
            ppv.validate_plan(value)

    # The same reference is fine on a kind whose verdict does not turn on base-versus-patch.
    value = json.loads(plan_path.read_text())
    next(c for c in value["checks"] if c["kind"] == "suite")["env"] = {"WHICH": "{side}"}
    ppv.validate_plan(value)
    assert base["case_id"]


def test_side_is_withheld_from_exploit_checks_at_runtime(tmp_path: Path) -> None:
    """Plan-time rejection is not enough: a helper script could read the variable directly."""
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    # A helper file, not inline argv: the plan validator already rejects argv that names
    # PPV_SIDE, so the interesting question is whether a script can still read it at runtime.
    probe = plan_path.parent / "probe.py"
    probe.write_text(
        "import os, pathlib, re\n"
        "def fd_path(fd):\n"
        "    try:\n"
        "        import fcntl\n"
        "        return fcntl.fcntl(fd, 50, b'\\0' * 1024).split(b'\\0', 1)[0].decode()\n"
        "    except (ImportError, OSError):\n"
        "        try:\n"
        "            return os.readlink(f'/proc/self/fd/{fd}')\n"
        "        except OSError:\n"
        "            return ''\n"
        "print('PPV_REACHED', flush=True)\n"
        "assert 'PPV_SIDE' not in os.environ, 'side leaked via environment'\n"
        "leaf = pathlib.Path(os.environ['PPV_CHECKOUT']).name\n"
        "assert leaf not in {'base', 'patched'}, 'side leaked via checkout path'\n"
        "for fd in (1, 2):\n"
        "    assert not re.search(r'-(base|patched)\\.(stdout|stderr)$', fd_path(fd))\n"
    )
    exploit = next(c for c in value["checks"] if c["kind"] == "exploit")
    exploit["argv"] = [sys.executable, "{plan_dir}/probe.py"]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    run(plan_path, output)
    result = json.loads((output / "result.json").read_text())
    exploit_run = next(c for c in result["checks"] if c["kind"] == "exploit")["runs"]["base"]
    # The probe exits 0 when side-blinding holds, and an exploit must fail on base, so a green
    # blinding check reads as S3 here. What matters is that the probe's assertions all held.
    assert exploit_run["marker"] is True
    assert exploit_run["exit_code"] == 0


def test_output_descriptor_path_cannot_manufacture_s1(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    oracle = plan_path.parent / "fd-oracle.py"
    oracle.write_text(
        "import os, sys\n"
        "try:\n"
        "    import fcntl\n"
        "    path = fcntl.fcntl(1, 50, b'\\0' * 1024).split(b'\\0', 1)[0].decode()\n"
        "except (ImportError, OSError):\n"
        "    try:\n"
        "        path = os.readlink('/proc/self/fd/1')\n"
        "    except OSError:\n"
        "        path = ''\n"
        "print('PPV_REACHED', flush=True)\n"
        "sys.exit(1 if path.endswith('-base.stdout') else 0)\n"
    )
    for check in value["checks"]:
        if check["kind"] in {"exploit", "variant"}:
            check["argv"] = [sys.executable, "{plan_dir}/fd-oracle.py"]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    assert run(plan_path, output).returncode != 0
    result = json.loads((output / "result.json").read_text())
    assert result["verdict"]["code"] != "S1"
    for check in result["checks"]:
        if check["kind"] in {"exploit", "variant"}:
            for invocation in check["runs"].values():
                assert invocation["exit_code"] == 0


def test_allow_env_refuses_credentials_and_execution_hijacking(ppv, monkeypatch) -> None:
    for name in (
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "GITHUB_PAT",
        "NPM_AUTH",
        "DB_PASSWORD",
        "DB_PASS",
        "ENCRYPTION_KEY",
        "SIGNING_KEY",
        "AUTH_HEADER",
    ):
        monkeypatch.setenv(name, "sensitive")
        with pytest.raises(ppv.PlanError, match="reads as a credential"):
            ppv.resolve_forwarded_env([name])
    for name in ("LD_PRELOAD", "BASH_ENV", "NODE_OPTIONS", "GIT_SSH_COMMAND"):
        monkeypatch.setenv(name, "/tmp/evil")
        with pytest.raises(ppv.PlanError, match="changes which code runs"):
            ppv.resolve_forwarded_env([name])
    for name in ("TZ", "LC_ALL", "PYTHONHASHSEED", "PPV_SIDE", "PPV_SCRATCH"):
        monkeypatch.setenv(name, "host-value")
        with pytest.raises(ppv.PlanError, match="reserves or fixes"):
            ppv.resolve_forwarded_env([name])


def test_allow_env_forwards_only_named_variables_and_fails_closed(ppv, monkeypatch) -> None:
    monkeypatch.setenv("JAVA_HOME", "/opt/jdk")
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Fixture")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-forward")
    assert ppv.resolve_forwarded_env(["JAVA_HOME", "GIT_AUTHOR_NAME", "JAVA_HOME"]) == {
        "JAVA_HOME": "/opt/jdk",
        "GIT_AUTHOR_NAME": "Fixture",
    }
    with pytest.raises(ppv.PlanError, match="not set in this environment"):
        ppv.resolve_forwarded_env(["NOT_SET_ANYWHERE"])
    with pytest.raises(ppv.PlanError, match="not a valid variable name"):
        ppv.resolve_forwarded_env(["not-a-name"])


def test_per_invocation_scratch_is_archived_without_sharing_state(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    value["checks"][0]["argv"] = [
        sys.executable,
        "-c",
        "import os, pathlib; pathlib.Path(os.environ['PPV_SCRATCH'], 'note.txt').write_text('x')",
    ]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    output = tmp_path / "results"
    run(plan_path, output)
    notes = list((output / "scratch").glob("*/note.txt"))
    assert len(notes) == 2
    assert {note.read_text() for note in notes} == {"x"}
    snapshot = json.loads((output / "plan.snapshot.json").read_text())
    assert snapshot["case_id"] == value["case_id"]


def test_stable_environment_drops_secrets_and_overrides_locale(ppv, monkeypatch) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-forward")
    monkeypatch.setenv("PATH", "/fixture/bin")
    env = ppv.stable_env({"LC_ALL": "host-locale", "CASE_VALUE": "explicit"})
    assert env["PATH"] == "/fixture/bin"
    assert env["CASE_VALUE"] == "explicit"
    assert env["LC_ALL"] == "C"
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_allow_env_reaches_the_checks_and_is_recorded(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    value["checks"][0]["argv"] = [
        sys.executable,
        "-c",
        "import os; assert os.environ['FIXTURE_HOME'] == '/opt/fixture'",
    ]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    output = tmp_path / "results"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "run",
            "--plan",
            str(plan_path),
            "--output",
            str(output),
            "--allow-env",
            "FIXTURE_HOME",
        ],
        env={**os.environ, "FIXTURE_HOME": "/opt/fixture"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    recorded = json.loads((output / "result.json").read_text())["inputs"]["forwarded_env"]
    assert recorded == {"FIXTURE_HOME": "/opt/fixture"}
    assert "**Forwarded environment:** FIXTURE_HOME" in (output / "report.md").read_text()


def test_moved_ref_fails_closed(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan = tmp_path / "case" / "plan.json"
    scaffold(repo, plan)
    (repo / "README.md").write_text("move the ref\n")
    git(repo, "add", "README.md")
    git(repo, "commit", "-q", "-m", "move HEAD")
    result = run(plan, tmp_path / "results")
    assert result.returncode == 64
    assert "patched ref moved" in result.stderr


def test_missing_repository_fails_cleanly(tmp_path: Path) -> None:
    result = command(
        sys.executable,
        str(SCRIPT),
        "scaffold",
        "--repo",
        str(tmp_path / "missing"),
        "--base-ref",
        "HEAD",
        "--patched-ref",
        "HEAD",
        "--finding-id",
        "TEST-MISSING",
        "--finding-summary",
        "missing repository",
        "--evidence-level",
        "source",
        "--output",
        str(tmp_path / "plan.json"),
        check=False,
    )
    assert result.returncode == 64
    assert "failed to run git" in result.stderr
    assert "Traceback" not in result.stderr


def test_relative_argv0_hash_uses_check_cwd(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    value["checks"][0].update({"cwd": "scripts", "argv": ["./verify.sh"]})
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    assert run(plan_path, output).returncode == 0
    result = json.loads((output / "result.json").read_text())
    control = next(check for check in result["checks"] if check["kind"] == "control")
    expected = ppv_sha256(repo / "scripts" / "verify.sh")
    assert control["runs"]["base"]["argv0_sha256"] == expected
    assert control["runs"]["patched"]["argv0_sha256"] == expected


def test_interpreter_helper_is_hashed_and_archived(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    helper = plan_path.parent / "probe.py"
    helper_source = b"raise SystemExit(0)\n"
    helper.write_bytes(helper_source)
    value["checks"][0]["argv"] = [sys.executable, "{plan_dir}/probe.py"]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    assert run(plan_path, output).returncode == 0
    result = json.loads((output / "result.json").read_text())
    control = next(check for check in result["checks"] if check["kind"] == "control")
    expected = hashlib.sha256(helper_source).hexdigest()
    for side in ("base", "patched"):
        helper_record = next(
            record for record in control["runs"][side]["argv_files"] if record["index"] == 1
        )
        assert helper_record["argument"] == "{plan_dir}/probe.py"
        assert helper_record["sha256"] == expected
        artifact = output / helper_record["artifact"]
        assert artifact.read_bytes() == helper_source

    helper.write_text("raise SystemExit(7)\n")
    helper_artifact = output / "helpers" / expected
    assert helper_artifact.read_bytes() == helper_source
    manifest = json.loads((output / "artifact-manifest.json").read_text())
    helper_entry = next(item for item in manifest["files"] if item["path"] == f"helpers/{expected}")
    assert helper_entry["sha256"] == expected


def test_external_file_argument_is_hashed_but_not_archived(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    secret = tmp_path / "credential.txt"
    secret.write_text("PRIVATE")
    value["checks"][0]["argv"] = [
        sys.executable,
        "-c",
        "import pathlib,sys; assert pathlib.Path(sys.argv[1]).read_text() == 'PRIVATE'",
        str(secret),
    ]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    assert run(plan_path, output).returncode == 0
    result = json.loads((output / "result.json").read_text())
    control = next(check for check in result["checks"] if check["kind"] == "control")
    expected = hashlib.sha256(b"PRIVATE").hexdigest()
    for side in ("base", "patched"):
        record = next(item for item in control["runs"][side]["argv_files"] if item["index"] == 3)
        assert record["sha256"] == expected
        assert record["artifact"] is None
        assert "outside the isolated" in record["archive_reason"]
    assert not (output / "helpers" / expected).exists()


def ppv_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_scratch_state_cannot_reveal_base_then_patch_order(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    oracle = (
        "import os, pathlib, sys; "
        "p = pathlib.Path(os.environ['PPV_SCRATCH'], 'seen'); "
        "print('PPV_REACHED', flush=True); "
        "seen = p.exists(); "
        "p.write_text('x'); "
        "sys.exit(0 if seen else 1)"
    )
    for check in value["checks"]:
        if check["kind"] in {"exploit", "variant"}:
            check["argv"] = [sys.executable, "-c", oracle]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    assert run(plan_path, output).returncode == 3
    result = json.loads((output / "result.json").read_text())
    assert result["verdict"]["code"] == "S3"
    for check in result["checks"]:
        if check["kind"] in {"exploit", "variant"}:
            assert check["runs"]["base"]["exit_code"] == 1
            assert check["runs"]["patched"]["exit_code"] == 1
            assert check["runs"]["base"]["scratch"] != check["runs"]["patched"]["scratch"]


def test_plan_directory_state_cannot_reveal_base_then_patch_order(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    oracle = (
        "import os, pathlib, sys; "
        "p = pathlib.Path(os.environ['PPV_PLAN_DIR'], 'seen'); "
        "print('PPV_REACHED', flush=True); "
        "seen = p.exists(); "
        "p.write_text('x'); "
        "sys.exit(0 if seen else 1)"
    )
    for check in value["checks"]:
        if check["kind"] in {"exploit", "variant"}:
            check["argv"] = [sys.executable, "-c", oracle]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    assert run(plan_path, output).returncode == 3
    result = json.loads((output / "result.json").read_text())
    assert result["verdict"]["code"] == "S3"
    for check in result["checks"]:
        if check["kind"] in {"exploit", "variant"}:
            assert check["runs"]["base"]["exit_code"] == 1
            assert check["runs"]["patched"]["exit_code"] == 1


def test_checkout_ancestor_state_cannot_reveal_base_then_patch_order(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    for check in value["checks"]:
        if check["kind"] in {"exploit", "variant"}:
            oracle = (
                "import os, pathlib, sys; "
                "root = pathlib.Path(os.environ['PPV_CHECKOUT']).parent.parent; "
                f"p = root / {check['id']!r}; "
                "print('PPV_REACHED', flush=True); "
                "seen = p.exists(); "
                "p.write_text('x'); "
                "sys.exit(0 if seen else 1)"
            )
            check["argv"] = [sys.executable, "-c", oracle]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    assert run(plan_path, output).returncode == 3
    result = json.loads((output / "result.json").read_text())
    assert result["verdict"]["code"] == "S3"
    for check in result["checks"]:
        if check["kind"] in {"exploit", "variant"}:
            assert check["runs"]["base"]["exit_code"] == 1
            assert check["runs"]["patched"]["exit_code"] == 1


def test_private_plan_copy_excludes_plan_pins_and_prior_results(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    prior = plan_path.parent / "old-results"
    prior.mkdir()
    (prior / "result.json").write_text("{}")
    (prior / "artifact-manifest.json").write_text("{}")
    (prior / "sentinel").write_text("old evidence")
    value["checks"][0]["argv"] = [
        sys.executable,
        "-c",
        "import os,pathlib; p=pathlib.Path(os.environ['PPV_PLAN_DIR']); "
        "assert not (p/'plan.json').exists(); assert not (p/'old-results').exists()",
    ]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    assert run(plan_path, tmp_path / "results").returncode == 0


def test_clean_plan_template_is_not_left_writable_on_disk(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path)
    (plan_path.parent / "template-marker").write_text("snapshot me")
    value["checks"][0]["argv"] = [
        sys.executable,
        "-c",
        "import os,pathlib; root=pathlib.Path(os.environ['PPV_CHECKOUT']).parents[2]; "
        "assert not list(root.glob('ppv-plan-template-*/plan/template-marker'))",
    ]
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    assert run(plan_path, tmp_path / "results").returncode == 0


def test_concurrent_runs_share_repository_without_worktree_races(tmp_path: Path) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan_path = tmp_path / "case" / "plan.json"
    scaffold(repo, plan_path)
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "run",
                "--plan",
                str(plan_path),
                "--output",
                str(tmp_path / f"results-{index}"),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for index in range(2)
    ]
    completed = [process.communicate(timeout=30) + (process.returncode,) for process in processes]
    assert all(returncode == 0 for _, _, returncode in completed), completed
    assert git(repo, "worktree", "list", "--porcelain").count("worktree ") == 1


def test_legacy_pid_worktree_locks_are_reclaimed(tmp_path: Path, ppv) -> None:
    repo, _, _ = create_repo(tmp_path)
    stale = tmp_path / "stale-worktree"
    git(repo, "worktree", "add", "-q", "--detach", str(stale), "HEAD")
    dead_pid = 99_999_999
    assert not ppv.process_is_running(dead_pid)
    git(
        repo,
        "worktree",
        "lock",
        "--reason",
        f"{ppv.WORKTREE_LOCK_REASON_PREFIX}{dead_pid}",
        str(stale),
    )
    shutil.rmtree(stale)

    with ppv.worktree_metadata_lock(repo):
        ppv.unlock_stale_validator_worktrees(repo)

    assert git(repo, "worktree", "list", "--porcelain").count("worktree ") == 1


def test_owner_leases_distinguish_active_and_stale_worktrees(tmp_path: Path, ppv) -> None:
    repo, _, _ = create_repo(tmp_path)
    stale = tmp_path / "leased-worktree"
    git(repo, "worktree", "add", "-q", "--detach", str(stale), "HEAD")
    owner = ppv.acquire_worktree_owner(repo)
    git(
        repo,
        "worktree",
        "lock",
        "--reason",
        f"{ppv.WORKTREE_LOCK_REASON_PREFIX}{owner.token}",
        str(stale),
    )
    assert str(stale) not in ppv.stale_validator_worktrees(repo)

    ppv.close_worktree_owner(owner)
    shutil.rmtree(stale)
    with ppv.worktree_metadata_lock(repo):
        ppv.unlock_stale_validator_worktrees(repo)

    assert git(repo, "worktree", "list", "--porcelain").count("worktree ") == 1


def test_worktree_metadata_lock_io_errors_are_plan_errors(tmp_path: Path, ppv, monkeypatch) -> None:
    repo, _, _ = create_repo(tmp_path)
    original_open = Path.open

    def guarded_open(path: Path, *args, **kwargs):
        if path.name == "post-patch-validation.lock":
            raise PermissionError("fixture denies lock creation")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    with (
        pytest.raises(ppv.PlanError, match="could not open worktree metadata lock"),
        ppv.worktree_metadata_lock(repo),
    ):
        pass


def test_reports_are_verdict_and_evidence_level_specific(ppv) -> None:
    for level in ppv.EVIDENCE_LEVELS:
        for code, (label, exit_code) in ppv.VERDICTS.items():
            result = {
                "finding": {"id": "TEST", "summary": "summary"},
                "inputs": {
                    "base_commit": "0" * 40,
                    "patch_sha256": "0" * 64,
                    "evidence_level": level,
                    "submodules": {},
                    "forwarded_env": {},
                },
                "checks": [],
                "verdict": {
                    "code": code,
                    "label": label,
                    "exit_code": exit_code,
                    "human_review_required": True,
                    "reasons": ["fixture"],
                },
            }
            report = ppv.markdown_report(result)
            assert f"**Evidence level:** {level} — {ppv.EVIDENCE_LEVEL_SUMMARIES[level]}" in report
            assert ppv.VERDICT_SUMMARIES[code] in report
            if code != "S1":
                assert ppv.VERDICT_SUMMARIES["S1"] not in report


def test_patch_inside_pinned_submodule_is_initialized_without_fetch(tmp_path: Path) -> None:
    submodule = tmp_path / "library"
    submodule.mkdir()
    git(submodule, "init", "-q", "-b", "main")
    git(submodule, "config", "user.name", "Fixture")
    git(submodule, "config", "user.email", "fixture@example.invalid")
    (submodule / "app.py").write_text(
        "def sanitize(value):\n    if value is None:\n        return None\n    return value\n"
    )
    git(submodule, "add", "app.py")
    git(submodule, "commit", "-q", "-m", "vulnerable")
    submodule_base = git(submodule, "rev-parse", "HEAD")
    (submodule / "app.py").write_text(
        "def sanitize(value):\n"
        "    if value is None:\n"
        "        return None\n"
        "    return value.replace('<', '&lt;')\n"
    )
    git(submodule, "commit", "-qam", "fix")
    submodule_patch = tmp_path / "submodule.patch"
    submodule_patch.write_bytes(
        subprocess.run(
            [
                "git",
                "diff",
                "--binary",
                "--full-index",
                "--src-prefix=a/vendor/library/",
                "--dst-prefix=b/vendor/library/",
                submodule_base,
                "HEAD",
                "--",
                "app.py",
            ],
            cwd=submodule,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
    )

    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(
        repo,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        "--name",
        "mylib",
        str(submodule),
        "vendor/library",
    )
    git(
        repo,
        "config",
        "-f",
        ".gitmodules",
        "submodule.mylib.url",
        "https://example.invalid/must-not-fetch.git",
    )
    git(repo / "vendor/library", "checkout", "-q", submodule_base)
    git(repo, "add", ".gitmodules", "vendor/library")
    git(repo, "commit", "-q", "-m", "pin vulnerable submodule")
    git(repo, "tag", "vulnerable")

    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path, patch_file=submodule_patch)
    assert value["submodules"] == ["vendor/library"]
    for check in value["checks"]:
        check["cwd"] = "vendor/library"
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    completed = run(plan_path, output)
    assert completed.returncode == 0, completed.stderr
    result = json.loads((output / "result.json").read_text())
    assert result["inputs"]["submodules"] == {
        "vendor/library": {
            "base_commit": submodule_base,
            "patched_commit": submodule_base,
        }
    }
    assert git(repo, "status", "--short") == ""


def test_patch_file_gitlink_bump_checks_out_and_records_patched_pin(tmp_path: Path) -> None:
    submodule = tmp_path / "library"
    submodule.mkdir()
    git(submodule, "init", "-q", "-b", "main")
    git(submodule, "config", "user.name", "Fixture")
    git(submodule, "config", "user.email", "fixture@example.invalid")
    (submodule / "app.py").write_text(
        "def sanitize(value):\n    if value is None:\n        return None\n    return value\n"
    )
    git(submodule, "add", "app.py")
    git(submodule, "commit", "-q", "-m", "vulnerable")
    submodule_base = git(submodule, "rev-parse", "HEAD")
    (submodule / "app.py").write_text(
        "def sanitize(value):\n"
        "    if value is None:\n"
        "        return None\n"
        "    return value.replace('<', '&lt;')\n"
    )
    git(submodule, "commit", "-qam", "fix")
    submodule_fixed = git(submodule, "rev-parse", "HEAD")

    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(
        repo,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        "--name",
        "mylib",
        str(submodule),
        "vendor/library",
    )
    git(repo / "vendor/library", "checkout", "-q", submodule_base)
    git(
        repo,
        "config",
        "-f",
        ".gitmodules",
        "submodule.mylib.url",
        "https://example.invalid/must-not-fetch.git",
    )
    git(repo, "add", ".gitmodules", "vendor/library")
    git(repo, "commit", "-q", "-m", "pin vulnerable submodule")
    git(repo, "tag", "vulnerable")

    git(repo / "vendor/library", "checkout", "-q", submodule_fixed)
    git(repo, "add", "vendor/library")
    gitlink_patch = tmp_path / "gitlink.patch"
    gitlink_patch.write_bytes(
        subprocess.run(
            ["git", "diff", "--cached", "--binary", "--full-index", "--"],
            cwd=repo,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
    )
    git(repo, "reset", "-q", "--hard", "HEAD")
    git(repo / "vendor/library", "checkout", "-q", submodule_base)

    plan_path = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan_path, patch_file=gitlink_patch)
    assert value["submodules"] == ["vendor/library"]
    for check in value["checks"]:
        check["cwd"] = "vendor/library"
    plan_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    output = tmp_path / "results"
    completed = run(plan_path, output)
    assert completed.returncode == 0, completed.stderr
    result = json.loads((output / "result.json").read_text())
    assert result["inputs"]["submodules"] == {
        "vendor/library": {
            "base_commit": submodule_base,
            "patched_commit": submodule_fixed,
        }
    }
