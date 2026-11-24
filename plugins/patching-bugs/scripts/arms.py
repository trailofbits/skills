# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""Build baseline, patched and reverted commits in isolated worktrees."""

import argparse
import hashlib
import json
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from records import write_manifest


class Arm(TypedDict):
    name: str
    commit: str
    build_exit: int | None
    diagnostic_matched: bool
    artifact_sha256: str | None
    loaded_identity: bool
    reached: bool
    exit_code: int | None


@dataclass
class ArmSpec:
    build_argv: list[str]
    poc_argv: list[str]
    target_artifact: str | None
    timeout_s: int = 600
    failure_type: str = "runtime"
    expected_diagnostic: str | None = None


def _validate_spec(spec: ArmSpec) -> None:
    if not spec.build_argv or spec.failure_type not in {"runtime", "compile"}:
        raise ValueError("build_argv and a runtime or compile failure_type are required")
    if spec.failure_type == "compile":
        if not spec.expected_diagnostic or not spec.expected_diagnostic.strip():
            raise ValueError("compile proof requires a nonempty expected_diagnostic")
        if spec.poc_argv or spec.target_artifact is not None:
            raise ValueError("compile proof requires empty poc_argv and null target_artifact")
        return
    if not spec.poc_argv or not spec.target_artifact:
        raise ValueError("runtime proof requires poc_argv and target_artifact")
    artifact = Path(spec.target_artifact)
    if artifact.is_absolute() or ".." in artifact.parts:
        raise ValueError("target_artifact must stay inside each worktree")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _run(argv: list[str], cwd: Path, out: Path, timeout_s: int) -> tuple[int | None, str, str]:
    started = time.monotonic()
    try:
        result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout_s, check=False)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        code, stdout, stderr = None, exc.stdout or b"", exc.stderr or b""
    except OSError as exc:
        code, stdout, stderr = None, b"", str(exc).encode()
    out.mkdir(parents=True, exist_ok=True)
    (out / "stdout.txt").write_bytes(stdout)
    (out / "stderr.txt").write_bytes(stderr)
    (out / "exit.json").write_text(
        json.dumps({"exit_code": code, "elapsed_s": round(time.monotonic() - started, 3)}) + "\n"
    )
    return code, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _loaded_matches(stdout: str, artifact: Path, digest: str | None) -> bool:
    lines = [
        line.removeprefix("PATCH_LOADED ")
        for line in stdout.splitlines()
        if line.startswith("PATCH_LOADED ")
    ]
    if len(lines) != 1 or digest is None:
        return False
    try:
        observation = json.loads(lines[0])
    except json.JSONDecodeError:
        return False
    if not isinstance(observation, dict) or not isinstance(observation.get("path"), str):
        return False
    loaded = Path(observation["path"])
    return (
        loaded.is_absolute()
        and loaded.resolve() == artifact.resolve()
        and observation.get("sha256") == digest
        and hashlib.sha256(artifact.read_bytes()).hexdigest() == digest
    )


def _arm(name: str, worktree: Path, commit: str, spec: ArmSpec, out: Path) -> Arm:
    build_code, stdout, stderr = _run(spec.build_argv, worktree, out / "build", spec.timeout_s)
    matched = bool(spec.expected_diagnostic and spec.expected_diagnostic in stdout + stderr)
    arm: Arm = {
        "name": name,
        "commit": commit,
        "build_exit": build_code,
        "diagnostic_matched": matched,
        "artifact_sha256": None,
        "loaded_identity": False,
        "reached": False,
        "exit_code": None,
    }
    if spec.failure_type == "compile":
        arm["reached"] = build_code == 0 or (build_code is not None and build_code > 0 and matched)
        arm["exit_code"] = build_code
    elif build_code == 0:
        _runtime_arm(arm, worktree, spec, out)
    (out / "arm.json").write_text(json.dumps(arm, indent=2) + "\n")
    return arm


def _runtime_arm(arm: Arm, worktree: Path, spec: ArmSpec, out: Path) -> None:
    assert spec.target_artifact is not None
    artifact = worktree / spec.target_artifact
    if (
        artifact.is_file()
        and not artifact.is_symlink()
        and artifact.resolve().is_relative_to(worktree)
    ):
        arm["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    code, stdout, _ = _run(spec.poc_argv, worktree, out / "poc", spec.timeout_s)
    arm["reached"] = "PATCH_REACHED" in stdout.splitlines()
    arm["exit_code"] = code
    try:
        arm["loaded_identity"] = _loaded_matches(stdout, artifact, arm["artifact_sha256"])
    except (OSError, ValueError):
        arm["loaded_identity"] = False


def _result(arms: dict[str, Arm], failure_type: str) -> dict:
    baseline, patched, reverted = (arms[name] for name in ("baseline", "patched", "reverted"))
    hashes = {name: arm["artifact_sha256"] for name, arm in arms.items()}
    identity = (
        "pass"
        if all(arm["loaded_identity"] for arm in arms.values())
        and baseline["artifact_sha256"] != patched["artifact_sha256"]
        else "fail"
    )
    if not all(arm["reached"] for arm in arms.values()):
        revert_status = "inconclusive"
    elif (
        baseline["exit_code"] not in (None, 0)
        and reverted["exit_code"] == baseline["exit_code"]
        and patched["exit_code"] == 0
    ):
        revert_status = "pass"
    else:
        revert_status = "fail"
    note = None
    if reverted["artifact_sha256"] != baseline["artifact_sha256"]:
        note = "reverted artifact differs from baseline"
    return {
        "failure_type": failure_type,
        "reverted": revert_status,
        "build_identity": "not_applicable" if failure_type == "compile" else identity,
        "hashes": hashes,
        "reverted_hash_note": note,
    }


def _restore_baseline(root: Path, baseline: str, patch_commit: str, out: Path) -> None:
    reverted = root / "reverted"
    # Only this helper-owned worktree is reset. Its entire tracked tree is the baseline.
    _git(reverted, "read-tree", "--reset", "-u", baseline)
    trees = {name: _git(root / name, "write-tree") for name in ("baseline", "patched", "reverted")}
    if trees["reverted"] != trees["baseline"]:
        raise ValueError("reverted tree does not match the original baseline")
    _git(reverted, "diff", "--exit-code")
    receipts = out / "receipts"
    receipts.mkdir(exist_ok=True)
    (receipts / "source.json").write_text(
        json.dumps(
            {"baseline_commit": baseline, "patch_commit": patch_commit, "trees": trees}, indent=2
        )
        + "\n"
    )


def run_arms(repo: Path, baseline: str, patch_commit: str, spec: ArmSpec, out: Path) -> dict:
    """Run three arms without changing the caller checkout."""
    _validate_spec(spec)
    baseline = _git(repo, "rev-parse", "--verify", f"{baseline}^{{commit}}")
    patch_commit = _git(repo, "rev-parse", "--verify", f"{patch_commit}^{{commit}}")
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="patch-arms-", dir=out.parent) as temp:
        root = Path(temp)
        created = []
        try:
            for name, commit in (
                ("baseline", baseline),
                ("patched", patch_commit),
                ("reverted", patch_commit),
            ):
                path = root / name
                _git(repo, "worktree", "add", "--detach", str(path), commit)
                created.append(path)
            _restore_baseline(root, baseline, patch_commit, out)
            arms = {
                name: _arm(name, root / name, commit, spec, out / "receipts" / name)
                for name, commit in (
                    ("baseline", baseline),
                    ("patched", patch_commit),
                    ("reverted", patch_commit),
                )
            }
            write_manifest(out)
            return _result(arms, spec.failure_type)
        finally:
            for path in reversed(created):
                _git(repo, "worktree", "remove", "--force", str(path))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run"])
    for name in ("repo", "baseline", "patch", "build", "out"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--poc", default="[]")
    parser.add_argument("--artifact")
    parser.add_argument("--failure-type", choices=["runtime", "compile"], default="runtime")
    parser.add_argument("--expected-diagnostic")
    args = parser.parse_args()
    result = run_arms(
        Path(args.repo),
        args.baseline,
        args.patch,
        ArmSpec(
            json.loads(args.build),
            json.loads(args.poc),
            args.artifact,
            failure_type=args.failure_type,
            expected_diagnostic=args.expected_diagnostic,
        ),
        Path(args.out),
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
