"""Prepare persistent native fixtures and run capability probes."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from catalog import BACKENDS, SCOPES, allowed_backend, canonical_language
from contracts import psalm_fixture, semgrep_fixture
from joern_fixture import joern_fixture
from runner_artifacts import artifact, reserve, write_json
from runner_config import SEMGREP
from runner_contracts import (
    capability_limitations,
    check_probe_baseline,
    expected_sites,
    optional_capabilities,
)

JsonObject = dict[str, Any]


@dataclass
class ProbePlan:
    root: Path
    scope: str = "intraprocedural"
    expect: JsonObject = field(default_factory=dict)
    optional_expect: JsonObject = field(default_factory=dict)
    argv: list[str] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)
    native_output: Path | None = None
    version_argv: list[str] | None = None
    baseline_argv: list[str] | None = None


def semgrep_command(executable: str, backend: str, root: Path, file: str) -> list[str]:
    import runner

    _, help_out, help_err, _ = runner.execute([executable, "scan", "--help"], root, 30)
    help_text = help_out + help_err
    flags = []
    if backend == "semgrep":
        if "--oss-only" in help_text:
            flags = ["--oss-only"]
        elif "--oss" in help_text:
            flags = ["--oss"]
    elif backend == "semgrep-pro":
        flags = ["--pro-languages"]
    return [
        executable,
        "scan",
        *flags,
        "--json",
        "--dataflow-traces",
        *(["--metrics=off"] if backend != "opengrep" else []),
        "--no-git-ignore",
        "--config",
        "rule.json",
        file,
    ]


def expand_command(command: Any, root: Path) -> list[str]:
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(arg, str) and arg for arg in command)
    ):
        raise ValueError("Contract commands must be nonempty argument arrays")
    return [
        arg.replace("{fixture_root}", str(root)).replace("{workdir}", str(root)) for arg in command
    ]


def custom_plan(plan: ProbePlan, contract: Path, backend: str, language: str) -> None:
    data = json.loads(contract.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Capability contract must be a JSON object")
    if data.get("backend") != backend or canonical_language(
        data.get("language", "")
    ) != canonical_language(language):
        raise ValueError("Capability contract language/backend mismatch")
    source = (contract.parent / data["fixture_root"]).resolve()
    if not source.is_dir() or plan.root.is_relative_to(source):
        raise ValueError("Fixture source must be a separate, existing directory")
    shutil.copytree(source, plan.root, dirs_exist_ok=True)
    plan.scope, plan.expect = data["scope"], data["expect"]
    commands = data["commands"]
    if not isinstance(commands, list) or not commands:
        raise ValueError("Capability contract has no native commands")
    plan.commands = [expand_command(command, plan.root) for command in commands]
    plan.argv = plan.commands[-1]
    if data.get("version_command"):
        plan.version_argv = expand_command(data["version_command"], plan.root)
    if data.get("native_output"):
        plan.native_output = Path(expand_command([data["native_output"]], plan.root)[0])
        if not (plan.root / plan.native_output).resolve().is_relative_to(plan.root):
            raise ValueError("Probe native output must stay inside its fixture directory")


def psalm_plan(plan: ProbePlan, executable: str) -> None:
    fixture = psalm_fixture(plan.root)
    plan.scope, plan.expect = fixture["scope"], fixture["expect"]
    plan.optional_expect = fixture["optional_expect"]
    plan.argv = [
        executable,
        "--taint-analysis",
        "--debug",
        "--no-cache",
        "--output-format=json",
        f"--config={plan.root / 'psalm.xml'}",
    ]
    plan.baseline_argv = [*plan.argv[:-1], f"--config={plan.root / fixture['baseline_config']}"]


def builtin_plan(plan: ProbePlan, backend: str, language: str, executable: str | None) -> None:
    if backend in SEMGREP:
        fixture = semgrep_fixture(plan.root, language)
        plan.scope, plan.expect = fixture["scope"], fixture["expect"]
        plan.argv = semgrep_command(
            executable or BACKENDS[backend]["executable"], backend, plan.root, fixture["file"]
        )
    elif backend == "psalm":
        psalm_plan(plan, executable or "psalm")
    elif backend == "joern":
        fixture = joern_fixture(plan.root, language, executable or "joern")
        plan.scope, plan.expect = fixture["scope"], fixture["expect"]
        plan.commands = fixture["commands"]
        plan.argv, plan.version_argv = plan.commands[-1], fixture["version_command"]
        plan.native_output = Path(fixture["native_output"])
    else:
        raise ValueError(f"{backend} requires a real backend-specific capability contract")


def prepare_commands(plan: ProbePlan, output: Path, errors: list[str]) -> list[JsonObject]:
    import runner

    preparation = []
    for index, command in enumerate(plan.commands[:-1]):
        rc, stdout, stderr, step_errors = runner.execute(command, plan.root, 300)
        captured: JsonObject = {"argv": command, "returncode": rc}
        for name, value in (("stdout", stdout), ("stderr", stderr)):
            path = output.with_name(f"{output.name}.prepare-{index}.{name}")
            path.write_text(value, encoding="utf-8")
            captured[name] = artifact(path)
        preparation.append(captured)
        errors.extend(step_errors)
        if rc != 0:
            errors.append(f"Probe preparation command failed: {command}")
            break
    return preparation


def initialize_plan(
    plan: ProbePlan,
    backend: str,
    language: str,
    output: Path,
    contract: Path | None,
    executable: str | None,
    errors: list[str],
) -> tuple[list[JsonObject], list[JsonObject]]:
    fixture_files, preparation = [], []
    try:
        if not allowed_backend(backend, language):
            raise ValueError(f"Unsupported language/backend combination: {language}/{backend}")
        if contract:
            custom_plan(plan, contract.resolve(), backend, language)
        else:
            builtin_plan(plan, backend, language, executable)
        if plan.scope not in SCOPES:
            raise ValueError(f"Unknown capability scope: {plan.scope}")
        fixture_files = [artifact(path) for path in sorted(plan.root.rglob("*")) if path.is_file()]
        preparation = prepare_commands(plan, output, errors)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        errors.append(str(exc))
    return fixture_files, preparation


def probe_record(
    plan: ProbePlan,
    backend: str,
    language: str,
    run_path: Path,
    fixture_files: list[JsonObject],
    preparation: list[JsonObject],
    errors: list[str],
) -> JsonObject:
    return {
        "schema_version": 1,
        "kind": "probe",
        "backend": backend,
        "language": canonical_language(language),
        "scope": plan.scope,
        "status": "failed",
        "run": str(run_path),
        "fixture_root": str(plan.root),
        "expect": plan.expect,
        "optional_expect": plan.optional_expect,
        "optional_capabilities": {},
        "limitations": [],
        "fixture_files": fixture_files,
        "preparation": preparation,
        "errors": errors,
    }


def probe_baseline(plan: ProbePlan, proof: JsonObject, output: Path, errors: list[str]) -> None:
    import runner

    if plan.baseline_argv is None:
        return
    baseline_path = output.with_name(output.name + ".baseline.json")
    proof.update(profile="psalm-taint-contracts-v3", baseline_run=str(baseline_path))
    if errors:
        return
    baseline = runner.run_native(
        backend=proof["backend"],
        language=proof["language"],
        phase="baseline",
        scope=plan.scope,
        output=baseline_path,
        argv=plan.baseline_argv,
        cwd=plan.root,
    )
    errors.extend(runner.check_run(baseline, baseline_path))
    if baseline.get("findings"):
        errors.append("Unmodeled capability baseline unexpectedly reported taint findings")


def probe_target(plan: ProbePlan, proof: JsonObject, contract: Path | None) -> None:
    import runner

    path = Path(proof["run"])
    models = [plan.root / "probe.php"] if proof["backend"] == "psalm" and contract is None else []
    run = runner.run_native(
        backend=proof["backend"],
        language=proof["language"],
        phase="probe",
        scope=plan.scope,
        output=path,
        argv=plan.argv,
        cwd=plan.root,
        native_output=plan.native_output,
        version_argv=plan.version_argv,
        models=models,
    )
    proof["errors"].extend(runner.check_run(run, path))
    proof["errors"].extend(expected_sites(proof, run))
    proof["errors"].extend(check_probe_baseline(proof, run))
    capabilities = optional_capabilities(proof, run)
    limitations = capability_limitations(capabilities)
    proof["optional_capabilities"] = capabilities
    proof["limitations"] = list(dict.fromkeys([*run["limitations"], *limitations]))
    if limitations:
        run["limitations"] = list(dict.fromkeys([*run["limitations"], *limitations]))
        if run["status"] != "failed":
            run["status"] = "limited"
        write_json(path, run)


def probe(
    *,
    backend: str,
    language: str,
    output: Path,
    contract: Path | None = None,
    executable: str | None = None,
) -> JsonObject:
    output = reserve(output)
    plan = ProbePlan(output.with_name(output.name + ".fixtures"))
    plan.root.mkdir()
    errors: list[str] = []
    files, preparation = initialize_plan(
        plan, backend, language, output, contract, executable, errors
    )
    proof = probe_record(
        plan,
        backend,
        language,
        output.with_name(output.name + ".run.json"),
        files,
        preparation,
        errors,
    )
    probe_baseline(plan, proof, output, errors)
    if not errors:
        probe_target(plan, proof, contract)
    proof["status"] = "failed" if errors else "passed"
    write_json(output, proof)
    return proof
