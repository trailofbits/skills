"""Capture and validate native model/configuration bindings."""

from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml

from catalog import canonical_language
from runner_artifacts import artifact

SEMGREP = {"semgrep", "semgrep-pro", "opengrep"}
JsonObject = dict[str, Any]


def option_values(argv: list[str], options: set[str]) -> list[str]:
    values = []
    for index, arg in enumerate(argv):
        if arg in options and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif arg.split("=", 1)[0] in options and "=" in arg:
            values.append(arg.split("=", 1)[1])
    return values


def rule_files(argv: list[str], cwd: Path) -> list[Path]:
    configs = option_values(argv, {"-c", "-f", "--config"})
    if not configs:
        raise ValueError("Semgrep/OpenGrep needs explicit local taint configuration")
    files = []
    for config in configs:
        path = (cwd / config).resolve()
        if path.is_dir():
            files.extend(p for p in path.rglob("*") if p.suffix in {".yml", ".yaml", ".json"})
        elif path.is_file():
            files.append(path)
        else:
            raise ValueError(f"Rule configuration is not a local file/directory: {config}")
    return sorted(set(files))


def applicable_rule(rule: Any, language: str) -> bool:
    if not isinstance(rule, dict) or rule.get("mode") != "taint":
        return False
    languages = rule.get("languages", [])
    return isinstance(languages, list) and any(
        canonical_language(str(item)) == canonical_language(language) for item in languages
    )


def rule_ids(path: Path, language: str) -> list[str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise TypeError(f"Rule file has no rules array: {path}")
    ids = []
    for rule in data["rules"]:
        if not applicable_rule(rule, language):
            continue
        if not rule.get("id") or not rule.get("pattern-sources") or not rule.get("pattern-sinks"):
            raise ValueError(f"Incomplete applicable taint rule in {path}")
        ids.append(str(rule["id"]))
    return ids


def rule_excluded(rule: str, excluded: list[str]) -> bool:
    return any(
        rule == item or item.endswith("." + rule) or rule.endswith("." + item) for item in excluded
    )


def taint_rules(argv: list[str], cwd: Path, language: str) -> tuple[list[str], list[Path]]:
    """Resolve loaded local taint rules and retain explicit rule exclusions."""
    files = rule_files(argv, cwd)
    excluded = option_values(argv, {"--exclude-rule"})
    ids = [
        rule
        for path in files
        for rule in rule_ids(path, language)
        if not rule_excluded(rule, excluded)
    ]
    if not files or not ids:
        raise ValueError("Zero applicable mode: taint rules with sources and sinks were loaded")
    return sorted(set(ids)), files


def psalm_config(argv: list[str], cwd: Path) -> Path:
    values = option_values(argv, {"--config", "-c"})
    if values:
        return (cwd / values[0]).resolve()
    for name in ("psalm.xml", "psalm.xml.dist"):
        if (cwd / name).is_file():
            return cwd / name
    raise ValueError("Psalm models require a readable native XML configuration")


def xml_paths(element: ET.Element, base: Path) -> list[tuple[Path, bool]]:
    entries = []
    for item in element:
        tag, name = item.tag.rsplit("}", 1)[-1], item.get("name")
        if tag in {"file", "directory"} and name:
            entries.append(((base / name).resolve(), tag == "directory"))
    return entries


def psalm_inputs(config: Path, original: Path, cwd: Path) -> dict[str, list[tuple[Path, bool]]]:
    tree = ET.parse(config).getroot()
    base = cwd if tree.get("resolveFromConfigFile") == "false" else original.parent
    inputs: dict[str, list[tuple[Path, bool]]] = {"included": [], "excluded": [], "stubbed": []}
    for section in tree:
        tag = section.tag.rsplit("}", 1)[-1]
        if tag == "stubs":
            inputs["stubbed"].extend(xml_paths(section, base))
        elif tag in {"projectFiles", "extraFiles"}:
            inputs["included"].extend(xml_paths(section, base))
            for child in section:
                if child.tag.rsplit("}", 1)[-1] == "ignoreFiles":
                    inputs["excluded"].extend(xml_paths(child, base))
    return inputs


def matches_path(path: Path, entries: list[tuple[Path, bool]]) -> bool:
    return any(
        path == candidate or (directory and path.is_relative_to(candidate))
        for candidate, directory in entries
    )


def psalm_model_errors(
    config: Path, original: Path, cwd: Path, models: list[JsonObject]
) -> list[str]:
    inputs = psalm_inputs(config, original, cwd)
    return [
        "Psalm model is absent from configured source roots/stubs or is ignored: "
        f"{item['original_path']}"
        for item in models
        if not matches_path(Path(item["original_path"]), inputs["stubbed"])
        and (
            not matches_path(Path(item["original_path"]), inputs["included"])
            or matches_path(Path(item["original_path"]), inputs["excluded"])
        )
    ]


def argument_binds(path: Path, argv: list[str], cwd: Path, backend: str) -> bool:
    values = option_values(argv, {"--pulse-taint-config"}) if backend == "infer" else []
    if backend == "clang":
        values.extend(arg.split(":Config=", 1)[1] for arg in argv if ":Config=" in arg)
    return any((cwd / value).resolve() == path for value in values)


def snapshot_files(output: Path, paths: list[Path], kind: str) -> list[JsonObject]:
    captured = []
    for index, path in enumerate(paths):
        snapshot = output.with_name(f"{output.name}.{kind}-{index}{path.suffix}")
        shutil.copyfile(path, snapshot)
        captured.append({**artifact(snapshot), "original_path": str(path)})
    return captured


def capture_configuration(
    backend: str,
    language: str,
    argv: list[str],
    cwd: Path,
    output: Path,
    models: list[JsonObject],
) -> tuple[list[JsonObject], list[str], list[str], list[str]]:
    if backend in SEMGREP:
        ids, rules = taint_rules(argv, cwd, language)
        errors = [
            "Model file is not in the loaded rule configuration: " + item["original_path"]
            for item in models
            if Path(item["original_path"]) not in rules
        ]
        return snapshot_files(output, rules, "config"), ids, errors, []
    if backend == "psalm":
        config = psalm_config(argv, cwd)
        configs = snapshot_files(output, [config], "config")
        errors = psalm_model_errors(Path(configs[0]["path"]), config, cwd, models)
        return configs, [], errors, []
    return [], [], *model_binding(backend, argv, cwd, models)


def model_binding(
    backend: str, argv: list[str], cwd: Path, models: list[JsonObject]
) -> tuple[list[str], list[str]]:
    if not models:
        return [], []
    if backend in {"clang", "infer"}:
        errors = [
            "Native model configuration is not bound in analyzer arguments: "
            + item["original_path"]
            for item in models
            if not argument_binds(Path(item["original_path"]), argv, cwd, backend)
        ]
        return errors, []
    return [], [
        "Native model discovery requires review of this backend's config/pack loading; "
        "snapshot capture alone does not establish that each model was consumed."
    ]


def check_semgrep_configuration(record: JsonObject, cwd: Path) -> list[str]:
    snapshots = [item["path"] for item in record.get("config_files", [])]
    config_argv = [arg for path in snapshots for arg in ("--config", path)]
    for excluded in option_values(record["argv"], {"--exclude-rule"}):
        config_argv.extend(["--exclude-rule", excluded])
    ids, _ = taint_rules(config_argv, cwd, record["language"])
    errors = []
    if ids != record.get("taint_rule_ids", []):
        errors.append("Recorded taint rule IDs disagree with captured configuration")
    captured = {Path(item["original_path"]).resolve() for item in record["config_files"]}
    errors.extend(check_rule_bindings(record, cwd, captured))
    return errors


def check_rule_bindings(record: JsonObject, cwd: Path, captured: set[Path]) -> list[str]:
    targets = [
        (cwd / value).resolve() for value in option_values(record["argv"], {"-c", "-f", "--config"})
    ]
    if (
        not targets
        or any(not any(path.is_relative_to(target) for target in targets) for path in captured)
        or any(not any(path.is_relative_to(target) for path in captured) for target in targets)
    ):
        return ["Rule configuration snapshots are not bound to the native command"]
    return [
        "Model file is not in the loaded rule configuration: " + item["original_path"]
        for item in record.get("model_files", [])
        if Path(item["original_path"]).resolve() not in captured
    ]


def check_psalm_configuration(record: JsonObject, cwd: Path) -> list[str]:
    configs = record.get("config_files", [])
    if len(configs) != 1:
        return ["Psalm run has no captured native XML configuration"]
    errors = []
    config = configs[0]
    if Path(config["original_path"]) != psalm_config(record["argv"], cwd):
        errors.append("Psalm configuration snapshot is not bound to the native command")
    errors.extend(
        psalm_model_errors(
            Path(config["path"]), Path(config["original_path"]), cwd, record["model_files"]
        )
    )
    return errors


def check_configuration(record: JsonObject, cwd: Path) -> list[str]:
    backend = record["backend"]
    if backend in SEMGREP:
        return check_semgrep_configuration(record, cwd)
    if backend == "psalm":
        return check_psalm_configuration(record, cwd)
    errors, limitations = model_binding(backend, record["argv"], cwd, record.get("model_files", []))
    if limitations and record.get("status") != "limited":
        errors.append("Review-driven native model discovery cannot be reported as fully analyzed")
    return errors
