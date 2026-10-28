"""Check native invocation contracts without interpreting or propagating taint."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

NAMES = {
    "psalm": r"psalm(?:-\d+(?:\.\d+)*)?(?:\.phar)?",
    "pysa": r"pyre",
    "clang": r"clang(?:\+\+)?(?:-[\d.]+)?",
    "infer": r"infer",
    "joern": r"joern",
    "checker-framework": r"javac(?:-[\d.]+)?",
    "semgrep": r"semgrep",
    "semgrep-pro": r"semgrep",
    "opengrep": r"opengrep",
    "codeql": r"codeql",
}
PRO_FLAGS = {"--pro", "--pro-intrafile", "--pro-languages", "--pro-path-sensitive"}
UV_VALUED = {
    "--project",
    "--directory",
    "--with",
    "--with-editable",
    "--with-requirements",
    "--python",
    "--extra",
    "--group",
    "--env-file",
    "--index",
    "--index-url",
    "--default-index",
    "--from",
    "--package",
}


def name_matches(value: str, pattern: str) -> bool:
    return bool(re.fullmatch(pattern + r"(?:\.exe|\.cmd|\.bat)?", Path(value).name))


def uv_prefix(argv: list[str]) -> int:
    if argv[1:2] == ["run"]:
        index = 2
    elif argv[1:3] == ["tool", "run"]:
        index = 3
    else:
        raise ValueError("uv must launch the native analyzer with run or tool run")
    while index < len(argv) and argv[index].startswith("-"):
        if argv[index] == "--":
            return index + 1
        index += 2 if argv[index] in UV_VALUED else 1
    return index


def php_prefix(argv: list[str], index: int) -> int:
    index += 1
    while index < len(argv) and argv[index].startswith("-"):
        option = argv[index]
        if option in {"-d", "-c", "--define", "--php-ini"}:
            index += 2
        elif option in {"-n", "-q", "-f"} or option.startswith(("-d", "-c")):
            index += 1
        else:
            raise ValueError("PHP must launch the Psalm script, not evaluate PHP code")
    return index


def invocation(backend: str, argv: list[str]) -> tuple[list[str], list[str]]:
    """Keep interpreter/environment prefixes tied to the native executable."""
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise ValueError("Native command must be a nonempty argument array")
    index = uv_prefix(argv) if name_matches(argv[0], r"uv") else 0
    if backend == "psalm" and index < len(argv) and name_matches(argv[index], r"php[\d.]*"):
        index = php_prefix(argv, index)
    if index >= len(argv) or not name_matches(argv[index], NAMES.get(backend, r"(?!)")):
        raise ValueError(f"Native executable does not match selected backend {backend}")
    return argv[: index + 1], argv[index + 1 :]


def option_values(args: list[str], option: str) -> list[str]:
    values = []
    for index, arg in enumerate(args):
        if arg == option and index + 1 < len(args):
            values.append(args[index + 1])
        elif arg.startswith(option + "="):
            values.append(arg.split("=", 1)[1])
    return values


def clang_errors(args: list[str], flags: set[str]) -> list[str]:
    errors = []
    if not flags & {"--analyze", "-analyze"}:
        errors.append("Clang target invocation must enable static analyzer mode")
    checkers = {c for value in option_values(args, "-analyzer-checker") for c in value.split(",")}
    if not checkers & {"optin", "optin.taint", "optin.taint.GenericTaint"}:
        errors.append("Clang target invocation must enable optin.taint.GenericTaint")
    disabled = option_values(args, "-analyzer-disable-checker")
    if any("taint" in value or value == "optin" for value in disabled):
        errors.append("Clang target invocation disables a required taint checker")
    if "-analyzer-disable-all-checks" in flags:
        errors.append("Clang target invocation disables all analyzer checks")
    return errors


def infer_errors(args: list[str], flags: set[str]) -> list[str]:
    errors = []
    if not flags & {"--pulse", "--pulse-only"} or "--no-pulse" in flags:
        errors.append("Infer target invocation must explicitly enable Pulse")
    if args and args[0] in {"capture", "report", "compile", "explore", "help"}:
        errors.append("Infer capture/report commands do not execute Pulse analysis")
    if any(flag.endswith("-only") and flag != "--pulse-only" for flag in flags):
        errors.append("Infer target invocation selects a different checker exclusively")
    return errors


def checker_errors(args: list[str], flags: set[str]) -> list[str]:
    errors = []
    processors = {p for value in option_values(args, "-processor") for p in value.split(",")}
    if not processors & {
        "TaintingChecker",
        "org.checkerframework.checker.tainting.TaintingChecker",
    }:
        errors.append("Checker Framework target invocation must select TaintingChecker")
    if "-proc:none" in flags:
        errors.append("javac -proc:none disables the TaintingChecker processor")
    return errors


def direct_errors(backend: str, args: list[str]) -> list[str]:
    requirements = {
        "psalm": (
            "--taint-analysis" in args,
            "Psalm target invocation must enable --taint-analysis",
        ),
        "pysa": ("analyze" in args, "Pysa target invocation must run pyre analyze"),
        "joern": (
            bool(option_values(args, "--script")),
            "Joern target invocation must execute the native dataflow query with --script",
        ),
        "codeql": (
            args[:2] == ["database", "analyze"],
            "CodeQL target invocation must execute database analyze",
        ),
    }
    valid, message = requirements.get(backend, (True, ""))
    return [] if valid else [message]


def scan_errors(backend: str, args: list[str], flags: set[str]) -> list[str]:
    errors = []
    if args and not args[0].startswith("-") and args[0] != "scan":
        errors.append("Semgrep/OpenGrep target invocation must run a scan")
    if flags & {"--validate", "--test", "--dump-ast", "--show-supported-languages"}:
        errors.append("Semgrep/OpenGrep command validates or inspects without scanning")
    if backend in {"semgrep", "opengrep"} and flags & PRO_FLAGS:
        errors.append("Selected backend cannot activate these analysis-mode flags")
    return errors


def opengrep_scope_errors(flags: set[str], scope: str) -> list[str]:
    if scope not in {"intraprocedural", "intrafile"}:
        return ["OpenGrep scope cannot exceed cross-function analysis within a file"]
    if scope == "intrafile" and "--taint-intrafile" not in flags:
        return ["OpenGrep intrafile scope requires --taint-intrafile activation"]
    return []


def extended_semgrep_mode(flags: set[str], scope: str) -> tuple[str, list[str]]:
    pro, errors = flags & PRO_FLAGS, []
    if not pro or flags & {"--oss", "--oss-only"}:
        errors.append("Selected Semgrep mode requires explicit activation without OSS flags")
    if "--pro" in pro:
        engine, supported = (
            "semgrep-pro-interfile",
            {"intraprocedural", "intrafile", "interprocedural"},
        )
    elif pro & {"--pro-intrafile", "--pro-path-sensitive"}:
        engine, supported = "semgrep-pro-intrafile", {"intraprocedural", "intrafile"}
    else:
        engine, supported = "semgrep-pro-languages", {"intraprocedural"}
    if scope not in supported:
        errors.append("Requested scope exceeds the activated Semgrep analysis mode")
    return engine, errors


def semgrep_contract(
    backend: str,
    args: list[str],
    flags: set[str],
    scope: str,
) -> tuple[str, list[str]]:
    errors = scan_errors(backend, args, flags)
    if backend == "semgrep":
        if scope != "intraprocedural":
            errors.append("This invocation enables only intraprocedural taint scope")
        return "semgrep-ce", errors
    if backend == "opengrep":
        return backend, errors + opengrep_scope_errors(flags, scope)
    engine, scope_errors = extended_semgrep_mode(flags, scope)
    return engine, errors + scope_errors


CHECKERS: dict[str, Callable[[list[str], set[str]], list[str]]] = {
    "clang": clang_errors,
    "infer": infer_errors,
    "checker-framework": checker_errors,
}


def command_contract(backend: str, argv: list[str], scope: str) -> tuple[str, list[str]]:
    """Require target runs, as well as fixtures, to activate selected analysis."""
    try:
        _, args = invocation(backend, argv)
    except ValueError as exc:
        return backend, [str(exc)]
    args = args[: args.index("--")] if "--" in args else args
    if backend == "clang":
        args = [arg for arg in args if arg != "-Xclang"]
    flags = {arg.split("=", 1)[0] for arg in args if arg.startswith("-")}
    errors = []
    if flags & {"--help", "-h", "--version", "-version"}:
        errors.append("Native command requests help/version rather than taint analysis")
    if backend in {"semgrep", "semgrep-pro", "opengrep"}:
        engine, scan = semgrep_contract(backend, args, flags, scope)
        return engine, errors + scan
    checker = CHECKERS.get(backend)
    errors += checker(args, flags) if checker else direct_errors(backend, args)
    return backend, errors


def reported_engines(raw: str) -> list[Any]:
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []  # Invalid native output is rejected by the format reader.
    if not isinstance(data, dict) or not isinstance(data.get("results", []), list):
        return []
    engines = [data.get("engine_requested")]
    for result in data.get("results", []):
        if isinstance(result, dict) and isinstance(result.get("extra", {}), dict):
            engines.append(result.get("extra", {}).get("engine_kind"))
    return engines


def engine_name(value: Any) -> str:
    if isinstance(value, list) and value:
        value = value[0]  # Native PRO_REQUIRED includes a feature object after the tag.
    return value if isinstance(value, str) else ""


def reported_engine_errors(raw: str, backend: str) -> list[str]:
    """Reject analysis-mode mismatches disclosed in native JSON."""
    if backend not in {"semgrep", "semgrep-pro"}:
        return []
    for value in reported_engines(raw):
        name = engine_name(value)
        mismatch = (backend == "semgrep" and "PRO" in name.upper()) or (
            backend == "semgrep-pro" and name.upper() == "OSS"
        )
        if mismatch:
            return [f"Native reported engine {name} disagrees with selected backend {backend}"]
    return []
